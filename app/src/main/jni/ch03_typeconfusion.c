/*
 * Challenge 03: JNI Type Confusion
 * Difficulty: 3/5
 *
 * The gate functions take loosely typed Java arguments. Gate 1 is
 * declared for a String, but the native side accepts any jobject.
 * When a specially crafted byte[] is passed instead of a String, the
 * type mismatch triggers an alternate code path.
 *
 * The challenge has 4 "gates" -- each gate leaks a fragment of the key
 * when triggered with the right type confusion. Combine all 4 fragments
 * to reconstruct the flag.
 *
 * To solve:
 *   1. Reverse the .so to understand the 4 gate conditions
 *   2. Use Frida to call native functions with wrong types
 *   3. Collect leaked key fragments from each gate
 *   4. XOR fragments together with the master key to get the flag
 */

#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>
#include "flag_core.h"

#define TAG "ch03"

/* Key fragments -- leaked by type confusion on each gate */
static const uint8_t fragment_a[10] = {0xc9, 0xa1, 0xf3, 0xd7, 0xe2, 0x04, 0x5b, 0x86, 0xa3, 0xc7};
static const uint8_t fragment_b[10] = {0xe1, 0xd4, 0x9f, 0x02, 0xb5, 0x68, 0x7d, 0x4e, 0xa3, 0xc1};
static const uint8_t fragment_c[10] = {0x92, 0x3a, 0x7c, 0xb0, 0x18, 0xd5, 0xe9, 0x46, 0xf3, 0x01};
static const uint8_t fragment_d[10] = {0x55, 0x8e, 0x2b, 0xc4, 0x71, 0xa9, 0x3f, 0xd0, 0x67, 0xbc};

/*
 * Master XOR key for combining fragments.
 * Written by scripts/gen_flags.py. Do not edit by hand.
 */
/* gen_flags begin master_key */
static const uint8_t master_key[40] = {
    0xfe, 0xc7, 0xc4, 0xb6, 0x81, 0x35, 0x6c, 0xb6,
    0x94, 0xa3, 0x80, 0xe2, 0xac, 0x33, 0xd6, 0x5b,
    0x19, 0x7e, 0x95, 0xf9, 0xa7, 0x0e, 0x19, 0x87,
    0x7d, 0xb7, 0xd0, 0x7e, 0xc2, 0x65, 0x31, 0xb8,
    0x1f, 0xa0, 0x40, 0x98, 0x59, 0xe4, 0x55, 0x8e
};
/* gen_flags end master_key */

/* Gate state tracker */
static volatile int gates_unlocked = 0;
static uint8_t collected_fragments[40];

/*
 * Gate 1: Declared for a String.
 * If called with a byte[] of length 16 or more whose first byte is
 * 0x42, the mismatch path leaks fragment_a.
 */
JNIEXPORT jint JNICALL
Java_com_ctf_nativectf_challenges_Ch03_gate1(JNIEnv *env, jobject obj,
                                               jobject input) {
    (void)obj;
    const char *str;

    if (!input) return -1;

    /*
     * The Java signature takes Object, so any type can arrive here.
     * GetStringUTFChars on a non-String raises no Java exception:
     * CheckJNI aborts the process and a release runtime reads the
     * object as if it were a String. The type is therefore tested
     * first and the mismatch is handled as the alternate path.
     */
    if (!(*env)->IsInstanceOf(env, input,
            (*env)->FindClass(env, "java/lang/String"))) {
        /* Type confusion path: a byte[] with the magic header */
        if ((*env)->IsInstanceOf(env, input,
                (*env)->FindClass(env, "[B"))) {
            jbyteArray arr = (jbyteArray)input;
            jsize len = (*env)->GetArrayLength(env, arr);
            if (len >= 16) {
                jbyte first;
                (*env)->GetByteArrayRegion(env, arr, 0, 1, &first);
                if ((uint8_t)first == 0x42) {
                    /* Gate 1 unlocked -- leak fragment */
                    memcpy(collected_fragments, fragment_a, 10);
                    gates_unlocked |= 1;
                    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "Gate 1 unlocked. Fragment: %02x%02x%02x...",
                        fragment_a[0], fragment_a[1], fragment_a[2]);
                    return 1;
                }
            }
        }
        return -1;
    }

    /* Normal String path -- returns length, boring */
    str = (*env)->GetStringUTFChars(env, (jstring)input, NULL);
    if (!str) return -1;

    int len = (int)strlen(str);
    (*env)->ReleaseStringUTFChars(env, (jstring)input, str);
    return len;
}

/*
 * Gate 2: Expects an int[], but casts without check.
 * Pass a float[] with specific IEEE 754 pattern.
 */
JNIEXPORT jint JNICALL
Java_com_ctf_nativectf_challenges_Ch03_gate2(JNIEnv *env, jobject obj,
                                               jobject input) {
    (void)obj;

    /* Check for float[] confusion */
    if ((*env)->IsInstanceOf(env, input,
            (*env)->FindClass(env, "[F"))) {
        jfloatArray farr = (jfloatArray)input;
        jsize len = (*env)->GetArrayLength(env, farr);
        if (len >= 4) {
            jfloat vals[4];
            (*env)->GetFloatArrayRegion(env, farr, 0, 4, vals);

            /* Check for magic float pattern: NaN with specific payload */
            uint32_t *raw = (uint32_t *)vals;
            if ((raw[0] & 0x7FC00000) == 0x7FC00000 &&
                (raw[0] & 0xFFFF) == 0x1337) {
                memcpy(collected_fragments + 10, fragment_b, 10);
                gates_unlocked |= 2;
                __android_log_print(ANDROID_LOG_INFO, TAG,
                    "Gate 2 unlocked. Fragment: %02x%02x%02x...",
                    fragment_b[0], fragment_b[1], fragment_b[2]);
                return 2;
            }
        }
    }

    /* Normal int[] path */
    if ((*env)->IsInstanceOf(env, input,
            (*env)->FindClass(env, "[I"))) {
        jintArray iarr = (jintArray)input;
        jsize len = (*env)->GetArrayLength(env, iarr);
        return (jint)len;
    }

    return -1;
}

/*
 * Gate 3: Time-of-check-time-of-use on object field.
 * The native code reads a field, validates it, then reads it again.
 * If you modify the field between reads (via another thread), gate opens.
 */
JNIEXPORT jint JNICALL
Java_com_ctf_nativectf_challenges_Ch03_gate3(JNIEnv *env, jobject obj,
                                               jobject validator) {
    (void)obj;
    jclass cls = (*env)->GetObjectClass(env, validator);
    jfieldID fid = (*env)->GetFieldID(env, cls, "token", "I");

    if (!fid) return -1;

    /* First read: check */
    jint val1 = (*env)->GetIntField(env, validator, fid);
    if (val1 != 0xCAFE) return -1;

    /* Deliberate delay -- window for TOCTOU */
    volatile unsigned int delay = 0;   /* unsigned: the sum wraps by design */
    for (int i = 0; i < 1000000; i++) { delay += (unsigned int)i; }

    /* Second read: use */
    jint val2 = (*env)->GetIntField(env, validator, fid);

    /* Gate 3: value changed between check and use */
    if (val2 != val1 && val2 == 0xBEEF) {
        memcpy(collected_fragments + 20, fragment_c, 10);
        gates_unlocked |= 4;
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "Gate 3 unlocked. Fragment: %02x%02x%02x...",
            fragment_c[0], fragment_c[1], fragment_c[2]);
        return 3;
    }

    return 0;
}

/*
 * Gate 4: Serialize/deserialize confusion.
 * Pass a Parcelable-like object that, when fields are read in native,
 * produces a specific checksum.
 */
JNIEXPORT jint JNICALL
Java_com_ctf_nativectf_challenges_Ch03_gate4(JNIEnv *env, jobject obj,
                                               jbyteArray payload) {
    (void)obj;
    if (!payload) return -1;

    jsize len = (*env)->GetArrayLength(env, payload);
    if (len != 32) return -1;

    jbyte *data = (*env)->GetByteArrayElements(env, payload, NULL);
    if (!data) return -1;

    /* Compute checksum of payload */
    uint32_t checksum = 0;
    for (int i = 0; i < 32; i++) {
        checksum = (checksum << 3) | (checksum >> 29);
        checksum ^= (uint8_t)data[i];
        checksum += (uint32_t)(uint8_t)data[i] * (uint32_t)(i + 1);
    }

    (*env)->ReleaseByteArrayElements(env, payload, data, JNI_ABORT);

    /* Magic checksum value unlocks gate 4 */
    if (checksum == 0xA3B7C9D1) {
        memcpy(collected_fragments + 30, fragment_d, 10);
        gates_unlocked |= 8;
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "Gate 4 unlocked. Fragment: %02x%02x%02x...",
            fragment_d[0], fragment_d[1], fragment_d[2]);
        return 4;
    }

    return 0;
}

/*
 * Combine all fragments when all 4 gates are unlocked.
 * XOR collected_fragments with master_key to get the inner flag.
 */
JNIEXPORT jstring JNICALL
Java_com_ctf_nativectf_challenges_Ch03_combine(JNIEnv *env, jobject obj) {
    (void)obj;
    char flag[48];
    int i;

    if (gates_unlocked != 0x0F) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Gates unlocked: %d/4. Keep going.", __builtin_popcount(gates_unlocked));
        return (*env)->NewStringUTF(env, msg);
    }

    memcpy(flag, "FLAG{", 5);
    for (i = 0; i < 40; i++) {
        uint8_t decrypted = collected_fragments[i] ^ master_key[i];
        /* Convert to hex char */
        flag[5 + i] = decrypted;
    }
    flag[45] = '}';
    flag[46] = '\0';

    return (*env)->NewStringUTF(env, flag);
}

JNIEXPORT jboolean JNICALL
Java_com_ctf_nativectf_challenges_Ch03_verifyFlag(JNIEnv *env, jobject obj,
                                                    jstring input) {
    (void)obj;
    const char *str = (*env)->GetStringUTFChars(env, input, NULL);
    if (!str) return JNI_FALSE;

    int result = verify_flag(2, str);

    (*env)->ReleaseStringUTFChars(env, input, str);
    return result ? JNI_TRUE : JNI_FALSE;
}
