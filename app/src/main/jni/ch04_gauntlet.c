/*
 * Challenge 04: Anti-Debug Gauntlet
 * Difficulty: 3/5
 *
 * Seven anti-analysis checks guard the flag:
 *   1. TracerPid check (/proc/self/status)
 *   2. Frida detection (/proc/self/maps scan for frida)
 *   3. ptrace self-attach
 *   4. Timing check (execution time threshold)
 *   5. Breakpoint detection (scan for 0xD4 BRK instruction on ARM64)
 *   6. Java debugger check (android.os.Debug.isDebuggerConnected)
 *   7. APK signature verification
 *
 * Each bypassed check contributes a byte to the decryption key.
 * All 7 must pass (or be bypassed) to reveal the flag.
 *
 * To solve: Use Frida to hook each check function and force-return
 * the expected value. Or binary-patch the .so.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/ptrace.h>
#include <android/log.h>
#include "flag_core.h"

#define TAG "ch04"
#define NUM_CHECKS 7

/* Encrypted flag -- decrypted only when all checks pass */
static const uint8_t enc_flag[42] = {
    0x97, 0xb3, 0x2e, 0xc5, 0x41, 0xf8, 0x7a, 0x09,
    0xd4, 0x63, 0xbe, 0x15, 0x8c, 0xa0, 0x37, 0xef,
    0x52, 0xc9, 0x06, 0x7d, 0xb1, 0x48, 0xa3, 0xde,
    0x5f, 0x94, 0x20, 0xcb, 0x67, 0xf1, 0x8e, 0x0a,
    0xd3, 0x75, 0xbc, 0x42, 0xe9, 0x16, 0xa7, 0x5b,
    0xc0, 0x3d
};

/* Expected check return values (correct key bytes) */
static const uint8_t expected_bytes[NUM_CHECKS] = {
    0xA3, 0x5C, 0x91, 0x2E, 0xF7, 0x48, 0xD6
};

/* --- Check 1: TracerPid --- */
static uint8_t __attribute__((noinline)) check_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    int traced = 0;

    if (!f) return 0;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            if (pid != 0) traced = 1;
            break;
        }
    }
    fclose(f);

    /* Return expected byte if NOT being traced */
    return traced ? 0x00 : expected_bytes[0];
}

/* --- Check 2: Frida detection --- */
static uint8_t __attribute__((noinline)) check_frida(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    int frida_found = 0;

    if (!f) return expected_bytes[1]; /* can't check = assume clean */

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "gadget") ||
            strstr(line, "linjector")) {
            frida_found = 1;
            break;
        }
    }
    fclose(f);

    return frida_found ? 0x00 : expected_bytes[1];
}

/* --- Check 3: ptrace self-attach --- */
static uint8_t __attribute__((noinline)) check_ptrace(void) {
    long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (ret == -1) {
        /* Already being traced */
        return 0x00;
    }
    /* Detach */
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
    return expected_bytes[2];
}

/* --- Check 4: Timing check --- */
static uint8_t __attribute__((noinline)) check_timing(void) {
    struct timespec start, end;
    volatile int result = 0;
    int i;

    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Simple computation that should take < 10ms normally */
    for (i = 0; i < 100000; i++) {
        result += i * 3;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                      (end.tv_nsec - start.tv_nsec);

    /* If under debugger with breakpoints, this takes much longer */
    if (elapsed_ns > 100000000L) { /* 100ms threshold */
        return 0x00;
    }

    return expected_bytes[3];
}

/* --- Check 5: Breakpoint detection (ARM64 BRK scan) --- */
static uint8_t __attribute__((noinline)) check_breakpoints(void) {
    /*
     * Scan our own .text for BRK (0xD4200000) or software breakpoint
     * patterns. A debugger inserts these.
     */
    uint32_t *code_start = (uint32_t *)check_tracer_pid;
    int suspicious = 0;
    int i;

    for (i = 0; i < 256; i++) {
        uint32_t instr = code_start[i];
        /* BRK #0 = 0xD4200000, BRK #imm = 0xD42000xx */
        if ((instr & 0xFFE0001F) == 0xD4200000) {
            suspicious++;
        }
    }

    return (suspicious > 2) ? 0x00 : expected_bytes[4];
}

/* --- Check 6: Java debugger check --- */
static uint8_t __attribute__((noinline)) check_java_debugger(JNIEnv *env) {
    jclass debug_cls = (*env)->FindClass(env, "android/os/Debug");
    if (!debug_cls) return expected_bytes[5];

    jmethodID mid = (*env)->GetStaticMethodID(env, debug_cls,
                                               "isDebuggerConnected", "()Z");
    if (!mid) return expected_bytes[5];

    jboolean connected = (*env)->CallStaticBooleanMethod(env, debug_cls, mid);

    return connected ? 0x00 : expected_bytes[5];
}

/* --- Check 7: APK signature verification --- */
static uint8_t __attribute__((noinline)) check_signature(JNIEnv *env, jobject context) {
    if (!context) return 0x00;

    jclass ctx_cls = (*env)->GetObjectClass(env, context);
    jmethodID getPM = (*env)->GetMethodID(env, ctx_cls, "getPackageManager",
                                           "()Landroid/content/pm/PackageManager;");
    jmethodID getPkg = (*env)->GetMethodID(env, ctx_cls, "getPackageName",
                                            "()Ljava/lang/String;");
    if (!getPM || !getPkg) return 0x00;

    jobject pm = (*env)->CallObjectMethod(env, context, getPM);
    jstring pkgName = (jstring)(*env)->CallObjectMethod(env, context, getPkg);
    if (!pm || !pkgName) return 0x00;

    jclass pm_cls = (*env)->GetObjectClass(env, pm);
    jmethodID getPI = (*env)->GetMethodID(env, pm_cls, "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (!getPI) return 0x00;

    jobject pkgInfo = (*env)->CallObjectMethod(env, pm, getPI, pkgName, 0x40);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return 0x00;
    }
    if (!pkgInfo) return 0x00;

    /* Check that signatures exist (repackaged APKs often fail here) */
    jclass pi_cls = (*env)->GetObjectClass(env, pkgInfo);
    jfieldID sigField = (*env)->GetFieldID(env, pi_cls, "signatures",
                                            "[Landroid/content/pm/Signature;");
    if (!sigField) return 0x00;

    jobjectArray sigs = (jobjectArray)(*env)->GetObjectField(env, pkgInfo, sigField);
    if (!sigs || (*env)->GetArrayLength(env, sigs) == 0) return 0x00;

    return expected_bytes[6];
}

/* --- Flag derivation --- */
static void derive_flag(const uint8_t *key_bytes, char *out) {
    uint8_t full_key[42];
    int i;

    /* Expand 7 key bytes to 42 bytes via PRNG */
    uint32_t state = 0;
    for (i = 0; i < NUM_CHECKS; i++) {
        state ^= (uint32_t)key_bytes[i] << ((i % 4) * 8);
    }

    for (i = 0; i < 42; i++) {
        state = state * 1103515245 + 12345;
        full_key[i] = (uint8_t)((state >> 16) & 0xFF);
    }

    /* Decrypt */
    memcpy(out, "FLAG{", 5);
    for (i = 0; i < 42; i++) {
        uint8_t decrypted = enc_flag[i] ^ full_key[i];
        out[5 + i] = decrypted;
    }
    out[47] = '}';
    out[48] = '\0';
}

/* --- Main entry point --- */
JNIEXPORT jstring JNICALL
Java_com_ctf_nativectf_challenges_Ch04_getFlag(JNIEnv *env, jobject obj,
                                                 jobject context) {
    (void)obj;
    uint8_t key[NUM_CHECKS];
    int passed = 0;
    char flag[64];

    /* Run all 7 checks */
    key[0] = check_tracer_pid();
    key[1] = check_frida();
    key[2] = check_ptrace();
    key[3] = check_timing();
    key[4] = check_breakpoints();
    key[5] = check_java_debugger(env);
    key[6] = check_signature(env, context);

    /* Count passed checks */
    for (int i = 0; i < NUM_CHECKS; i++) {
        if (key[i] == expected_bytes[i]) passed++;
    }

    if (passed < NUM_CHECKS) {
        char msg[64];
        snprintf(msg, sizeof(msg),
                 "Checks passed: %d/%d. Bypass them all.", passed, NUM_CHECKS);
        return (*env)->NewStringUTF(env, msg);
    }

    /* All checks passed -- derive flag */
    derive_flag(key, flag);

    __android_log_print(ANDROID_LOG_INFO, TAG, "All checks bypassed!");

    return (*env)->NewStringUTF(env, flag);
}

/* Debug: report which checks failed */
JNIEXPORT jint JNICALL
Java_com_ctf_nativectf_challenges_Ch04_checkStatus(JNIEnv *env, jobject obj,
                                                     jobject context) {
    (void)obj;
    int status = 0;

    if (check_tracer_pid() == expected_bytes[0]) status |= (1 << 0);
    if (check_frida() == expected_bytes[1])       status |= (1 << 1);
    if (check_ptrace() == expected_bytes[2])       status |= (1 << 2);
    if (check_timing() == expected_bytes[3])       status |= (1 << 3);
    if (check_breakpoints() == expected_bytes[4]) status |= (1 << 4);
    if (check_java_debugger(env) == expected_bytes[5]) status |= (1 << 5);
    if (check_signature(env, context) == expected_bytes[6]) status |= (1 << 6);

    return (jint)status;
}

JNIEXPORT jboolean JNICALL
Java_com_ctf_nativectf_challenges_Ch04_verifyFlag(JNIEnv *env, jobject obj,
                                                    jstring input) {
    (void)obj;
    const char *str = (*env)->GetStringUTFChars(env, input, NULL);
    if (!str) return JNI_FALSE;

    int result = verify_flag(3, str);

    (*env)->ReleaseStringUTFChars(env, input, str);
    return result ? JNI_TRUE : JNI_FALSE;
}
