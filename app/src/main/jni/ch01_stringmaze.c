/*
 * Challenge 01: String Maze
 * Difficulty: 1/5
 *
 * The flag is encrypted with three layers:
 *   Layer 1: XOR with rolling key derived from compile-time constants
 *   Layer 2: Byte permutation (shuffle table)
 *   Layer 3: XOR with scattered .rodata constants
 *
 * To solve: Reverse the decryption chain. Trace solve() in Ghidra/IDA.
 * The key material is all in the binary -- just hard to find.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include "flag_core.h"

/* Scattered constants -- these form the Layer 3 XOR key when combined */
static const uint8_t rodata_frag_a[] = {0x4d, 0x1a, 0xf3, 0x82, 0x6e, 0x05, 0xc7, 0x39};
static const uint8_t rodata_frag_b[] = {0xb1, 0x54, 0x28, 0x9f, 0xe0, 0x73, 0x16, 0xac};
static const uint8_t rodata_frag_c[] = {0xd5, 0x62, 0x8b, 0x47, 0x1c, 0xa9, 0xf4, 0x30};
static const uint8_t rodata_frag_d[] = {0x09, 0xce, 0x77, 0xb3, 0x5a, 0xd1, 0x48, 0x6f};
static const uint8_t rodata_frag_e[] = {0x93, 0x2e, 0xa6, 0x51, 0x84, 0xfb, 0x3d, 0xc2};

/* Layer 2: byte permutation table (shuffle indices for 40 bytes) */
static const uint8_t perm_table[40] = {
    23,  7, 31, 14,  2, 38, 19,  5, 27, 11,
    35,  0, 16, 33,  9, 22, 39,  3, 28, 12,
    36,  8, 24, 17,  1, 30, 13,  6, 34, 20,
    37, 10, 25, 18,  4, 29, 15, 32, 21, 26
};

/* Layer 1: rolling XOR key seed */
static const uint32_t xor_seed = 0xDEAD1337;

/*
 * The encrypted flag blob.
 * This is the flag after Layer1(Layer2(Layer3(plaintext))).
 * Size: 40 bytes (without FLAG{} wrapper, the inner content).
 */
static const uint8_t encrypted_flag[40] = {
    0xe7, 0x2b, 0x94, 0x58, 0xc1, 0x3f, 0xa6, 0x7d,
    0x12, 0xd9, 0x45, 0xbe, 0x03, 0x8a, 0xf1, 0x6c,
    0xb7, 0x24, 0x9e, 0x53, 0xd0, 0x47, 0xa8, 0x1f,
    0x69, 0xc4, 0x30, 0x8b, 0xe5, 0x16, 0x7a, 0xdf,
    0x42, 0xb3, 0x08, 0x9d, 0x5e, 0xc6, 0x21, 0x74
};

/* Build Layer 3 key from scattered fragments */
static void build_layer3_key(uint8_t *key40) {
    memcpy(key40,      rodata_frag_a, 8);
    memcpy(key40 + 8,  rodata_frag_b, 8);
    memcpy(key40 + 16, rodata_frag_c, 8);
    memcpy(key40 + 24, rodata_frag_d, 8);
    memcpy(key40 + 32, rodata_frag_e, 8);
}

/* Reverse Layer 2: inverse permutation */
static void inverse_permute(const uint8_t *in, uint8_t *out) {
    int i;
    for (i = 0; i < 40; i++) {
        out[perm_table[i]] = in[i];
    }
}

/* Reverse Layer 1: XOR with rolling key */
static void xor_rolling(uint8_t *data, size_t len, uint32_t seed) {
    uint32_t state = seed;
    size_t i;
    for (i = 0; i < len; i++) {
        data[i] ^= (uint8_t)(state & 0xFF);
        /* LCG step */
        state = state * 1103515245 + 12345;
    }
}

/*
 * Full decryption: undo Layer1, then Layer2, then Layer3.
 * Returns a malloc'd buffer with the decrypted inner flag (null-terminated).
 */
static char *decrypt_flag(void) {
    uint8_t buf[40];
    uint8_t tmp[40];
    uint8_t key3[40];
    char *result;
    int i;

    /* Copy encrypted data */
    memcpy(buf, encrypted_flag, 40);

    /* Undo Layer 1: rolling XOR */
    xor_rolling(buf, 40, xor_seed);

    /* Undo Layer 2: inverse permutation */
    inverse_permute(buf, tmp);

    /* Undo Layer 3: XOR with scattered key */
    build_layer3_key(key3);
    for (i = 0; i < 40; i++) {
        tmp[i] ^= key3[i];
    }

    /* Build full flag: FLAG{<inner>} */
    result = (char *)malloc(47); /* 5 + 40 + 1 + 1 */
    if (!result) return NULL;
    memcpy(result, "FLAG{", 5);
    memcpy(result + 5, tmp, 40);
    result[45] = '}';
    result[46] = '\0';

    return result;
}

/*
 * JNI entry: solve the challenge.
 * In real CTF, the solve() function would have additional obfuscation.
 * The player must reverse engineer the decryption to recover the flag.
 *
 * This function returns a "hint" -- not the flag directly.
 * The actual flag is only obtainable by reversing the .so.
 */
JNIEXPORT jstring JNICALL
Java_com_ctf_nativectf_challenges_Ch01_solve(JNIEnv *env, jobject obj) {
    (void)obj;
    /* In the compiled .so, this function is obfuscated.
     * For the source-code version, we return a hint. */
    char *flag = decrypt_flag();
    if (!flag) {
        return (*env)->NewStringUTF(env, "ERROR: decryption failed");
    }

    /* Return first 10 chars as hint, rest is masked */
    char hint[48];
    memcpy(hint, flag, 10);
    memcpy(hint + 10, "****************************", 28);
    hint[38] = '}';
    hint[39] = '\0';

    /* Clean up actual flag from memory */
    memset(flag, 0, 47);
    free(flag);

    return (*env)->NewStringUTF(env, hint);
}

/*
 * JNI: verify user-submitted flag
 */
JNIEXPORT jboolean JNICALL
Java_com_ctf_nativectf_challenges_Ch01_verifyFlag(JNIEnv *env, jobject obj,
                                                    jstring input) {
    (void)obj;
    const char *str = (*env)->GetStringUTFChars(env, input, NULL);
    if (!str) return JNI_FALSE;

    int result = verify_flag(0, str);

    (*env)->ReleaseStringUTFChars(env, input, str);
    return result ? JNI_TRUE : JNI_FALSE;
}
