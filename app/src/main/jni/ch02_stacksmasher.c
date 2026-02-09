/*
 * Challenge 02: Stack Smasher
 * Difficulty: 2/5
 *
 * A classic buffer overflow in a JNI function.
 * The processInput() function has a 64-byte stack buffer.
 * Overflow it to overwrite a function pointer on the stack.
 * The hidden function compute_secret() generates the flag seed.
 *
 * To solve:
 *   1. Reverse the .so to find processInput() buffer size (64 bytes)
 *   2. Find compute_secret() address
 *   3. Overflow to redirect execution to compute_secret()
 *   4. The return value from compute_secret() is the flag seed
 *   5. Feed the seed into the derivation function to get FLAG{...}
 *
 * Note: Compiled with -fno-stack-protector for this challenge.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>
#include "flag_core.h"

#define TAG "ch02"
#define BUFFER_SIZE 64

/* This struct lives on the stack. The handler pointer is right after the buffer. */
typedef struct {
    char buffer[BUFFER_SIZE];
    int (*handler)(const char *, size_t);
    uint64_t canary_fake;  /* not a real canary -- just a decoy */
    uint32_t state;
} input_context;

/* Normal handler -- does nothing useful */
static int normal_handler(const char *data, size_t len) {
    (void)data;
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "normal_handler: %zu bytes", len);
    return 0;
}

/*
 * Hidden function. NOT called anywhere in normal flow.
 * Must be reached via overflow to overwrite ctx.handler.
 *
 * Returns a 64-byte hex seed that, when hashed with the
 * challenge-specific derivation, produces the flag.
 */
static int __attribute__((used)) compute_secret(const char *data, size_t len) {
    (void)data;
    (void)len;

    /*
     * The "seed" is derived from a chain of constants.
     * Reversing this function reveals the algorithm.
     * The correct seed value passed through derive_flag()
     * produces: FLAG{b2d4e8f01a3c5967d82e4b0f7a19c3d568e2f4a03b}
     */
    static const uint32_t magic[] = {
        0x62326434, 0x65386630, 0x31613363, 0x35393637,
        0x64383265, 0x34623066, 0x37613139, 0x63336435,
        0x36386532, 0x66346130, 0x33620000
    };

    uint8_t seed[44];
    int i;

    for (i = 0; i < 10; i++) {
        seed[i * 4]     = (uint8_t)(magic[i] >> 24);
        seed[i * 4 + 1] = (uint8_t)(magic[i] >> 16);
        seed[i * 4 + 2] = (uint8_t)(magic[i] >> 8);
        seed[i * 4 + 3] = (uint8_t)(magic[i]);
    }
    seed[40] = (uint8_t)(magic[10] >> 24);
    seed[41] = (uint8_t)(magic[10] >> 16);
    seed[42] = 0;
    seed[43] = 0;

    __android_log_print(ANDROID_LOG_INFO, TAG,
        "SECRET UNLOCKED: %s", (char *)seed);

    return 1;
}

/*
 * Intentionally vulnerable: no bounds check on input length.
 * Copies user input into a 64-byte buffer without length validation.
 * The function pointer `handler` sits right after the buffer on the stack.
 */
JNIEXPORT jint JNICALL
Java_com_ctf_nativectf_challenges_Ch02_processInput(JNIEnv *env, jobject obj,
                                                     jbyteArray input) {
    (void)obj;
    input_context ctx;
    jsize input_len;
    jbyte *input_bytes;

    memset(&ctx, 0, sizeof(ctx));
    ctx.handler = normal_handler;
    ctx.canary_fake = 0xDEADBEEFCAFEBABEULL;
    ctx.state = 0;

    input_len = (*env)->GetArrayLength(env, input);
    input_bytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (!input_bytes) return -1;

    /*
     * VULNERABILITY: No bounds check.
     * If input_len > 64, we overflow into ctx.handler.
     * At offset 64: handler function pointer (8 bytes on arm64)
     * At offset 72: canary_fake
     * At offset 80: state
     */
    memcpy(ctx.buffer, input_bytes, input_len);  /* OVERFLOW HERE */

    (*env)->ReleaseByteArrayElements(env, input, input_bytes, JNI_ABORT);

    /* Call handler -- if overwritten, calls compute_secret instead */
    if (ctx.handler) {
        ctx.handler(ctx.buffer, (size_t)input_len);
    }

    return (jint)ctx.state;
}

/*
 * Get the address hint for compute_secret (offset from lib base).
 * In the stripped release build, this won't have a symbol name,
 * but the offset hint helps locate it.
 */
JNIEXPORT jlong JNICALL
Java_com_ctf_nativectf_challenges_Ch02_getHiddenOffset(JNIEnv *env, jobject obj) {
    (void)env;
    (void)obj;
    /* Return the relative offset as a "teaser" */
    uintptr_t base = (uintptr_t)Java_com_ctf_nativectf_challenges_Ch02_processInput;
    uintptr_t target = (uintptr_t)compute_secret;
    return (jlong)(target - base);
}

JNIEXPORT jboolean JNICALL
Java_com_ctf_nativectf_challenges_Ch02_verifyFlag(JNIEnv *env, jobject obj,
                                                    jstring input) {
    (void)obj;
    const char *str = (*env)->GetStringUTFChars(env, input, NULL);
    if (!str) return JNI_FALSE;

    int result = verify_flag(1, str);

    (*env)->ReleaseStringUTFChars(env, input, str);
    return result ? JNI_TRUE : JNI_FALSE;
}
