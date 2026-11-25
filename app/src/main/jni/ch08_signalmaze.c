/*
 * Challenge 08: Signal Maze
 * Difficulty: 4/5
 *
 * walk(code) takes a 16-character code. The function itself does almost
 * nothing: for every character it stores the byte and raises SIGTRAP.
 * The work happens in the signal handlers.
 *
 * There are three handlers, the "rooms". Each one mixes the current byte
 * into a 64-bit state in its own way, compares 16 bits of the result
 * with a checkpoint, and then installs the handler for the next step.
 * Which room comes next depends on the state, so the order of the rooms
 * depends on the code that was entered.
 *
 * A wrong byte leaves the path and the walk ends as LOST. A debugger
 * that swallows SIGTRAP has the same effect, because no room runs.
 * When all 16 checkpoints match, the final state is the key that
 * decrypts the flag.
 *
 * To solve:
 *   1. Find the handlers through the sigaction calls. The function that
 *      Java calls only shows a loop around raise().
 *   2. Reverse the three mixing functions and the rule that picks the
 *      next room.
 *   3. Rebuild the walk offline. Each step has one byte that reaches
 *      its checkpoint, so the code falls out one character at a time.
 *   4. Call walk() with the code.
 */

#include <jni.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <android/log.h>
#include "flag_core.h"

#define TAG "ch08"
#define CODE_LEN  16
#define MAZE_SEED 0x2B793292D24F0071ULL

#define ROL64(v, r) (((v) << (r)) | ((v) >> (64 - (r))))   /* r is 1..63 */

/*
 * Checkpoints of the one valid walk and the encrypted flag.
 * Written by scripts/gen_flags.py. Do not edit by hand.
 */
/* gen_flags begin ch08_tables */
static const uint16_t checkpoints[CODE_LEN] = {
    0x2aa3, 0xdfb3, 0x646c, 0x3dda, 0xf5d5, 0x57be, 0x2955, 0x478f,
    0xf201, 0xd327, 0x654f, 0xa31f, 0x7e41, 0x20da, 0xe49b, 0x06c0
};
static const uint8_t flag_blob[46] = {
    0x25, 0x47, 0xcb, 0x07, 0x88, 0x37, 0x0c, 0xa2,
    0xb6, 0x0e, 0xd2, 0x14, 0xac, 0x56, 0x17, 0x4a,
    0x2a, 0x0b, 0xac, 0x39, 0x3a, 0xcf, 0x55, 0x20,
    0xca, 0x30, 0x9a, 0xd1, 0x1b, 0x36, 0xfc, 0xab,
    0x74, 0x53, 0x87, 0xd2, 0x2f, 0xac, 0x6e, 0x14,
    0xd9, 0x2f, 0x4c, 0xff, 0x5d, 0x78
};
/* gen_flags end ch08_tables */

/* Shared between walk() and the handlers, hence volatile. */
static volatile struct {
    uint64_t state;
    uint32_t step;
    uint8_t  in;
    uint8_t  lost;
} maze;

typedef void (*room_fn)(int, siginfo_t *, void *);

static void room_a(int sig, siginfo_t *info, void *ctx);
static void room_b(int sig, siginfo_t *info, void *ctx);
static void room_c(int sig, siginfo_t *info, void *ctx);

static const room_fn rooms[3] = { room_a, room_b, room_c };

static void enter(room_fn room) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = room;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTRAP, &sa, NULL);
}

/* Common exit of every room: check the step, then choose the next room. */
static void leave(uint64_t state) {
    uint32_t step = maze.step;
    if (step < CODE_LEN && (uint16_t)(state >> 24) != checkpoints[step]) maze.lost = 1;
    maze.state = state;
    maze.step = step + 1;
    enter(rooms[(state >> 7) % 3]);
}

static void room_a(int sig, siginfo_t *info, void *ctx) {
    uint64_t s = maze.state;
    (void)sig; (void)info; (void)ctx;
    s ^= (uint64_t)maze.in + 0x9E3779B97F4A7C15ULL * (uint64_t)(maze.step + 1);
    s = ROL64(s, 13) * 0xBF58476D1CE4E5B9ULL;
    leave(s);
}

static void room_b(int sig, siginfo_t *info, void *ctx) {
    uint64_t s = maze.state;
    (void)sig; (void)info; (void)ctx;
    s += (uint64_t)maze.in << ((maze.step % 7) * 8);
    s ^= s >> 29;
    s *= 0x94D049BB133111EBULL;
    leave(s);
}

static void room_c(int sig, siginfo_t *info, void *ctx) {
    uint64_t s = maze.state;
    (void)sig; (void)info; (void)ctx;
    s ^= (uint64_t)maze.in * 0x0101010101010101ULL;
    s = ROL64(s, 31) + 0xD6E8FEB86659FD93ULL * (uint64_t)maze.step;
    leave(s);
}

JNIEXPORT jstring JNICALL
Java_com_ctf_nativectf_challenges_Ch08_walk(JNIEnv *env, jobject obj,
                                             jstring code) {
    struct sigaction previous;
    const char *text;
    uint64_t x;
    size_t i;
    int lost;
    char out[sizeof(flag_blob) + 1];
    (void)obj;

    if (!code) return (*env)->NewStringUTF(env, "LOST");
    text = (*env)->GetStringUTFChars(env, code, NULL);
    if (!text) return NULL;
    if (strlen(text) != CODE_LEN) {
        (*env)->ReleaseStringUTFChars(env, code, text);
        return (*env)->NewStringUTF(env, "LOST");
    }

    /* Borrow SIGTRAP for the walk and hand it back afterwards. */
    sigaction(SIGTRAP, NULL, &previous);
    maze.state = MAZE_SEED;
    maze.step = 0;
    maze.lost = 0;
    enter(room_a);

    for (i = 0; i < CODE_LEN; i++) {
        maze.in = (uint8_t)text[i];
        raise(SIGTRAP);
    }

    sigaction(SIGTRAP, &previous, NULL);
    (*env)->ReleaseStringUTFChars(env, code, text);

    /* step stays below CODE_LEN when something else consumed the signals */
    lost = maze.lost || maze.step != CODE_LEN;
    if (lost) return (*env)->NewStringUTF(env, "LOST");

    x = maze.state;
    for (i = 0; i < sizeof(flag_blob); i++) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        out[i] = (char)(flag_blob[i] ^ (uint8_t)((x * 0x2545F4914F6CDD1DULL) >> 56));
    }
    out[sizeof(flag_blob)] = '\0';

    __android_log_print(ANDROID_LOG_INFO, TAG, "maze walked");
    return (*env)->NewStringUTF(env, out);
}

JNIEXPORT jboolean JNICALL
Java_com_ctf_nativectf_challenges_Ch08_verifyFlag(JNIEnv *env, jobject obj,
                                                    jstring input) {
    (void)obj;
    const char *str = (*env)->GetStringUTFChars(env, input, NULL);
    if (!str) return JNI_FALSE;

    int result = verify_flag(7, str);

    (*env)->ReleaseStringUTFChars(env, input, str);
    return result ? JNI_TRUE : JNI_FALSE;
}
