/*
 * Challenge 05: Heap Feng Shui
 * Difficulty: 4/5
 *
 * Custom slab allocator with 8 slots of 64 bytes each.
 * Vulnerability: free() nullifies the slot entry but doesn't clear the pointer
 * in any "alias" references. Combined with an off-by-16 overflow in edit(),
 * you can corrupt adjacent slot metadata.
 *
 * Exploitation path:
 *   1. allocate(0) -> slot A
 *   2. allocate(1) -> slot B (adjacent to A)
 *   3. free(1) -> B freed but A's overflow can still reach B's metadata
 *   4. allocate(2) -> slot C, reuses B's memory
 *   5. edit(0, overflow_payload) -> corrupt C's vtable pointer
 *   6. read(2) -> triggers C's corrupted vtable -> flag_generator()
 *
 * The flag_generator function is hidden and only reachable via vtable hijack.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>
#include "flag_core.h"

#define TAG "ch05"
#define NUM_SLOTS  8
#define SLOT_SIZE  64
#define MAX_DATA   (SLOT_SIZE + 16) /* off-by-16 overflow */

/* Slot metadata */
typedef struct slot {
    uint8_t   data[SLOT_SIZE];
    int       (*read_handler)(struct slot *self, uint8_t *out, size_t max);
    uint32_t  magic;
    uint8_t   active;
    uint8_t   pad[3];
} slot_t;

/* Arena: contiguous memory for all slots */
static slot_t arena[NUM_SLOTS];
static int initialized = 0;

/* Normal read handler */
static int normal_read(slot_t *self, uint8_t *out, size_t max) {
    size_t copy_len = max < SLOT_SIZE ? max : SLOT_SIZE;
    memcpy(out, self->data, copy_len);
    return (int)copy_len;
}

/*
 * The flag, XOR-masked with a rolling byte key so it does not sit in
 * .rodata as a readable string.
 * Written by scripts/gen_flags.py. Do not edit by hand.
 */
#define FLAG_MASK_SEED 0xA7
#define FLAG_MASK_MUL  5
#define FLAG_MASK_ADD  0x3B

/* gen_flags begin masked_flag */
static const uint8_t masked_flag[48] = {
    0xe1, 0x32, 0xf0, 0xf7, 0xd0, 0xab, 0x24, 0xc6,
    0x57, 0x02, 0x08, 0x6a, 0x97, 0xc8, 0x25, 0xf4,
    0x01, 0x2c, 0xf2, 0x62, 0x59, 0x03, 0x10, 0xc4,
    0x9e, 0x55, 0x2f, 0xcb, 0xb7, 0xf9, 0x18, 0x24,
    0xf4, 0x2a, 0xb2, 0x33, 0xfd, 0x57, 0x56, 0x27,
    0xea, 0x63, 0x61, 0xcf, 0x22, 0xad, 0x0d, 0x11
};
/* gen_flags end masked_flag */

/*
 * Hidden flag generator. Address must be discovered via reversing.
 * When called as a read_handler, it writes the flag to the output buffer.
 */
static int __attribute__((used)) flag_generator(slot_t *self, uint8_t *out, size_t max) {
    (void)self;
    char flag[sizeof(masked_flag) + 1];
    size_t flag_len = sizeof(masked_flag);
    size_t copy_len = max < flag_len ? max : flag_len;
    uint8_t key = FLAG_MASK_SEED;
    size_t i;

    for (i = 0; i < flag_len; i++) {
        flag[i] = (char)(masked_flag[i] ^ key);
        key = (uint8_t)(key * FLAG_MASK_MUL + FLAG_MASK_ADD);
    }
    flag[flag_len] = '\0';

    memcpy(out, flag, copy_len);
    if (max > flag_len) out[flag_len] = '\0';
    memset(flag, 0, sizeof(flag));

    __android_log_print(ANDROID_LOG_INFO, TAG,
        "FLAG GENERATOR TRIGGERED VIA VTABLE HIJACK");

    return (int)copy_len;
}

static void init_arena(void) {
    if (initialized) return;
    memset(arena, 0, sizeof(arena));
    for (int i = 0; i < NUM_SLOTS; i++) {
        arena[i].read_handler = normal_read;
        arena[i].magic = 0xDEAD0000 + i;
        arena[i].active = 0;
    }
    initialized = 1;
}

/* Allocate a slot */
JNIEXPORT jint JNICALL
Java_com_ctf_nativectf_challenges_Ch05_allocate(JNIEnv *env, jobject obj,
                                                  jint slot_id, jbyteArray data) {
    (void)env; (void)obj;
    init_arena();

    if (slot_id < 0 || slot_id >= NUM_SLOTS) return -1;
    if (arena[slot_id].active) return -2;

    arena[slot_id].active = 1;
    arena[slot_id].read_handler = normal_read;
    arena[slot_id].magic = 0xDEAD0000 + slot_id;

    if (data) {
        jsize len = (*env)->GetArrayLength(env, data);
        jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
        if (bytes) {
            size_t copy = (size_t)len < SLOT_SIZE ? (size_t)len : SLOT_SIZE;
            memcpy(arena[slot_id].data, bytes, copy);
            (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
        }
    }

    __android_log_print(ANDROID_LOG_DEBUG, TAG,
        "Allocated slot %d at arena offset %zu",
        slot_id, (size_t)slot_id * sizeof(slot_t));

    return 0;
}

/* Free a slot */
JNIEXPORT jint JNICALL
Java_com_ctf_nativectf_challenges_Ch05_release(JNIEnv *env, jobject obj,
                                                 jint slot_id) {
    (void)env; (void)obj;
    init_arena();

    if (slot_id < 0 || slot_id >= NUM_SLOTS) return -1;
    if (!arena[slot_id].active) return -2;

    /*
     * VULNERABILITY: We mark the slot as inactive and zero the data,
     * but we DON'T reset the read_handler to NULL.
     * The handler pointer is left dangling.
     */
    arena[slot_id].active = 0;
    memset(arena[slot_id].data, 0, SLOT_SIZE);
    /* read_handler NOT cleared -- UAF vector */

    return 0;
}

/*
 * Edit slot data.
 * VULNERABILITY: Writes up to SLOT_SIZE + 16 bytes.
 * The extra 16 bytes overflow into the next field: read_handler (8 bytes)
 * and magic (4 bytes) + active (1 byte) + pad (3 bytes).
 *
 * By overflowing, you can overwrite the CURRENT slot's read_handler,
 * or if adjacent slots are considered, you corrupt the next slot.
 */
JNIEXPORT jint JNICALL
Java_com_ctf_nativectf_challenges_Ch05_edit(JNIEnv *env, jobject obj,
                                              jint slot_id, jbyteArray data) {
    (void)obj;
    init_arena();

    if (slot_id < 0 || slot_id >= NUM_SLOTS) return -1;
    if (!arena[slot_id].active) return -2;

    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (!bytes) return -3;

    /*
     * VULNERABILITY: Off-by-16 overflow.
     * MAX_DATA = SLOT_SIZE + 16 = 80 bytes.
     * This writes past the data[64] buffer into read_handler and magic.
     */
    size_t copy = (size_t)len < MAX_DATA ? (size_t)len : MAX_DATA;
    memcpy(arena[slot_id].data, bytes, copy);

    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);

    return (jint)copy;
}

/* Read from a slot using its handler */
JNIEXPORT jbyteArray JNICALL
Java_com_ctf_nativectf_challenges_Ch05_read(JNIEnv *env, jobject obj,
                                              jint slot_id) {
    (void)obj;
    init_arena();

    if (slot_id < 0 || slot_id >= NUM_SLOTS) return NULL;
    if (!arena[slot_id].active) return NULL;

    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    /*
     * Calls the read_handler function pointer.
     * If overwritten via overflow, this calls flag_generator() instead.
     */
    if (arena[slot_id].read_handler) {
        arena[slot_id].read_handler(&arena[slot_id], buf, sizeof(buf));
    }

    jbyteArray result = (*env)->NewByteArray(env, 256);
    (*env)->SetByteArrayRegion(env, result, 0, 256, (jbyte *)buf);
    return result;
}

/* Debug: get address info for exploitation */
JNIEXPORT jlong JNICALL
Java_com_ctf_nativectf_challenges_Ch05_getArenaBase(JNIEnv *env, jobject obj) {
    (void)env; (void)obj;
    init_arena();
    return (jlong)(uintptr_t)arena;
}

JNIEXPORT jlong JNICALL
Java_com_ctf_nativectf_challenges_Ch05_getSlotSize(JNIEnv *env, jobject obj) {
    (void)env; (void)obj;
    return (jlong)sizeof(slot_t);
}

JNIEXPORT jboolean JNICALL
Java_com_ctf_nativectf_challenges_Ch05_verifyFlag(JNIEnv *env, jobject obj,
                                                    jstring input) {
    (void)obj;
    const char *str = (*env)->GetStringUTFChars(env, input, NULL);
    if (!str) return JNI_FALSE;

    int result = verify_flag(4, str);

    (*env)->ReleaseStringUTFChars(env, input, str);
    return result ? JNI_TRUE : JNI_FALSE;
}
