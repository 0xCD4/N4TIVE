/*
 * Challenge 07: Ghost Export
 * Difficulty: 3/5
 *
 * Java declares
 *     native String reveal(String passphrase);
 * and this library exports a function with the matching JNI name. That
 * export is a decoy. It accepts a passphrase that sits in .rodata as
 * plain text and answers with a flag the verifier rejects.
 *
 * The function Java really reaches is bound at load time:
 *   1. A constructor in .init_array runs before JNI_OnLoad. It walks the
 *      library's own program headers, finds a custom ELF note and copies
 *      a 16-byte key out of it. No code refers to that key by address.
 *      The same constructor uses the key to unmask the class, method and
 *      signature strings needed for registration.
 *   2. JNI_OnLoad calls RegisterNatives, which replaces the exported
 *      name with the hidden implementation.
 *
 * To solve:
 *   1. Notice that the export is never the one that runs. Follow
 *      .init_array and JNI_OnLoad, or hook RegisterNatives.
 *   2. Find the key in the ELF note (readelf -n shows an unknown note).
 *   3. Reverse the passphrase check in the hidden function and invert it.
 *   4. Call reveal() with the passphrase. The flag is decrypted with a
 *      key derived from it, so it cannot be dumped without it.
 */

#include <jni.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "flag_core.h"

#define PASS_LEN  12
#define KEY_LEN   16
#define NOTE_TYPE 0x4e34
#define STR_MASK  0xA5

/* The key the hidden function works with. It lives only inside the note. */
#define NOTE_KEY 0x8b, 0x12, 0x21, 0x64, 0x03, 0xeb, 0xd6, 0xac, 0xa8, 0xc7, 0xa6, 0x73, 0xce, 0x62, 0x51, 0xd1

struct n4_note {
    uint32_t namesz;
    uint32_t descsz;
    uint32_t type;
    char     name[8];            /* "N4TIVE" + NUL, padded to 4 bytes */
    uint8_t  desc[KEY_LEN];
};

__attribute__((section(".note.n4tive"), used, aligned(4)))
static const struct n4_note key_note = {
    7, KEY_LEN, NOTE_TYPE, "N4TIVE", { NOTE_KEY }
};

/*
 * Passphrase targets and the encrypted flag.
 * Written by scripts/gen_flags.py. Do not edit by hand.
 */
/* gen_flags begin ch07_tables */
static const uint8_t pass_target[PASS_LEN] = {
    0x88, 0x4b, 0x0d, 0xa1, 0x22, 0xaf, 0xe1, 0xf3,
    0x0f, 0xbd, 0x69, 0xd5
};
static const uint8_t flag_blob[46] = {
    0x92, 0x98, 0x74, 0x09, 0xd9, 0x8e, 0xac, 0xee,
    0xc7, 0xd0, 0xac, 0x9a, 0x11, 0x8a, 0x19, 0xda,
    0x97, 0x15, 0x82, 0x29, 0x8a, 0x70, 0x2c, 0x7a,
    0xda, 0x4e, 0x49, 0x4a, 0x80, 0x68, 0x1a, 0x85,
    0xc3, 0x76, 0x09, 0xb0, 0x78, 0x9b, 0xea, 0xb1,
    0x34, 0x2e, 0x24, 0xde, 0xa4, 0x0b
};
/* gen_flags end ch07_tables */

/* Registration strings, XOR-masked with (STR_MASK ^ index ^ note key byte). */
static const uint8_t masked_class[] = {   /* com/ctf/nativectf/challenges/Ch07 */
    0x4d, 0xd9, 0xeb, 0xed, 0xc1, 0x3f, 0x13, 0x21, 0x6b, 0x0a, 0x7d, 0xb4,
    0x11, 0xaf, 0x99, 0x0f, 0x58, 0x89, 0xf5, 0xba, 0xd3, 0x37, 0x09, 0x7b,
    0x7b, 0x1c, 0x7c, 0xbe, 0x58, 0x99, 0x82, 0x5b, 0x39
};
static const uint8_t masked_name[] = {    /* reveal */
    0x5c, 0xd3, 0xf0, 0xa7, 0xc3, 0x27
};
static const uint8_t masked_sig[] = {     /* (Ljava/lang/String;)Ljava/lang/String; */
    0x06, 0xfa, 0xec, 0xa3, 0xd4, 0x2a, 0x5a, 0x62, 0x64, 0x05, 0x6e, 0xf2,
    0x34, 0xbe, 0x88, 0x12, 0x50, 0xc1, 0xad, 0xfb, 0xfe, 0x31, 0x04, 0x68,
    0x74, 0x54, 0x75, 0xac, 0x19, 0xbd, 0xc5, 0x38, 0x7a, 0xe4, 0xcf, 0x8c,
    0xe5, 0x50
};

static uint8_t g_key[KEY_LEN];
static int     g_key_ready;
static char    g_class[sizeof(masked_class) + 1];
static char    g_name[sizeof(masked_name) + 1];
static char    g_sig[sizeof(masked_sig) + 1];
static uintptr_t g_fn;           /* hidden implementation, masked with g_cookie */
static uintptr_t g_cookie;

static jstring hidden_reveal(JNIEnv *env, jobject obj, jstring passphrase);

/*
 * The mask includes the note key. The key only exists at run time, so the
 * compiler cannot fold these strings back into .rodata as plain text.
 */
static void unmask(const uint8_t *in, size_t len, char *out) {
    size_t i;
    for (i = 0; i < len; i++) {
        out[i] = (char)(in[i] ^ (uint8_t)(STR_MASK ^ i) ^ g_key[i % KEY_LEN]);
    }
    out[len] = '\0';
}

/* Look for the note in the object that contains this very function. */
static int find_note(struct dl_phdr_info *info, size_t size, void *data) {
    uintptr_t self = (uintptr_t)&find_note;
    int mine = 0;
    int i;
    (void)size; (void)data;

    for (i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        uintptr_t start = (uintptr_t)info->dlpi_addr + ph->p_vaddr;
        if (ph->p_type == PT_LOAD && self >= start && self < start + ph->p_memsz) mine = 1;
    }
    if (!mine) return 0;

    for (i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        const uint8_t *p, *end;
        size_t align;
        if (ph->p_type != PT_NOTE) continue;

        p = (const uint8_t *)((uintptr_t)info->dlpi_addr + ph->p_vaddr);
        end = p + ph->p_memsz;
        align = ph->p_align == 8 ? 8 : 4;
        while (p + sizeof(ElfW(Nhdr)) <= end) {
            const ElfW(Nhdr) *nh = (const ElfW(Nhdr) *)p;
            const uint8_t *name = p + sizeof(*nh);
            const uint8_t *desc = name + ((nh->n_namesz + align - 1) & ~(align - 1));
            const uint8_t *next = desc + ((nh->n_descsz + align - 1) & ~(align - 1));
            if (next > end || next <= p) break;
            if (nh->n_type == NOTE_TYPE && nh->n_namesz == 7 &&
                nh->n_descsz == KEY_LEN && memcmp(name, "N4TIVE", 7) == 0) {
                memcpy(g_key, desc, KEY_LEN);
                g_key_ready = 1;
                return 1;
            }
            p = next;
        }
    }
    return 1;   /* our object was searched, stop iterating */
}

/* Runs from .init_array, before JNI_OnLoad. */
__attribute__((constructor))
static void ghost_init(void) {
    dl_iterate_phdr(find_note, NULL);
    unmask(masked_class, sizeof(masked_class), g_class);
    unmask(masked_name, sizeof(masked_name), g_name);
    unmask(masked_sig, sizeof(masked_sig), g_sig);
    g_cookie = (uintptr_t)&g_cookie ^ (uintptr_t)0x4e34a5c3u;
    g_fn = (uintptr_t)&hidden_reveal ^ g_cookie;
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    JNINativeMethod method;
    jclass cls;
    (void)reserved;

    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;

    /* Without the note there is nothing to register; the export stays in place. */
    if (!g_key_ready) return JNI_VERSION_1_6;

    cls = (*env)->FindClass(env, g_class);
    if (!cls) return JNI_ERR;

    method.name = g_name;
    method.signature = g_sig;
    method.fnPtr = (void *)(g_fn ^ g_cookie);
    if ((*env)->RegisterNatives(env, cls, &method, 1) != JNI_OK) return JNI_ERR;

    return JNI_VERSION_1_6;
}

static uint8_t rol8(uint8_t v, unsigned r) {   /* r is 1..7 */
    return (uint8_t)((v << r) | (v >> (8 - r)));
}

/* The implementation Java reaches after JNI_OnLoad. */
static jstring hidden_reveal(JNIEnv *env, jobject obj, jstring passphrase) {
    const char *pass;
    size_t len, i;
    uint8_t prev = 0x5A;
    uint8_t diff = 0;
    uint32_t state;
    char out[sizeof(flag_blob) + 1];
    (void)obj;

    if (!passphrase) return (*env)->NewStringUTF(env, "wrong passphrase");
    pass = (*env)->GetStringUTFChars(env, passphrase, NULL);
    if (!pass) return NULL;

    len = strlen(pass);
    if (len != PASS_LEN || !g_key_ready) {
        (*env)->ReleaseStringUTFChars(env, passphrase, pass);
        return (*env)->NewStringUTF(env, "wrong passphrase");
    }

    /* Each byte is chained to the previous result, keyed, then rotated. */
    for (i = 0; i < PASS_LEN; i++) {
        uint8_t v = (uint8_t)((uint8_t)pass[i] + prev) ^ g_key[i];
        v = rol8(v, (unsigned)(i % 7) + 1);
        diff |= (uint8_t)(v ^ pass_target[i]);
        prev = v;
    }

    /* FNV-1a over the passphrase, mixed with the tail of the note key. */
    state = 2166136261u;
    for (i = 0; i < PASS_LEN; i++) {
        state = (state ^ (uint8_t)pass[i]) * 16777619u;
    }
    state ^= (uint32_t)g_key[12] | ((uint32_t)g_key[13] << 8) |
             ((uint32_t)g_key[14] << 16) | ((uint32_t)g_key[15] << 24);
    (*env)->ReleaseStringUTFChars(env, passphrase, pass);

    if (diff != 0) return (*env)->NewStringUTF(env, "wrong passphrase");

    for (i = 0; i < sizeof(flag_blob); i++) {
        state = state * 1103515245u + 12345u;
        out[i] = (char)(flag_blob[i] ^ (uint8_t)(state >> 16));
    }
    out[sizeof(flag_blob)] = '\0';

    return (*env)->NewStringUTF(env, out);
}

/*
 * The decoy. It carries the JNI name, so every disassembler lists it
 * first, but RegisterNatives has replaced it by the time Java calls.
 */
JNIEXPORT jstring JNICALL
Java_com_ctf_nativectf_challenges_Ch07_reveal(JNIEnv *env, jobject obj,
                                               jstring passphrase) {
    const char *pass;
    int match;
    (void)obj;

    if (!passphrase) return (*env)->NewStringUTF(env, "wrong passphrase");
    pass = (*env)->GetStringUTFChars(env, passphrase, NULL);
    if (!pass) return NULL;
    match = strcmp(pass, "letmein-n4tive") == 0;
    (*env)->ReleaseStringUTFChars(env, passphrase, pass);

    if (!match) return (*env)->NewStringUTF(env, "wrong passphrase");
    return (*env)->NewStringUTF(env, "FLAG{deadc0dedeadc0dedeadc0dedeadc0dedeadc0de}");
}

JNIEXPORT jboolean JNICALL
Java_com_ctf_nativectf_challenges_Ch07_verifyFlag(JNIEnv *env, jobject obj,
                                                    jstring input) {
    (void)obj;
    const char *str = (*env)->GetStringUTFChars(env, input, NULL);
    if (!str) return JNI_FALSE;

    int result = verify_flag(6, str);

    (*env)->ReleaseStringUTFChars(env, input, str);
    return result ? JNI_TRUE : JNI_FALSE;
}
