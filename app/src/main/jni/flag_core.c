#include "flag_core.h"
#include <string.h>
#include <stdlib.h>

/* --- SHA-256 Implementation --- */

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define EP1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx *ctx, const uint8_t *data) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, w[64];
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(sha256_ctx *ctx) {
    ctx->bitcount = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i;
    size_t idx = (size_t)((ctx->bitcount / 8) % 64);
    ctx->bitcount += (uint64_t)len * 8;

    for (i = 0; i < len; i++) {
        ctx->buffer[idx++] = data[i];
        if (idx == 64) {
            sha256_transform(ctx, ctx->buffer);
            idx = 0;
        }
    }
}

void sha256_final(sha256_ctx *ctx, uint8_t *digest) {
    size_t idx = (size_t)((ctx->bitcount / 8) % 64);
    uint8_t pad = 0x80;
    int i;

    ctx->buffer[idx++] = pad;
    if (idx > 56) {
        memset(ctx->buffer + idx, 0, 64 - idx);
        sha256_transform(ctx, ctx->buffer);
        idx = 0;
    }
    memset(ctx->buffer + idx, 0, 56 - idx);

    for (i = 0; i < 8; i++) {
        ctx->buffer[63 - i] = (uint8_t)(ctx->bitcount >> (i * 8));
    }
    sha256_transform(ctx, ctx->buffer);

    for (i = 0; i < 8; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

/* --- HMAC-SHA256 --- */

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out) {
    sha256_ctx ctx;
    uint8_t k_ipad[SHA256_BLOCK_SIZE];
    uint8_t k_opad[SHA256_BLOCK_SIZE];
    uint8_t tk[SHA256_DIGEST_SIZE];
    size_t i;

    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, tk);
        key = tk;
        key_len = SHA256_DIGEST_SIZE;
    }

    memset(k_ipad, 0x36, SHA256_BLOCK_SIZE);
    memset(k_opad, 0x5c, SHA256_BLOCK_SIZE);
    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* inner hash */
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, out);

    /* outer hash */
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, out, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, out);
}

/* --- Flag Verification --- */

/*
 * Per-challenge salts. These are NOT the flags.
 * The salt is combined with the submitted flag via HMAC.
 * Only the resulting digest is compared.
 */
static const uint8_t challenge_salts[6][32] = {
    /* ch01 */ {0xa3,0x7f,0x12,0x8e,0x4b,0xc9,0x01,0xd6,
                0x55,0x3a,0xe8,0x7c,0x90,0x2f,0xb4,0x63,
                0x17,0xde,0x48,0xa1,0x5c,0x09,0xf3,0x6b,
                0x82,0xc7,0x3e,0x94,0xd0,0x56,0x1a,0xef},
    /* ch02 */ {0xb1,0x4c,0x93,0x27,0xe5,0x68,0x0a,0xdf,
                0x71,0xbc,0x3f,0x85,0xc2,0x16,0x9d,0x54,
                0xe0,0x43,0x7a,0x2e,0xb9,0x05,0xf6,0x8c,
                0xd3,0x61,0xa8,0x4f,0x97,0x2b,0xce,0x70},
    /* ch03 */ {0xc5,0x38,0xa4,0x19,0xf7,0x6d,0x02,0xe1,
                0x8b,0xd4,0x53,0x96,0x2a,0xcf,0x74,0x40,
                0xb8,0x1e,0x65,0x0c,0xa9,0xf2,0x37,0xdb,
                0x89,0x4e,0xc1,0x76,0x03,0x5d,0xea,0xb6},
    /* ch04 */ {0xd7,0x2c,0xb5,0x41,0x98,0x0e,0xf4,0x63,
                0xa2,0x59,0xcc,0x87,0x3b,0xe6,0x10,0x7d,
                0x4a,0xbf,0x26,0xd1,0x5e,0x93,0x08,0xf8,
                0x6c,0xc3,0x35,0xa7,0xe9,0x42,0x1b,0x80},
    /* ch05 */ {0xe9,0x14,0xc6,0x5b,0xa0,0x3d,0xf1,0x72,
                0x8f,0xd8,0x46,0xbb,0x07,0x9e,0x23,0xe4,
                0x58,0xcd,0x31,0x7e,0xb3,0x0a,0xf5,0x69,
                0xac,0x47,0xd5,0x82,0x1f,0x96,0x6e,0xc0},
    /* ch06 */ {0xf2,0x0b,0xd9,0x64,0xb7,0x28,0xe3,0x5a,
                0x91,0xce,0x43,0xa6,0x1d,0x8d,0x36,0xf0,
                0x75,0xde,0x49,0xbc,0x02,0x67,0xab,0x5f,
                0xc4,0x38,0xea,0x13,0x7b,0xd2,0x84,0x50}
};

/*
 * Stored HMAC digests for each challenge.
 * Verification: HMAC-SHA256(user_input, salt) == stored_digest
 * Flags cannot be recovered from these hashes.
 */
static const uint8_t stored_digests[6][SHA256_DIGEST_SIZE] = {
    /* ch01 */ {0x73,0x03,0xc5,0xe3,0xb8,0xa2,0x48,0x90,
                0x20,0xce,0x25,0x23,0x45,0xb1,0xf2,0xcb,
                0x20,0x8d,0x25,0x79,0x76,0x8d,0x6c,0xd1,
                0x1a,0x01,0x4f,0x2e,0x5b,0x53,0x2b,0x8e},
    /* ch02 */ {0xe6,0x0a,0x52,0xe7,0xae,0xc9,0x94,0x5e,
                0xce,0x80,0x53,0x1a,0x50,0xbb,0xab,0xb8,
                0x4c,0xfd,0x7a,0x89,0x97,0x41,0x1e,0xb7,
                0x26,0x1c,0xc8,0xda,0x92,0xf0,0x41,0x65},
    /* ch03 */ {0xfd,0xc6,0x64,0xcf,0x1d,0x8a,0xe0,0x8d,
                0x25,0x25,0x7a,0x18,0x0f,0x2b,0xb6,0xe9,
                0x5f,0x26,0x64,0x92,0x73,0x41,0xbf,0x7b,
                0x32,0xfb,0xe4,0x50,0xca,0x2d,0xfe,0x17},
    /* ch04 */ {0xae,0x40,0xa9,0xa6,0xd2,0xf8,0xa3,0xd1,
                0x19,0xcf,0x4a,0x83,0xad,0x74,0xf7,0xfe,
                0xaf,0x93,0x71,0x4c,0x49,0x21,0x8e,0xcb,
                0x85,0x92,0x52,0x7f,0x82,0x15,0xfe,0x69},
    /* ch05 */ {0x65,0x00,0xae,0xd3,0x72,0x58,0x2a,0xa5,
                0x1a,0x49,0x91,0x89,0xa3,0x67,0x74,0xe9,
                0x84,0xe9,0x04,0x75,0x78,0xfb,0x26,0xd4,
                0x66,0x83,0x4c,0xf2,0x93,0x6a,0x72,0xd5},
    /* ch06 */ {0x7c,0x5e,0xdc,0x4f,0x88,0x35,0xc3,0x72,
                0xf1,0xe4,0x5e,0xbf,0xc5,0x62,0x81,0x5c,
                0x0e,0x0e,0xa4,0x4a,0x1c,0x16,0xd8,0xaf,
                0xd2,0x72,0xe5,0xea,0xb2,0x3b,0xcf,0xbf}
};

int verify_flag(int challenge_id, const char *user_input) {
    uint8_t computed[SHA256_DIGEST_SIZE];
    size_t input_len;

    if (challenge_id < 0 || challenge_id > 5) return 0;
    if (!user_input) return 0;

    input_len = strlen(user_input);
    if (input_len < 6 || input_len > FLAG_MAX_LEN) return 0;

    hmac_sha256(challenge_salts[challenge_id], 32,
                (const uint8_t *)user_input, input_len,
                computed);

    /* constant-time comparison to prevent timing attacks */
    {
        volatile uint8_t diff = 0;
        int i;
        for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
            diff |= computed[i] ^ stored_digests[challenge_id][i];
        }
        return diff == 0;
    }
}

void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_out) {
    static const char hex_chars[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        hex_out[i * 2]     = hex_chars[(bytes[i] >> 4) & 0x0f];
        hex_out[i * 2 + 1] = hex_chars[bytes[i] & 0x0f];
    }
    hex_out[len * 2] = '\0';
}

int check_integrity(void *func_start, size_t func_size, uint32_t expected_crc) {
    uint32_t crc = 0xFFFFFFFF;
    uint8_t *p = (uint8_t *)func_start;
    size_t i;

    for (i = 0; i < func_size; i++) {
        uint8_t byte = p[i];
        int j;
        crc ^= byte;
        for (j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }

    return (crc ^ 0xFFFFFFFF) == expected_crc;
}
