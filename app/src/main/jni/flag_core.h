#ifndef FLAG_CORE_H
#define FLAG_CORE_H

#include <stdint.h>
#include <stddef.h>

/*
 * Flag verification via HMAC-SHA256.
 *
 * Flags are NEVER stored in the binary. Only the HMAC digest is stored.
 * Each challenge has a unique salt. The flag is derived from solving
 * the actual challenge -- there is no shortcut.
 *
 * Verification: HMAC-SHA256(user_input, challenge_salt) == stored_digest
 */

#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32
#define FLAG_MAX_LEN       128

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t  buffer[64];
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t *digest);

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out);

/*
 * Verify a flag submission.
 *   challenge_id  : 0-5
 *   user_input    : submitted flag string
 * Returns 1 if correct, 0 if wrong.
 */
int verify_flag(int challenge_id, const char *user_input);

/*
 * Convert raw bytes to hex string.
 */
void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_out);

/*
 * Anti-tampering: check .text section integrity.
 * Returns 1 if intact, 0 if modified.
 */
int check_integrity(void *func_start, size_t func_size, uint32_t expected_crc);

#endif
