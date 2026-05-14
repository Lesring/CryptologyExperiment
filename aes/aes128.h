/* AES-128 ECB block API (single block). Keys: 11 x 128-bit round keys inline. */
#ifndef AES128_H
#define AES128_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t rk[44]; /* column words (same layout as aes128.c) */
    /*
     * Packed round keys for aes128_ni.c: 11 x 16 bytes, AES-NI byte order.
     * Filled only by aes128_ni.c setkey. Must be 16-byte aligned for XMM load/store.
     * Unused if you link aes128.c only.
     */
#if defined(_MSC_VER)
    __declspec(align(16))
#endif
#if defined(__GNUC__) || defined(__clang__)
        __attribute__((aligned(16)))
#endif
    uint8_t ni_rk[11 * 16];
} AES128CTX;

void aes128_set_encrypt_key(AES128CTX *ctx, const uint8_t key[16]);

void aes128_set_decrypt_key(AES128CTX *ctx, const uint8_t key[16]);

void aes128_encrypt_block(const AES128CTX *ctx, uint8_t out[16],
                          const uint8_t in[16]);

void aes128_decrypt_block(const AES128CTX *ctx, uint8_t out[16],
                          const uint8_t in[16]);

/*
 * ECB bulk helpers (caller handles IV/mode semantics).
 * nbytes must be multiple of 16.
 */
void aes128_encrypt_ecb(const AES128CTX *ctx, uint8_t *dst,
                          const uint8_t *src, size_t nbytes);

void aes128_decrypt_ecb(const AES128CTX *ctx, uint8_t *dst,
                          const uint8_t *src, size_t nbytes);

#endif
