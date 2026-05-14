#ifndef SM4_H
#define SM4_H

#include <stddef.h>
#include <stdint.h>

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define SM4_ROUNDS 32

typedef struct sm4_key {
	uint32_t rk[SM4_ROUNDS];
} sm4_key_t;

void sm4_setkey_enc(sm4_key_t *key, const uint8_t user_key[SM4_KEY_SIZE]);
void sm4_setkey_dec(sm4_key_t *key, const uint8_t user_key[SM4_KEY_SIZE]);

void sm4_encrypt(const sm4_key_t *key, const uint8_t in[SM4_BLOCK_SIZE],
		 uint8_t out[SM4_BLOCK_SIZE]);
void sm4_decrypt(const sm4_key_t *key, const uint8_t in[SM4_BLOCK_SIZE],
		 uint8_t out[SM4_BLOCK_SIZE]);

void sm4_encrypt_blocks(const sm4_key_t *key, const uint8_t *in, size_t nblocks,
			uint8_t *out);
void sm4_decrypt_blocks(const sm4_key_t *key, const uint8_t *in, size_t nblocks,
			uint8_t *out);

#endif
