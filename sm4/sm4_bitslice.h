#ifndef SM4_BITSLICE_H
#define SM4_BITSLICE_H

#include <stdint.h>

/* Parallel SM4: 32 blocks; each word is one bit position across lanes. */
#define SM4_BS_WIDTH 32
typedef uint32_t sm4_bs_word;

#include "sm4_bs_sbox.h"

typedef struct sm4_bs_key {
	sm4_bs_word rk[32][32];
} sm4_bs_key_t;

void sm4_bs_key_enc(sm4_bs_key_t *k, const uint8_t user_key[16]);
void sm4_bs_key_dec(sm4_bs_key_t *k, const uint8_t user_key[16]);

void sm4_bs_pack(const uint8_t *blocks, sm4_bs_word st[128]);
void sm4_bs_unpack(const sm4_bs_word st[128], uint8_t *blocks);

void sm4_bs_encrypt(const sm4_bs_key_t *k, sm4_bs_word st[128]);
void sm4_bs_decrypt(const sm4_bs_key_t *k, sm4_bs_word st[128]);

#endif
