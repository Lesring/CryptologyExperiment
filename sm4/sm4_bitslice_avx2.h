#ifndef SM4_BITSLICE_AVX2_H
#define SM4_BITSLICE_AVX2_H

/*
 * Bitsliced SM4 with AVX2: each __m256i is 256 parallel boolean wires.
 * Throughput = 256 blocks per encrypt call (vs 32 for sm4_bitslice.h).
 *
 * Requires: -mavx2, CPU with AVX2.
 */
#include <immintrin.h>
#include <stdint.h>

#define SM4_BS_AVX2_WIDTH 256

typedef __m256i sm4_bs_avx2_word;

typedef struct sm4_bs_avx2_key {
	sm4_bs_avx2_word rk[32][32];
} sm4_bs_avx2_key_t;

void sm4_bs_avx2_key_enc(sm4_bs_avx2_key_t *k, const uint8_t user_key[16]);
void sm4_bs_avx2_key_dec(sm4_bs_avx2_key_t *k, const uint8_t user_key[16]);

/* blocks: SM4_BS_AVX2_WIDTH * 16 bytes (row-major blocks). */
void sm4_bs_avx2_pack(const uint8_t *blocks, sm4_bs_avx2_word st[128]);
void sm4_bs_avx2_unpack(const sm4_bs_avx2_word st[128], uint8_t *blocks);

void sm4_bs_avx2_encrypt(const sm4_bs_avx2_key_t *k, sm4_bs_avx2_word st[128]);
void sm4_bs_avx2_decrypt(const sm4_bs_avx2_key_t *k, sm4_bs_avx2_word st[128]);

#endif
