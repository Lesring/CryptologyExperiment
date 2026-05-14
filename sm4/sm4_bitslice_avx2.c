/*
 * AVX2 bitsliced SM4: _mm256_xor_si256 / _mm256_and_si256,
 * pointer rotate (no memcpy in Feistel), always_inline S-box ANF,
 * pack: 32x32 bit-matrix transpose per 32-block stripe (fewer loads),
 * unpack: _mm256_extract_epi64 (no store to stack per bit),
 * L: indexed rotates (no rol scratch arrays), round / XOR unrolling.
 */
#if defined(__AVX2__)

#include "sm4_bitslice_avx2.h"

#include <stddef.h>

#include "sm4_bs_sbox_avx2.h"
#include "sm4.h"

#ifdef __GNUC__
#define SM4_BS_AVX2_PREFETCH(p) __builtin_prefetch((p), 0, 3)
#define SM4_BS_AVX2_PRAGMA_UNROLL32 _Pragma("GCC unroll 32")
#define SM4_BS_AVX2_PRAGMA_UNROLL8 _Pragma("GCC unroll 8")
#else
#define SM4_BS_AVX2_PREFETCH(p) ((void)0)
#define SM4_BS_AVX2_PRAGMA_UNROLL32
#define SM4_BS_AVX2_PRAGMA_UNROLL8
#endif

static SM4_BS_AVX2_INLINE uint32_t sm4_bs_avx2_load_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static SM4_BS_AVX2_INLINE void sm4_bs_avx2_transpose32_stage(uint32_t a[32],
							      int s, uint32_t m)
{
	int j, k;

	for (j = 0; j < 32; j += s << 1) {
		for (k = 0; k < s; k++) {
			uint32_t *x = &a[j + k];
			uint32_t *y = &a[j + k + s];
			uint32_t t = ((*x >> (unsigned)s) ^ *y) & m;

			*x ^= t << (unsigned)s;
			*y ^= t;
		}
	}
}

/*
 * 32x32 bit-matrix transpose by Eklundh/SWAR butterfly network.
 * rows[i] is row i (bit j = matrix[i][j]); after return, rows[j] is column j.
 */
static SM4_BS_AVX2_INLINE void sm4_bs_avx2_transpose32_bmat(uint32_t a[32])
{
	sm4_bs_avx2_transpose32_stage(a, 1, 0x55555555u);
	sm4_bs_avx2_transpose32_stage(a, 2, 0x33333333u);
	sm4_bs_avx2_transpose32_stage(a, 4, 0x0f0f0f0fu);
	sm4_bs_avx2_transpose32_stage(a, 8, 0x00ff00ffu);
	sm4_bs_avx2_transpose32_stage(a, 16, 0x0000ffffu);
}

static SM4_BS_AVX2_INLINE uint64_t sm4_bs_avx2_lane_u64(__m256i v, int lane)
{
	switch (lane) {
	case 0:
		return (uint64_t)_mm256_extract_epi64(v, 0);
	case 1:
		return (uint64_t)_mm256_extract_epi64(v, 1);
	case 2:
		return (uint64_t)_mm256_extract_epi64(v, 2);
	case 3:
		return (uint64_t)_mm256_extract_epi64(v, 3);
	default:
		return 0;
	}
}

static SM4_BS_AVX2_INLINE void sm4_bs_avx2_broadcast_u32(sm4_bs_avx2_word y[32],
							 uint32_t x)
{
	int b;

	for (b = 0; b < 32; b++)
		y[b] = (x & (1u << b)) ? _mm256_set1_epi32(-1) : _mm256_setzero_si256();
}

void sm4_bs_avx2_key_enc(sm4_bs_avx2_key_t *bk, const uint8_t user_key[16])
{
	sm4_key_t k;
	int r;

	sm4_setkey_enc(&k, user_key);
	for (r = 0; r < 32; r++)
		sm4_bs_avx2_broadcast_u32(bk->rk[r], k.rk[r]);
}

void sm4_bs_avx2_key_dec(sm4_bs_avx2_key_t *bk, const uint8_t user_key[16])
{
	sm4_key_t k;
	int r;

	sm4_setkey_dec(&k, user_key);
	for (r = 0; r < 32; r++)
		sm4_bs_avx2_broadcast_u32(bk->rk[r], k.rk[r]);
}

/* --- pack: stripe 32 blocks -> 32x32 bit transpose -> merge 8 stripes --- */
void sm4_bs_avx2_pack(const uint8_t *blocks, sm4_bs_avx2_word st[128])
{
	int w, g, i, b;
	uint32_t rows[32];
	uint32_t stripe[8][32];

	for (w = 0; w < 4; w++) {
		const uint8_t *word0 = blocks + (size_t)w * 4;

		for (g = 0; g < 8; g++) {
			const int base_blk = g * 32;
			const uint8_t *p0 = word0 + (size_t)base_blk * 16;

#ifdef __GNUC__
			SM4_BS_AVX2_PRAGMA_UNROLL8
#endif
			for (i = 0; i < 32; i++) {
				if ((i & 7) == 0)
					SM4_BS_AVX2_PREFETCH(p0 + (size_t)(i + 8) * 16);
				rows[i] = sm4_bs_avx2_load_be32(p0 + (size_t)i * 16);
			}
			sm4_bs_avx2_transpose32_bmat(rows);
#ifdef __GNUC__
			SM4_BS_AVX2_PRAGMA_UNROLL8
#endif
			for (b = 0; b < 32; b++)
				stripe[g][b] = rows[b];
		}
		for (b = 0; b < 32; b++) {
			uint64_t u0, u1, u2, u3;

			u0 = ((uint64_t)stripe[1][b] << 32) | (uint64_t)stripe[0][b];
			u1 = ((uint64_t)stripe[3][b] << 32) | (uint64_t)stripe[2][b];
			u2 = ((uint64_t)stripe[5][b] << 32) | (uint64_t)stripe[4][b];
			u3 = ((uint64_t)stripe[7][b] << 32) | (uint64_t)stripe[6][b];
			st[w * 32 + b] = _mm256_set_epi64x((long long)u3,
							   (long long)u2,
							   (long long)u1,
							   (long long)u0);
		}
	}
}

void sm4_bs_avx2_unpack(const sm4_bs_avx2_word st[128], uint8_t *blocks)
{
	int w, g, i, b;
	uint32_t rows[32];

	for (w = 0; w < 4; w++) {
		for (g = 0; g < 8; g++) {
			const int lane = g >> 1;
			const int shift = (g & 1) << 5;
			const int base_blk = g * 32;

#ifdef __GNUC__
			SM4_BS_AVX2_PRAGMA_UNROLL32
#endif
			for (b = 0; b < 32; b++) {
				uint64_t u = sm4_bs_avx2_lane_u64(st[w * 32 + b],
								  lane);

				rows[b] = (uint32_t)(u >> (unsigned)shift);
			}
			sm4_bs_avx2_transpose32_bmat(rows);
#ifdef __GNUC__
			SM4_BS_AVX2_PRAGMA_UNROLL32
#endif
			for (i = 0; i < 32; i++) {
				uint8_t *blk = blocks + (size_t)(base_blk + i) * 16;
				uint32_t W = rows[i];

				blk[w * 4 + 0] = (uint8_t)(W >> 24);
				blk[w * 4 + 1] = (uint8_t)(W >> 16);
				blk[w * 4 + 2] = (uint8_t)(W >> 8);
				blk[w * 4 + 3] = (uint8_t)W;
			}
		}
	}
}

static SM4_BS_AVX2_INLINE void sm4_bs_avx2_L_enc(const sm4_bs_avx2_word B[32],
						   sm4_bs_avx2_word Y[32])
{
	int i;

#ifdef __GNUC__
	SM4_BS_AVX2_PRAGMA_UNROLL32
#endif
	for (i = 0; i < 32; i++) {
		sm4_bs_avx2_word t = _mm256_xor_si256(B[(i - 2) & 31],
						       B[(i - 10) & 31]);

		t = _mm256_xor_si256(t, B[(i - 18) & 31]);
		t = _mm256_xor_si256(t, B[(i - 24) & 31]);
		Y[i] = _mm256_xor_si256(B[i], t);
	}
}

static SM4_BS_AVX2_INLINE void sm4_bs_avx2_tau_inplace(sm4_bs_avx2_word B[32])
{
	static const int lo_byte[4] = { 24, 16, 8, 0 };
	int kb, j;
	sm4_bs_avx2_word iv[8], ov[8];

	for (kb = 0; kb < 4; kb++) {
		int lo = lo_byte[kb];

		for (j = 0; j < 8; j++)
			iv[j] = B[lo + 7 - j];
		/* sm4_bs_sbox_avx2: static always_inline ANF in sm4_bs_sbox_avx2.h */
		sm4_bs_sbox_avx2(iv, ov);
		for (j = 0; j < 8; j++)
			B[lo + 7 - j] = ov[j];
	}
}

static SM4_BS_AVX2_INLINE void sm4_bs_avx2_T_enc(sm4_bs_avx2_word U[32],
						 sm4_bs_avx2_word Y[32])
{
	sm4_bs_avx2_tau_inplace(U);
	sm4_bs_avx2_L_enc(U, Y);
}

#ifdef __GNUC__
__attribute__((target("avx2")))
__attribute__((optimize("unroll-loops")))
#endif
void sm4_bs_avx2_encrypt(const sm4_bs_avx2_key_t *key, sm4_bs_avx2_word st[128])
{
	sm4_bs_avx2_word w[5][32];
	sm4_bs_avx2_word *x0 = w[0];
	sm4_bs_avx2_word *x1 = w[1];
	sm4_bs_avx2_word *x2 = w[2];
	sm4_bs_avx2_word *x3 = w[3];
	sm4_bs_avx2_word *x4 = w[4];
	sm4_bs_avx2_word t2[32];
	sm4_bs_avx2_word *tmp;
	int i;

#ifdef __GNUC__
	SM4_BS_AVX2_PRAGMA_UNROLL32
#endif
	for (i = 0; i < 32; i++) {
		x0[i] = st[i];
		x1[i] = st[32 + i];
		x2[i] = st[64 + i];
		x3[i] = st[96 + i];
	}

#define SM4_BS_AVX2_ROUND(R)                                                   \
	do {                                                                   \
		const sm4_bs_avx2_word *rk_ = key->rk[(R)];                    \
                                                                               \
		SM4_BS_AVX2_PRAGMA_UNROLL32                                    \
		for (i = 0; i < 32; i++) {                                     \
			sm4_bs_avx2_word x = _mm256_xor_si256(x2[i], x3[i]);   \
                                                                               \
			x = _mm256_xor_si256(x, rk_[i]);                       \
			x4[i] = _mm256_xor_si256(x1[i], x);                    \
		}                                                              \
		sm4_bs_avx2_T_enc(x4, t2);                                     \
		SM4_BS_AVX2_PRAGMA_UNROLL32                                    \
		for (i = 0; i < 32; i++)                                      \
			x4[i] = _mm256_xor_si256(x0[i], t2[i]);                \
		tmp = x0;                                                       \
		x0 = x1;                                                        \
		x1 = x2;                                                        \
		x2 = x3;                                                        \
		x3 = x4;                                                        \
		x4 = tmp;                                                       \
	} while (0)

	SM4_BS_AVX2_ROUND(0);
	SM4_BS_AVX2_ROUND(1);
	SM4_BS_AVX2_ROUND(2);
	SM4_BS_AVX2_ROUND(3);
	SM4_BS_AVX2_ROUND(4);
	SM4_BS_AVX2_ROUND(5);
	SM4_BS_AVX2_ROUND(6);
	SM4_BS_AVX2_ROUND(7);
	SM4_BS_AVX2_ROUND(8);
	SM4_BS_AVX2_ROUND(9);
	SM4_BS_AVX2_ROUND(10);
	SM4_BS_AVX2_ROUND(11);
	SM4_BS_AVX2_ROUND(12);
	SM4_BS_AVX2_ROUND(13);
	SM4_BS_AVX2_ROUND(14);
	SM4_BS_AVX2_ROUND(15);
	SM4_BS_AVX2_ROUND(16);
	SM4_BS_AVX2_ROUND(17);
	SM4_BS_AVX2_ROUND(18);
	SM4_BS_AVX2_ROUND(19);
	SM4_BS_AVX2_ROUND(20);
	SM4_BS_AVX2_ROUND(21);
	SM4_BS_AVX2_ROUND(22);
	SM4_BS_AVX2_ROUND(23);
	SM4_BS_AVX2_ROUND(24);
	SM4_BS_AVX2_ROUND(25);
	SM4_BS_AVX2_ROUND(26);
	SM4_BS_AVX2_ROUND(27);
	SM4_BS_AVX2_ROUND(28);
	SM4_BS_AVX2_ROUND(29);
	SM4_BS_AVX2_ROUND(30);
	SM4_BS_AVX2_ROUND(31);

#undef SM4_BS_AVX2_ROUND

#ifdef __GNUC__
	SM4_BS_AVX2_PRAGMA_UNROLL32
#endif
	for (i = 0; i < 32; i++) {
		st[i] = x3[i];
		st[32 + i] = x2[i];
		st[64 + i] = x1[i];
		st[96 + i] = x0[i];
	}
}

void sm4_bs_avx2_decrypt(const sm4_bs_avx2_key_t *key, sm4_bs_avx2_word st[128])
{
	sm4_bs_avx2_encrypt(key, st);
}

#else /* !__AVX2__ */

#include "sm4_bitslice_avx2.h"
#include <stdio.h>

void sm4_bs_avx2_key_enc(sm4_bs_avx2_key_t *k, const uint8_t user_key[16])
{
	(void)k;
	(void)user_key;
	fprintf(stderr, "sm4_bitslice_avx2: build with -mavx2\\n");
}

void sm4_bs_avx2_key_dec(sm4_bs_avx2_key_t *k, const uint8_t user_key[16])
{
	(void)k;
	(void)user_key;
}

void sm4_bs_avx2_pack(const uint8_t *blocks, sm4_bs_avx2_word st[128])
{
	(void)blocks;
	(void)st;
}

void sm4_bs_avx2_unpack(const sm4_bs_avx2_word st[128], uint8_t *blocks)
{
	(void)st;
	(void)blocks;
}

void sm4_bs_avx2_encrypt(const sm4_bs_avx2_key_t *k, sm4_bs_avx2_word st[128])
{
	(void)k;
	(void)st;
}

void sm4_bs_avx2_decrypt(const sm4_bs_avx2_key_t *k, sm4_bs_avx2_word st[128])
{
	(void)k;
	(void)st;
}

#endif
