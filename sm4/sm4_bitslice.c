#include "sm4_bitslice.h"

#include <string.h>

#include "sm4.h"

/*
 * Layout: 4 x uint32 words (big-endian value). Word w uses indices w*32 + b
 * where b is uint32 bit index (0 = LSB of that word).
 */

static void sm4_bs_broadcast_u32(sm4_bs_word y[32], uint32_t x)
{
	int b;

	for (b = 0; b < 32; b++)
		y[b] = (x & (1u << b)) ? ~(sm4_bs_word)0 : 0;
}

void sm4_bs_key_enc(sm4_bs_key_t *bk, const uint8_t user_key[16])
{
	sm4_key_t k;
	int r;

	sm4_setkey_enc(&k, user_key);
	for (r = 0; r < 32; r++)
		sm4_bs_broadcast_u32(bk->rk[r], k.rk[r]);
}

void sm4_bs_key_dec(sm4_bs_key_t *bk, const uint8_t user_key[16])
{
	sm4_key_t k;
	int r;

	sm4_setkey_dec(&k, user_key);
	for (r = 0; r < 32; r++)
		sm4_bs_broadcast_u32(bk->rk[r], k.rk[r]);
}

void sm4_bs_pack(const uint8_t *blocks, sm4_bs_word st[128])
{
	int k, w, b;

	memset(st, 0, 128 * sizeof(st[0]));
	for (k = 0; k < SM4_BS_WIDTH; k++) {
		const uint8_t *blk = blocks + (size_t)k * 16;

		for (w = 0; w < 4; w++) {
			uint32_t W = ((uint32_t)blk[w * 4 + 0] << 24) |
				     ((uint32_t)blk[w * 4 + 1] << 16) |
				     ((uint32_t)blk[w * 4 + 2] << 8) |
				     (uint32_t)blk[w * 4 + 3];
			for (b = 0; b < 32; b++) {
				if (W >> b & 1u)
					st[w * 32 + b] |= (sm4_bs_word)1u << k;
			}
		}
	}
}

void sm4_bs_unpack(const sm4_bs_word st[128], uint8_t *blocks)
{
	int k, w, b;

	for (k = 0; k < SM4_BS_WIDTH; k++) {
		uint8_t *blk = blocks + (size_t)k * 16;

		for (w = 0; w < 4; w++) {
			uint32_t W = 0;

			for (b = 0; b < 32; b++) {
				if (st[w * 32 + b] >> k & 1u)
					W |= 1u << b;
			}
			blk[w * 4 + 0] = (uint8_t)(W >> 24);
			blk[w * 4 + 1] = (uint8_t)(W >> 16);
			blk[w * 4 + 2] = (uint8_t)(W >> 8);
			blk[w * 4 + 3] = (uint8_t)W;
		}
	}
}

static void sm4_bs_rol(const sm4_bs_word a[32], sm4_bs_word o[32], int n)
{
	int k;

	for (k = 0; k < 32; k++)
		o[k] = a[(k - n) & 31];
}

static void sm4_bs_L_enc(const sm4_bs_word B[32], sm4_bs_word out[32])
{
	sm4_bs_word r2[32], r10[32], r18[32], r24[32];
	int i;

	sm4_bs_rol(B, r2, 2);
	sm4_bs_rol(B, r10, 10);
	sm4_bs_rol(B, r18, 18);
	sm4_bs_rol(B, r24, 24);
	for (i = 0; i < 32; i++)
		out[i] = B[i] ^ r2[i] ^ r10[i] ^ r18[i] ^ r24[i];
}

static void sm4_bs_tau_32w(sm4_bs_word B[32])
{
	static const int lo_byte[4] = { 24, 16, 8, 0 };
	int kb, b;
	uint32_t iv[8], ov[8];

	for (kb = 0; kb < 4; kb++) {
		int lo = lo_byte[kb];

		for (b = 0; b < 8; b++)
			iv[b] = B[lo + 7 - b];
		sm4_bs_sbox_byte(iv, ov);
		for (b = 0; b < 8; b++)
			B[lo + 7 - b] = ov[b];
	}
}

static void sm4_bs_T_enc(const sm4_bs_word U[32], sm4_bs_word Y[32])
{
	sm4_bs_word B[32];

	memcpy(B, U, sizeof(B));
	sm4_bs_tau_32w(B);
	sm4_bs_L_enc(B, Y);
}

void sm4_bs_encrypt(const sm4_bs_key_t *key, sm4_bs_word st[128])
{
	sm4_bs_word x0[32], x1[32], x2[32], x3[32], x4[32], t1[32], t2[32];
	int r, i;

	memcpy(x0, st + 0, sizeof(x0));
	memcpy(x1, st + 32, sizeof(x1));
	memcpy(x2, st + 64, sizeof(x2));
	memcpy(x3, st + 96, sizeof(x3));

	for (r = 0; r < 32; r++) {
		for (i = 0; i < 32; i++)
			t1[i] = x1[i] ^ x2[i] ^ x3[i] ^ key->rk[r][i];
		sm4_bs_T_enc(t1, t2);
		for (i = 0; i < 32; i++)
			x4[i] = x0[i] ^ t2[i];
		memcpy(x0, x1, sizeof(x0));
		memcpy(x1, x2, sizeof(x1));
		memcpy(x2, x3, sizeof(x2));
		memcpy(x3, x4, sizeof(x3));
	}

	/* Ciphertext word order = (X35,X34,X33,X32) = (x3,x2,x1,x0) here. */
	memcpy(st + 0, x3, sizeof(x3));
	memcpy(st + 32, x2, sizeof(x2));
	memcpy(st + 64, x1, sizeof(x1));
	memcpy(st + 96, x0, sizeof(x0));
}

void sm4_bs_decrypt(const sm4_bs_key_t *key, sm4_bs_word st[128])
{
	sm4_bs_encrypt(key, st);
}
