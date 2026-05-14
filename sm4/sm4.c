#include "sm4.h"

extern const uint32_t SM4_T0[256];
extern const uint32_t SM4_T1[256];
extern const uint32_t SM4_T2[256];
extern const uint32_t SM4_T3[256];
extern const uint32_t SM4_KS0[256];
extern const uint32_t SM4_KS1[256];
extern const uint32_t SM4_KS2[256];
extern const uint32_t SM4_KS3[256];

#if defined(__GNUC__) && !defined(SM4_NO_PREFETCH)
#define SM4_PREFETCH_R(p) __builtin_prefetch((const void *)(p), 0, 3)
#else
#define SM4_PREFETCH_R(p) ((void)0)
#endif

#if defined(__GNUC__)
#define SM4_HOT __attribute__((hot))
#else
#define SM4_HOT
#endif

static const uint32_t SM4_FK[4] = {
	0xa3b1bac6u, 0x56aa3350u, 0x677d9197u, 0xb27022dcu,
};

static const uint32_t SM4_CK[32] = {
	0x00070e15u, 0x1c232a31u, 0x383f464du, 0x545b6269u,
	0x70777e85u, 0x8c939aa1u, 0xa8afb6bdu, 0xc4cbd2d9u,
	0xe0e7eef5u, 0xfc030a11u, 0x181f262du, 0x343b4249u,
	0x50575e65u, 0x6c737a81u, 0x888f969du, 0xa4abb2b9u,
	0xc0c7ced5u, 0xdce3eaf1u, 0xf8ff060du, 0x141b2229u,
	0x30373e45u, 0x4c535a61u, 0x686f767du, 0x848b9299u,
	0xa0a7aeb5u, 0xbcc3cad1u, 0xd8dfe6edu, 0xf4fb0209u,
	0x10171e25u, 0x2c333a41u, 0x484f565du, 0x646b7279u,
};

static inline uint32_t load_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void store_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

#define SM4_ROUND(i, rkarr, X0, X1, X2, X3, X4)                   \
	do {                                                      \
		(X4) = (X1) ^ (X2) ^ (X3) ^ (rkarr)[i];          \
		(X4) = SM4_T0[(uint8_t)((X4) >> 24)] ^            \
		       SM4_T1[(uint8_t)((X4) >> 16)] ^            \
		       SM4_T2[(uint8_t)((X4) >> 8)] ^             \
		       SM4_T3[(uint8_t)(X4)] ^ (X0);              \
	} while (0)

#define SM4_ROUND_PAIR(i, rkarr, X0, X1, X2, X3, X4, Y0, Y1, Y2, Y3, Y4) \
	do {                                                              \
		SM4_ROUND(i, rkarr, X0, X1, X2, X3, X4);                 \
		SM4_ROUND(i, rkarr, Y0, Y1, Y2, Y3, Y4);                 \
	} while (0)

static inline void sm4_encrypt_one(const uint32_t *rk, const uint8_t *in,
				   uint8_t *out)
{
	uint32_t X0, X1, X2, X3, X4;

	X0 = load_be32(in);
	X1 = load_be32(in + 4);
	X2 = load_be32(in + 8);
	X3 = load_be32(in + 12);

	SM4_ROUND(0, rk, X0, X1, X2, X3, X4);
	SM4_ROUND(1, rk, X1, X2, X3, X4, X0);
	SM4_ROUND(2, rk, X2, X3, X4, X0, X1);
	SM4_ROUND(3, rk, X3, X4, X0, X1, X2);
	SM4_ROUND(4, rk, X4, X0, X1, X2, X3);
	SM4_ROUND(5, rk, X0, X1, X2, X3, X4);
	SM4_ROUND(6, rk, X1, X2, X3, X4, X0);
	SM4_ROUND(7, rk, X2, X3, X4, X0, X1);
	SM4_ROUND(8, rk, X3, X4, X0, X1, X2);
	SM4_ROUND(9, rk, X4, X0, X1, X2, X3);
	SM4_ROUND(10, rk, X0, X1, X2, X3, X4);
	SM4_ROUND(11, rk, X1, X2, X3, X4, X0);
	SM4_ROUND(12, rk, X2, X3, X4, X0, X1);
	SM4_ROUND(13, rk, X3, X4, X0, X1, X2);
	SM4_ROUND(14, rk, X4, X0, X1, X2, X3);
	SM4_ROUND(15, rk, X0, X1, X2, X3, X4);
	SM4_ROUND(16, rk, X1, X2, X3, X4, X0);
	SM4_ROUND(17, rk, X2, X3, X4, X0, X1);
	SM4_ROUND(18, rk, X3, X4, X0, X1, X2);
	SM4_ROUND(19, rk, X4, X0, X1, X2, X3);
	SM4_ROUND(20, rk, X0, X1, X2, X3, X4);
	SM4_ROUND(21, rk, X1, X2, X3, X4, X0);
	SM4_ROUND(22, rk, X2, X3, X4, X0, X1);
	SM4_ROUND(23, rk, X3, X4, X0, X1, X2);
	SM4_ROUND(24, rk, X4, X0, X1, X2, X3);
	SM4_ROUND(25, rk, X0, X1, X2, X3, X4);
	SM4_ROUND(26, rk, X1, X2, X3, X4, X0);
	SM4_ROUND(27, rk, X2, X3, X4, X0, X1);
	SM4_ROUND(28, rk, X3, X4, X0, X1, X2);
	store_be32(out + 12, X2);
	SM4_ROUND(29, rk, X4, X0, X1, X2, X3);
	store_be32(out + 8, X3);
	SM4_ROUND(30, rk, X0, X1, X2, X3, X4);
	store_be32(out + 4, X4);
	SM4_ROUND(31, rk, X1, X2, X3, X4, X0);
	store_be32(out, X0);
}

static void sm4_encrypt_two(const uint32_t *rk, const uint8_t *in, uint8_t *out)
{
	uint32_t X0, X1, X2, X3, X4;
	uint32_t Y0, Y1, Y2, Y3, Y4;

	X0 = load_be32(in);
	X1 = load_be32(in + 4);
	X2 = load_be32(in + 8);
	X3 = load_be32(in + 12);
	Y0 = load_be32(in + 16);
	Y1 = load_be32(in + 20);
	Y2 = load_be32(in + 24);
	Y3 = load_be32(in + 28);

	SM4_ROUND_PAIR(0, rk, X0, X1, X2, X3, X4, Y0, Y1, Y2, Y3, Y4);
	SM4_ROUND_PAIR(1, rk, X1, X2, X3, X4, X0, Y1, Y2, Y3, Y4, Y0);
	SM4_ROUND_PAIR(2, rk, X2, X3, X4, X0, X1, Y2, Y3, Y4, Y0, Y1);
	SM4_ROUND_PAIR(3, rk, X3, X4, X0, X1, X2, Y3, Y4, Y0, Y1, Y2);
	SM4_ROUND_PAIR(4, rk, X4, X0, X1, X2, X3, Y4, Y0, Y1, Y2, Y3);
	SM4_ROUND_PAIR(5, rk, X0, X1, X2, X3, X4, Y0, Y1, Y2, Y3, Y4);
	SM4_ROUND_PAIR(6, rk, X1, X2, X3, X4, X0, Y1, Y2, Y3, Y4, Y0);
	SM4_ROUND_PAIR(7, rk, X2, X3, X4, X0, X1, Y2, Y3, Y4, Y0, Y1);
	SM4_ROUND_PAIR(8, rk, X3, X4, X0, X1, X2, Y3, Y4, Y0, Y1, Y2);
	SM4_ROUND_PAIR(9, rk, X4, X0, X1, X2, X3, Y4, Y0, Y1, Y2, Y3);
	SM4_ROUND_PAIR(10, rk, X0, X1, X2, X3, X4, Y0, Y1, Y2, Y3, Y4);
	SM4_ROUND_PAIR(11, rk, X1, X2, X3, X4, X0, Y1, Y2, Y3, Y4, Y0);
	SM4_ROUND_PAIR(12, rk, X2, X3, X4, X0, X1, Y2, Y3, Y4, Y0, Y1);
	SM4_ROUND_PAIR(13, rk, X3, X4, X0, X1, X2, Y3, Y4, Y0, Y1, Y2);
	SM4_ROUND_PAIR(14, rk, X4, X0, X1, X2, X3, Y4, Y0, Y1, Y2, Y3);
	SM4_ROUND_PAIR(15, rk, X0, X1, X2, X3, X4, Y0, Y1, Y2, Y3, Y4);
	SM4_ROUND_PAIR(16, rk, X1, X2, X3, X4, X0, Y1, Y2, Y3, Y4, Y0);
	SM4_ROUND_PAIR(17, rk, X2, X3, X4, X0, X1, Y2, Y3, Y4, Y0, Y1);
	SM4_ROUND_PAIR(18, rk, X3, X4, X0, X1, X2, Y3, Y4, Y0, Y1, Y2);
	SM4_ROUND_PAIR(19, rk, X4, X0, X1, X2, X3, Y4, Y0, Y1, Y2, Y3);
	SM4_ROUND_PAIR(20, rk, X0, X1, X2, X3, X4, Y0, Y1, Y2, Y3, Y4);
	SM4_ROUND_PAIR(21, rk, X1, X2, X3, X4, X0, Y1, Y2, Y3, Y4, Y0);
	SM4_ROUND_PAIR(22, rk, X2, X3, X4, X0, X1, Y2, Y3, Y4, Y0, Y1);
	SM4_ROUND_PAIR(23, rk, X3, X4, X0, X1, X2, Y3, Y4, Y0, Y1, Y2);
	SM4_ROUND_PAIR(24, rk, X4, X0, X1, X2, X3, Y4, Y0, Y1, Y2, Y3);
	SM4_ROUND_PAIR(25, rk, X0, X1, X2, X3, X4, Y0, Y1, Y2, Y3, Y4);
	SM4_ROUND_PAIR(26, rk, X1, X2, X3, X4, X0, Y1, Y2, Y3, Y4, Y0);
	SM4_ROUND_PAIR(27, rk, X2, X3, X4, X0, X1, Y2, Y3, Y4, Y0, Y1);
	SM4_ROUND_PAIR(28, rk, X3, X4, X0, X1, X2, Y3, Y4, Y0, Y1, Y2);
	store_be32(out + 12, X2);
	store_be32(out + 28, Y2);
	SM4_ROUND_PAIR(29, rk, X4, X0, X1, X2, X3, Y4, Y0, Y1, Y2, Y3);
	store_be32(out + 8, X3);
	store_be32(out + 24, Y3);
	SM4_ROUND_PAIR(30, rk, X0, X1, X2, X3, X4, Y0, Y1, Y2, Y3, Y4);
	store_be32(out + 4, X4);
	store_be32(out + 20, Y4);
	SM4_ROUND_PAIR(31, rk, X1, X2, X3, X4, X0, Y1, Y2, Y3, Y4, Y0);
	store_be32(out, X0);
	store_be32(out + 16, Y0);
}

void sm4_setkey_enc(sm4_key_t *key, const uint8_t user_key[SM4_KEY_SIZE])
{
	uint32_t X0 = load_be32(user_key) ^ SM4_FK[0];
	uint32_t X1 = load_be32(user_key + 4) ^ SM4_FK[1];
	uint32_t X2 = load_be32(user_key + 8) ^ SM4_FK[2];
	uint32_t X3 = load_be32(user_key + 12) ^ SM4_FK[3];
	uint32_t X4;
	int i;

	for (i = 0; i < 32; i++) {
		X4 = X1 ^ X2 ^ X3 ^ SM4_CK[i];
		X4 = SM4_KS0[(uint8_t)(X4 >> 24)] ^
		     SM4_KS1[(uint8_t)(X4 >> 16)] ^
		     SM4_KS2[(uint8_t)(X4 >> 8)] ^ SM4_KS3[(uint8_t)X4] ^ X0;
		key->rk[i] = X4;
		X0 = X1;
		X1 = X2;
		X2 = X3;
		X3 = X4;
	}
}

void sm4_setkey_dec(sm4_key_t *key, const uint8_t user_key[SM4_KEY_SIZE])
{
	uint32_t X0 = load_be32(user_key) ^ SM4_FK[0];
	uint32_t X1 = load_be32(user_key + 4) ^ SM4_FK[1];
	uint32_t X2 = load_be32(user_key + 8) ^ SM4_FK[2];
	uint32_t X3 = load_be32(user_key + 12) ^ SM4_FK[3];
	uint32_t X4;
	int i;

	for (i = 0; i < 32; i++) {
		X4 = X1 ^ X2 ^ X3 ^ SM4_CK[i];
		X4 = SM4_KS0[(uint8_t)(X4 >> 24)] ^
		     SM4_KS1[(uint8_t)(X4 >> 16)] ^
		     SM4_KS2[(uint8_t)(X4 >> 8)] ^ SM4_KS3[(uint8_t)X4] ^ X0;
		key->rk[31 - i] = X4;
		X0 = X1;
		X1 = X2;
		X2 = X3;
		X3 = X4;
	}
}

void sm4_encrypt(const sm4_key_t *key, const uint8_t in[SM4_BLOCK_SIZE],
		 uint8_t out[SM4_BLOCK_SIZE])
{
	sm4_encrypt_one(key->rk, in, out);
}

void sm4_decrypt(const sm4_key_t *key, const uint8_t in[SM4_BLOCK_SIZE],
		 uint8_t out[SM4_BLOCK_SIZE])
{
	sm4_encrypt(key, in, out);
}

SM4_HOT void sm4_encrypt_blocks(const sm4_key_t *key, const uint8_t *in,
				size_t nblocks, uint8_t *out)
{
	const uint32_t *rk = key->rk;

	while (nblocks >= 2) {
		if (nblocks >= 4)
			SM4_PREFETCH_R(in + 32);
		sm4_encrypt_two(rk, in, out);
		in += 32;
		out += 32;
		nblocks -= 2;
	}
	if (nblocks)
		sm4_encrypt_one(rk, in, out);
}

void sm4_decrypt_blocks(const sm4_key_t *key, const uint8_t *in, size_t nblocks,
			uint8_t *out)
{
	sm4_encrypt_blocks(key, in, nblocks, out);
}
