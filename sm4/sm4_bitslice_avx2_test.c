#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "sm4.h"
#include "sm4_bitslice_avx2.h"

#if !defined(__AVX2__)
int main(void)
{
	printf("skip: compile with -mavx2\n");
	return 0;
}
#else

static int memeq(const uint8_t *a, const uint8_t *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}

int main(void)
{
	static const uint8_t key[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	static const uint8_t pt[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	uint8_t blocks[SM4_BS_AVX2_WIDTH * 16];
	sm4_bs_avx2_word st[128];
	sm4_bs_avx2_key_t bsk;
	sm4_key_t refk;
	uint8_t ref_ct[16];
	int i, fail = 0;

	sm4_setkey_enc(&refk, key);
	sm4_encrypt(&refk, pt, ref_ct);

	for (i = 0; i < SM4_BS_AVX2_WIDTH; i++)
		memcpy(blocks + (size_t)i * 16, pt, 16);

	sm4_bs_avx2_key_enc(&bsk, key);
	sm4_bs_avx2_pack(blocks, st);
	sm4_bs_avx2_encrypt(&bsk, st);
	sm4_bs_avx2_unpack(st, blocks);

	for (i = 0; i < SM4_BS_AVX2_WIDTH; i++) {
		if (!memeq(blocks + (size_t)i * 16, ref_ct, 16)) {
			printf("FAIL lane %d encrypt\n", i);
			fail = 1;
			break;
		}
	}

	for (i = 0; i < SM4_BS_AVX2_WIDTH; i++)
		memcpy(blocks + (size_t)i * 16, ref_ct, 16);
	sm4_bs_avx2_key_dec(&bsk, key);
	sm4_bs_avx2_pack(blocks, st);
	sm4_bs_avx2_decrypt(&bsk, st);
	sm4_bs_avx2_unpack(st, blocks);

	for (i = 0; i < SM4_BS_AVX2_WIDTH; i++) {
		if (!memeq(blocks + (size_t)i * 16, pt, 16)) {
			printf("FAIL lane %d decrypt\n", i);
			fail = 1;
			break;
		}
	}

	if (!fail)
		printf("sm4_bitslice_avx2: all %d-lane tests passed\n",
		       SM4_BS_AVX2_WIDTH);
	return fail ? 1 : 0;
}

#endif
