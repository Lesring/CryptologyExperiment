#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sm4_bitslice_avx2.h"

#ifndef SM4_BS_AVX2_BENCH_LOOPS
#define SM4_BS_AVX2_BENCH_LOOPS 80000u
#endif

#if !defined(__AVX2__)
int main(void)
{
	printf("skip: use -mavx2\n");
	return 0;
}
#else

int main(void)
{
	static uint8_t blocks[SM4_BS_AVX2_WIDTH * 16];
	static sm4_bs_avx2_word st[128];
	static const uint8_t key[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	sm4_bs_avx2_key_t enc, dec;
	uint32_t j;
	clock_t t0, t1;
	double sec, bytes, gbps;

	memset(blocks, 0x5Au, sizeof blocks);
	sm4_bs_avx2_key_enc(&enc, key);
	sm4_bs_avx2_key_dec(&dec, key);

	for (j = 0; j < 20u; j++) {
		sm4_bs_avx2_pack(blocks, st);
		sm4_bs_avx2_encrypt(&enc, st);
		sm4_bs_avx2_unpack(st, blocks);
	}

	t0 = clock();
	for (j = 0; j < SM4_BS_AVX2_BENCH_LOOPS; j++) {
		sm4_bs_avx2_pack(blocks, st);
		sm4_bs_avx2_encrypt(&enc, st);
		sm4_bs_avx2_unpack(st, blocks);
	}
	t1 = clock();
	sec = (double)(t1 - t0) / (double)CLOCKS_PER_SEC;
	bytes = (double)SM4_BS_AVX2_BENCH_LOOPS * (double)SM4_BS_AVX2_WIDTH * 16.0;
	gbps = (bytes * 8.0) / sec / 1e9;
	printf("AVX2 bitslice: pack+encrypt+unpack, %u batches x %d blocks\n",
	       (unsigned)SM4_BS_AVX2_BENCH_LOOPS, SM4_BS_AVX2_WIDTH);
	printf("  CPU:          %.3f s\n", sec);
	printf("  Throughput:   %.3f Gbit/s\n", gbps);
	printf("  Encrypt-only: ");

	for (j = 0; j < 20u; j++)
		sm4_bs_avx2_encrypt(&enc, st);
	t0 = clock();
	for (j = 0; j < SM4_BS_AVX2_BENCH_LOOPS; j++)
		sm4_bs_avx2_encrypt(&enc, st);
	t1 = clock();
	sec = (double)(t1 - t0) / (double)CLOCKS_PER_SEC;
	gbps = (bytes * 8.0) / sec / 1e9;
	printf("%.3f Gbit/s\n", gbps);

	return 0;
}

#endif
