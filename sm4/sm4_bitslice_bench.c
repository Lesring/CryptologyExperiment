/*
 * Bitslice SM4 throughput. Each sm4_bs_encrypt is 32 blocks in parallel.
 * Gbit/s = (bytes * 8) / sec / 1e9 (decimal).
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sm4_bitslice.h"

#ifndef SM4_BS_BENCH_LOOPS
#define SM4_BS_BENCH_LOOPS 200000u
#endif

int main(void)
{
	static uint8_t blocks[SM4_BS_WIDTH * 16];
	static sm4_bs_word st[128];
	static const uint8_t key[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};

	sm4_bs_key_t enc, dec;
	clock_t t0, t1;
	double sec, bytes, gbps;
	uint32_t j;

	memset(blocks, 0x5Au, sizeof blocks);

	sm4_bs_key_enc(&enc, key);
	sm4_bs_key_dec(&dec, key);

	/* Warmup */
	for (j = 0; j < 50u; j++) {
		sm4_bs_pack(blocks, st);
		sm4_bs_encrypt(&enc, st);
		sm4_bs_unpack(st, blocks);
	}

	/* pack + encrypt + unpack (32 blocks per iteration) */
	t0 = clock();
	for (j = 0; j < SM4_BS_BENCH_LOOPS; j++) {
		sm4_bs_pack(blocks, st);
		sm4_bs_encrypt(&enc, st);
		sm4_bs_unpack(st, blocks);
	}
	t1 = clock();
	sec = (double)(t1 - t0) / (double)CLOCKS_PER_SEC;
	bytes = (double)SM4_BS_BENCH_LOOPS * (double)SM4_BS_WIDTH * 16.0;
	gbps = (bytes * 8.0) / sec / 1e9;

	printf("SM4 bitslice: pack+encrypt+unpack, %u batches x 32 blocks\n",
	       (unsigned)SM4_BS_BENCH_LOOPS);
	printf("  CPU time:     %.3f s\n", sec);
	printf("  Data:         %.2f MiB (%.3f GB)\n", bytes / (1024.0 * 1024.0),
	       bytes / 1e9);
	printf("  Throughput:   %.3f Gbit/s (decimal)\n", gbps);
	printf("  Per batch:    %.2f us (32 blocks)\n\n",
	       sec * 1e6 / (double)SM4_BS_BENCH_LOOPS);

	/* core encrypt only */
	for (j = 0; j < 50u; j++)
		sm4_bs_encrypt(&enc, st);
	t0 = clock();
	for (j = 0; j < SM4_BS_BENCH_LOOPS; j++)
		sm4_bs_encrypt(&enc, st);
	t1 = clock();
	sec = (double)(t1 - t0) / (double)CLOCKS_PER_SEC;
	bytes = (double)SM4_BS_BENCH_LOOPS * (double)SM4_BS_WIDTH * 16.0;
	gbps = (bytes * 8.0) / sec / 1e9;
	printf("SM4 bitslice: sm4_bs_encrypt only (same logical data volume)\n");
	printf("  CPU time:     %.3f s\n", sec);
	printf("  Throughput:   %.3f Gbit/s (decimal)\n", gbps);
	printf("  Per batch:    %.2f us (32 blocks)\n\n",
	       sec * 1e6 / (double)SM4_BS_BENCH_LOOPS);

	/* decrypt pipeline */
	for (j = 0; j < 50u; j++) {
		sm4_bs_pack(blocks, st);
		sm4_bs_decrypt(&dec, st);
		sm4_bs_unpack(st, blocks);
	}
	t0 = clock();
	for (j = 0; j < SM4_BS_BENCH_LOOPS; j++) {
		sm4_bs_pack(blocks, st);
		sm4_bs_decrypt(&dec, st);
		sm4_bs_unpack(st, blocks);
	}
	t1 = clock();
	sec = (double)(t1 - t0) / (double)CLOCKS_PER_SEC;
	bytes = (double)SM4_BS_BENCH_LOOPS * (double)SM4_BS_WIDTH * 16.0;
	gbps = (bytes * 8.0) / sec / 1e9;
	printf("SM4 bitslice: pack+decrypt+unpack\n");
	printf("  CPU time:     %.3f s\n", sec);
	printf("  Throughput:   %.3f Gbit/s (decimal)\n", gbps);

	return 0;
}
