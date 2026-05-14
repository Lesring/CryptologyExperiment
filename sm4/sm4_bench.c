/*
 * SM4 throughput benchmark (single-thread, table + dual-block interleave).
 * Reports decimal gigabits per second (Gbit/s): bytes * 8 / s / 1e9.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sm4.h"

#ifndef SM4_BENCH_BATCH
#define SM4_BENCH_BATCH 4096u
#endif

#ifndef SM4_BENCH_LOOPS
#define SM4_BENCH_LOOPS 40000u
#endif

int main(void)
{
	static uint8_t buf[SM4_BENCH_BATCH * SM4_BLOCK_SIZE];
	static const uint8_t key[SM4_KEY_SIZE] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};

	sm4_key_t enc, dec;
	clock_t t0, t1;
	double sec, bytes, gbps;

	memset(buf, 0xA5, sizeof buf);

	sm4_setkey_enc(&enc, key);
	sm4_setkey_dec(&dec, key);

#define BENCH_BODY(name, call)                                               \
	do {                                                                 \
		uint32_t j;                                                  \
		for (j = 0; j < 100u; j++)                                   \
			(call);                                              \
		t0 = clock();                                                \
		for (j = 0; j < SM4_BENCH_LOOPS; j++)                        \
			(call);                                              \
		t1 = clock();                                                \
		sec = (double)(t1 - t0) / (double)CLOCKS_PER_SEC;             \
		bytes = (double)SM4_BENCH_LOOPS * (double)SM4_BENCH_BATCH *   \
			(double)SM4_BLOCK_SIZE;                              \
		gbps = (bytes * 8.0) / sec / 1e9;                            \
		printf(name " (%u blocks/call, %u calls)\n",                   \
		       (unsigned)SM4_BENCH_BATCH,                            \
		       (unsigned)SM4_BENCH_LOOPS);                           \
		printf("  CPU time:     %.3f s\n", sec);                     \
		printf("  Data:         %.2f MiB (%.3f GB)\n",               \
		       bytes / (1024.0 * 1024.0), bytes / 1e9);             \
		printf("  Throughput:   %.3f Gbit/s (decimal)\n", gbps);      \
		printf("  Per block:    %.2f ns (avg)\n\n",                  \
		       sec * 1e9 /                                             \
			       ((double)SM4_BENCH_LOOPS *                    \
				(double)SM4_BENCH_BATCH));                   \
	} while (0)

	BENCH_BODY("SM4 encrypt",
		   sm4_encrypt_blocks(&enc, buf, SM4_BENCH_BATCH, buf));
	BENCH_BODY("SM4 decrypt",
		   sm4_decrypt_blocks(&dec, buf, SM4_BENCH_BATCH, buf));

	return 0;
}
