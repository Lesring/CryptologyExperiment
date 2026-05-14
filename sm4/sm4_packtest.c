#include <string.h>
#include <stdio.h>
#include "sm4_bitslice_avx2.h"

int main(void)
{
	uint8_t a[256 * 16], b[256 * 16];
	sm4_bs_avx2_word st[128];

	memset(a, 0x3c, sizeof a);
	sm4_bs_avx2_pack(a, st);
	sm4_bs_avx2_unpack(st, b);
	if (memcmp(a, b, sizeof a) != 0) {
		printf("pack/unpack fail\n");
		return 1;
	}
	printf("pack/unpack ok\n");
	return 0;
}
