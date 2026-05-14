#include <stdio.h>
#include <string.h>

#include "sm4.h"

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
	/* GB/T 32907 example: same key and plaintext block */
	static const uint8_t key_pt[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	/* Same block as key; reference matches GB/T examples / PyCA SM4. */
	static const uint8_t expect_ct[16] = {
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
	};

	sm4_key_t enc, dec;
	uint8_t ct[16], pt[16];
	int fail = 0;

	sm4_setkey_enc(&enc, key_pt);
	sm4_encrypt(&enc, key_pt, ct);
	if (!memeq(ct, expect_ct, 16)) {
		printf("FAIL encrypt\n");
		fail = 1;
	}

	sm4_setkey_dec(&dec, key_pt);
	sm4_decrypt(&dec, ct, pt);
	if (!memeq(pt, key_pt, 16)) {
		printf("FAIL decrypt\n");
		fail = 1;
	}

	{
		uint8_t buf[32], out[32];
		memcpy(buf, key_pt, 16);
		memcpy(buf + 16, key_pt, 16);
		sm4_encrypt_blocks(&enc, buf, 2, out);
		if (!memeq(out, expect_ct, 16) || !memeq(out + 16, expect_ct, 16)) {
			printf("FAIL encrypt_blocks\n");
			fail = 1;
		}
		sm4_decrypt_blocks(&dec, out, 2, buf);
		if (!memeq(buf, key_pt, 16) || !memeq(buf + 16, key_pt, 16)) {
			printf("FAIL decrypt_blocks\n");
			fail = 1;
		}
	}

	if (!fail)
		printf("sm4: all tests passed\n");
	return fail ? 1 : 0;
}
