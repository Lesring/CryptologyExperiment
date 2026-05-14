/* Link exactly one of: aes128.c | aes128_ni.c | aes128_ni_vaes.c (with matching flags). */
#include "aes128.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    static const uint8_t key[16] = {
        0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU,
    };
    static const uint8_t pt[16] = {
        0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
        0x88U, 0x99U, 0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU, 0xffU,
    };
    static const uint8_t expect[16] = {
        0x69U, 0xc4U, 0xe0U, 0xd8U, 0x6aU, 0x7bU, 0x04U, 0x30U,
        0xd8U, 0xcdU, 0xb7U, 0x80U, 0x70U, 0xb4U, 0xc5U, 0x5aU,
    };
    uint8_t buf[16];
    AES128CTX e, d;

    aes128_set_encrypt_key(&e, key);
    aes128_encrypt_block(&e, buf, pt);
    if (memcmp(buf, expect, 16) != 0) {
        fputs("FAIL: encrypt vector\n", stderr);
        return 1;
    }
    aes128_set_decrypt_key(&d, key);
    aes128_decrypt_block(&d, buf, buf);
    if (memcmp(buf, pt, 16) != 0) {
        fputs("FAIL: decrypt roundtrip\n", stderr);
        return 2;
    }
    static const uint8_t z32[32] = {0};
    uint8_t ecb_src[64], ecb_dst[64];
    size_t i;
    for (i = 0; i < sizeof ecb_src; i++)
        ecb_src[i] = (uint8_t)(i * 7u + 13u);
    memcpy(ecb_dst, z32, 32);
    aes128_set_encrypt_key(&e, key);
    aes128_encrypt_ecb(&e, ecb_dst, ecb_src, 32u);
    memcpy(ecb_dst + 32, ecb_src + 32, 32);
    aes128_encrypt_ecb(&e, ecb_dst + 32, ecb_src + 32, 32u);
    aes128_set_decrypt_key(&d, key);
    aes128_decrypt_ecb(&d, ecb_dst, ecb_dst, 64u);
    if (memcmp(ecb_dst, ecb_src, 64) != 0) {
        fputs("FAIL: ecb 64-byte roundtrip\n", stderr);
        return 3;
    }
    fputs("OK: vectors + ecb64\n", stdout);
    return 0;
}
