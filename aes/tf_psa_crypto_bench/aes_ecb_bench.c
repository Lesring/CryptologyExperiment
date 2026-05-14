/*
 * Single-thread AES-128 ECB encrypt throughput using TF-PSA-Crypto builtin AES
 * (drivers/builtin/src/aes.c et al., linked via libtfpsacrypto).
 */
#include "mbedtls/private/aes.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

static const char *impl_str(mbedtls_aes_implementation i)
{
    switch (i) {
    case MBEDTLS_AES_IMP_SOFTWARE:
        return "software (T-tables)";
    case MBEDTLS_AES_IMP_AESCE:
        return "AES-CE (ARMv8)";
    case MBEDTLS_AES_IMP_AESNI_ASM:
        return "AES-NI asm";
    case MBEDTLS_AES_IMP_AESNI_INTRINSICS:
        return "AES-NI intrinsics";
    default:
        return "unknown";
    }
}

static void encrypt_buffer_ecb_inplace(mbedtls_aes_context *ctx,
                                       unsigned char *buf, size_t nbytes)
{
    size_t off;
    for (off = 0; off < nbytes; off += 16) {
        if (mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, buf + off,
                                  buf + off) != 0) {
            fprintf(stderr, "mbedtls_aes_crypt_ecb failed\n");
            exit(1);
        }
    }
}

int main(void)
{
    const size_t bufsize = (size_t)1 << 24;
    const size_t repetitions = (size_t)400;
    mbedtls_aes_context aes;
    unsigned char *buf;
    unsigned char key[16];
    size_t r;
    volatile unsigned char sink = 0;

#if defined(_WIN32)
    LARGE_INTEGER f, t0, t1;
#endif
    double sec;
    double gb;
    double mbps;
    size_t i;

    for (i = 0; i < sizeof key; i++) {
        key[i] = (unsigned char)i;
    }

    buf = (unsigned char *)malloc(bufsize);
    if (!buf) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }
    for (i = 0; i < bufsize; i++) {
        buf[i] = (unsigned char)i;
    }

    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0) {
        fprintf(stderr, "mbedtls_aes_setkey_enc failed\n");
        free(buf);
        return 1;
    }

    printf("TF-PSA-Crypto builtin AES (mbedtls_aes_crypt_ecb), single-thread\n");
    printf(
        "AES backend after key setup: %s\n",
        impl_str(mbedtls_aes_get_implementation()));

    encrypt_buffer_ecb_inplace(&aes, buf, bufsize);

#if defined(_WIN32)
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    for (r = 0; r < repetitions; r++) {
        encrypt_buffer_ecb_inplace(&aes, buf, bufsize);
    }
    QueryPerformanceCounter(&t1);
    sec = (double)(t1.QuadPart - t0.QuadPart) / (double)f.QuadPart;
#else
    /* Portable fallback; extend if you run this bench on non-Windows. */
    sec = 0.0;
    (void)r;
#endif

    sink ^= buf[bufsize - 1];
    gb = (double)bufsize * (double)repetitions / (1024.0 * 1024.0 * 1024.0);
    mbps =
        (double)bufsize * (double)repetitions * 8.0 / (sec > 0 ? sec * 1e6 : 1e-6);

    printf("Buffer: %zu MiB   Repeats: %zu   Bytes total: ~%.2f GiB\n",
           bufsize / (1024u * 1024u), repetitions, gb);
    printf("Time:   %.6f s\n", sec);
    printf("Throughput: %.2f Mbps (%.2f MB/s)\n", mbps,
           (double)bufsize * (double)repetitions /
               (sec > 0 ? sec * 1024.0 * 1024.0 : 1e-6));

    mbedtls_aes_free(&aes);
    free(buf);
    (void)sink;
    return 0;
}
