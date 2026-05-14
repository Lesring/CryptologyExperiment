/*
 * AES-128 ECB throughput bench for aes128_ni.c (AES-NI).
 * Build: gcc -O2 -maes -msse2 -o aes128_ni_bench aes128_ni.c aes128_ni_bench.c
 * VAES 变体测速见 aes128_ni_vaes_bench.c + aes128_ni_vaes.c。
 */
#include "aes128.h"

#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <windows.h>
#endif

int main(void)
{
    AES128CTX enc_ctx, dec_ctx;
#if defined(_WIN32)
    LARGE_INTEGER f, a, b;
#endif
    const size_t bufsize = ((size_t)1 << 24);
    const size_t repetitions = (size_t)400;
    unsigned char *buf;
    double sec;
    volatile unsigned char sink = 0;
    size_t r;
    volatile size_t k;
    unsigned i;
    const unsigned char user_key[16] = {
        0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U,
    };
    double gb;
    double mbps;

    buf = (unsigned char *)malloc(bufsize);
    if (!buf) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }
    for (i = 0; i < bufsize; i++)
        buf[i] = (unsigned char)i;

    aes128_set_encrypt_key(&enc_ctx, user_key);

    for (k = 0; k < bufsize; k += 16)
        aes128_encrypt_block(&enc_ctx, buf + k, buf + k);

#if defined(_WIN32)
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&a);
    for (r = 0; r < repetitions; r++)
        aes128_encrypt_ecb(&enc_ctx, buf, buf, bufsize);
    QueryPerformanceCounter(&b);
    sec = (double)(b.QuadPart - a.QuadPart) / (double)f.QuadPart;
#else
    sec = 1.0;
    (void)r;
#endif

    sink ^= buf[bufsize - 1];
    gb = (double)bufsize * (double)repetitions / (1024.0 * 1024.0 * 1024.0);
    mbps = (double)bufsize * (double)repetitions * 8.0 / (sec * 1e6);

    printf("AES-128 ECB encrypt (single-thread, AES-NI)\n");
    printf("Buffer: %zu MiB   Repeats: %zu   Bytes total: ~%.2f GiB\n",
           (size_t)(bufsize / (1024 * 1024)), repetitions, gb);
    printf("Time:   %.6f s\n", sec);
    printf("Throughput: %.2f Mbps (%.2f MB/s)\n", mbps,
           (double)bufsize * (double)repetitions / (sec * 1024.0 * 1024.0));

    for (i = 0; i < bufsize; i++)
        buf[i] = (unsigned char)i;
    aes128_encrypt_ecb(&enc_ctx, buf, buf, bufsize);
    aes128_set_decrypt_key(&dec_ctx, user_key);
    for (k = 0; k < bufsize; k += 16)
        aes128_decrypt_block(&dec_ctx, buf + k, buf + k);

#if defined(_WIN32)
    QueryPerformanceCounter(&a);
    for (r = 0; r < repetitions; r++)
        aes128_decrypt_ecb(&dec_ctx, buf, buf, bufsize);
    QueryPerformanceCounter(&b);
    sec = (double)(b.QuadPart - a.QuadPart) / (double)f.QuadPart;
#endif

    sink ^= buf[bufsize - 1];
    gb = (double)bufsize * (double)repetitions / (1024.0 * 1024.0 * 1024.0);
    mbps = (double)bufsize * (double)repetitions * 8.0 / (sec * 1e6);

    printf("\nAES-128 ECB decrypt (single-thread, AES-NI)\n");
    printf("Buffer: %zu MiB   Repeats: %zu   Bytes total: ~%.2f GiB\n",
           (size_t)(bufsize / (1024 * 1024)), repetitions, gb);
    printf("Time:   %.6f s\n", sec);
    printf("Throughput: %.2f Mbps (%.2f MB/s)\n", mbps,
           (double)bufsize * (double)repetitions / (sec * 1024.0 * 1024.0));

    free(buf);
    (void)sink;
    return 0;
}
