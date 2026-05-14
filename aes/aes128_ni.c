/*
 * AES-128 实现：Intel/AMD AES-NI 硬件指令（_vaesenc / aesdec 等）。
 *
 * 适用：x86-64 且 CPU 支持 AES-NI（你的 Ryzen 7 8845H 支持）。
 * 与 aes128.h 的 API 完全一致，可作为 aes128.c（T 表版）的替代品链接，
 * 勿在同一程序中同时链接两者的对象文件（符号会重复）。
 *
 * ECB 大块：8× 与 4× XMM 交错执行 AESENC/AESDEC，隐藏轮延迟（较单路 VAES 在部分 Zen
 * 上解密更快、更稳）。仅需 -maes -msse2。若要用 VAES 双块路径，改链接
 * aes128_ni_vaes.c（编译加 -mavx2 -mvaes）。
 *   MSVC: cl /O2 /arch:AES /c aes128_ni.c
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "aes128.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#include <wmmintrin.h>
#elif defined(_MSC_VER)
#include <wmmintrin.h>
#else
#error "aes128_ni.c: 仅支持带 WMmintrinsics 的 x86 编译器（GCC/Clang/MSVC）"
#endif

#define GETU32(p)                                                                      \
    (((uint32_t)(p)[0] << 24) | ((uint32_t)(p)[1] << 16) | ((uint32_t)(p)[2] << 8) | \
     ((uint32_t)(p)[3]))

#define PUTU32(p, v)                          \
    do {                                       \
        (p)[0] = (uint8_t)((uint32_t)(v) >> 24); \
        (p)[1] = (uint8_t)((uint32_t)(v) >> 16); \
        (p)[2] = (uint8_t)((uint32_t)(v) >> 8);  \
        (p)[3] = (uint8_t)((uint32_t)(v));      \
    } while (0)

static const uint8_t SB[256] = {
    0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U, 0x30U, 0x01U, 0x67U, 0x2bU,
    0xfeU, 0xd7U, 0xabU, 0x76U, 0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U,
    0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U, 0xb7U, 0xfdU, 0x93U, 0x26U,
    0x36U, 0x3fU, 0xf7U, 0xccU, 0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U,
    0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU, 0x07U, 0x12U, 0x80U, 0xe2U,
    0xebU, 0x27U, 0xb2U, 0x75U, 0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U,
    0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U, 0x53U, 0xd1U, 0x00U, 0xedU,
    0x20U, 0xfcU, 0xb1U, 0x5bU, 0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU,
    0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U, 0x45U, 0xf9U, 0x02U, 0x7fU,
    0x50U, 0x3cU, 0x9fU, 0xa8U, 0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U,
    0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U, 0xcdU, 0x0cU, 0x13U, 0xecU,
    0x5fU, 0x97U, 0x44U, 0x17U, 0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U,
    0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U, 0x46U, 0xeeU, 0xb8U, 0x14U,
    0xdeU, 0x5eU, 0x0bU, 0xdbU, 0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU,
    0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U, 0xe7U, 0xc8U, 0x37U, 0x6dU,
    0x8dU, 0xd5U, 0x4eU, 0xa9U, 0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U,
    0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U, 0xe8U, 0xddU, 0x74U, 0x1fU,
    0x4bU, 0xbdU, 0x8bU, 0x8aU, 0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU,
    0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU, 0xe1U, 0xf8U, 0x98U, 0x11U,
    0x69U, 0xd9U, 0x8eU, 0x94U, 0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU,
    0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U, 0x41U, 0x99U, 0x2dU, 0x0fU,
    0xb0U, 0x54U, 0xbbU, 0x16U};

static const uint32_t RCON[10] = {
    0x01000000U, 0x02000000U, 0x04000000U, 0x08000000U, 0x10000000U,
    0x20000000U, 0x40000000U, 0x80000000U, 0x1b000000U, 0x36000000U};

static inline uint32_t sub_word(uint32_t w)
{
    return ((uint32_t)SB[(w >> 24) & 0xffU] << 24U) |
           ((uint32_t)SB[(w >> 16) & 0xffU] << 16U) |
           ((uint32_t)SB[(w >> 8) & 0xffU] << 8U) |
           (uint32_t)SB[w & 0xffU];
}

static inline uint32_t rot_word(uint32_t w) { return (w << 8U) | (w >> 24U); }

static inline __m128i round_key_m128i(const uint32_t *w)
{
    uint8_t b[16];
    PUTU32(b + 0, w[0]);
    PUTU32(b + 4, w[1]);
    PUTU32(b + 8, w[2]);
    PUTU32(b + 12, w[3]);
    return _mm_loadu_si128((const __m128i *)b);
}

static void aes128_ni_pack_rk(AES128CTX *ctx)
{
    int j;
    for (j = 0; j < 11; j++)
        _mm_store_si128((__m128i *)(void *)(ctx->ni_rk + j * 16),
                         round_key_m128i(ctx->rk + j * 4));
}

static inline uint8_t gf_mul_uint8(uint8_t a, uint8_t x)
{
    uint8_t p = 0;
    int n;
    for (n = 0; n < 8; n++) {
        if ((x & 1U) != 0)
            p ^= a;
        {
            uint8_t h = (uint8_t)(a & 0x80U);
            a <<= 1;
            if (h)
                a ^= 0x1bU;
        }
        x >>= 1;
    }
    return p;
}

static void inv_mix_column_bytes(uint8_t u[4])
{
    uint8_t a = u[0], b = u[1], c = u[2], d = u[3];
    u[0] = (uint8_t)(gf_mul_uint8(a, 0xeU) ^ gf_mul_uint8(b, 0xbU) ^ gf_mul_uint8(c, 0xdU) ^
                     gf_mul_uint8(d, 0x9U));
    u[1] = (uint8_t)(gf_mul_uint8(a, 0x9U) ^ gf_mul_uint8(b, 0xeU) ^ gf_mul_uint8(c, 0xbU) ^
                     gf_mul_uint8(d, 0xdU));
    u[2] = (uint8_t)(gf_mul_uint8(a, 0xdU) ^ gf_mul_uint8(b, 0x9U) ^ gf_mul_uint8(c, 0xeU) ^
                     gf_mul_uint8(d, 0xbU));
    u[3] = (uint8_t)(gf_mul_uint8(a, 0xbU) ^ gf_mul_uint8(b, 0xdU) ^ gf_mul_uint8(c, 0x9U) ^
                     gf_mul_uint8(d, 0xeU));
}

static void inv_mix_columns_round_key(uint32_t w[4])
{
    uint8_t s[16];
    int col;
    PUTU32(s + 0, w[0]);
    PUTU32(s + 4, w[1]);
    PUTU32(s + 8, w[2]);
    PUTU32(s + 12, w[3]);
    for (col = 0; col < 4; col++)
        inv_mix_column_bytes(&s[col * 4]);
    w[0] = GETU32(s + 0);
    w[1] = GETU32(s + 4);
    w[2] = GETU32(s + 8);
    w[3] = GETU32(s + 12);
}

void aes128_set_encrypt_key(AES128CTX *ctx, const uint8_t key[16])
{
    uint32_t *rk = ctx->rk;
    int i;
    rk[0] = GETU32(key + 0);
    rk[1] = GETU32(key + 4);
    rk[2] = GETU32(key + 8);
    rk[3] = GETU32(key + 12);
    for (i = 4; i < 44; i++) {
        uint32_t t = rk[i - 1];
        if ((i & 3) == 0)
            t = sub_word(rot_word(t)) ^ RCON[(i >> 2) - 1];
        rk[i] = rk[i - 4] ^ t;
    }
    aes128_ni_pack_rk(ctx);
}

void aes128_set_decrypt_key(AES128CTX *ctx, const uint8_t key[16])
{
    AES128CTX enc;
    uint32_t *dk = ctx->rk;
    int j;
    aes128_set_encrypt_key(&enc, key);

    dk[0] = enc.rk[40];
    dk[1] = enc.rk[41];
    dk[2] = enc.rk[42];
    dk[3] = enc.rk[43];

    for (j = 1; j <= 9; j++) {
        memcpy(dk + j * 4, enc.rk + (10 - j) * 4, 4 * sizeof(uint32_t));
        inv_mix_columns_round_key(dk + j * 4);
    }

    dk[40] = enc.rk[0];
    dk[41] = enc.rk[1];
    dk[42] = enc.rk[2];
    dk[43] = enc.rk[3];
    aes128_ni_pack_rk(ctx);
}

static inline void aes128i_encrypt_with_rk(const __m128i k[11], uint8_t out[16],
                                           const uint8_t in[16])
{
    __m128i s = _mm_loadu_si128((const __m128i *)in);
    int i;

    s = _mm_xor_si128(s, k[0]);
    for (i = 1; i <= 9; i++)
        s = _mm_aesenc_si128(s, k[i]);
    s = _mm_aesenclast_si128(s, k[10]);
    _mm_storeu_si128((__m128i *)out, s);
}

static inline void aes128i_decrypt_with_rk(const __m128i k[11], uint8_t out[16],
                                           const uint8_t in[16])
{
    __m128i s = _mm_loadu_si128((const __m128i *)in);
    int i;

    s = _mm_xor_si128(s, k[0]);
    for (i = 1; i <= 9; i++)
        s = _mm_aesdec_si128(s, k[i]);
    s = _mm_aesdeclast_si128(s, k[10]);
    _mm_storeu_si128((__m128i *)out, s);
}

static inline void aes128_ni_load_k(const AES128CTX *ctx, __m128i k[11])
{
    int j;
    for (j = 0; j < 11; j++)
        k[j] = _mm_load_si128((const __m128i *)(const void *)(ctx->ni_rk + j * 16));
}

void aes128_encrypt_block(const AES128CTX *ctx, uint8_t out[16], const uint8_t in[16])
{
    __m128i k[11];
    aes128_ni_load_k(ctx, k);
    aes128i_encrypt_with_rk(k, out, in);
}

void aes128_decrypt_block(const AES128CTX *ctx, uint8_t out[16], const uint8_t in[16])
{
    __m128i k[11];
    aes128_ni_load_k(ctx, k);
    aes128i_decrypt_with_rk(k, out, in);
}

void aes128_encrypt_ecb(const AES128CTX *ctx, uint8_t *dst, const uint8_t *src, size_t nbytes)
{
    if (nbytes < 16u)
        return;

    {
        __m128i k[11];
        int j;
        aes128_ni_load_k(ctx, k);

        while (nbytes >= 128u) {
            __m128i s0 = _mm_loadu_si128((const __m128i *)(const void *)(src + 0));
            __m128i s1 = _mm_loadu_si128((const __m128i *)(const void *)(src + 16));
            __m128i s2 = _mm_loadu_si128((const __m128i *)(const void *)(src + 32));
            __m128i s3 = _mm_loadu_si128((const __m128i *)(const void *)(src + 48));
            __m128i s4 = _mm_loadu_si128((const __m128i *)(const void *)(src + 64));
            __m128i s5 = _mm_loadu_si128((const __m128i *)(const void *)(src + 80));
            __m128i s6 = _mm_loadu_si128((const __m128i *)(const void *)(src + 96));
            __m128i s7 = _mm_loadu_si128((const __m128i *)(const void *)(src + 112));
            s0 = _mm_xor_si128(s0, k[0]);
            s1 = _mm_xor_si128(s1, k[0]);
            s2 = _mm_xor_si128(s2, k[0]);
            s3 = _mm_xor_si128(s3, k[0]);
            s4 = _mm_xor_si128(s4, k[0]);
            s5 = _mm_xor_si128(s5, k[0]);
            s6 = _mm_xor_si128(s6, k[0]);
            s7 = _mm_xor_si128(s7, k[0]);
            for (j = 1; j <= 9; j++) {
                s0 = _mm_aesenc_si128(s0, k[j]);
                s1 = _mm_aesenc_si128(s1, k[j]);
                s2 = _mm_aesenc_si128(s2, k[j]);
                s3 = _mm_aesenc_si128(s3, k[j]);
                s4 = _mm_aesenc_si128(s4, k[j]);
                s5 = _mm_aesenc_si128(s5, k[j]);
                s6 = _mm_aesenc_si128(s6, k[j]);
                s7 = _mm_aesenc_si128(s7, k[j]);
            }
            s0 = _mm_aesenclast_si128(s0, k[10]);
            s1 = _mm_aesenclast_si128(s1, k[10]);
            s2 = _mm_aesenclast_si128(s2, k[10]);
            s3 = _mm_aesenclast_si128(s3, k[10]);
            s4 = _mm_aesenclast_si128(s4, k[10]);
            s5 = _mm_aesenclast_si128(s5, k[10]);
            s6 = _mm_aesenclast_si128(s6, k[10]);
            s7 = _mm_aesenclast_si128(s7, k[10]);
            _mm_storeu_si128((__m128i *)(void *)(dst + 0), s0);
            _mm_storeu_si128((__m128i *)(void *)(dst + 16), s1);
            _mm_storeu_si128((__m128i *)(void *)(dst + 32), s2);
            _mm_storeu_si128((__m128i *)(void *)(dst + 48), s3);
            _mm_storeu_si128((__m128i *)(void *)(dst + 64), s4);
            _mm_storeu_si128((__m128i *)(void *)(dst + 80), s5);
            _mm_storeu_si128((__m128i *)(void *)(dst + 96), s6);
            _mm_storeu_si128((__m128i *)(void *)(dst + 112), s7);
            src += 128;
            dst += 128;
            nbytes -= 128u;
        }
        while (nbytes >= 64u) {
            __m128i s0 = _mm_loadu_si128((const __m128i *)(const void *)(src + 0));
            __m128i s1 = _mm_loadu_si128((const __m128i *)(const void *)(src + 16));
            __m128i s2 = _mm_loadu_si128((const __m128i *)(const void *)(src + 32));
            __m128i s3 = _mm_loadu_si128((const __m128i *)(const void *)(src + 48));
            s0 = _mm_xor_si128(s0, k[0]);
            s1 = _mm_xor_si128(s1, k[0]);
            s2 = _mm_xor_si128(s2, k[0]);
            s3 = _mm_xor_si128(s3, k[0]);
            for (j = 1; j <= 9; j++) {
                s0 = _mm_aesenc_si128(s0, k[j]);
                s1 = _mm_aesenc_si128(s1, k[j]);
                s2 = _mm_aesenc_si128(s2, k[j]);
                s3 = _mm_aesenc_si128(s3, k[j]);
            }
            s0 = _mm_aesenclast_si128(s0, k[10]);
            s1 = _mm_aesenclast_si128(s1, k[10]);
            s2 = _mm_aesenclast_si128(s2, k[10]);
            s3 = _mm_aesenclast_si128(s3, k[10]);
            _mm_storeu_si128((__m128i *)(void *)(dst + 0), s0);
            _mm_storeu_si128((__m128i *)(void *)(dst + 16), s1);
            _mm_storeu_si128((__m128i *)(void *)(dst + 32), s2);
            _mm_storeu_si128((__m128i *)(void *)(dst + 48), s3);
            src += 64;
            dst += 64;
            nbytes -= 64u;
        }
        while (nbytes >= 16u) {
            aes128i_encrypt_with_rk(k, dst, src);
            src += 16;
            dst += 16;
            nbytes -= 16u;
        }
    }
}

void aes128_decrypt_ecb(const AES128CTX *ctx, uint8_t *dst, const uint8_t *src, size_t nbytes)
{
    if (nbytes < 16u)
        return;

    {
        __m128i k[11];
        int j;
        aes128_ni_load_k(ctx, k);

        while (nbytes >= 128u) {
            __m128i s0 = _mm_loadu_si128((const __m128i *)(const void *)(src + 0));
            __m128i s1 = _mm_loadu_si128((const __m128i *)(const void *)(src + 16));
            __m128i s2 = _mm_loadu_si128((const __m128i *)(const void *)(src + 32));
            __m128i s3 = _mm_loadu_si128((const __m128i *)(const void *)(src + 48));
            __m128i s4 = _mm_loadu_si128((const __m128i *)(const void *)(src + 64));
            __m128i s5 = _mm_loadu_si128((const __m128i *)(const void *)(src + 80));
            __m128i s6 = _mm_loadu_si128((const __m128i *)(const void *)(src + 96));
            __m128i s7 = _mm_loadu_si128((const __m128i *)(const void *)(src + 112));
            s0 = _mm_xor_si128(s0, k[0]);
            s1 = _mm_xor_si128(s1, k[0]);
            s2 = _mm_xor_si128(s2, k[0]);
            s3 = _mm_xor_si128(s3, k[0]);
            s4 = _mm_xor_si128(s4, k[0]);
            s5 = _mm_xor_si128(s5, k[0]);
            s6 = _mm_xor_si128(s6, k[0]);
            s7 = _mm_xor_si128(s7, k[0]);
            for (j = 1; j <= 9; j++) {
                s0 = _mm_aesdec_si128(s0, k[j]);
                s1 = _mm_aesdec_si128(s1, k[j]);
                s2 = _mm_aesdec_si128(s2, k[j]);
                s3 = _mm_aesdec_si128(s3, k[j]);
                s4 = _mm_aesdec_si128(s4, k[j]);
                s5 = _mm_aesdec_si128(s5, k[j]);
                s6 = _mm_aesdec_si128(s6, k[j]);
                s7 = _mm_aesdec_si128(s7, k[j]);
            }
            s0 = _mm_aesdeclast_si128(s0, k[10]);
            s1 = _mm_aesdeclast_si128(s1, k[10]);
            s2 = _mm_aesdeclast_si128(s2, k[10]);
            s3 = _mm_aesdeclast_si128(s3, k[10]);
            s4 = _mm_aesdeclast_si128(s4, k[10]);
            s5 = _mm_aesdeclast_si128(s5, k[10]);
            s6 = _mm_aesdeclast_si128(s6, k[10]);
            s7 = _mm_aesdeclast_si128(s7, k[10]);
            _mm_storeu_si128((__m128i *)(void *)(dst + 0), s0);
            _mm_storeu_si128((__m128i *)(void *)(dst + 16), s1);
            _mm_storeu_si128((__m128i *)(void *)(dst + 32), s2);
            _mm_storeu_si128((__m128i *)(void *)(dst + 48), s3);
            _mm_storeu_si128((__m128i *)(void *)(dst + 64), s4);
            _mm_storeu_si128((__m128i *)(void *)(dst + 80), s5);
            _mm_storeu_si128((__m128i *)(void *)(dst + 96), s6);
            _mm_storeu_si128((__m128i *)(void *)(dst + 112), s7);
            src += 128;
            dst += 128;
            nbytes -= 128u;
        }
        while (nbytes >= 64u) {
            __m128i s0 = _mm_loadu_si128((const __m128i *)(const void *)(src + 0));
            __m128i s1 = _mm_loadu_si128((const __m128i *)(const void *)(src + 16));
            __m128i s2 = _mm_loadu_si128((const __m128i *)(const void *)(src + 32));
            __m128i s3 = _mm_loadu_si128((const __m128i *)(const void *)(src + 48));
            s0 = _mm_xor_si128(s0, k[0]);
            s1 = _mm_xor_si128(s1, k[0]);
            s2 = _mm_xor_si128(s2, k[0]);
            s3 = _mm_xor_si128(s3, k[0]);
            for (j = 1; j <= 9; j++) {
                s0 = _mm_aesdec_si128(s0, k[j]);
                s1 = _mm_aesdec_si128(s1, k[j]);
                s2 = _mm_aesdec_si128(s2, k[j]);
                s3 = _mm_aesdec_si128(s3, k[j]);
            }
            s0 = _mm_aesdeclast_si128(s0, k[10]);
            s1 = _mm_aesdeclast_si128(s1, k[10]);
            s2 = _mm_aesdeclast_si128(s2, k[10]);
            s3 = _mm_aesdeclast_si128(s3, k[10]);
            _mm_storeu_si128((__m128i *)(void *)(dst + 0), s0);
            _mm_storeu_si128((__m128i *)(void *)(dst + 16), s1);
            _mm_storeu_si128((__m128i *)(void *)(dst + 32), s2);
            _mm_storeu_si128((__m128i *)(void *)(dst + 48), s3);
            src += 64;
            dst += 64;
            nbytes -= 64u;
        }
        while (nbytes >= 16u) {
            aes128i_decrypt_with_rk(k, dst, src);
            src += 16;
            dst += 16;
            nbytes -= 16u;
        }
    }
}
