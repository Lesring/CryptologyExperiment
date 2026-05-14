# SM4 Implementations And Benchmarks

This directory contains several SM4 implementations used for correctness tests,
bitslice experiments, and performance benchmarking. The current optimization
focus is the 256-lane AVX2 bitsliced implementation.

## File Overview

### Core SM4

- `sm4.h`: public interface for the scalar SM4 implementation.
- `sm4.c`: scalar SM4 key schedule and block encryption/decryption logic.
- `sm4_tables.c`: precomputed SM4 tables used by the scalar implementation.
- `gen_tables.py`: script for generating SM4 lookup tables.

### Scalar Bitslice

- `sm4_bitslice.h`: public interface for the 32-lane bitslice implementation.
- `sm4_bitslice.c`: scalar bitsliced SM4 using `uint32_t` as the lane word.
- `sm4_bs_sbox.h`: generated bitsliced SM4 S-box for scalar bitslice.
- `gen_bs_sbox.py`: generator for `sm4_bs_sbox.h`.

The scalar bitslice version processes 32 blocks in parallel. It is useful as a
reference for the AVX2 version and for comparing the cost of bitslice packing,
round functions, and unpacking.

### AVX2 Bitslice

- `sm4_bitslice_avx2.h`: public interface for the 256-lane AVX2 bitslice path.
- `sm4_bitslice_avx2.c`: optimized AVX2 bitsliced SM4 implementation.
- `sm4_bs_sbox_avx2.h`: generated AVX2 bitsliced SM4 S-box.
- `gen_bs_sbox_avx2.py`: generator for `sm4_bs_sbox_avx2.h`.

The AVX2 version uses `__m256i` as the bitslice word type:

```c
typedef __m256i sm4_bs_avx2_word;
```

Each `__m256i` stores one Boolean wire across 256 parallel SM4 blocks.

Current AVX2 optimization points:

- Uses `_mm256_xor_si256` and `_mm256_and_si256` for Boolean operations.
- Processes 256 blocks per encryption batch.
- Uses pointer rotation for the Feistel state instead of repeated `memcpy`.
- Uses a 32x32 SWAR/butterfly bit-matrix transpose in pack and unpack.
- Keeps the generated S-box as `static always_inline` AVX2 ANF code.
- Explicitly unrolls the 32 SM4 rounds to improve compiler scheduling.
- Avoids stack stores in unpack by extracting AVX2 lanes and transposing by
  32-block stripes.

## Test Programs

- `sm4_test.c`: scalar SM4 correctness test.
- `sm4_bitslice_test.c`: scalar bitslice correctness test.
- `sm4_bitslice_avx2_test.c`: AVX2 bitslice correctness test.
- `sm4_packtest.c`: pack/unpack related test code.

Build and run the AVX2 correctness test:

```sh
gcc -O3 -mavx2 -Wall -Wextra -std=c99 sm4_bitslice_avx2_test.c sm4_bitslice_avx2.c sm4.c sm4_tables.c -o sm4_bitslice_avx2_test.exe
./sm4_bitslice_avx2_test.exe
```

Expected output:

```text
sm4_bitslice_avx2: all 256-lane tests passed
```

## Benchmark Programs

- `sm4_bench.c`: scalar SM4 benchmark.
- `sm4_bitslice_bench.c`: scalar bitslice benchmark.
- `sm4_bitslice_avx2_bench.c`: AVX2 bitslice benchmark.

Build and run the AVX2 benchmark:

```sh
gcc -O3 -mavx2 -Wall -Wextra -std=c99 sm4_bitslice_avx2_bench.c sm4_bitslice_avx2.c sm4.c sm4_tables.c -o sm4_bitslice_avx2_bench.exe
./sm4_bitslice_avx2_bench.exe
```

The benchmark reports two numbers:

- `pack+encrypt+unpack`: end-to-end bitslice throughput, including conversion
  from normal block layout into bitslice layout and back.
- `Encrypt-only`: core bitsliced round function throughput after data is already
  in bitslice layout.

## Current Performance Result

On the current test machine, compiled with MinGW GCC using `-O3 -mavx2`, the
current AVX2 bitslice benchmark result was:

```text
AVX2 bitslice: pack+encrypt+unpack, 80000 batches x 256 blocks
  CPU:          1.881 s
  Throughput:   1.394 Gbit/s
  Encrypt-only: 1.669 Gbit/s
```

For the shorter 10000-loop benchmark after optimizing unpack with the symmetric
stripe transpose path:

```text
AVX2 bitslice: pack+encrypt+unpack, 10000 batches x 256 blocks
  CPU:          0.233 s
  Throughput:   1.406 Gbit/s
  Encrypt-only: 1.638 Gbit/s
```

Before the optimized unpack path, the same short benchmark was about:

```text
AVX2 bitslice: pack+encrypt+unpack, 10000 batches x 256 blocks
  CPU:          0.544 s
  Throughput:   0.602 Gbit/s
  Encrypt-only: 1.672 Gbit/s
```

So the biggest recent improvement came from replacing per-block/per-bit unpack
work with a 32-block stripe transpose.

## Notes

- AVX2 code must be compiled with `-mavx2`.
- The AVX2 test should be run on a CPU with AVX2 support.
- Generated `.exe` files are build artifacts and should not be committed.
- Further optimization work should focus on reducing the generated S-box gate
  count and improving instruction scheduling around the nonlinear layer.
