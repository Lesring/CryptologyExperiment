# SM4 实现与基准测试

本目录包含多种 SM4 实现，用于正确性测试、bitslice 实验与性能基准。当前优化重点是 **256 路 AVX2 bitslice** 实现。

## 文件概览

### 标量 SM4（基础实现）

- `sm4.h`：标量 SM4 的对外接口。
- `sm4.c`：标量 SM4 密钥扩展与分组加解密逻辑。
- `sm4_tables.c`：标量实现使用的预计算 SM4 查表。
- `gen_tables.py`：生成 SM4 查表的脚本。

### 标量 Bitslice

- `sm4_bitslice.h`：32 路 bitslice 实现的对外接口。
- `sm4_bitslice.c`：以 `uint32_t` 作为 lane 字的标量 bitslice SM4。
- `sm4_bs_sbox.h`：由生成器产出的标量 bitslice S 盒。
- `gen_bs_sbox.py`：`sm4_bs_sbox.h` 的生成脚本。

标量 bitslice 版本一次并行处理 32 个分组，可作为 AVX2 版本的参照，并用于对比 bitslice 打包、轮函数与解包的开销。

### AVX2 Bitslice

- `sm4_bitslice_avx2.h`：256 路 AVX2 bitslice 路径的对外接口。
- `sm4_bitslice_avx2.c`：经优化的 AVX2 bitslice SM4 实现。
- `sm4_bs_sbox_avx2.h`：由生成器产出的 AVX2 bitslice S 盒。
- `gen_bs_sbox_avx2.py`：`sm4_bs_sbox_avx2.h` 的生成脚本。

AVX2 版本以 `__m256i` 作为 bitslice 字类型：

```c
typedef __m256i sm4_bs_avx2_word;
```

每个 `__m256i` 在 256 个并行 SM4 分组上表示一条布尔线。

当前 AVX2 侧的优化要点：

- 布尔运算使用 `_mm256_xor_si256`、`_mm256_and_si256`。
- 每次加密批处理 256 个分组。
- Feistel 状态用指针轮转代替反复 `memcpy`。
- 打包/解包采用 32×32 的 SWAR/蝶形比特矩阵转置。
- 生成的 S 盒保持为 `static always_inline` 的 AVX2 ANF 形式。
- 对 32 轮 SM4 做显式展开以改善编译器调度。
- 解包时通过提取 AVX2 lane 并按 32 分组条带转置，避免在栈上大量暂存。

## 测试程序

- `sm4_test.c`：标量 SM4 正确性测试。
- `sm4_bitslice_test.c`：标量 bitslice 正确性测试。
- `sm4_bitslice_avx2_test.c`：AVX2 bitslice 正确性测试。
- `sm4_packtest.c`：与 pack/unpack 相关的测试代码。

编译并运行**标量**正确性测试（GB/T 32907 示例向量，单分组以及 `encrypt_blocks` / `decrypt_blocks`）：

```sh
gcc -O3 -Wall -Wextra -std=c99 sm4_test.c sm4.c sm4_tables.c -o sm4_test.exe
./sm4_test.exe
```

预期输出：

```text
sm4: all tests passed
```

编译并运行 **AVX2** 正确性测试：

```sh
gcc -O3 -mavx2 -Wall -Wextra -std=c99 sm4_bitslice_avx2_test.c sm4_bitslice_avx2.c sm4.c sm4_tables.c -o sm4_bitslice_avx2_test.exe
./sm4_bitslice_avx2_test.exe
```

预期输出：

```text
sm4_bitslice_avx2: all 256-lane tests passed
```

## 基准程序

- `sm4_bench.c`：标量 SM4 吞吐基准。
- `sm4_bitslice_bench.c`：标量 bitslice 基准。
- `sm4_bitslice_avx2_bench.c`：AVX2 bitslice 基准。

编译并运行**标量**基准：

```sh
gcc -O3 -Wall -Wextra -std=c99 sm4_bench.c sm4.c sm4_tables.c -o sm4_bench.exe
./sm4_bench.exe
```

`sm4_bench.c` 会分别打印加密、解密各一轮的 CPU 时间、数据量、十进制 Gbit/s，以及平均每分组纳秒数。

编译并运行 **AVX2** 基准：

```sh
gcc -O3 -mavx2 -Wall -Wextra -std=c99 sm4_bitslice_avx2_bench.c sm4_bitslice_avx2.c sm4.c sm4_tables.c -o sm4_bitslice_avx2_bench.exe
./sm4_bitslice_avx2_bench.exe
```

AVX2 基准会报告两个指标：

- `pack+encrypt+unpack`：端到端 bitslice 吞吐，包含从普通分组布局与 bitslice 布局之间的往返转换。
- `Encrypt-only`：数据已在 bitslice 布局下，仅核心 bitslice 轮函数的吞吐。

## 标量 SM4 本机验证记录

**2026-05-14**，Windows 10，**MinGW-W64 GCC 8.1.0**（`x86_64-win32-sjlj`），使用 `-O3 -Wall -Wextra -std=c99` 编译的 `sm4_test.exe` 输出：

```text
sm4: all tests passed
```

同一工具链与编译选项下的 `sm4_bench.exe`（默认每次 `4096` 个分组，`40000` 次循环）输出：

```text
SM4 encrypt (4096 blocks/call, 40000 calls)
  CPU time:     8.068 s
  Data:         2500.00 MiB (2.621 GB)
  Throughput:   2.599 Gbit/s (decimal)
  Per block:    49.24 ns (avg)

SM4 decrypt (4096 blocks/call, 40000 calls)
  CPU time:     8.094 s
  Data:         2500.00 MiB (2.621 GB)
  Throughput:   2.591 Gbit/s (decimal)
  Per block:    49.40 ns (avg)
```

上述吞吐数字**与机器强相关**；若更换硬件、编译器或编译选项，请重新执行上文命令并更新本节。

## 当前 AVX2 性能记录

在当前测试机上，使用 MinGW GCC、`-O3 -mavx2` 编译，AVX2 bitslice 基准曾得到：

```text
AVX2 bitslice: pack+encrypt+unpack, 80000 batches x 256 blocks
  CPU:          1.881 s
  Throughput:   1.394 Gbit/s
  Encrypt-only: 1.669 Gbit/s
```

在将解包优化为对称条带转置路径之后，较短（10000 次循环）的基准约为：

```text
AVX2 bitslice: pack+encrypt+unpack, 10000 batches x 256 blocks
  CPU:          0.233 s
  Throughput:   1.406 Gbit/s
  Encrypt-only: 1.638 Gbit/s
```

优化解包路径之前，同参数短基准约为：

```text
AVX2 bitslice: pack+encrypt+unpack, 10000 batches x 256 blocks
  CPU:          0.544 s
  Throughput:   0.602 Gbit/s
  Encrypt-only: 1.672 Gbit/s
```

可见近期最大的收益来自：用 **32 分组条带转置** 替代原先按分组/按比特的解包方式。

## 说明

- AVX2 代码编译时必须加 `-mavx2`。
- AVX2 测试需在支持 AVX2 的 CPU 上运行。
- 生成的 `.exe` 为构建产物，不宜纳入版本库。
- 后续优化可侧重：降低生成 S 盒的门数量，以及改善非线性层附近的指令调度。
