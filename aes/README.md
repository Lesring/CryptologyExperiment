# AES-128（本仓库）

面向课程/实验的 **AES-128 ECB**：**软件 T 表**、**AES-NI（推荐）**、可选 **VAES** 变体，以及与 **TF-PSA-Crypto** 的吞吐对比基准。

## 实现概览（与演进）

| 路线 | 核心思路 | 适用场景 |
|------|----------|----------|
| **T 表**（`aes128.c`） | 查 `TE0`–`TE3` / `TD0`–`TD3` 与 S 盒，纯软件 | 任意 CPU；最慢，无额外编译开关 |
| **AES-NI**（`aes128_ni.c`） | `_mm_aesenc_si128` 等；`setkey` 时把 11 轮密钥写入对齐的 `ni_rk`；ECB 大块用 **8× / 4× XMM 交错** 隐藏单条 AES 指令的流水线延迟 | x86-64 且支持 AES-NI（常见 Ryzen / Core）；**默认首选** |
| **VAES**（`aes128_ni_vaes.c`） | 在 ECB 中若长度 ≥32 字节，用 **256 位 VAES** 每次处理 **2 个块**，轮密钥预广播为 `rk2[11]`；余量仍回退到与 `aes128_ni.c` 相同的 XMM 8×/4×/单块 | CPU 支持 VAES；需 `-mavx2 -mvaes`。**在部分 Zen 上解密 VAES 比纯 XMM 交错慢**，必须对目标机实测 |

历史优化简述：`AES128CTX` 增加 `ni_rk` 后，避免在热路径上对每块每轮做 `PUTU32` 式的轮密钥重组；ECB 内先将 `ni_rk` 装入局部 `k[11]`，便于寄存器分配。VAES 路径在 Zen 上曾出现解密吞吐明显落后，因此 **从主文件拆出** `aes128_ni_vaes.c`，默认仍用 `aes128_ni.c`。

## 源码与链接（三选一）

**`aes128.c`、`aes128_ni.c`、`aes128_ni_vaes.c` 只能链接其一**（符号同名），与 `aes128.h` 搭配即可。

| 文件 | 说明 |
|------|------|
| `aes128.h` | 公共 API：`AES128CTX`、加/解密密钥、单块、`aes128_*_ecb`。结构体含 `rk[44]` 与 **16 字节对齐** 的 `ni_rk[11*16]`；仅链 `aes128.c` 时后者不会被写入，可忽略。 |
| `aes128.c` | **T 表**实现，内含大表；带 `main`（自检 + 与下文同量级的 ECB 测速）。 |
| `aes128_ni.c` | **推荐**：`-maes -msse2`（建议 `-O2`）。 |
| `aes128_ni_vaes.c` | **可选 VAES**：`-maes -msse2 -mavx2 -mvaes`。GCC 8 等上 `_mm256_aesenc_epi128` 第二参数为 `__m256i`，本实现已对轮密钥做 `broadcast`。 |
| `aes128_vectors_test.c` | **正确性**：单块已知向量 + 64 B ECB 加解密环回。须与 **`aes128_ni.c` 或 `aes128_ni_vaes.c` 之一** 链接（**勿**与带 `main` 的 `aes128.c` 同编）。 |

**MinGW / GCC 示例**

```text
# T 表 + 可执行测速
gcc -O2 -o aes128_bench aes128.c

# 向量 + ECB 小块环回（AES-NI 实现）
gcc -O2 -maes -msse2 -o aes128_vectors_test.exe aes128_ni.c aes128_vectors_test.c
./aes128_vectors_test.exe

# AES-NI 对象文件
gcc -O2 -maes -msse2 -c aes128_ni.c

# VAES 变体对象文件（勿与 aes128_ni.c 同向链接）
gcc -O2 -maes -msse2 -mavx2 -mvaes -c aes128_ni_vaes.c
```

**MSVC**：NI 可用 `/O2 /arch:AES`；VAES 需按版本额外启用 AVX2 等，见官方说明。

## 独立 ECB 吞吐基准

与 `aes128.c` 内 `main` 一致：**单线程**、**16 MiB × 400 轮**（约 **6.25 GiB**）、原位 `aes128_encrypt_ecb` / `aes128_decrypt_ecb`，测的是 **大块 ECB 稳态**，不含 IV、不含其他模式开销。

| 程序 | 链接对象 | 典型编译 |
|------|-----------|-----------|
| `aes128_ni_bench.c` | `aes128_ni.c` | `gcc -O2 -maes -msse2 -o aes128_ni_bench aes128_ni.c aes128_ni_bench.c` |
| `aes128_ni_vaes_bench.c` | `aes128_ni_vaes.c` | 上式加上 `-mavx2 -mvaes`，并将 `aes128_ni.c` 换成 `aes128_ni_vaes.c` |

## 本机全面测试记录（实测）

以下为在同一台开发机上**一次性跑完**的构建与结果，便于复现与对比。测试包括：`aes128.c` 内置自检与 ECB 吞吐；`aes128_vectors_test.c` 分别链接 **NI** / **VAES** 实现；两份独立 bench。

| 项目 | 值 |
|------|-----|
| **日期** | 2026-05-14（UTC+8） |
| **CPU** | AMD Ryzen 7 8845H w/ Radeon 780M Graphics |
| **系统** | Windows NT 10.0.26200 |
| **编译器** | gcc.exe (x86_64-win32-sjlj, **MinGW-W64**) **8.1.0** |
| **优化** | `-O2`；NI 使用 `-maes -msse2`；VAES 额外 `-mavx2 -mvaes` |

**正确性**

- `aes128.c`：`main` 内 `aes128_tv_ok()`，失败会直接退出；本次运行已进入 ECB 测速，**视同自检通过**。
- `aes128_ni.c` + `aes128_vectors_test.c`：输出 `OK: vectors + ecb64`。
- `aes128_ni_vaes.c` + `aes128_vectors_test.c`：输出 `OK: vectors + ecb64`。

**ECB 吞吐**（单线程，**16 MiB 缓冲区 × 400 轮** ≈ **6.25 GiB**，与 `aes128.c` 的 `main` / `*_bench.c` 一致）

| 实现 | 加密时间 (s) | 加密吞吐 | 解密时间 (s) | 解密吞吐 |
|------|-------------:|----------|-------------:|----------|
| **T 表** `aes128.c` | 14.772 | **3634 Mbps**（**433 MB/s**） | 14.735 | **3644 Mbps**（**434 MB/s**） |
| **AES-NI** `aes128_ni.c` | 0.460 | **116.8 Gbps**（**13.9 GB/s**） | 0.460 | **116.6 Gbps**（**13.9 GB/s**） |
| **VAES** `aes128_ni_vaes.c` | 0.472 | **113.8 Gbps**（**13.6 GB/s**） | 0.827 | **64.9 Gbps**（**7.7 GB/s**） |

**结论（与本机一致）**：默认使用 **`aes128_ni.c`**；**VAES 版加密与 NI 接近，解密明显变慢**，与 Zen 上常见行为一致，VAES 源文件仅作对比保留。

复现命令摘要：

```text
gcc -O2 -o aes128_bench.exe aes128.c && aes128_bench.exe
gcc -O2 -maes -msse2 -o t.exe aes128_ni.c aes128_vectors_test.c && t.exe
gcc -O2 -maes -msse2 -mavx2 -mvaes -o t.exe aes128_ni_vaes.c aes128_vectors_test.c && t.exe
gcc -O2 -maes -msse2 -o b.exe aes128_ni.c aes128_ni_bench.c && b.exe
gcc -O2 -maes -msse2 -mavx2 -mvaes -o b.exe aes128_ni_vaes.c aes128_ni_vaes_bench.c && b.exe
```

子目录中 **TF-PSA-Crypto** 通过 mbedtls 使用内置 AES-NI 时，单线程 ECB 常见 **约 20+ Gbps** 量级，高于纯 T 表、通常低于本仓库重度手调的 `aes128_ni.c`，属正常现象。本次文档更新时 **未重新构建** `tf_psa_aes_ecb_bench.exe`，故无对应本机秒表数据。

## TF-PSA-Crypto 基准（子目录）

构建产物示例（路径以本机 CMake 输出为准）：

```text
d:\26study\402\aes\tf_psa_crypto_bench\build\tf_psa_aes_ecb_bench.exe
```

源码与说明见 `tf_psa_crypto_bench/aes_ecb_bench.c`。若 clone 后缺子模块导致 CMake 失败，可在子仓库内执行：

```text
git -C TF-PSA-Crypto submodule update --init --recursive --depth 1
```

## 硬件与课程提示

- **AES-NI**：近年 x86-64 笔记本/台式（如 AMD Ryzen 7 8845H 等）普遍具备；无指令集时请勿链接 `aes128_ni*.c`，应使用 `aes128.c`。
- **VAES**：额外指令集；**不等同于一定更快**，尤其解密在 Zen 上可能劣于 XMM 交错。
- **显卡 / 大内存**：对本仓库 **CPU 侧 AES ECB** 几乎不是瓶颈；GPU AES 通常也受拷贝与内核启动限制。
- **ECB**：仅适合实验与演示；实际系统多用 **CBC、CTR、GCM** 等；本仓库 API 仍以 ECB 块工具为主，上层模式需自行拼接。
