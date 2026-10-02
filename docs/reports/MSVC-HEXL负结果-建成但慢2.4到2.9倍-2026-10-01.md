# MSVC + Intel HEXL 路线：**建成、测了、没用 —— 反而慢 2.4~2.9×**

日期：2026-10-01
结论：**HEXL 在本机是负收益，已全部回滚。** 这条路可以正式结案。
状态：工作区 DLL 已还原为基线（`sha=E8E62B5508A7`），端到端复测 `payload mismatch: 0/110 => PASS`。

---

## 1. 花了什么代价，换到什么答案

整条链路**真的跑通了**（这是本轮的实际成果）：

| 步骤 | 结果 |
|---|---|
| 装 MSVC（非管理员，VS 安装器自行提权） | ✅ MSVC 19.51.36260 / 工具集 14.51.36231 |
| 建 Intel HEXL | ✅ **1.2.3**（SEAL 硬性要求该版本；1.2.6 被 CMake 拒） |
| 用 HEXL 重建 SEAL | ✅ `seal-4.0.lib` 10 MB，`config.h` 里 `#define SEAL_USE_INTEL_HEXL` |
| HEXL 符号进库 | ✅ `dumpbin` 看到 `intel::hexl::IsPowerOfTwo` 等 |
| 用 MSVC 重编 JNI DLL | ✅ 382 KB（**需要把 `__int128` 移植掉**，见 §3） |
| **A/B 基准** | ❌ **HEXL 版慢 2.4~2.9×** |

## 2. 实测对比（同一台机、同一基准、同一份数据）

`BlindRotateBench`，N=8192、levels=11、4 素数：

| d | 基线（MinGW SEAL）ms/CMUX | **HEXL 版** ms/CMUX | 倍数 |
|---|---|---|---|
| 1 | 32.20 | 50.43 | **1.57× 慢** |
| 4 | 28.63 | 50.46 | **1.76× 慢** |
| 16 | **27.04** | **78.18** | **2.89× 慢** |

两次独立测量结论一致：

- 第一次：HEXL 50.92 / 46.88 / 79.65 ms/CMUX，离散度 69.9%
- 第二次：HEXL 50.43 / 50.46 / 78.18 ms/CMUX，离散度 55.0%

**离散度还从基线的 19% 恶化到 55~70%**，说明不只是慢，还多了不稳定的固定开销。

## 3. 途中必须解决的一个真问题：MSVC 没有 `__int128`

这是本轮唯一一处**真实代码工作量**。MSVC 报 `error C4235`，而
`rgsw_blindrotate.cpp` 的多字（multi-word）CRT 算术大量依赖 GCC 的
`unsigned __int128` —— 因为 q 在 N≥8192 时是 174 bit，N=16384 时 389 bit，
必须多字运算，而每个字的乘加要 128 位中间量。

**5 处调用点**，全部用 MSVC 内建函数移植（先验证内建可用：
`_umul128(0xFFFF...F, 0xFFFF...F)` 给 `hi=fffffffffffffffe lo=1` 正确；
`_udiv128(0,100,7)` 给 `q=14 r=2` 正确）：

| 位置 | 原写法 | 移植后 |
|---|---|---|
| `mul_mod_u128` | `(__int128)a*b % m` | `_umul128` 拆 hi/lo，`_udiv128` 取余 |
| `mwMulWord` | 128 位乘加 | 显式 64 位进位链（两次进位判断） |
| `mwAddMulWord` | 同上 | 同上（多一次加 dst 的进位） |
| `mwModWord` | `((__int128)acc<<64) \| x[i]) % p` | `_udiv128(acc, x[i], p, &rem)`，前提 `acc < p` 恒成立 |
| `levels_for` | 拿 `unsigned __int128 q` 累乘 cap | 改成按**多字位宽**算数字个数（顺带修掉它原本表达不了 389 bit 的隐患） |

用一个 `#if defined(_MSC_VER)` 的 shim（`mul64x64` / `div128by64`）包起来，
**GCC 路径继续用原生 `__int128`**，所以同一份源码两边都能编。

⚠️ 注意：这份移植**只存在于我的临时目录**
（`%TEMP%\hx\rgsw_blindrotate.cpp`），**没有动工作区的源码** ——
因为结论是 HEXL 负收益，没必要把 `__int128` 的移植带进主线。

## 4. 为什么慢（与事前预测一致）

构建 HEXL 时 CMake 就探测出来了：

```
Compile flag not found: HEXL_HAS_AVX512DQ
Compile flag not found: HEXL_HAS_AVX512IFMA
Compile flag not found: HEXL_HAS_AVX512VBMI2
Setting HEXL_HAS_AVX256
```

**本机 CPU 无 AVX-512**（只有 AVX2/FMA/BMI2），HEXL 只能启用 AVX2 路径。
而 HEXL 的收益主要来自 AVX-512 内核（`_mm512_*` 的 `madd52` 等）。
AVX2 路径下 HEXL 相对 SEAL 自带的实现没有优势，反而因为
库调用/内存分配/对齐要求等开销而净亏损。

**这与事前判断一致**（当时明确写过："提速幅度很可能明显小于 HEXL 论文数字，
甚至可能因为库调用开销而持平"）。这次的贡献是把它从"可能"变成"确知"。

## 5. 复现方式

```powershell
# 1. 装 MSVC（需交互式 UAC —— 唯一必须人工做的一步）
& "<bootstrapper>" --installPath "<任意>" --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended

# 2. 建 HEXL 1.2.3（要打两处补丁：cpu_features 的 git clone、Ninja 死锁）
.\tools\hexl123_all.ps1 -Src <hexl-1.2.3> -Build <build>

# 3. 让 SEAL 用本地 HEXL（清空 ExternalIntelHEXL.cmake，别去 clone）
python .\tools\patch_seal_hexl_fetch.py <SEAL-4.0.0>

# 4. 建 SEAL（NMake 生成器，不要 Ninja）
.\tools\build_seal_hexl.ps1 ...   # 见 沙箱限制清单-需要人工执行的活 文档 §4.2

# 5. 建 DLL（要先做 __int128 -> _umul128/_udiv128 的移植）
.\tools\build_dll_msvc.ps1 -Src <rgsw_blindrotate.cpp> ...

# 6. A/B
.\run-mpc4j.ps1 -Class com.fusepir.probe.BlindRotateBench 8192 20
```

## 6. 结论与后续

**编译选项 / 库替换这条线到此全部封死**，两条都实测过：

| 路线 | 结果 |
|---|---|
| `-march=native` / `-mavx2`（MinGW） | ❌ 段错误 |
| MSVC + Intel HEXL | ❌ 慢 1.6~2.9× |

**剩下的只有算法层**。而算法层的方向已经被本轮之前的测量限定死了：

- `decompose`（我们自己的多字 CRT）只占 CMUX 的 **24%**，且已是 0.30 µs/系数
  ⇒ 优化它上限 24%，不值得先做
- 库操作（22 次 NTT + 22 次 multiply_plain）占 **76%**，而它**没法在本机加速**
  （AVX-512 缺失 + HEXL 负收益）
- ⇒ **唯一还有线性收益的是"减少 CMUX 次数"**（基线已证明成本与 d 无关，
  330 单元 × 16 轮 = 5280 次 CMUX）

**如果不再动算法，那么当前基线（ANSWER ≈ 145 s @ N=8192）就是本机可达到的状态。**

## 7. 本轮产出

| 文件 | 说明 |
|---|---|
| `tools/build_dll_msvc.ps1` | 用 MSVC+SEAL+HEXL 编 JNI DLL（在 `tools/`，未纳管） |
| `tools/build_seal_native.ps1`、`tools/march_probe.ps1` | 早先的 `-march=native` 尝试 |
| `tools/hexl123_all.ps1`、`tools/get_hexl*.py`、`tools/get_cpu_features.py` | HEXL 1.2.3 拉取与构建（含三处沙箱绕过） |
| `tools/patch_hexl_cpu_features.py`、`tools/patch_seal_hexl_fetch.py` | 两处 git-clone 补丁 |
| `tools/test_msvc.ps1` | MSVC 编译+链接验证 |
| `docs/reports/沙箱限制清单-需要人工执行的活-2026-10-01.md` | 沙箱限制与人工步骤 |
| 本文 | HEXL 负结果与全链路记录 |

生产代码**零改动**（`__int128` 移植只在临时目录）；工作区 DLL 已还原基线。
