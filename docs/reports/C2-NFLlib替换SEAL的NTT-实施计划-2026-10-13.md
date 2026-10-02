# C2 实施计划：用 NFLlib 的 AVX2 NTT 替换 SEAL 的标量 NTT

> 目标：打掉 CMUX 里最大的一块 —— **明文 NTT**。
> 依据：OnionPIR（SEAL 同批作者，CCS'21）§6.1 原文
> 「the NTT implementation in SEAL is quite slow … we instead use **NFLlib** …
> **2−3× faster than SEAL**」，机器只要 **AVX2**（AWS c5.2xlarge，8 cores with AVX）。
> 状态：**等 NFLlib 源码到位**；本文件把接口与障碍先钉死。

---

## 1. 现状基线（现网配置：N=8192, t=2³², base=2³², levels=6, k=3, B_pay=59, 177 单元）

`CmuxBreakdown`（同机实测，2026-10-13）：

| 指标 | 值 |
|---|---|
| **一次 CMUX** | **12.07 ms** |
| 其中 **明文 NTT** | **41.2% = 4.97 ms/CMUX** |
| mul_plain | 20.5% = 2.47 ms |
| 多字算术（`crtComposeMw`+`decomposeValueMw`） | 28.3% = 3.41 ms |
| 正向 NTT（decompose 内部） | 3.4% = 0.41 ms |
| 其他 | 6.7% = 0.81 ms |
| 每层 | 2.012 ms |
| ANSWER（177 单元） | 实测 **37.3 s** |

**明文 NTT 的次数**：一次 CMUX = 一次 `external_product`
= `2 分量 × levels` 次 `transform_to_ntt`（明文 digit）
⇒ **2 × 6 = 12 次/CMUX** ⇒ 单次 `transform_to_ntt(Plaintext, N=8192, 4 素数)`
≈ **4.97 / 12 = 0.414 ms**。

## 2. 预期收益（按 OnionPIR 的 2–3× 建模）

设明文 NTT 由 4.97 ms 变为 4.97/x：

| x | 明文NTT | ms/CMUX | 相对 12.07 | ANSWER | 相对 37.3 s |
|---|---|---|---|---|---|
| 1（不变） | 4.97 | 12.07 | — | 37.3 s | — |
| **2×** | 2.49 | **9.59** | **−20.5%** | **≈29.7 s** | **−20.5%** |
| **3×** | 1.66 | **8.76** | **−27.4%** | **≈27.1 s** | **−27.4%** |

> 校验：37.3 s ÷ 177 单元 = 210.7 ms/单元 ÷ 12.07 ms/CMUX = 17.5 倍率（与剖面一致）。

**⇒ C2 是当前唯一还剩的大头：预期 −20~27%。**

---

## 3. 替换点：只有 3 个函数

SEAL 的 `ntt.cpp`（476 行）**没有任何 SIMD 内在函数**（`__m256/_mm_` 计数为 0），
所以它确实是标量实现。内核签名：

```cpp
// seal/util/ntt.cpp:407
void ntt_negacyclic_harvey(CoeffIter operand, const NTTTables &tables)
```

批量入口在 `seal/util/ntt.h`，**我们全部走这三个**：

| 行 | 签名 | 谁在用 |
|---|---|---|
| `ntt.h:231` | `void ntt_negacyclic_harvey(CoeffIter, const NTTTables &)` | — |
| `ntt.h:233` | `inline void ntt_negacyclic_harvey(RNSIter, size_t coeff_modulus_size, ConstNTTTablesIter)` | `Evaluator::transform_to_ntt`、`multiply_plain_ntt`、`TPHESampler` 等 |
| `ntt.h:303` | `void inverse_ntt_negacyclic_harvey(CoeffIter, const NTTTables &)` | 我们 `decompose` 里的 `transform_from_ntt`（另见 §5） |

⇒ 替换面收敛到 3 个函数，不必改 `Evaluator`。

## 4. ⚠️ 集成障碍（源码到手前必须先想清楚的）

**障碍 1：NFLlib 是「固定模数」设计，SEAL 是 RNS 多模数。**
NFLlib 的算子模板化在 `nfl::modulus<p>` 上（模数类型里带 `shoup`/`barrett` 预计算），
而我们有 **4 个素数**（q = 174 bit）。所以不能「整体替换」，
只能是**对单个素数逐次调用** NFLlib 内核，外层循环保留 `coeff_modulus_size`。

**障碍 2（最关键）：预计算常量不通用。**
NFLlib 的模数类型里带自己的 `shoup`/`barrett` 表，SEAL 的 `Modulus` 里带 `const_ratio`
（另一套 Barrett）。两边的 NTT 根表格式也不同（NFLlib 用 `powers_of_root` 的
固定布局）。⇒ 必须**从 SEAL 的参数构造 NFLlib 的模数对象与根表**，
不能传指针复用。要核对：
- NFLlib 的根是否为**前向 NTT 根**（我们 `NTTTables::get_root()` 是）；
- NFLlib 是否要求 `n | (p−1)` 及根的中心化/非中心化表示；
- 逐素数调用时的**数据布局**：SEAL 的 `RNSIter` 是「同素数连续 n 个」，
  NFLlib 是否接受该布局（它通常要求对齐 `ALIGN`）。

**障碍 3：`transform_to_ntt` 不只是 NTT。**
`evaluator.cpp:2033` 里还有 plain-lift（`add_uint`/`decompose_array`）与
`plain.resize(coeff_count * coeff_modulus_size)`。
所以「替换 NTT」实际是替换 `evaluator.cpp:2121` 那一行
（`ntt_negacyclic_harvey(plain_iter, coeff_modulus_size, ntt_tables)`），
而 plain-lift 部分照旧。**这也说明收益上限是明文 NTT 那 41.2% 里"纯 NTT"的部分**，
不含 plain-lift —— 所以真实收益可能**低于** §2 的 2–3× 模型。

**障碍 4：我们还需要 `lazy` 变体。**
`ntt.h:195` 的 `ntt_negacyclic_harvey_lazy` 在 SEAL 的 HEXL 路径里用；
NFLlib 是否提供等价的「不立即归约」语义要核对，否则数值结果模板会有差异。

## 5. 源码到手后的动作清单

1. **先量「纯 NTT」的比例**（**这是第一步，也是最该先做的一步**）：
   现在 `CmuxBreakdown` 里的 `明文NTT` 那一栏量的是
   `transform_to_ntt_inplace` 的**整体**（含 plain-lift 与数据搬运），
   而换 NFLlib 只能加速其中 `evaluator.cpp:2121` 那一行。
   ⇒ **必须先把这个比例量出来，才能知道 §2 的 2~3× 模型要打几折。**

   > 我（本轮）试图用一个新的 native 探针 `nativePtnProfile` 直接量它，
   > 但那个探针在 `it_seed` 的作用域上连续两次编译失败，我按「不在测量代码上
   > 无限投入」的纪律**撤回了它**（源与 Java 绑定都已还原，回归 4 PASS）。
   > 所以这一步**仍未完成** —— 留给源码到位后一起做，或单独做都行，成本很低。
2. **写单函数微基准**：对 `RNSIter` 版的 `ntt_negacyclic_harvey`
   直接计 100 次，得到 SEAL 标量版的 ns/NTT。
   （N=8192、4 素数 ⇒ 一次调用覆盖 4×8192 个系数。）
3. **接 NFLlib 单素数内核**，按 §4 的三个核对点逐个验证；
   用**同一个输入/输出**与 SEAL 版本逐系数比对（必须完全一致，NTT 是精确变换）。
4. **逐素数循环**跑通后，替换 `evaluator.cpp:2121` 的调用，重跑：
   - `nativeBlindRotate` 自测（4 PASS 是硬门槛）；
   - `CmuxBreakdown`（看 `明文NTT` 那一栏的占比变化）；
   - `CapeDemoService` 端到端（`payloadMismatch=0`）。
5. **A/B**：保留旧 DLL（`git show <commit>:native-jni/lib/blindrotate.dll`）交替跑，
   像 C6 那样同批比较 —— **不要跨时点引用绝对值**（本项目已多次因此误判）。

## 6. 风险与退路

| 风险 | 退路 |
|---|---|
| NFLlib 与 SEAL 模数/根表不兼容，改造量超预期 | 只取其 **AVX2 montgomery/butterfly 内核的写法**，自己写一个 SEAL 兼容版（工作量更大但可控） |
| NFLlib 需要编译进 SEAL（改 SEAL 源码/CMake） | 我们已有 `tools/build_seal.ps1` 与 MinGW 工具链，且 SEAL 4.0.0 源码在 `tools/downloads/SEAL-4.0.0.zip` |
| 收益低于预期（plain-lift 占比大） | 先做 §5.1 的「纯 NTT 比例」测量，若占比小就直接放弃，不投入集成 |
| 本机缺 AVX-512 | **不影响**：NFLlib 的收益来自 AVX2，本机有（`HEXL_HAS_AVX256`；`-march=native` 崩与 AVX2 无关，是 MinGW 代码生成问题） |

## 7. 与其它项的关系

- **C6 已落地**（`decompose` 两次正向 NTT 合并为一次，同批 A/B −3.5%）；
  它把 `正向NTT` 从 6.6% 降到 3.4%，**也正是 C2 能拿的上限里的一小块**。
- **C1 已关闭**（逐素数单字分解：前提 `q ≤ 2¹²⁴` 在我们 `q=174bit` 下不成立；
  Barrett 替换 128 位除法实测大幅变慢）——见 `速度差距-逐篇检索记录` §17.4/§17.5。
- **C4（延迟归约）** 与 C2 是同一片区域（`multiply_plain` 侧），
  若 NFLlib 集成顺利可一并试，但 C4 收益未证实，优先级低于 C2。

---

## 附：给「取源码」的人的清单

需要的文件（放 `E:\学习\密码赛\NFLlib\` 即可）：

| 文件 | 为什么要 |
|---|---|
| `nfllib/nfl/ntt.hpp` / `ntt.cpp` | NTT 内核本体（含 `ntt_avx` 特化） |
| `nfllib/nfl/arith.hpp` / `arith.cpp` | 模运算（`shoup`/`barrett` 预计算） |
| `nfllib/nfl/modulus.hpp` | 模数类型与预计算表布局（§4 障碍 2 要核对它） |
| `nfllib/nfl/generator.hpp` | NTT 根表怎么生成（核对是否与 SEAL 的根一致） |
| `nfllib/CMakeLists.txt` | 看它的编译选项（`-mavx2`、对齐宏） |
| `nfllib/nfl/params.hpp` | 对齐常量 `ALIGN` / 循环展开策略 |

⚠️ **优先找 2017–2019 年前后的版本**。OnionPIR 说「2–3× faster than SEAL」是那个时期的
NFLlib；最新版 API 可能大改（`nfl::` 命名空间与 `poly<N, p>` 模板都变过）。
