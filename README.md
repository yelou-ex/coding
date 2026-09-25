# `coding/` —— CAPE / FusePIR 的 Java 复现

> **硬约束**：不能改变原论文的算法（`Submission_usenix_232.pdf` / USENIX'232）。
> 参数与实现可以自选，但**必须记录在案**。
>
> **默认路线**：**B —— 纯 Java**（`lib/` 里那个 MPC4J SEAL 移植版 + 我们打的 Galois 补丁）。
> 另有 native 对照路线（真 SEAL 4.0.0，仅用于性能对照与交叉校验）与已弃用的自研路线。
> 三者的边界见 [`默认实现一览.md`](默认实现一览.md)，路线审计见 [`RLWE路线审计.md`](RLWE路线审计.md)。
>
> **2026-09-19 基准整改**：复现基准定为 **CAPE（算法 2）**，锚检索走 **FusePIR（算法 1）**；
> **不实现 CAPE-C / FusePIR-C**。因此 `LWEtoRGSW` **不在关键路径上**（详见第〇节）。
> 同时**纠正列选择的语义**：它是**密文×明文**（`CtPtMul`），不是密文×密文（详见第一节）。
>
> **⚠️ 2026-09-19 晚 追加更正（重要，会推翻一条旧结论）**：
> **盲旋转不能算做完。** `BlindRotateOps.blindRotate` 的旋转机构是对的（d 扫到 512 都稳），
> 但它把 LWE 相位 **1:1 当成旋转指数**——实测**索引噪声 `e=±1` 就会选到相邻的那一行**，
> 而现有三个测试造索引时**都没有误差项**，所以此前一路绿灯。
> 真实 `LWE.Enc(r_a)` 必然带噪声 ⇒ **按现在的实现会稳定取错行**。
> 机制未定，候选 (a)/(b)/(c) 见 **3.4**，整改项 **R3b**，优先级列为**第 0 项**。
>
> **✅ 同日晚 的进展（实测，见 5.1）**：`AnswerPathMini` 把 **ANSWER 骨干真跑通了**——
> 列选择（`CtPtMul`）→ 盲旋转 → `SampleExtract_0` → 三路相加 → 解密，
> N=2048/4096、d=64/512、小值与全值域载荷**全过**。
> 这关闭了缺口"(a) 列选择的累加器能不能喂给盲旋转"，并顺带抓出+修掉一个真 bug
> （**`a_i ≡ 0 (mod 2N)` 会让 CMUX 抛 `transparent`**，d=512 时约 12% 概率撞上）——见**附录 A 第 9 条**。
> **仍然不成立的只有索引噪声那一条。**

---

# 〇、总体实现依据（2026-09-19 定稿，先看这一节）

**本项目复现的是 `Submission_usenix_232/` 那篇论文里的 `CAPE`（算法 2），不是 `CAPE-C`（算法 5）。**

论文一共给了四个方案，一层套一层：

| 方案 | 论文位置 | 锚检索用谁 | 客户端发的选择器 | 需要 `LWEtoRGSW`？ |
|---|---|---|---|---|
| **FusePIR** | 算法 1（§3.1） | — | **RLWE one-hot 列选择器 + LWE 行选择器** | ❌ 不需要 |
| **CAPE** ← ✅ **我们的目标** | **算法 2（§4.1）** | `FusePIR.Answer` | 同 FusePIR，另加**加密 Bloom 查询向量** | **❌ 不需要** |
| FusePIR-C | 算法 4（附录 B） | — | 紧凑**种子化 LWE** 坐标 | ✅ 需要 |
| CAPE-C | 算法 5（附录 C） | `FusePIR-C.Answer` | 同 FusePIR-C，另加加密 Bloom 向量 | ✅ 需要 |

**依据一：CAPE 的锚检索调用的是 `FusePIR.Answer`，不是 `FusePIR-C.Answer`。**
算法 2 第 2 行原文：`resp_anc ← FusePIR.Answer(st_S^F, q_anc)`；
而算法 5（CAPE-C）才是 `resp_anc ← FusePIR-C.Answer(st_S, q_anc)`。

**依据二：`LWEtoRGSW` 是查询压缩变体专有的。**
附录 B 原文：

> Instead of directly sending the **RLWE one-hot column selectors and LWE row selectors**, the client sends
> compact seeded LWE encryptions of their binary coordinates. … The resulting LWE encryptions are converted
> to RGSW form by **`LWEtoRGSW`**; the column bits are then expanded into the encrypted one-hot selector,
> while the row bits drive the bit-wise evaluation of `BlindRotate`.

§2.5 对 `LWEtoRGSW` 的定义同样只说了一件事：

> `LWEtoRGSW(ct_L) → C_μ`：… converting the encrypted bit into the RGSW representation used for
> **selector expansion in the query-compressed variants**.

**结论（对旧文档的更正）：**

1. `LWEtoRGSW` **不必实现**，也不必为它去啃 circuit bootstrapping。它在 C 变体里才出现。
2. 旧文档"**唯一的硬障碍是 `LWEtoRGSW`**"这一结论**作废**——那是**误把 CAPE-C 的结构当成了目标**。
3. 真正的问题换成另一个（见第三节）：**CAPE 的盲旋转要用 `d` 个 RGSW 做自举密钥，`d=512` 时体积 25.6 GB**。
   这是工程成本问题，不是"某个原语没写出来"的问题。

---

# 一、列选择的正确定义（2026-09-19 纠正）

## 1.1 之前错在哪

旧文档写的是：「**CAPE 的列选择与加密 Bloom 得分都必须是密文×密文**（论文算法 2 第 4 行明确写 `CtCtMul`）」。
**前半句是错的。**

论文 §2.5 在给出四个同态操作后，紧接着写了一句把用途钉死的话：

> `CtCtAdd(ct_0,ct_1) → Enc(m_0+m_1)`,
> `CtPtMul(ct_0,m_1) → Enc(m_0·m_1)`,
> `CtCtMul(ct_0,ct_1) → Enc(m_0·m_1)`,
> `CtRotate(ct,i) → Enc(Rot(m,i))`.
> **The first two operations are used extensively in FusePIR for encrypted selection and reconstruction.
> CAPE additionally uses ciphertext–ciphertext multiplication and rotation to evaluate encrypted Bloom scores.**

即：

- **加密选择（列选择）与 BFF 重建 → 只用 `CtCtAdd` / `CtPtMul`（密文 × 明文）**；
- **`CtCtMul` 与 `CtRotate` → 只用于 CAPE 的加密 Bloom 得分**（算法 2 第 4~7 行）。

`CtCtMul` 出现在算法 2 里，但**不是**用在列选择上。

## 1.2 正确的列选择语义

1. **客户端**把列坐标 `c_a` 做成 one-hot 向量 `e_{c_a} = (0,…,1,…,0) ∈ {0,1}^C`，
   **把它的每一位当作明文多项式的一个系数**，然后**整体做一次 RLWE 加密**：

   ```
   q_col,a ← RLWE.Enc_{s_R}(e_{c_a})          ← 只发一个密文，不是"每位一个密文"
   ```

2. **服务端**把**数据库的每一列**打包成一个**明文多项式**（服务端本来就有明文 DB，这一侧不需要加密）：

   ```
   P_{c,b}(X) ← Σ_{r=0}^{R−1} D[r + cR][b] · X^r        （算法 1 SETUP 第 14 行）
   ```

   论文原文（§3.1）：*"We further represent the array into a two-dimensional layout and **pack each
   column into polynomial coefficients**. This design allows the server to **select the target column
   homomorphically** and then extract the desired entry using the encrypted row index."*

3. 两者做**明文–密文同态内积**（`CtPtMul`，密文 × 明文）：

   ```
   Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul(q_col,a[c], P_{c,b}(X))      （算法 1 ANSWER 第 5 行）
   ```

   —— `q_col,a[c]` 是"加密选择器的第 c 位"，`P_{c,b}(X)` 是"第 c 列"；求和就是内积，
   结果 `Acc_{a,b}` 是**被选中那一列**的加密。

4. **之后**才用**行选择器**做盲旋转，把目标行挪到常数位：

   ```
   Acc'_{a,b} ← BlindRotate(q_row,a, Acc_{a,b})                    （算法 1 ANSWER 第 6 行）
   ct_{a,b}   ← SampleExtract_0(Acc'_{a,b})                        （算法 1 ANSWER 第 7 行）
   ```

## 1.3 与旧理解的逐项对照

| 项 | ❌ 旧文档 | ✅ 正确 |
|---|---|---|
| 列选择的算子 | `CtCtMul`（密文×密文） | **`CtPtMul`（密文×明文）** |
| 列选择器的形态 | 每位一个 LWE 密文（再转 RGSW） | **一个 RLWE 密文**，one-hot 的每一位是**明文多项式的系数** |
| 数据库一侧 | 参与密文运算 | **是明文多项式**（每列一个），由服务端本地持有 |
| 行选择器的形态 | 逐位 LWE（`ℓ_r` 条） | **一条 `LWE.Enc(r_a)`**（不是逐位） |
| `CtCtMul` 用在哪 | 列选择 + Bloom 得分 | **只用于 Bloom 得分** |
| `LWEtoRGSW` 何时需要 | "CAPE 主流程必需" | **只有 C 变体需要** |

> **待与 artifact 对齐的一点（不阻塞主线）**：论文把内积写成 `C` 项之和，工程上可等价地压成
> **一次** `CtPtMul`——把整张表按列交错打进一个明文多项式、把选择器写成对应的负指数多项式即可。
> 两种写法在负循环环 `Z_t[X]/(X^N+1)` 里**符号约定**（`X^{−k} = −X^{N−k}`）必须逐位对拍；
> 落地时二选一，**以与作者 artifact 一致为准**。

---

# 二、整改需求（按优先级）

> 判定方式：**每一行都要能跑出一个"通过/不通过"的结论**。
> 状态：`✅ 已合规` / `🔧 待整改` / `⏸ 本次不做`

### R1. 基准结构从 CAPE-C 改回 CAPE（最高优先级）

| | |
|---|---|
| **论文依据** | 算法 2 第 2 行 `resp_anc ← FusePIR.Answer(...)`；附录 B「`LWEtoRGSW` … for the query-compressed variants」 |
| **现状** | README / `CAPE_子程序实现对照表.md` 把 `LWEtoRGSW` 列为"唯一硬障碍"，按 CAPE-C 的位口径组织 |
| **整改** | 文档基准改为 **CAPE = FusePIR + Bloom**；`LWEtoRGSW` 从缺项清单与实施顺序中移除，降为 `⏸ 仅 C 变体` |
| **验收** | README、对照表、实施顺序三处不再把 `LWEtoRGSW` 列为必需；不再出现"唯一硬障碍是 LWEtoRGSW"的表述 |

### R2. 列选择改为 `CtPtMul`（密文 × 明文），并纠正文档

| | |
|---|---|
| **论文依据** | §2.5「The first two operations [`CtCtAdd`/`CtPtMul`] are used extensively in FusePIR for encrypted selection」；算法 1 ANSWER 第 5 行 |
| **现状** | 文档把列选择当成 `CtCtMul`；实现里只做了底层算子，**没有 `selectColumn` 这一步** |
| **整改** | ①文档按第 1.2 节改写；②实现 `Acc = Σ_c CtPtMul(ct_col[c], P_{c,b}(X))`（或 1.3 的单次乘法等价式）；③把 `P_{c,b}(X)` 的二维列打包从明文侧接进密文流水线 |
| **验收** | 给定 `ct_col` 与 `{P_{c,b}}`，`Acc` 解密后**逐系数等于被选中列**；换 `c_a` 再验一次 |
| **进度** | 🟢 **②已实测通过**（`AnswerPathMini` 用例 A0：0/64 错位，含全值域载荷、d=512，见 5.1）；**①③未做**——`P_{c,b}(X)` 目前在测试里手工构造 |

### R3. 行选择器收敛为"单条 LWE 密文"，盲旋转用 d 轮口径

| | |
|---|---|
| **论文依据** | 算法 1 QUERY 第 4 行 `q_row,a ← LWE.Enc_{s_L}(r_a)`；§2.5 `BlindRotate(ct_L, ct_R)` 的第一个参数是 **LWE 密文** |
| **现状** | 两种口径都已实现并互验通过；但文档把 `blindRotateByBits`（逐索引位、控制位是 RGSW）称作"论文口径" |
| **整改** | 明确 **`BlindRotateOps.blindRotate`（d 轮、按秘密位）才是 CAPE 的口径**；`blindRotateByBits` 归给 **CAPE-C**（它的控制位来自 `LWEtoRGSW`） |
| **验收** | `BlindRotate(LWE.Enc(r_a), Acc)` 端到端跑通，常数位 = 目标行；接口签名与论文一致（**输入是 `(a,β)`，不是逐位 RGSW**） |

### R3b. 盲旋转必须处理**索引噪声**（⚠️ 新增，**优先级最高的未知项**）

| | |
|---|---|
| **论文依据** | 算法 1 QUERY 第 4 行 `q_row,a ← LWE.Enc_{s_L}(r_a)`——是真 LWE 密文，**必然带噪声**；§2.5「RGSW ciphertexts are used **internally by blind rotation**」 |
| **现状** | ❌ **实测零容忍**：`β = ⟨a,s⟩+r+e` 里 `e=±1` 就把行号推偏一格，结果严丝合缝等于 `p[r+e]`（见 3.4）。而**测试点造的索引都没有误差项**，所以此前一路绿灯。<br>**当前处理**：按 **3.7** 的工程决定，小规模跑通阶段**不引入索引噪声**（= 候选 (b)），并已用 `AnswerPathMini` 把链路跑通 |
| **整改** | 定下 `BlindRotate` 内部消噪声的机制（3.4 的候选 (a)/(b)/(c)），然后改实现；**在此之前不要把它当作可用原语** |
| **验收** | 用**真带噪**的 `LWE.Enc(r_a)`（σ²=3.192 或对齐后的值）跑盲旋转，命中率 100%（或给出可量化的失败率）；并给出**噪声预算**：噪声幅度允许到多大仍然取对行 |

> **与此相关的口径**：现在 `BlindRotateOps.blindRotate` 的接口本身是对的（收 `(a,β)`），
> **缺的是里面的噪声处理**，不是接口。所以这一项是"实现内补一环"，不是"重做"。

### R4. `CtCtMul` / `CtRotate` 的用途收敛到 Bloom 打分

| | |
|---|---|
| **论文依据** | 算法 2 第 4~7 行：`ct_score,j ← CtCtMul(q_BF, ct_j^BF)`，再 `for r=0..log₂ℓ_BF−1: ct_score,j ← CtCtAdd(ct_score,j, CtRotate(ct_score,j, 2^r))` |
| **现状** | `CtCtMul`（346+143 ms、0/16384 错位）与 `CtRotate`（85 ms）**实测已就绪**，但**打分循环没写** |
| **整改** | 实现 `bloomScore(q_BF, ct_j^BF)`，即上面的乘 + 折叠相加循环；轮数 = `log₂ℓ_BF` |
| **验收** | 命中候选解密得分 = τ = ‖b_qry‖₁，不命中 < τ；用构造好的正反例各验一遍 |

### R5. 客户端 QUERY 逻辑按算法 1 第 2~5 行实现

| | |
|---|---|
| **论文依据** | `u_a ← h_a(K)`，`r_a ← u_a mod R`，`c_a ← ⌊u_a/R⌋`；`q_col,a ← RLWE.Enc(e_{c_a})`；`q_row,a ← LWE.Enc(r_a)`；`q_a ← (q_col,a, q_row,a)` |
| **现状** | LWE 加密 ✅、RLWE 加密 ✅、one-hot 构造 ❌（**且没有 `u_a → (c_a, r_a)` 的坐标拆分**） |
| **整改** | 实现坐标拆分 + one-hot 的 RLWE 加密 + `r_a` 的 LWE 加密 |
| **验收** | `(c_a, r_a)` 与 `u_a` 满足 `u_a = c_a·R + r_a`；`q_col,a` 解密后恰为第 `c_a` 位为 1 的 one-hot |

### R6. 自举密钥体积（工程成本，不是"缺原语"）

| | |
|---|---|
| **论文依据** | 论文取 `ℓ_rgsw = 8`（Pirouette Table 4）；我们现状 `levels = 25` |
| **现状** | 论文规模下 1 个 RGSW ≈ 50 MB；`d=512` 时 BK ≈ **25.6 GB**（外推），盲旋转 ≈ 352 s |
| **整改** | 用 **RNS / 直接切段**把 `ℓ` 从 25 降到 8 → 每个 RGSW ≈ 16 MB，BK ≈ **8.2 GB**；详见第三节路线 1 |
| **验收** | 同参数下 `describe()` 的 `levels` 降到 8；`RGSW(1)⊗c=c` / `RGSW(0)⊗c=0` / CMUX 三条用例仍全对 |

### R7. 参数表收口（`ℓ_BF`、`R`/`C`、密文字节数）

| | |
|---|---|
| **论文依据** | SETUP 第 4 行 `Select R,C such that RC ≥ L_BFF, R ≤ N`；§5.1 Bloom 参数 |
| **现状** | `R`/`C` **未定值**；`ℓ_BF = N = 16384` 是由"查询定长"反推的；通信量按 **9 素数** 估，实测密文是 **8 素数**（差 12.5%） |
| **整改** | 定下 `R`、`C`、`ℓ_BF` 并写进 `CAPE_参数表.md`；把按 9 素数推出来的字节数**用实测值重算** |
| **验收** | 参数表里每个数字都标注"论文给的 / 反推的 / 实测的"；`SizeProbe` 能量出真实 query/response 字节数 |

### R8. 端到端联调（SETUP → QUERY → ANSWER → DECODE）

| | |
|---|---|
| **论文依据** | 算法 1/2 全流程 |
| **现状** | 四步里所有**密码学原语**都在论文参数下验证过，但**流程没串起来**：客户端 QUERY 与密文侧 DECODE 都缺 |
| **整改** | 按四步顺序串起来；DECODE 侧补 BFF 重构（k=3 分量相加 mod t）+ 指纹校验（40 bit）+ 载荷解析 |
| **验收** | 跑通一次完整检索：命中返回正确值集，**不命中返回 ⊥**（指纹不匹配） |

### R9. 文档一致性

| | |
|---|---|
| **整改** | ①`CAPE_子程序实现对照表.md`：第 4c/4f/14 项"列选择必须密文×密文"的理由改写；第 9 项 `LWEtoRGSW` 由 ❌ 改回 **⏸（仅 C 变体）**；②本 README 第〇~三节为最新基准，**冲突时以本节为准** |
| **验收** | 全仓库搜索 `LWEtoRGSW`，不再出现"CAPE 主流程必需"的表述 |

---

# 三、探索：不需要 `LWEtoRGSW` 的盲旋转（只用 LWE 输入）

## 3.1 先纠正前提：论文的 `BlindRotate` 本来就是"只吃 LWE"

§2.5 原文：

> **`BlindRotate(ct_L, ct_R) → ct'_R`**：Given a **LWE encryption** `ct_L ← LWE.Enc_s(r)` and an RLWE
> encryption of an accumulator `P(X) = Σ p_i X^i`, it homomorphically rotates the accumulator according to
> the encrypted index `r`, such that `p_r` is moved to the designated coefficient of `ct'_R`, which we take
> to be the constant coefficient.

也就是说：**CAPE/FusePIR 的盲旋转，输入就是一条 LWE 密文**（行选择器 `q_row,a = LWE.Enc(r_a)`），
**它根本不经过 `LWEtoRGSW`**。我们要找的"不需要 LWE→RGSW 的盲旋转"，**就是算法 1 里那个 `BlindRotate`**。

## 3.2 为什么它不需要 `LWEtoRGSW`

因为它按**秘密位**分解，而不是按**索引位**：

```
X^{−r} = X^{−β} · X^{⟨a,s⟩} = X^{−β} · Π_i X^{a_i·s_i}
```

- `a_i` 是**公开**的（算法 4 里由种子 ρ 经 PRG 派生，线上只传 ρ 与 β），所以 `X^{a_i}` 是**公开旋转**；
- 只有 `s_i ∈ {0,1}` 需要保密，而 `BK_i = RGSW(s_i)` 是**密钥持有者在 SETUP 阶段生成的公开评估材料**
  （算法 4 SETUP 第 2 行："Generate the **public evaluation material** required by …"）；
- 每轮就是 `ACC ← CMUX(BK_i, ACC, ACC·X^{a_i})`，共 `d` 轮，末尾补一次公开旋转 `X^{−β}`。

**要点：`BK` 是"秘密位的 RGSW"，不是"把查询的比特转成 RGSW"。** 后者（`LWEtoRGSW`）才是
circuit bootstrapping，只有 C 变体才需要。

## 3.3 现状修正：旋转**机构**已验证，但它还不是论文的 `BlindRotate`

> ⚠️ **2026-09-19 晚更正**：本节原先写的是"这个盲旋转我们已经有了，而且实测通过"。
> **那指的是旋转机构，不是论文的 `BlindRotate`。** 真正的缺口见 3.4 —— 现有自检里的
> "LWE 索引"其实是**无噪声**的，所以那个绿灯说明不了协议可用性。别再按旧说法对外表述。

**机构层面（本轮实跑，可以放心的部分）：**

| 项 | 实测 |
|---|---|
| d 轮口径正确性 | N=2048：`r=777`、`r=31` 两个下标都对，整条累加器 2048/2048 一致 |
| **轮数稳定性（d 扫描，新增）** | d=64 / 128 / 256 / **512 全对**；d=512 时盲旋转 1541 ms、整条 2048/2048 —— **512 轮 CMUX 的噪声累加没有塌**（原先担心这一点，实测证明不是问题） |
| `BlindRotateComplete`（真实载荷 + 加密索引 + SampleExtract + Pack） | **4/4**，常数位 = `payload[r]` |
| 两口径互验 | 口径 1（`⌈log₂N⌉` 轮）与口径 2（d 轮）结果**完全一致** |
| 论文规模单轮成本 | 外部乘积 726 ms / CMUX 688 ms / 公开旋转 ≈0 ms |

**接口签名与论文一致**：`blindRotate(..., long[] a, long beta, ...)` —— 吃的就是 `(a, β)`。

## 3.4 ⚠️ 缺的那一环：索引噪声**零容忍**（2026-09-19 实测发现）

用 `BlindRotateStress.java` 扫了一遍 `β = ⟨a,s⟩ + r + e` 里的噪声 `e`（N=2048、d=512）：

```
e=  0 | 常数位=235 | p[r]=235 p[r+e]=235 | = p[r]     ✅ 正确
e=  1 | 常数位=236 | p[r]=235 p[r+e]=236 | = p[r+e]  ⚠️ 整体推移   1 格
e= -1 | 常数位=234 | p[r]=235 p[r+e]=234 | = p[r+e]  ⚠️ 整体推移  -1 格
e=256 | 常数位=491 | p[r]=235 p[r+e]=491 | = p[r+e]  ⚠️ 整体推移 256 格
```

**噪声不是"污染"，而是精确地把行号推偏**——`got` 严丝合缝等于 `p[r+e]`。
也就是说：现在的实现把 LWE 相位 **1:1 当成旋转指数**，**一格噪声就取到相邻的那一条记录**。

**为什么这是协议级问题，不是测试瑕疵**：CAPE/FusePIR 的 `q_row,a = LWE.Enc_{s_L}(r_a)`
是**真 LWE 密文，必然带噪声**；而 `blindRotate` 里只有

```java
for (i) { cur = cmux(bk[i], cur, multiplyPowerOfX(cur, a[i])); }
return multiplyPowerOfX(cur, -b);      // ← 相位直接当指数，没有取整/吸收噪声的环节
```

**没有任何一步把"带噪声的相位"变成"精确的旋转指数"。** 按现在的实现，真实查询会**稳定地取错行**。

**为什么之前一路绿灯**：三个测试点造索引时**都没有误差项**（代码里就是 `beta = sum + r`，`sum = ⟨a,s⟩`）：
`BlindRotateOps.lweEncryptIndex`、`BlindRotateComplete`、`LweToRgswOps`。所以那条"LWE 密文"其实不满足 LWE 的噪声模型。

### 要定下来的问题：`BlindRotate` 内部怎么消噪声？

| 候选 | 说明 | 疑点 |
|---|---|---|
| **(a) 载荷布局留间隙** | 每行在多项式里占一个宽度 `Δ` 的块（值在块内重复填满），则噪声落在 `−Δ/2 < e < Δ/2` 内会回到同一行 | 但论文 SETUP 第 14 行是 `P_{c,b}(X) = Σ_{r=0}^{R−1} D[r+cR][b]·X^r`——**一行一个系数、没有复制**，和原文对不上，要查清 |
| **(b) 索引密文噪声被压到 ≈0** | 靠参数选择让噪声可忽略 | 无噪声 LWE 的安全性存疑，且要把安全论证重看一遍 |
| **(c) `BlindRotate` 内部还有一步** | §2.5 说 "RGSW ciphertexts are used **internally by blind rotation**"，暗示内部可能先做一次**比特提取**（带舍入测试多项式的盲旋转）再进 CMUX | 我们在 `LweToRgswOps` 里正撞到过这个"舍入测试多项式"；**BitDecomp 干的就是"把带噪 LWE 变成精确比特"** |

> **一个耐人寻味的推论**：候选 (c) 若成立，那 CAPE-C 走 `BitDecomp → LWEtoRGSW` 那条路
> **反而顺手把噪声问题解决了**（BitDecomp 用舍入多项式做一次盲旋转，本来就是消噪声取精确比特）。
> 而 FusePIR 的非压缩路径省掉了 BitDecomp，这个环节就必须藏在 `BlindRotate` 内部——
> **这也许正是 §2.5 说"盲旋转内部要用 RGSW"的原因。**

**结论：第 6 项在对照表里不能算 ✅。** 现在的准确表述是
**"旋转机构已实现并验证（含 d=512 稳态），但把带噪 LWE 索引安全地转成精确旋转的那一环没有"**。

## 3.5 真正的成本问题：`d` 个 RGSW

| 口径 | 轮数（N=16384） | 自举密钥 | 盲旋转耗时 | 用在哪 |
|---|---|---|---|---|
| **按秘密位（d 轮）** | **512**（d=512） | **512 个 RGSW** ≈ 25.6 GB | ≈ 352 s（外推） | **CAPE / FusePIR** ← 我们的基准 |
| 按索引位（`⌈log₂N⌉` 轮） | 14 | 14 个 RGSW ≈ 700 MB | 19.9 s（实测） | CAPE-C / FusePIR-C（**需 `LWEtoRGSW`**） |

**CAPE 用上面那一行**：不需要 `LWEtoRGSW`，但密钥大 37 倍。**这是 CAPE 与 CAPE-C 的核心取舍。**
所以"探索"的目标不只是"找一个不需要 `LWEtoRGSW` 的盲旋转"，而是两件事合起来：
**① 把自举密钥和轮数压下来；② 让"带噪 LWE 索引 → 精确旋转"这一步成立（3.4）。**
后者是正确性问题，优先级高于前者。

## 3.6 三条可选路线

### 路线 1（推荐，改动最小）：保留 BK，把每个 RGSW 做小 —— RNS / 直接切段

- 现状 `levels=25` 是因为切段数字必须以**明文**喂进 `multiplyPlain`，而明文窗口只有 `±t/2 = ±32768`
  → 逼出 `B ≤ t`、`ℓ = ⌈389/16⌉ = 25`。
- 改用 **RNS/直接切段**（Garner 还原 / SEAL 的 `util::decompose` 同款分解）可对齐 Pirouette 的 `ℓ_rgsw = 8`：

  | 手段 | levels | 每个 RGSW | BK（d=512） |
  |---|---|---|---|
  | 现状（明文切段，B=2¹⁶） | 25 | 50 MB | **25.6 GB** |
  | **RNS/直接切段（ℓ=8）** | **8** | ≈16 MB | **≈8.2 GB** |

- **不改变协议结构**，纯实现优化，**风险最低**；对拍用例现成（`RGSW(1)⊗c=c`、`RGSW(0)⊗c=0`、CMUX 两分支）。

### 路线 2（备选，激进）：彻底去掉 RGSW —— 双 one-hot 选择器 + 重线性化

**想法**：既然**列**选择能用"密文 × 明文"做（选择器作明文系数），**行**选择也能用同一招——
只要客户端把**行**也加密成 one-hot，并把两次选择合成一次乘法：

```
ct_prod ← CtCtMul(ct_col, ct_row)        然后重线性化（规模 3 → 2）
ct_out  ← CtPtMul(ct_prod, P*_b(X))      明文：整张表按 2D 交错打包
ct_L    ← SampleExtract_0(ct_out)        → 目标条目的 LWE 密文
```

**不需要 BK、不需要 RGSW、不需要 512 轮 CMUX。** 服务端侧：

| | 论文口径（d 轮 CMUX） | 路线 2 |
|---|---|---|
| 服务端耗时（外推） | ≈352 s | **≈0.5 s**（346+143 ms 的 CtCtMul + 一次 CtPtMul + SampleExtract） |
| SETUP 评估材料 | 512 个 RGSW ≈ 25.6 GB | **一把重线性化密钥** |
| 查询里行选择器 | 一条 LWE（≈36 B） | **一个 RLWE one-hot（≈1 MB）** |
| 环约束 | `R ≤ N` | **`RC ≤ N`** |

**代价与风险（必须写清楚）：**

1. **它改变了论文的协议步骤**——不再使用论文的 `BlindRotate`。按本项目"**不改变原论文的算法**"的硬约束，
   它**不能作为主线**，只能作**性能对照 / 成本备选**（或作为单独立项的研究记录）。
2. 查询从"3 RLWE + 3 LWE"变成"6 RLWE"，**上传量增加**；方向上与 FusePIR-C 恰好相反
   （C 变体是"查询更小、服务端更贵"，这条是"查询更大、服务端更便宜"）。
3. 需要在负循环环里把**符号约定**（`X^{−k} = −X^{N−k}`）逐位对拍，并用
   `SampleExtract → Pack → 库解密` 的**真实解密**验收（**不能用自证式恒等式验收**）。
4. 安全性论证要重写一遍（选择器整体 one-hot 加密，应仍由 RLWE IND-CPA 覆盖，但不能只靠"看起来可以"）。

> **📌 3.4 的发现给路线 2 加了一条新理由**：路线 2 **完全没有"按相位旋转"这一步**——
> 行选择器是一个 RLWE one-hot 密文，用 `CtCtMul` 做选择，**不存在"带噪 LWE 相位 → 旋转指数"的转换**，
> 所以**索引噪声问题在路线 2 里根本不存在**。
> 也就是说：**如果 3.4 的候选 (a)/(b) 都不成立、CAPE 的非压缩行选择器确有这层障碍，
> 路线 2 就是一个"绕开整个问题"的退路**。这让它在"风险兜底"上的价值变高了
> ——但代价仍然是改变论文的协议步骤，**只能作备选**。

### 路线 3（探索性）：混合 / 分层压缩 BK

- 把 `d` 位分块，块内用更小的 gadget 因子，或让 BK 只在 RLWE 层用**更小的模数**（BK 不参与 `q_L` 的旋转群约束），
  以进一步压体积。
- 论文没有给这些优化，**属于工程优化，风险中等，收益不确定**；建议在路线 1 落地后再评估。

### 建议

> **主线走路线 1**（保留 CAPE 的结构与 `BlindRotate`，只把 `ℓ` 从 25 压到 8）。
> **路线 2 单独立项做实验**，成果只用于"性能对照 / 成本备选"，**不要混进主流程**——
> 否则就违反了"不改变原论文的算法"。
> 路线 3 暂缓。
>
> **补充（2026-09-19 晚）**：`AnswerPathMini` 已实测证明 **CAPE 的骨干链路本身是通的**
> （列选择 → 盲旋转 → 样本提取 → 三路相加，N=2048/4096、d=64/512 全过）。
> 所以主线**不需要**退到路线 2；路线 2 现在的定位就是纯粹的"成本备选 + 风险兜底"。

## 3.7 📌 已定：小规模跑通阶段**盲旋转不引入索引噪声**（= 候选 (b)）

> **这是一条已记录的工程决定，不是临时凑合。** 面向的目标就是"数据库规模不用大、能跑通就行"。

**决定内容**：客户端的行选择器 `q_row,a` 按 **Δ=1、无噪声** 造：

```
b = ⟨a,s⟩ + r        (mod q_L = 2N)      ← 没有误差项 e
r ∈ [0, R),  R ≤ N
```

配套已就绪的实现：`BlindRotateOps.lweEncryptIndex(s, r, qL, rnd)` 造的就是这种密文；
`blindRotate` 直接吃它的 `(a, b)`。**`AnswerPathMini` 已经用这条约定跑通全链路。**

**为什么可以这么做（阶段目标）**：

- 盲旋转的**旋转机构**本身已经完全正确（d 扫到 512 稳态、整条累加器一致）；
- `AnswerPathMini` 证明**列选择的累加器 + 512 轮 CMUX** 也扛得住；
- 于是 **"带噪相位 → 精确旋转"这一环是当前唯一没有机制的地方**，而它**不阻塞**
  把 QUERY → ANSWER → DECODE 串起来、把数据库侧编码接通、把 Bloom 打分写出来。

**必须写明的代价与限制（不要省略）**：

| 项 | 说明 |
|---|---|
| ⚠️ **安全性未论证** | 无噪声 LWE 是"**带未知小消息的 LWE**"，与标准 LWE（小噪声、已知消息）**不是同一个问题**。**不能声称它安全**，也不能直接引用论文/标准参数的安全性论证。真要交付必须先过这一关。 |
| ⚠️ **与论文的偏差要声明** | 如果最终确认论文的 `q_row,a` 是带噪的，那么"零噪声"就是**本项目相对论文的一处偏差**，必须在报告里显式列出，不能藏在代码里 |
| ⚠️ **它是协议消息格式的一部分** | 改的是客户端 QUERY 造密文的方式，**不是实现细节**。将来切回带噪声，改动点在客户端 + 盲旋转内部，不在数据库侧 |
| ✅ **不影响已有的正确性结论** | `AnswerPathMini` 等的结论只在"无噪声"前提下成立；换成带噪索引后**这些测试必须重跑** |

**迁移路径（定下机制之后）**：

- 若最终确认是 **(b)** → 现在的实现**就是对的**，只需补安全性论证；
- 若是 **(a) 载荷块布局** → 改数据库打包 + `SampleExtract` 落点，盲旋转本身不动；
- 若是 **(c) 内部比特提取** → 要补 `BitDecomp`/`LWEtoRGSW` 那一套（1~2 周），
  并且此前把 `LWEtoRGSW` 判为 ⏸ 的结论要**一并推翻**。

> **因此：本项目在任何对外文字里，对盲旋转的表述都必须是**
> **"旋转机构已验证；索引噪声按工程决定暂不引入，机制待定"**，
> **不能写成"盲旋转已完成"。**

---

# 四、默认使用哪个文件夹（别拿错）

**一句话**：默认路线是**纯 Java**——**库在 `lib/`**，**实现的代码在 `rgsw-lab/` 与 `lwe-java/`**。
三份"看起来都像"的东西里只有一份是默认的，其余是对照或弃用。

| 功能 / 论文子程序 | ✅ **默认用这个文件夹** | 入口（文件 → 方法） | ❌ **不要用** |
|---|---|---|---|
| **RLWE 层**：`RLWE.Enc/Dec`、`CtCtAdd`、**`CtPtMul`**、`CtCtMul`、`CtRotate`、模数切换 | 库 **`lib/`** + 调用代码 **`rgsw-lab/`** | `lib/mpc4j-crypto-fhe-seal.jar`（**已打补丁**）<br>`rgsw-lab/.../Mpc4jRgsw.java`：<br>· `encrypt` / `decrypt`<br>· `add` / `sub` / `scalarMultiply`<br>· **`CtPtMul` = `evaluator.multiplyPlain`**（列选择就用它）<br>· `multiplyPowerOfX` = **`CtRotate`**（系数域）<br>· CtCtMul 用 `m.evaluator.multiply` + `relinearizeInplace`<br>· 旋转/模切换用 `m.evaluator.rotateRowsInplace` / `modSwitchToNextInplace` | ❌ **`rlwe-java/`**（自研，**已弃用**，缺缩放回落）<br>🔵 `native-jni/`（真 SEAL，**仅对照**） |
| **LWE 层**：`LWE.Enc/Dec`、模数切换 | **`lwe-java/`** | `src/main/java/cape/he/LWE.java`：`keyGenBinary` / `encrypt` / `decrypt`<br>`LWECiphertext.switchModulus` | ❌ **没有第二份可直接调用的 LWE 原语**。⚠️ 但注意：**MPC4J 并非"完全没有 LWE"**——它的 `cppir` 家族（ChalametPIR / SimplePIR / FrodoPIR / Piano / Plinko）本身就是 **LWE / 矩阵型 PIR**，内部用 `IntVector`/`IntMatrix` 做 `b = s·A`、`c = s·M` 这类运算，另有 `GaussianLweParam` 参数枚举（n=1024/1408、σ=6.4）。**但那是协议级实现，没有可复用的 `LWE.Enc/Dec` 原语**——所以做 CAPE 的 LWE 层仍以 `lwe-java/` 为准 |
| **RGSW**：`RGSW.Enc`、外部乘积、`CMUX` | **`rgsw-lab/`** | `Mpc4jRgsw.java`：<br>· `encryptRgswConstant(μ)`（**自举密钥 BK**）<br>· `encryptRgswPoly(m)`（一般多项式，`enc_sk` 用）<br>· `externalProduct(rgsw, ct)`<br>· `cmux(rgsw, a, b)` | ❌ `rgsw-lab/` 里的 `RgswOps.java`、`RgswCiphertext.java`、`MonomialOps.java`、`BootstrapKey.java`、`LabConfig.java`、`RgswLabMain.java`、`MonomialKeyTest.java`、`examples/RlweDemo.java`（**路线 C，已加弃用横幅**） |
| **`BlindRotate`** | **`rgsw-lab/`** | `BlindRotateOps.java`：**`blindRotate`（d 轮 = CAPE 口径 🟡）** / `blindRotateByBits`（逐索引位 = CAPE-C 口径）<br>`BlindRotateComplete.java`（端到端完整版）<br>`AnswerPathMini.java`（**最小 ANSWER 链路**，见 5.1） | ❌ 无替代 |
| **`SampleExtract_j`** / **`Pack`** / **LWE↔RLWE 桥** | **`rgsw-lab/`** | `LweRlweBridge.java`：`sampleExtract` / `packFromSample` / `decryptSampleViaPack`（q_R 下的系数 ↔ 样本映射）<br>**`LweRlweConversion.java`**：`extractLwe`（RLWE→LWE，含 `q_R→q_L` 模数切换，产出 `cape.he.LWECiphertext`）/ `packLwe` / `rlweSecretAsLweKey`<br>**调用说明 → `rgsw-lab/LWE_RLWE桥_调用说明.md`** | ❌ 无替代（互逆映射，故意写在一起） |
| **`LWEtoRGSW`** | **⏸ 本次不做** | `LweToRgswOps.java`（骨架，现测不通过）——**仅 CAPE-C 需要** | — |
| **数据库预处理**（明文侧：BFF / Bloom / 载荷 / **列多项式 `P_{c,b}(X)`**） | **`cape-fusepir-database-handoff/`** | `DatabasePreprocessor.java`、`BloomParameters.java`、`PlaintextPayload.java` | — |
| 参数位宽 / 性能测量 | `param-probe/`、`rlwe-bench/`、`rgsw-lab/SizeProbe.java` | — | — |

**为什么 RLWE 的"默认"是两处**：**库**（那个 jar）在 `lib/`，而**调用它的代码**在 `rgsw-lab/`
（`Mpc4jRgsw.java` 就是 RLWE 层的门面）。`rlwe-java/` 是**最早的自研版**，不是默认。

**最容易搞混的六处**：

1. **两个都叫 `lib` 的目录**：`coding/lib/` 是**Java jar**（默认）；`coding/native-jni/lib/` 是**真 SEAL 的 DLL**（仅对照）。
2. **`coding/rlwe-java/` 不是默认的 RLWE**——默认的 RLWE 调用代码在 **`coding/rgsw-lab/`**。
3. **两套 RGSW**：`Mpc4jRgsw.java`（默认）vs `RgswOps.java`（弃用）。
4. **`rgsw-lab/` 里有两个 run 脚本**：`run-mpc4j.ps1`（**默认入口**）vs `run.ps1`（路线 C，顶部有 `LEGACY - ROUTE C ONLY` 警示）。
5. **LWE 只有一份**：`coding/lwe-java/`。
6. **"MPC4J 的 SEAL"有两种形态**：`lib/mpc4j-crypto-fhe-seal.jar` 是**逐类翻译的 Java 重写**；`native-jni/lib/mpc4j-native-fhe.dll` 是**真 SEAL 的 C++ JNI 封装**。两者语义一致，但性能与内存上限不同。

> 库的门面（`Mpc4jRgsw`）同时承载 RLWE 与 RGSW 两个子程序，这是**故意的**：
> RGSW 必须在 RLWE 之上才能写，拆成两个文件会逼出大量重复代码。

---

# 五、四步 ↔ 代码总览

| 步骤 | 论文里做什么 | 对应代码 | 状态 |
|---|---|---|---|
| **SETUP** | 选参数；生成 HE 密钥与**评估材料**（重线性化密钥、旋转密钥、**自举密钥 BK**）；数据库预处理（BFF + Bloom + 载荷编码 + **列多项式打包**） | 明文侧：`cape-fusepir-database-handoff/`<br>密钥材料：`rgsw-lab/`、`lwe-java/` | 🟡 原语齐；**列打包未接**；BK 体积待压 |
| **QUERY** | 哈希 → BFF 位置 → 坐标 `(c_a,r_a)` → **列 one-hot 的 RLWE 加密** + **行 `r_a` 的 LWE 加密**（+ 加密 Bloom 向量） | `lwe-java/`（LWE ✓）<br>`rgsw-lab/`（RLWE ✓） | 🔴 **客户端查询逻辑未实现** |
| **ANSWER** | **`CtPtMul` 列选择** + **`BlindRotate`** + `SampleExtract_0` + 三路相加 + Bloom 打分（`CtCtMul` + `Σ CtRotate(·,2^r)`）+ 响应组装 | `rgsw-lab/`（`AnswerPathMini` 已跑通最小链路） | 🟢 **骨干链路已跑通**（列选择→盲旋转→样本提取→三路相加，见 5.1）；还缺：Bloom 打分、产品化列打包、**索引噪声处理**（3.4 / R3b） |
| **DECODE** | 解密 + BFF 重构（k=3 相加 mod t）+ 指纹校验（40 bit）+ 载荷解析（+ 阈值 τ 判定） | 明文侧结构 ✓ | 🟡 三路相加 + 解密已在 `AnswerPathMini` 验过；**指纹校验/载荷解析的密文侧编排未做** |

### 5.1 最小 ANSWER 路径已跑通（2026-09-19 晚实测）

`AnswerPathMini` 把 ANSWER 的骨干**真跑通了**——不是零件级，是链路级：

```
客户端：E(X) = X^{−cR}（one-hot 选择子）→ RLWE.Enc
服务端：Acc = CtPtMul(ct_col, A(X))        ← A(X) = 整张表按列交错打包的明文多项式
        Acc' = BlindRotate(LWE(r_a), Acc)  ← 索引无噪声
        ct_L = SampleExtract_0(Acc')
客户端：三路 ct_L 相加 → Pack → 解密
```

| 参数 | 小值载荷（1..1000） | 全值域载荷（随机 mod t） |
|---|---|---|
| N=2048, d=64 | ✅ 7/7 | ✅ |
| **N=2048, d=512** | ✅ 7/7 | ✅ |
| **N=4096, d=512** | ✅ 7/7 | ✅ |

其中包含两条关键中间验收：
- **A0 列选择本身**：`Acc` 解密后系数 `r` 逐个等于"被选中列的第 r 行"（**0/64 错位**）——证明 `CtPtMul` 的排列/符号约定（`X^{−cR} = −X^{N−cR}`）是对的；
- **A3 含零 a 分量**：见 **附录 A 第 9 条**（这是本轮抓到的真 bug）。

**这把两件事从"应该没问题"变成了"实测通过"**：
1. 列选择的累加器（噪声远大于全新密文）喂给盲旋转**扛得住**，连全值域载荷也行；
2. `CtPtMul` 列选择的**打包与符号约定**是可用的。

**仍然不成立的**：索引噪声（3.4 / R3b）——`AnswerPathMini` 的索引也是无噪声的。
另外这里 `A(X)` 是**测试里手工构造**的，`DatabasePreprocessor` 还没产出 `P_{c,b}(X)`（R2 的产品化部分）。

**一句话现状**：**四步的密码学骨干已经串通一环（ANSWER 链路）**，缺的是 QUERY 客户端逻辑、DECODE 编排、Bloom 打分，
以及两件非编排的事：**索引噪声机制（R3b）** 与 **BK 体积（R6）**。

---

# 六、项目结构

| 目录 | 定位 | 关键文件 |
|---|---|---|
| **`lib/`** | 默认路线的库：MPC4J 的 SEAL **Java 移植版**（**已打补丁**）+ 11 个运行期依赖 | `mpc4j-crypto-fhe-seal.jar`、`deps/` |
| **`patches/`** | 对第三方库的补丁 | `mpc4j-galois-lazy-permutation-tables.patch`（**没有它 N=16384 必 OOM**） |
| **`rgsw-lab/`** | **主实验场**：所有已实现的子程序 + 自检 + 实测文档 | 见下表 |
| **`lwe-java/`** | **LWE 层**（包 `cape.he`）。**唯一的通用 LWE 原语实现**——MPC4J 虽有 LWE/矩阵型 PIR（`cppir` 家族）与 `GaussianLweParam`，但**没有可复用的 `LWE.Enc/Dec` 类**，所以这一层是自研的 | `LWE.java`、`LWEParams.java`、`ModSwitchTest.java` |
| **`cape-fusepir-database-handoff/`** | 数据库预处理（**明文侧**）：BFF 布局、Bloom 过滤器、载荷编码、MovieLens 载入 | `DatabasePreprocessor.java`、`BloomParameters.java`、`PlaintextPayload.java` |
| **`native-jni/`** | 🔵 **对照路线**：真 SEAL 4.0.0 的 JNI 封装（`mpc4j-native-fhe.dll`） | `SealPirNativeTest`、`seal_params_probe.cpp` |
| **`rlwe-java/`** | ❌ **已弃用**：自研 RLWE（缺缩放回落，密文×密文做不出可用结果），仅作交叉校验 | — |
| `param-probe/`、`rlwe-bench/` | 测量工具（参数位宽、性能对照） | — |
| `pdf-extract/` | 三份 PDF 的**按栏切分**提取文本（原始提取是错行的） | `out_cape.txt`、`out_bkpir.txt`、`out_survey.txt` |
| `ml-latest-small/` | MovieLens 数据集（测试数据） | — |

`rgsw-lab/` 内部（**主实验场**）：

| 文件 | 实现的子程序 |
|---|---|
| `Mpc4jRgsw.java` | `RLWE.Enc/Dec`、`CtCtAdd`、**`CtPtMul`**、`CtCtMul`、**`CtRotate`**、`RGSW.Enc`（常数与一般多项式）、外部乘积、`CMUX` |
| `Mpc4jCapability.java` | 四项能力探针（打包 / ct×ct+重线性化 / 旋转 / 模数切换） |
| `BlindRotateOps.java` | **`BlindRotate`** 两种口径（**d 轮 = CAPE**；逐索引位 = CAPE-C） |
| `BlindRotateComplete.java` | 完整盲旋转（真实载荷 + 加密索引，端到端 4 项验收） |
| `LweRlweBridge.java` | **`SampleExtract_j`** + **`Pack`**（q_R 下的互逆映射，同一文件）；含 `crtCentered` |
| `LweRlweConversion.java` | **LWE ↔ RLWE 桥**：`extractLwe`（RLWE→LWE，含 `q_R→q_L` 模数切换，产出 `cape.he.LWECiphertext`）、`packLwe`、`rlweSecretAsLweKey`。**调用说明见 `LWE_RLWE桥_调用说明.md`** |
| `SizeProbe.java` | 实测真实密文的素数分量数与序列化字节数 |
| `BlindRotateStress.java` | **盲旋转压力测试**：轮数扫描（d=64→512）+ **索引噪声扫描**。就是它测出"噪声零容忍"的那个缺口（见 3.4）。**测试文件暂时保留** |
| `AnswerPathMini.java` | **最小 ANSWER 链路**：列选择（`CtPtMul`）→ 盲旋转 → `SampleExtract_0` → 三路相加 → 解密。含专项 A3（`a_0 = 0`，见附录 A 第 9 条）。见 5.1 |
| `LweToRgswOps.java` | `LWEtoRGSW`（❌ 未通过；**仅 CAPE-C 需要，本次不做**） |
| `RgswPolyTest.java`、`RgswPolyDiag.java` | 一般多项式 RGSW 的验证与诊断 |
| `RgswOps.java` 等 8 个 | ❌ **路线 C 遗留**（自研），已加弃用横幅 |
| `run-mpc4j.ps1` | 默认自检入口（`-Class` 可指定主类） |
| `run.ps1` | ❌ 路线 C 入口（顶部有 `LEGACY` 警示） |

---

# 七、SETUP

**论文要求**（§2.5、算法 1/4/5 SETUP）：选公开参数 `(N,d,t,q)`；生成 `sk=(s_L,s_R)`；
**`Select R, C such that RC ≥ L_BFF, R ≤ N`**；
生成**评估材料**——重线性化密钥、Galois 旋转密钥、**自举密钥 `BK={RGSW(s_i)}`**；
数据库侧构造 BFF（k=3 位置、段长 s、总长 `L_BFF ≈ 1.125n`）、每个值的 Bloom 过滤器、
载荷 `y_K = fp(K) ‖ m_i ‖ v_1 ‖ … ‖ v_m ∈ Z_t^{B_pay}`，
并把数组排成二维后**把每一列打包成一个多项式** `P_{c,b}(X) ← Σ_{r=0}^{R−1} D[r+cR][b]·X^r`。

**已有** ✅

| 项 | 位置 | 实测 |
|---|---|---|
| RLWE 密钥、上下文 | `Mpc4jRgsw` 构造函数 | N=16384 起效，`describe()` 打印声明/工作素数 |
| 重线性化密钥 | MPC4J `createRelinKeys` | 215 ms |
| **旋转密钥** | MPC4J `createStepGaloisKeys` | 118 ms；**论文只需 `{1,2,4,…,ℓ_BF/2}` 共 log₂ℓ_BF = 14 个步长**（由算法推得） |
| **自举密钥** `BK={RGSW(s_i)}` | `encryptRgswConstant` | 是盲旋转的 setup 材料（**CAPE 用它，不需要 `LWEtoRGSW`**） |
| LWE 密钥（二进制） | `lwe-java` `keyGenBinary` | 200/200 |
| 数据库预处理（明文侧） | `cape-fusepir-database-handoff/` | 含测试 |

**缺** ❌

1. ✅ **算术 BFF 已完成**（2026-09-23，PR #1）：`ArithmeticBffEncoder`（模 t 域 + 剥皮 + 换种子）+ `BffHashGen`
   （段长 `2^⌊log₃.₃₃(n)+2.11⌋`）+ `ArithmeticBff.reconstruct` + 指纹校验。
   实测：合成库 0 错；**真实 MovieLens 数据 936 个关键词全部重建正确、指纹 0 失败**。
2. ✅ **二维列打包已完成**：`BffMatrixLayout` 实现论文 SETUP 第 14 行 `P_{c,b}(X) = Σ_r D[r+cR][b]·X^r`
   （列优先、零拷贝视图），实测 38×38 = 1444 ≥ 表长 1408、逐槽一致。**这正是列选择 `CtPtMul` 要吃的明文多项式**（R2 的第 ③ 条）。
3. ⚠️ **载荷指纹长度仍是 48 位**（论文 40 位），且 `CapeParameters.fingerprintBits()` 从未被使用。
4. ⚠️ **Bloom 位位置仍把 value 混进哈希**（`digest(keyword + ":" + value)`）——**实质性错误**：
   客户端只能拿关键词构造查询向量，内积永远到不了 τ（见对照表第 11 项）。
5. **`R`、`C`、`ℓ_BF` 仍未定值**（对应整改 R7）；真实数据子集实测 `ℓ_BF = 558`。
6. **密钥/材料持久化**：setup 产物落盘、跨进程复用（现在全在内存里）。
7. **BK 体积**：`d=512` 时 25.6 GB（对应整改 R6 / 路线 1）。

---

# 八、QUERY

**论文要求**（算法 1 QUERY，对齐 CAPE 后）：

```
ℓ_c = ⌈log₂C⌉,  ℓ_r = ⌈log₂R⌉
for a = 0..2:
    u_a ← h_a(K),  r_a ← u_a mod R,  c_a ← ⌊u_a / R⌋
    q_col,a ← RLWE.Enc_{s_R}(e_{c_a})      ← one-hot 向量的 RLWE 加密（每一位 = 明文多项式的一个系数）
    q_row,a ← LWE.Enc_{s_L}(r_a)           ← 一条 LWE 密文（不是逐位）
    q_a ← (q_col,a, q_row,a)
q ← (q_0, q_1, q_2)
```

**CAPE 额外**：把 `K_2,…,K_Q` 插进一个 Bloom 过滤器得到 `b_qry`，本地保留 `τ = ‖b_qry‖₁`，
再 `q_BF ← RLWE.Enc_{s_R}(b_qry)`；`q ← (q_anc, q_BF)`。

> **注意**：`LWEtoRGSW`、`ρ` 种子压缩、`bin_{ℓc}(c_a)‖bin_{ℓr}(r_a)` 逐位加密**都属于 C 变体**，
> 本项目的 QUERY **不包含**这些步骤。

**已有** ✅：LWE 加密（含二进制密钥、模数切换、`q_L = 2N` 预设）；RLWE 加密；`Pack` 的单系数版本。

**缺** ❌

1. **坐标拆分 `u_a → (c_a, r_a)`** 与 BFF 位置计算（对应整改 R5）；
2. **列 one-hot 的 RLWE 加密**（把 `e_{c_a}` 摆成多项式系数再加密）；
3. **加密 Bloom 查询的定长构造**（`ℓ_BF` 待定，见 R7）；
4. **查询序列化**（线上格式）。

---

# 九、ANSWER

**论文要求**（算法 1 ANSWER + 算法 2 第 2~7 行）：

```
for a = 0..2:
    for b = 1..B_pay:
        Acc_{a,b}    ← Σ_{c=0}^{C−1} CtPtMul(q_col,a[c], P_{c,b}(X))   ← 列选择：密文 × 明文
        Acc'_{a,b}   ← BlindRotate(q_row,a, Acc_{a,b})                 ← 行选择：LWE 输入
        ct_{a,b}     ← SampleExtract_0(Acc'_{a,b})
for b: ct_pay,b ← ct_{0,b} + ct_{1,b} + ct_{2,b}
resp ← Pack({ct_pay,b})
# CAPE 追加（算法 2）：
for j = 1..m:
    ct_score,j ← CtCtMul(q_BF, ct_j^BF)
    for r = 0..log₂ℓ_BF−1: ct_score,j ← CtCtAdd(ct_score,j, CtRotate(ct_score,j, 2^r))
resp ← ({ct_vj, ct_score,j})_{j=1}^m
```

**已有** ✅（**全部在 N=16384 论文参数下实测**）

| 子程序 | 实测 |
|---|---|
| `CtCtAdd` / **`CtPtMul`** | ✅ |
| **`CtCtMul`**（含重线性化 + BFV 缩放回落） | ✅ 346+143 ms，0/16384 错位 |
| **`CtRotate`** | ✅ 85 ms（另 `rotateRows` 也通过） |
| 模数切换 | ✅ 9→8 素数，噪声 368→316 bit |
| **`RGSW.Enc`**（常数 + 一般多项式） | ✅ `RGSW(1)⊗c=c`、`RGSW(0)⊗c=0`、`RGSW(m)⊗c = m⊛msg` 全 0 错位 |
| 外部乘积 / `CMUX` | ✅ 726 ms / 688 ms |
| **`BlindRotate`**（**d 轮 = CAPE 口径**） | 🟡 机构 ✅：N=2048 两个下标全对；两口径结果一致；**d 扫到 512 不塌**（1541 ms）。<br>❌ **但索引噪声零容忍**（`e=±1` 就选到相邻行，见 3.4 / R3b）——**现有测试的索引是无噪声的，所以这个 ✅ 不成立** |
| **`BlindRotate`** 完整版（真实载荷 + 加密索引） | 🟡 **4/4，但同样用的是无噪声索引**（`BlindRotateComplete` 里 `beta = sum + r`，没有误差项） |
| **`SampleExtract_j`** / **`Pack`** | ✅ 往返 5 个系数 0 错；**`LweRlweConversion` 已把输出接进 `cape.he`**：N=2048/4096、q_L=2³²/2⁴⁰ 抽出样本解密 0 错；三条路径在 LWE 域相加正确 |
| 噪声余量（ct×ct 后） | ✅ **339 bit**（N=4096 时只有 24 bit） |

**缺** ❌

1. **⚠️ `BlindRotate` 的索引噪声处理**（对应整改 **R3b**）——**最优先的未知项**：
   真实 `LWE.Enc(r_a)` 带噪声，现在的实现会稳定取错行；
2. **列选择 `Σ_c CtPtMul(...)` 的编排**（对应整改 R2）——底层算子现成，**这一步没写**；
3. **二维布局（R×C）与列打包**（`P_{c,b}(X)` 的多项式构造，对应整改 R2/R7）；
4. **Bloom 打分编排**（`CtCtMul` + `Σ CtRotate(·,2^r)`，对应整改 R4）；
5. ⚠️ **BK 体积**：d 轮口径需要 `d` 个 RGSW，`d=512` 时约 **25.6 GB**（对应整改 R6 / 第三节路线 1）；
6. ⏸ **`LWEtoRGSW`**：**仅 CAPE-C 需要，本次不做**（第〇节）。

---

# 十、DECODE

**论文要求**：解密候选值密文与分数密文 → **BFF 重构**（把 k=3 个位置的值**分量相加 mod t**）
→ **指纹校验**（fp = 40 bit）→ **载荷解析**（按 `f=⌈m/N⌉`、`ℓ=⌈max|v|/t⌉` 切出 m 个值）
→ 合取时用**本地保留的阈值 τ**（查询 Bloom 的汉明重量）判定候选，**返回 `s_j = τ` 的候选集合**。

**已有** ✅：明文侧的数据结构与解析逻辑（`cape-fusepir-database-handoff/`，含测试）；
客户端可解密（库解密器 + `decryptSampleViaPack`）。

**缺** ❌：密文侧解码流程的编排（解密 → BFF 重构 → 指纹 → 解析）；阈值判定；四步串起来的端到端联调（整改 R8）。

---

# 十一、参数现状

| 参数 | 值 | 来源 |
|---|---|---|
| `t` | 65537 | ✅ 论文 §5.1 |
| `N` | 16384 | ✅ 论文 §5.1 |
| 系数模数 | 声明 9 素数 / 438 位；**工作层 8 素数 / 389 位**（BFV 留最后一个素数作 `q_last`） | 论文只说"SEAL 默认"；位数我们实测补出 |
| BFF `k` / 指纹 / `ε_BF` | 3 / 40 bit / 2⁻²⁰ | ✅ 论文 §5.1 |
| `ℓ_BF` | = N = 16384 | ⚠️ 由"查询恰为 1 个密文"反推（整改 R7 待核） |
| `R`、`C`、`ℓ_c`、`ℓ_r` | `R ≤ N`、`RC ≥ L_BFF`；`ℓ_c=⌈log₂C⌉`、`ℓ_r=⌈log₂R⌉` | ✅ 约束是论文给的；**具体取值未定** |
| **`d`（LWE 维数）** | **512** | ⚠️ **论文没给**，取自 Pirouette Table 4 |
| `q_L` | `2N`（结构约束：盲旋转要求 q 为 2 的幂且 q=2N） | ✅ 推得 |
| **行选择器索引编码** | **Δ=1 且无噪声**：`b = ⟨a,s⟩ + r`，`r ∈ [0,R)` | ⚠️ **本项目工程决定**（3.7，候选 (b)）；**安全性未论证** |
| `σ²` | 3.192（σ≈1.7866） | ⚠️ Pirouette |
| gadget 底 / 层数 | 现状 2¹⁶ / 25；（Pirouette：`B_rgsw=2²⁴`、`ℓ_rgsw=8`） | ⚠️ 有差距，见整改 R6 |
| 旋转密钥步长集 | `{1,2,4,…,ℓ_BF/2}` = 14 个 | ✅ 由算法推得 |

---

# 十二、所缺东西汇总

> **⚠️ 2026-09-23 重新分类**：原先这张表按"优先级"排，会让人以为**所有条目都是"跑通 CAPE"所需的**。
> **不是。** 下面分成两张表：**A = 小规模跑通必需**；**B = 论文对齐/工程优化，可推迟**。
>
> **判据**：把 CAPE 的四步走一遍，只保留"不做就跑不出结果"的。
> 判据的关键一问是：**这个量在协议里真的被用到吗？**

## A. 小规模跑通 CAPE 的**必需**清单（就这 5 条）

| # | 要做什么 | 现状 | 难度 | 整改 |
|---|---|---|---|---|
| **A1** | **统一 Bloom 生成**：抽出一份**双方共用**的 `BF.Gen`，位位置**只依赖关键词**（**顺带修掉第 11 项那个 value 混入哈希的错误**） | 服务端有一份但是 private 且混了 value；**客户端侧没有** | 低（半天） | 补 1 + 第 11 项 |
| **A2** | **列选择接线**：`BffMatrixLayout.coefficient(column, block, row)` → 拼出明文多项式 `A(X)` → `evaluator.multiplyPlain(ct_col, A(X))` | 两边都各自验过，**但没接起来**（`AnswerPathMini` 里的 `A(X)` 是**手工构造**的） | 低 | R2 |
| **A3** | **QUERY 编排**：`u_a = h_a(K)` → `(c_a, r_a)` → 列 one-hot 的 RLWE 加密 + 行 `LWE.Enc(r_a)`；以及 `b_qry`、`τ = ‖b_qry‖₁`、`q_BF = RLWE.Enc(b_qry)` | **全缺** | 中 | R5 |
| **A4** | **Bloom 打分编排**：`ct_score,j ← CtCtMul(q_BF, ct_j^BF)`，再 `Σ_r CtCtAdd(·, CtRotate(·, 2^r))` 折叠出汉明权重 | 算子齐（`CtCtMul`/`CtRotate` 都实测过），**循环没写** | 低 | R4 |
| **A5** | **DECODE 编排**：解密 → 指纹校验 → 载荷解析 → `s_j == τ` 判定 → 返回候选 / `⊥` | 明文侧的解析/校验**已有**（`PlaintextFusePirQuery` + `PayloadFingerprint`），缺的是接上密文侧 | 中 | R8 |

**A 清单里没有"研究级"任务**——全是编排 + 一次小重构（A1）。这也印证了第〇节的结论：
按 CAPE 的基准，**没有"缺某个原语"的硬障碍**。

## B. **不是**跑通必需的（论文对齐 / 工程优化 / 性能）

| # | 缺什么 | 为什么**不**阻塞跑通 |
|---|---|---|
| B1 | **`LweRlweConversion` 的 `q_R → q_L` 桥**（今天刚做的那套） | ⚠️ **这条要特别说明**：CAPE 的答案路径是 `SampleExtract → 三路相加 → Pack → 客户端解密`——抽出的 LWE 密文**从头到尾没被解密或消费**，只是**中间表示**。所以用 `long[][]`（q_R 残数）形态相加、再 `packFromSample` 打回 RLWE 就够，**这正是 `AnswerPathMini` 已经在跑通的路径**。<br>那套桥的价值是**让 `SampleExtract` 的输出严格等于论文语义**（一条真的 `LWE.Enc_s(m_j)`），属于**论文对齐**，不是跑通必需 |
| B2 | **`q_L = 2N` 的载荷模数问题** | 同上——载荷不需要走小模数 LWE |
| B3 | **补 2 `BF.Check`、补 3 `BFF.Check`、补 4 LWE 相加封装** | `BF.Check` 不在协议路径上；`BFF.Check` 已被 `reconstruct` 覆盖；**LWE 相加的操作已经在两处跑通**（`AnswerPathMini` T1、`LweRlweConversion` T2），只是没封装成 API——封装是**防错**，不是**必需** |
| B4 | **第 10 项 指纹 48 位 vs 论文 40 位** | 客户端与服务端**用的是同一份 `PayloadFingerprint`**，自洽，能正常 `⊥`；只是与论文位数不一致 |
| B5 | **第 6 项 盲旋转的索引噪声** | 按已记录的工程决定 **3.7**，小规模阶段用无噪声索引。**这是明示的偏差**，不是待办缺陷 |
| B6 | 第 12 项 BK 体积（25.6 GB→8.2 GB） | 小规模（N=2048、d=64）下 BK 只有 **8 MB**、盲旋转 416 ms——成本问题只在论文规模出现 |
| B7 | 第 9b 序列化/通信量统计、第 6 项参数收口（`R`/`C`/`ℓ_BF`）、密钥持久化 | 都是"跑通之后要报的数"，不影响跑通 |
| B8 | 补 5 `PRG`/`bin_ℓ`、第 9 项 `LWEtoRGSW` | **仅 C 变体需要** |

## C. 唯一"不做就必错"的一条

**A1 里的第 11 项**：Bloom 位位置混入了 value。不修的话，客户端算出的 `b_qry` 与服务端每个候选的 `b_v` **位位置对不上**，
`s_j` 永远小于 `τ` ⇒ **所有候选被拒**（100% false negative）。

> 所以"必需"清单实际上可以压缩成一句话：
> **先修 Bloom 哈希（A1），再把列选择、QUERY、打分、DECODE 四条线接起来（A2~A5）。**
> 其余全部可以推迟。

> **历史备注（2026-09-19 的旧结论，保留备查）**：
> 当时把"盲旋转索引噪声"列为第 0 项、并说"它是唯一会推翻已有结论的缺口"。
> 现在这条归入 **B5**——它确实是**未知项**，但按 3.7 的工程决定（无噪声索引）
> **不阻塞小规模跑通**；等要交付/对齐论文时再定机制。
>
> **已解决、不必再挂着的两件**：
> - ~~"列选择 `Σ CtPtMul` 的机制能否工作"~~ → `AnswerPathMini` 已实测通过；只需接线（A2）。
> - ~~"`a_i ≡ 0` 场景"~~ → 已修（附录 A 第 9 条）。

---

# 十三、跑起来

```powershell
# 默认路线（纯 Java）—— 各项自检
cd coding\rgsw-lab
.\run-mpc4j.ps1                                                  # RGSW + CMUX 自检（5 项）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.Mpc4jCapability 16384    # 论文规模四项能力
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateOps 2048      # 盲旋转两种口径
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.RgswPolyTest 2048        # 一般多项式 RGSW
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.LweRlweBridge 2048       # SampleExtract / Pack
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateComplete 16384 64   # 完整盲旋转（论文规模）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.SizeProbe                # 量真实密文的素数分量数与序列化字节数
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateStress 2048   # 盲旋转压力测试：轮数扫描 + 索引噪声扫描
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.AnswerPathMini 2048 512  # 最小 ANSWER 链路（列选择→盲旋转→样本提取→三路相加）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.LweRlweConversion 2048 32 # LWE↔RLWE 桥（RLWE→LWE 模数切换 / Pack / 三路相加）

# LWE 层（纯 JDK，无依赖；注意：lwe-java/ 下没有 run.ps1，按 README 手动 javac）
cd coding\lwe-java
# 见 lwe-java/README.md 的 javac 命令

# 对照路线（真 SEAL）
cd coding\native-jni
.\run.ps1 -N 16384
```

> **传参方式**：`-Class` 后面跟的数字会**原样转发**给 Java 程序作为 argv
> （`N`，有的程序还接第二个参数 `d`）。**跑之前先看它打印的 `[params]` 行确认规模生效**——
> 这个转发曾经是坏的（`$args` 没传给 java），导致 `-Class X 16384` **静默按默认规模跑**，
> 现已修复并实测（`LweRlweBridge 4096` → 打印 `N=4096, 3 素数/109 bit`）。

前提：JDK（`D:\Java\jdk` 或 PATH 里的 `javac/java`）。默认路线**不需要任何 C++ 工具链** ✓。

---

# 十四、文档索引

| 文档 | 内容 |
|---|---|
| `默认实现一览.md` | **哪条路线是默认、哪个文件夹放什么**（最容易被搞混的六处） |
| `RLWE路线审计.md` | 三条路线的逐文件判定、补丁带来的转折、论文规模实测结果 |
| `HE_三层调用说明汇总.md` | 三层（LWE / RLWE / RGSW）的关系与 API |
| `rgsw-lab/RGSW_调用说明.md` | RGSW 层的自检与参数；**踩坑记录**（七个坑 + MPC4J 新增的三个） |
| `rgsw-lab/BlindRotate_实测.md` | 盲旋转的论文定义原文、轮数口径修正、论文规模耗时 |
| `rgsw-lab/LWE_RLWE桥_调用说明.md` | **LWE ↔ RLWE 桥的调用说明**：三个约定（LWE-in-RLWE / 模数不匹配 / `q_L=2N` 装不下载荷）、API 速查、完整示例、**符号约定对照**、SEAL Java 移植版的三个坑、实测结果、边界 |
| `rgsw-lab/LWE_RLWE桥_实测.md` | SampleExtract / Pack 的**最早**实测记录与方法论警告（写于桥之前，其"还需与 q_L=2N 做模数切换"一句**已被 `LweRlweConversion` 解决**） |
| `../CAPE_子程序实现对照表.md` | 逐项状态表（**注意：其第 4c/9/14 项正按本 README 第〇、一节整改**） |
| `../CAPE_参数表.md` | 参数总表（论文给的 / 从 Pirouette 继承的 / 我们定的 / 实测的） |
| `../Submission_usenix_232/Submission_usenix_232_精读讲解.md` | 论文精读（算法 1~5 的逐行转写） |
| `SYNC.md` | 推送到远端的步骤与环境问题记录 |

---

# 附录 A、必须提前知道的坑（含本轮新增）

> 这份清单的价值在于：**它们几乎都是"能编译、小参数能跑、到真实规模才炸"的类型**。
> 小规模自检全绿**不代表**协议能跑——本项目的两次结论反复都是这么来的。

### 仍然有效的结论

1. **盲旋转是分水岭**——机构已跨过（含 d=512 稳态），但**索引噪声那一环还没有**（见 3.4）。
2. **JNI 结论不变：不搭。** C++ 侧只有盲旋转内部**一次**特殊乘法，其余全要自己写；且那块参数写死为 124 位。
   现在的分工是：**路线 B 当默认**，native 只作性能对照与交叉校验。
3. **两个模数不同是设计而非 bug**：LWE 的 `q=2N`（旋转群约束）与 RLWE 的多素数大模数，由**模数切换**连接。

### 路线 B（默认路线）的坑

4. **Galois 置换表被预分配成 `int[N][N]`**：`AbstractGaloisTool` 把表整个预分配，实际只用 `2·(log₂N−1)+1 = 27` 行；
   且 `row == null` 的惰性判断因为每行都被零填充而**永不成立**。打补丁后**每层 1.07 GB → 约 1.8 MB**。
   补丁在 `patches/mpc4j-galois-lazy-permutation-tables.patch`。**不打它，N=16384 直接 OOM。**
5. **工作模数比声明的少一个素数**：BFV 把最后一个素数留作 `q_last`，密文里只有 8 个分量。
   **N=2048 时只有 1 个素数、没有特殊素数，所以按 `coeffModulus().length` 索引是"巧合正确"**，到论文规模才崩
   （`Index 262144 out of bounds`）。修法：从真实密文的数组长度反推工作层素数个数。
6. **RGSW 一般多项式：`group1` 放的是与 `group0` 同一个量**，不要显式再乘一次 `s`——
   把同一个量放到第 1 个分量上，相位就自动多带一个 `·s`。
7. **验证方法论的坑（被骗过一次）**：用 `b + ⟨a,s⟩ = c0[j] + (c1⊛s)[j]` 去"验证" SampleExtract 是**同义反复**，
   换元后左右两边是同一个和式；它当时"通过"了，而真正的解密测试失败。
   **正确做法：把结果交给库自己的解密器读**（`AnswerPathMini` 全程用这一条）。
8. **轮数口径差 37 倍**：按索引位 14 轮、按秘密位 512 轮（自举密钥 700 MB vs 25.6 GB）。
   **CAPE 用后者**，CAPE-C 用前者。

### ⚠️ 本轮（2026-09-19 晚）新增的两条

9. **`a_i ≡ 0 (mod 2N)` 会让 CMUX 抛 `"result ciphertext is transparent"`** ——🔧 **已修复**
   - **现象**：N=2048、d=512 时跑最小 ANSWER 链路，中途抛 SEAL 的 `RuntimeException: result ciphertext is transparent`；d=64 时**从不出现**。
   - **原因**：`a_i ≡ 0 (mod 2N)` ⇒ `X^{a_i} = 1` ⇒ `multiplyPowerOfX(cur, a_i)` 返回与 `cur` 内容相同的密文
     ⇒ CMUX 的 `diff = 0` ⇒ `externalProduct` 拿到**全零明文** ⇒ SEAL 拒绝。
   - **为什么必然发生**：`a` 由 PRG 派生、取值在 `[0,2N)`，所以 `a_i = 0` 一定会出现：
     N=2048（q_L=4096）、d=512 时单次查询至少命中一个 0 的概率 ≈ **12%**；N=16384 时 ≈1.5%。
     **d 越小越难撞上**——又一个"小参数巧合能跑"的实例。
   - **修法**：这一轮本来是恒等变换，**直接跳过**（`BlindRotateOps.blindRotate` 里 `if (Math.floorMod(a[i], twoN) == 0) continue;`）。
   - **回归**：`AnswerPathMini` 专项 A3 强制 `a_0 = 0`，修复前必炸、修复后通过。

10. **盲旋转对索引噪声零容忍**（❌ **未修复**，机制未定）
    - `β = ⟨a,s⟩ + r + e` 里 `e=±1` 就把行号**整体推偏一格**，读到相邻记录（实测见 3.4）。
    - 现有所有自检（`BlindRotateOps` / `BlindRotateComplete` / `LweToRgswOps` / `AnswerPathMini`）
      造的索引**都没有误差项**，所以此前一路绿灯。
    - 候选机制 (a)/(b)/(c) 与工作量见 3.4 和整改项 **R3b**。

### 路线 C 时代的历史坑（代码已弃用，教训保留）

11. **`BigInteger.longValue()` 是有符号截断**：模数升到大整数后，残留的 `p.q.longValue()`
    在 15 素数（q=451 位、低字符号为负）时把选择器系数变成负数 → 归约成 p−4 → **外部乘积全错**。
12. **Shoup 常数会 ≥ 2⁶³**：用 `longValueExact()` 抛异常 → NTT 上下文建不起来 → **静默回退到 O(N²)**
    （4.8 ms 变 2011 ms）。**教训：逐位对照的自检比性能优化更值钱。**

---

# 附录 B、测试记录

> **图例**：✅ 全过 ／ 🟡 部分 ／ ❌ 预期失败（已知 ⏸ 项）
> **读表须知**：**每一行的参数必须看**。本项目多次出现"小参数全绿、真实参数才炸"，
> 单看 ✅ 个数会得出错误结论（详见附录 A）。

## B.1 2026-09-19（本轮全量重跑）

运行环境：JDK 25（`D:\Java\jdk`）、`coding\lib` 的 MPC4J SEAL Java 移植版 + Galois 补丁。

| # | 测试类 / 用例 | 参数 | 结果 | 说明 |
|---|---|---|---|---|
| 1 | `Mpc4jRgsw` 自检 | N=2048 | **5/5 ✅** | RLWE 往返、`RGSW(1)⊗c=c`、`RGSW(0)⊗c=0`、CMUX 两分支 |
| 2 | `RgswPolyTest` | N=2048 | **3/3 ✅** | 一般多项式 RGSW：`RGSW(m)⊗ct = m⊛msg`，0/2048 错位 |
| 3 | `LweRlweBridge` | N=2048 | **2/2 ✅** | SampleExtract→Pack→库解密往返；整条链读回 p_index |
| 4 | `BlindRotateOps` | N=2048 + **N=16384** | **4/4 ✅** | A1/A2/A3 两口径互验（N=2048）；B2 论文规模（N=16384，14 轮，19.9 s，index=12345→346） |
| 5 | `BlindRotateComplete` | N=2048, d=64 | **4/4 ✅** | 真实载荷 + 加密索引；自举密钥 8.0 MB、盲旋转 416 ms |
| 6 | `Mpc4jCapability` | N=4096 | **A/B/C/D ✅** | 槽打包往返 0 错位；ct×ct+重线性化 85+25 ms；槽旋转 13 ms；模数切换正确 |
| 7 | `lwe-java` `LWESelfTest` | Pirouette Table 4 | **9/9 ✅** | 含噪声分布（实测 σ=1.808 vs 设定 1.787）与参数扫描 |
| 8 | `lwe-java` `ModSwitchTest` | d=512 | **4/4 ✅** | 二值密钥 200/200；模数切换 q→2N，max noise=15（阈值 128） |
| 9 | `SizeProbe` | N=16384 | 数据采集 | 声明 9 素数/438 bit；**密文实际 8 素数/389 bit**；size-2 密文序列化 = 2,097,249 B |
| 10 | **`BlindRotateStress`** 轮数扫描 | N=2048, d=64→512 | **4/4 ✅** | d=512：盲旋转 1845 ms，整条 2048/2048 一致 → **512 轮噪声累加不塌** |
| 11 | **`BlindRotateStress`** 噪声扫描 | N=2048, d=512 | **⚠️ 发现缺口** | `e=±1` 即整体推移一格 → **零容忍**（3.4 / R3b） |
| 12 | **`AnswerPathMini`** | N=2048, d=64 | **7/7 ✅** | 最小 ANSWER 链路（小值 + 全值域载荷各 3 项 + 专项 A3） |
| 13 | **`AnswerPathMini`** | N=2048, **d=512** | **7/7 ✅** | 同上；**修复 `a_i=0` bug 前此处抛 `transparent`** |
| 14 | **`AnswerPathMini`** | **N=4096, d=512** | **7/7 ✅** | 同上 |
| 15 | `LweToRgswOps` | N=2048, d=64 | ❌ 1P/4F | **已知 ⏸ 项**（仅 CAPE-C 需要）；卡点位提取多项式 |

**本轮从中得到的结论**：

- ✅ **旋转机构 + 列选择累加器 + 512 轮** 都验证了（#10、#12~14）；
- 🔧 **修掉 1 个真 bug**：`a_i ≡ 0 (mod 2N)` → CMUX 抛 `transparent`（#13 暴露，附录 A 第 9 条）；
- ⚠️ **留下 1 个未解决缺口**：索引噪声零容忍（#11，R3b）；
- 📉 **推翻 1 条旧结论**：`LWEtoRGSW` 不在关键路径上（基准是 CAPE 而非 CAPE-C）。

## B.2 复现命令

```powershell
cd coding\rgsw-lab
.\run-mpc4j.ps1                                                  # #1  5/5
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.RgswPolyTest 2048        # #2  3/3
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.LweRlweBridge 2048       # #3  2/2
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateOps 2048      # #4  4/4（内含 N=16384 段，约 1 分钟）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateComplete 2048 64      # #5
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.Mpc4jCapability 4096     # #6
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.SizeProbe                # #9（N=16384 固定）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateStress 2048   # #10 #11
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.AnswerPathMini 2048 512  # #13
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.AnswerPathMini 4096 512  # #14

cd coding\lwe-java                                                # #7 #8（按 lwe-java/README.md 手动 javac）
```

> **注意**：`-Class` 后面的数字会转发给 Java 程序（N、d）。**跑之前看它打印的 `[params]` 行确认规模生效**——
> 这个转发曾经是坏的，导致命令静默按默认规模跑（已修，见附录 A 相关注释）。

## B.3 待补的测试（随整改项推进）

| 对应整改 | 要补的测试 | 验收 |
|---|---|---|
| **R3b** | 用**真带噪**索引跑 `AnswerPathMini`，量出噪声预算（哪一档开始取错行） | 给出噪声幅度上限；或命中率曲线 |
| R2 | `DatabasePreprocessor` 产出 `P_{c,b}(X)` 后接进流水线 | 列选择不再依赖手工构造的 `A(X)` |
| R4 | Bloom 打分循环（`CtCtMul` + `Σ CtRotate`） | 命中 = τ、不命中 < τ |
| R5 | 客户端 QUERY（坐标拆分 + one-hot 加密） | `u_a = c_a·R + r_a`；one-hot 解密正确 |
| R8 | 四步端到端（含指纹校验、⊥ 分支） | 命中返回值集，不命中返回 ⊥ |
