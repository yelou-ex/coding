# LWE → RLWE 打包（Ring Packing）调研

> **目的**：回答"论文的 `Pack` 到底怎么做"——即把**多条**「只加密一个比特」的 LWE 密文
> 打包成**一个** RLWE 密文、**每位落在一个槽位**上，从而能跑 SIMD 二进制同态内积。
> **触发原因**：`PackGoalCheck` 实测现有 `packFromSample` 四条子目标全部未达成（见 `README.md` §5.2 与对照表第 8 项）。
> **调研日期**：2026-09-27　**线索来源**：`OXTPIR.pptx` slide 30「使用 YPIR 的技术（USENIX'24）打包成一个 RLWE 密文」

---

## 〇、结论摘要（先看这个）

1. **这个原语有正式名字**：**Ring Packing**（环打包），也叫 **`RLWE-Pack`** / **LWE-to-RLWE conversion**。
2. **它不是 YPIR 发明的**。奠基工作是 **CDKS21**（Chen–Dai–Kim–Song, *Efficient Homomorphic Conversion Between (Ring) LWE Ciphertexts*, ePrint **2020/015**, CT-RSA 2021）——
   该文摘要明确写着同时覆盖 **"transformation from LWE to RLWE, as well as packing of multiple LWE ciphertexts in a single RLWE encryption"**。
   YPIR 是**使用者**，不是提出者。
3. **它是标准件**，近年的使用者包括：**YPIR**（USENIX Sec'24）、**InsPIRe**（ePrint 2025/1352，提出新算法 **InspiRING**）、
   **HERMES**（ePrint 2023/1244，用 MLWE）、**LOHEN**（USENIX Sec'25 / ePrint 2025/713）。
4. **核心构造需要一把"交换密钥"**：把 **LWE 私钥的各个系数**作为**常数**分别做 **RLWE 加密**（`SwK`），
   再用它把 LWE 相位里的 `⟨a,s⟩` 在**槽位域**上直接抵消掉。
5. ⚠️ **不能靠"系数摆放"绕过**——现有 `packFromSample` 之所以失败，根因是它的相位**不是纯常数**（其它系数上全是满量级污染）。
   Ring packing 的做法是**从一开始就在槽位域构造**，压根不走系数。
6. ⚠️ **本项目实现它的两个真实障碍**（详见 §四）：①**LWE-in-RLWE 会把交换密钥撑到 N 条**；②**BFV 的明文模数 t 限制了 gadget 底**。
7. ✅ **已经按 §二 的构造实现并跑通了**（`RingPack.java`，6/6 项自检全过）：
   多条 LWE 比特 → 一个 RLWE 密文、每位独占一个槽位 → **直接喂给 `BloomScoring` 得到正确的 ⟨b_qry, b_v⟩**。
   §五之二 是实测数据。**A4（Bloom 打分）到此闭合。**
8. ⚠️ **缩放（`q → t`）"能解码"，但把位值淹了** ——
   **⚠️ 2026-09-29 更正：本文件原先在这里写"缩放不是障碍"，是错的。**
   实测噪声只按 `√n` 增长、`n = N = 8192` 时最大偏差 **66**，相对明文半窗 `t/2 = 32768`
   确有 **496 倍**余量 —— **但那个比较只在问"还能不能解码"；Bloom 位值只有 1，而噪声是位值的 66 倍。**
   ⇒ 经 `RingPack` 打包出来的 **Bloom 位不再精确**，`s_j == τ` 的精确判定**不成立**。
   2026-09-29 用 `SampleToPackLink` 在 N=4096 上直接测量（残差最大 **40**，理论 std ≈ √N·0.289 ≈ 15）证实了这一点。
   见 §五之三。

---

## 一、这个原语叫什么、在哪定义

| 名称 | 出处 |
|---|---|
| **Ring Packing / `RLWE-Pack`** | LOHEN（USENIX Sec'25）："**RLWE-Pack**. This operation packs **n LWE ciphertexts in dimension n into an RLWE ciphertext**. This assigns the message **m_i** of …" |
| **LWE-to-RLWE conversion** | YPIR 相关的综述描述："Utilizing an **LWE-to-RLWE conversion algorithm [13]**, YPIR enables to response the RLWE c…" |
| **ring packing**（把 LWE 格式转成 RLWE 格式） | HERMES（ePrint 2023/1244）："converting LWE formats into RLWE format, which is called **ring packing**" |
| **InspiRING** | InsPIRe（ePrint 2025/1352）："a novel **ring packing algorithm, InspiRING, for transforming LWE ciphertexts into RLWE ciphertexts**" |

**奠基文献**：**CDKS21** = Hao Chen, Wei Dai, Miran Kim, Yongsoo Song,
*Efficient Homomorphic Conversion Between (Ring) LWE Ciphertexts*, **ePrint 2020/015**（CT-RSA 2021）。

> ⚠️ 注意作者：是 **Chen–Dai–Kim–Song**。有些二手资料写成 "Chen, Chillotti, Song"，**是错的**。

**参考性能**（PoPETs 2025 引述 CDKS 的测量）：
**把 `N` 条 LWE 密文换成 1 个 RLWE 密文，`N = 2¹²` 时约 7 秒**。

**LOHEN 给出的算法骨架**（USENIX Sec'25，原样摘录）：
```
RLWE-Pack((ct'''_j)_{i·n ≤ j < (i+1)·n});
ct̃ ∈ RLWE_{q',N} ← KS(Combine((ct''''_i)_{0 ≤ i < N/n}), swks_s);
ct_out ∈ RLWE_{Q,N} ← …
```
—— **`RLWE-Pack` → `Combine` → `KS`（密钥切换）** 三步，与下面的构造一致。

---

## 二、构造（重构，待原文核对）

> 本节是我从"要满足什么"反推 + 检索片段拼出来的。**标注为重构**，拿到原文后需逐条核对。
> **未能直接读原文**：本环境的 `web_fetch` 被限制（域名解析到非公网地址），只拿到了检索快照。

### 2.1 为什么"系数摆放"必然失败（已有实测）

`packFromSample(sample, j)` 摆出来的是：

```
c0 = b · X^j
c1 = Σ_k a_k · X^{j−k}
相位 (c0 + c1·s)[m] =  b·[m=j] + Σ_k a_k·s_{m−j+k}
                       └─ 在 m=j 处 = 消息 ✓      └─ 在 m≠j 处 = 【满量级污染】✗
```

多条相加时这些污染互相破坏 —— `PackGoalCheck` 实测：三条单独都对（1/2/3），**相加后变成 61215 / 746 / 7330**。

**根因**：相位**不是纯常数**。而"槽位"是相位的**求值**（NTT），一个"只有一个系数非零"的多项式，
它的求值是**铺满所有槽**的——所以没有任何槽等于消息（实测：槽位视图 4096 个槽里命中 **0** 个）。

### 2.2 正确的思路：**从一开始就在槽位域构造"纯常数"**

目标：对每条 LWE 样本 `(a^(i), b^(i))`，造一个 RLWE 密文，其**相位就是一个纯常数** `Δ·m_i`。
有了它，再乘上公开的「槽位选择子」`E_i`（槽 i 为 1、其余为 0），它就**只落在槽 i** 上 ✓；
把所有 `i` 加起来，就得到"一个密文、每位一个槽" ✓✓

关键是把 `Δ·m_i = b^(i) − ⟨a^(i), s⟩` 的两部分**分别在槽位域凑出来**：

| 部分 | 怎么来 |
|---|---|
| **`b^(i)`** | **公开量** —— 直接用明文多项式即可（平凡的密文） |
| **`⟨a^(i), s⟩ = Σ_j a^(i)_j · s_j`** | `a^(i)_j` **公开**、`s_j` **保密** ⇒ 用 **`SwK_j = RLWE(s_j)`**（把 LWE 私钥系数当**常数**加密），再乘公开标量 `a^(i)_j` 后求和 |

于是：

```
ct_i = 平凡密文( b^(i) )  −  Σ_j  a^(i)_j · SwK_j
       └ 相位 = 常数 b^(i) ┘   └ 相位 = 常数 Σ_j a_j s_j ┘
     ⇒ 相位 = 纯常数 ( b^(i) − ⟨a^(i),s⟩ ) = Δ·m_i + e_i      ✓ 没有污染

packed = Σ_i  ( ct_i  ⊗  明文 E_i )        ← E_i 由 BatchEncoder 造：槽 i = 1，其余 = 0
         ⇒ packed 的槽 i 解码出来就是 m_i   ✓✓✓
```

**"纯常数"是全部关键**：它让"乘槽选择子"这一步**只影响目标槽**，而不像系数摆放那样把污染铺满全环。

### 2.3 与我们所拥有原语的对应

| 构造需要 | 我们有没有 |
|---|---|
| `SwK_j = RLWE(s_j)`（常数消息的 RLWE 加密） | ✅ `Mpc4jRgsw.encrypt(long[])`（相位是系数，常数就是 `s_j` 放在系数 0） |
| 用公开标量乘密文 | ✅ `Mpc4jRgsw.scalarMultiply(Ciphertext, BigInteger)`；小标量也可用 `evaluator.multiplyPlain` |
| `E_i`（槽 i = 1 的明文多项式） | ✅ `BatchEncoder.encode` |
| 密文 × 明文 | ✅ `evaluator.multiplyPlain` |
| 密文相加 | ✅ `evaluator.addInplace` |
| 大规模标量的**分解**（噪声控制） | ⚠️ **`Mpc4jRgsw.decompose` 有（平衡位切段），但它是给 RGSW 用的**，要改成 key-switch 用 |
| Galois 密钥（本次不需要） | — |

**结论：原语齐了，缺的是"把 key switch 写出来"这件工程**。

---

## 三、噪声：为什么必须做 gadget 分解

`a^(i)_j ∈ [0, q)` 是**大数**（我们的 RLWE 工作模数 389 位；即使只算 LWE 层也要几十位）。

- 直接 `scalarMultiply` 一个 ~2^72 的标量 ⇒ 噪声被放大 ~2^72 倍 ⇒ **当场炸掉**
- 标准做法：把 `a^(i)_j` 按底 `B` 拆成若干小数字 `a_j = Σ_k d_k B^k`，
  配套的交换密钥写成 `SwK_{j,k} = RLWE(g_k · s_j)`，逐段相乘后累加

**这正是 CDKS21 全文的主题**（摘要："we present and combine **three ideas to improve the key-switching procedure**"）。

⚠️ **本项目特有的障碍**：BFV 的明文模数是 `t = 65537`，而 `multiplyPlain` 的明文窗口只有 `±t/2 = ±32768`。
所以 **gadget 底 `B ≤ t`**（和我们在 `Mpc4jRgsw.decompose` 里踩过的是同一个约束），
层数 = `⌈log_B(q)⌉`。这一点使我们的 gadget 参数**不能照抄 CDKS 的推荐值**，必须按 BFV 重算。

---

## 四、本项目实现它的两个真实障碍

### 障碍 1：**LWE-in-RLWE 会把交换密钥撑到 N 条**

标准 ring packing 里，LWE 维数 `n` 与环维度 `N` **互相独立**，通常取 `n ≪ N`。
一个交换密钥要 `n · ⌈log_B q⌉` 个 RLWE 密文。

而本项目为了省掉密钥切换，一直假设 **LWE 密钥就是 RLWE 密钥（LWE-in-RLWE，维数 = N）**。
若沿用这个假设，`SwK` 就要 **`N` 条**：

| N | 每条密文 | `SwK` 总量（仅 1 层） |
|---|---|---|
| 4096 | ~131 KB | ~537 MB |
| 16384 | ~1.00 MB | **~16 GB** |

⇒ **要上 ring packing，可能必须放弃"维数 = N"，改成真正的 `sk = (s_L, s_R)` 两把独立密钥**——
而论文的 SETUP 本来就是这么写的（`generate HE keys sk = (s_L, s_R)`）。
**这反过来证明：论文里 `s_L` 与 `s_R` 很可能确实是两把独立密钥，LWE-in-RLWE 是我们的简化。**

### 障碍 2：BFV 的 `t` 限制 gadget 底（见 §三）

层数会被迫变大 ⇒ `SwK` 更大、key switch 更慢。

---

## 五、实施计划

| 步 | 内容 | 状态 | 验收 |
|---|---|---|---|
| **1** | **拿到 CDKS21 原文**（ePrint 2020/015），逐条核对 §二的构造与 gadget 参数 | ⏸ 未做（`web_fetch` 被限制） | 构造与原文一致；把本文件的"重构"标记去掉 |
| **2** | 写 `RingPack`：`SwK` 生成（`skGen`）+ `pack({(a,b)}, slots)` | ✅ **已完成** | **实测 6/6 通过**，见 §五之二 P1/P4 |
| **3** | 接上 `BloomScoring` | ✅ **已完成** | **P2/P3 通过**：⟨q,v⟩ 精确复现，负对照也会跟着变 |
| **4** | 加 gadget 分解（噪声控制） | ✅ **已完成** | 底 `B=256`、3 段；`n` 扫到 512 全部正确 |
| **5** | 定 `n` 与 `s_L`/`s_R` 是否独立 | 🟡 **有数据，待决策** | §五之二 P4 + §四 障碍 1 |

---

## 五之二、实测结果（`RingPack.java`，N = 8192）

> 跑法：`.\run-mpc4j.ps1 -Class com.fusepir.rgsw.RingPack 8192 32`
> 记录日期 2026-09-27。

### 构造（与 §二 一致，只是把 `b` 也用密文乘常数实现）

```
SwK[j][k] = RLWE( B^k · s_j mod t )        常数消息，NTT 域
sum       = Σ_j Σ_k d_{j,k} · SwK[j][k]    消息 = ⟨a,s⟩（纯常数）
sum      -= b                               用「常数明文 × RLWE(1)」实现
sum       = −sum                            消息 = b − ⟨a,s⟩ = m（纯常数）
selected  = sum ⊗ E_i                       只落在槽 slots[i]
packed    = Σ_i selected
```

### 结果

| 项 | 内容 | 结果 |
|---|---|---|
| **P1** | 16 条 LWE 比特 → 1 个 RLWE 密文 | ✅ 槽位错 **0**，未写入的槽里非零 **0** |
| **P2** | 打包产物**直接**喂 `BloomScoring` | ✅ ⟨q,v⟩ = 5，算出 **5** |
| **P3** | 负对照：查询平移一格 | ✅ 期望 4、算出 **4**（≠ 5，排除常数巧合） |
| **P4** | LWE 维数扫 `n = 8 / 32 / 128 / 512` | ✅ 全部正确；密钥 **1536 条**时打包 **32 s** |
| **P5a** | 缩放后样本经同态路径 | ✅ **精确搬运**：打包结果 = 整数侧算出的残差，**0 误差** |
| **P5b** | 缩放噪声随 `n` 的增长 | ✅ `n=8192` 最大偏差 **66** vs 半窗 32768（**496 倍**余量） |

P5b 明细（明文侧，256 次试验取最大）：

| `n` | 32 | 512 | 2048 | 8192 |
|---|---|---|---|---|
| 最大偏差 | 3 | 16 | 31 | **66** |
| 余量倍数 | 10922 | 2048 | 1057 | **496** |

### 噪声与参数边界（实测）

- **`N = 4096` 不够**：P1（打包）过，但 P2/P3/P4（打分那一侧还要多一次密文×密文 + 重线性化 + 折叠）全崩。
  **`N = 8192` 起步**（4 个工作素数 / 174 bit）。原因就是 §三 说的 gadget 放大。
- **缩放不是瓶颈**：`round(b·t/q) − Σ round(a_j·t/q)·s_j` 的偏差 ~ `√n·0.3`，
  到真实协议量级 `n = N = 8192` 也只有 66，`t = 65537` 给的空间绰绰有余。

### 三条 SEAL 形态约束（踩坑，已记入 `README.md` 附录 A）

这三条都不是"设计选择"，是这套 Java 移植的硬检查，**不满足就抛异常或静默算错**：

| 算子 | 要求 | 后果 |
|---|---|---|
| `multiplyPlain`（槽位逐点乘） | 密文与明文**同为 NTT 域** | 不然抛 `NTT form mismatch`；更危险的是**若形态"碰巧一致"就会退化成多项式乘**，结果全错 |
| `BatchEncoder.encode` | **产出系数形态明文**（C++ SEAL 是 NTT 形态！） | 必须补一次 `transformToNttInplace(pt, parmsId)` |
| `addPlain` / `bfv_multiply` | 分别要求**非 NTT** / **非 NTT** | `addPlain` 在 BFV 下用不了（`setParmsId` 会把明文标成 NTT）；密文×密文前要把打包产物转回系数域 |

`addPlain` 的绕法：加常数 `c` 用 **`multiplyPlain(RLWE(1), 常数明文 c)`**——
纯 `multiplyPlain`，没有形态约束，结果仍是"纯常数"，且不引入额外复杂度。

---

## 五之三、2026-09-29 新增：**缩放这一步才是真障碍**（`SampleToPackLink`）

### 背景

把 ANSWER 后半段做成全程密文时，`ct_{a,b}` 来自 `SampleExtract_0`，它在 **q_R** 上；
而 `RingPack` 要求在 **Z_t** 上。中间的 `x → round(x·t/q_R)` 就是本节的主角。

### 连接点验证（N=4096）

直接加密一个已知明文多项式 → `sampleExtract_j` → 按【`a` 取负 + 缩放】处理 →
在整数上算 `b − ⟨a,s⟩ mod t`：

| j | 真值 P[j] | b 缩放后 | 算出 | **残差** |
|---|---|---|---|---|
| 0 | 11 | 48061 | 65533 | **−15** |
| 1 | 1248 | 35700 | 1258 | **+10** |
| 7 | 8670 | 54692 | 8666 | **−4** |
| 100 | 58174 | 33636 | 58161 | **−13** |
| 2048 | 42981 | 8391 | 42953 | **−28** |
| 4095 | 19177 | 926 | 19183 | **+6** |

**残差不是随机的**，而是 `Σ_j δ_j·s_j`（`δ_j = round(a_j·t/q) − a_j·t/q ∈ [−1/2, 1/2]`），
理论 std ≈ `√(N·2/3)·0.289 ≈ 15.1`（N=4096、三元秘密），实测 `|残差|` 最大 **28** —— 与理论一致。

> ⚠️ **本表第一版是错的**：当时 `scaleToT` 用了 `BigInteger.divide`（**向零截断**），
> 对负数侧向上取整，而这里恰好要算 `−a` ⇒ 残差被系统性偏置，量出来"最大 40 / 一次跑到 109"。
> 改成真正的 floor 后就是上表。**教训见 `coding/README.md` 附录 A 第 16 条**。

### 两个结论要分开说

| 判据 | 结果 |
|---|---|
| **符号与结构** | ✅ **正确** —— 残差是缩放噪声，不是约定错（若符号错，残差会是满量级、看起来像随机数） |
| **可解码性** | ✅ 成立 —— 残差 ≈30 ≪ `t/2 = 32768`（余量约 1000 倍） |
| **位精确性** | ❌ **不成立** —— 噪声（`std ≈ 15`）是 Bloom 位值 **1** 的 **十几~几十倍** |

### 后果与正确做法

- 经 `RingPack` 打包出来的槽位值是 `m ± 40`，**不是精确的 0/1**；
  Bloom 内积会变成 `τ ± 40τ` ⇒ **`s_j == τ` 的精确判定不成立**。
- **本文件 §〇 第 8 条原先"缩放不是障碍"的结论据此作废**（`RingPack` 的 P5b 只比了明文半窗，
  没比位值）。
- **正确做法**：让 ring packing **直接在原生模数上做** —— 按 `q_LWE` 设计 gadget 与
  **缩放后的交换密钥**（`SwK = RLWE(Δ·s_j)` / 或在 `Z_{q_LWE}` 上分 gadget），
  而不是「先缩放到 t 再打包」。这正是 CDKS21 把"改进 key-switching"列为主题的原因。
- 因此 `CapeEndToEnd4` 里候选 Bloom 密文那一步**暂时保留"解密后重新加密"并显式标注**，
  而不是假称已同态。

---

## 六、对 CAPE 的影响

1. **`Pack` 的实现路径已经明确**（不再是"不知道怎么办"）：ring packing + 交换密钥 + gadget 分解。
2. **而且已经跑通了**（§五之二）：`RingPack.java` 6/6 通过，A4 的判据（打包产物直接进 `BloomScoring`）成立。
3. **但它不是"改几行"**：需要新的一类评估材料（`SwK`），且 `SwK` 的体积可能很大（见障碍 1）。
   实测 `n = 512` 时 `SwK` 有 1536 条、打包要 32 s；若 `n = N = 8192`，规模还要再涨 16 倍。
4. **可能必须放弃 LWE-in-RLWE**：这是本调研**最重要的副产品**——它同时解释了为什么论文写 `sk = (s_L, s_R)`、
   以及为什么 §2.5 说 `SampleExtract` "**必要时**包含到后续计算所用 LWE 密钥的**密钥切换**"。
5. 对照表**第 8 项**（`Pack`）与第 14 项（Bloom 得分）已据此改为 ✅，但**注明了"原型验证"而非"协议级实现"**：
   本原型的 LWE 模数取 `t`、样本是合成的；真实协议里还有 `SampleExtract → 缩放 → Pack` 这条链路，
   其中**缩放已单独验证（P5）**，剩下的是**把 `n` 从 512 提到 N 的工程量**，不是未知。

---

## 七、检索来源（本次可用的全部）

> ⚠️ 本环境 `web_fetch` 被限制（`URL hostname resolves to a non-public IP address`），
> 因此**未能直接读原文**，以下为检索快照中可引用的条目。**引用细节请以原文为准。**

| 文献 | 链接 | 用途 |
|---|---|---|
| CDKS21（奠基） | [ePrint 2020/015](https://eprint.iacr.org/2020/015) | LWE↔RLWE 转换 + **多条 LWE 打包进一个 RLWE** |
| YPIR | [USENIX Sec'24](https://www.usenix.org/conference/usenixsecurity24/presentation/menon) ・ [PDF](https://www.cs.utexas.edu/~dwu4/papers/YPIR.pdf) ・ [代码](https://github.com/menonsamir/ypir) | 讲稿点名的出处 |
| LOHEN | [ePrint 2025/713](https://eprint.iacr.org/2025/713.pdf) | **`RLWE-Pack` 的算法骨架**（`Pack → Combine → KS`） |
| InsPIRe / InspiRING | [ePrint 2025/1352](https://eprint.iacr.org/2025/1352) | 新一代 ring packing 算法 |
| HERMES | [ePrint 2023/1244 讨论](https://askcryp.to/t/resource-topic-2023-1244-hermes-efficient-ring-packing-using-mlwe-ciphertexts-and-application-to-transciphering/20474) | 用 MLWE 做 ring packing |
| PoPETs 2025 | [PDF](https://petsymposium.org/popets/2025/popets-2025-0047.pdf) | 性能参考：`N=2¹²` 约 **7 s** |
| Sample Extraction（RLWE→LWE，反方向） | [jeremykun.com](https://www.jeremykun.com/2023/02/27/sample-extraction-from-rlwe-to-lwe) | 反方向的原理 |

---

## 八、与其他文档的关系

| 文档 | 关系 |
|---|---|
| `../README.md` §5.2 | 列了"候选 Bloom 怎么进槽位"这个缺口，本文档是它的**后续调研** |
| `../README.md` 附录 A | 坑清单；本文档 §三 的 gadget 约束与附录 A 第 5 条同源 |
| `../../CAPE_子程序实现对照表.md` 第 8、14 项 | 状态随本调研的 §五 推进而变 |
| `LWE_RLWE桥_调用说明.md` | 讲的是**另一个方向**（RLWE→LWE 抽系数 + 模数切换），与本文档不是一回事，**别混** |
