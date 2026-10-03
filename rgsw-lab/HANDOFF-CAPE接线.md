# 交接：把 FusePIR 四步接进 CAPE（Algorithm 2）（2026-10-15 第四轮）

> ## 📌 开工读序（别跳）
> 1. `src/main/java/com/fusepir/MAP.md` 的 **§27（四步入口）→ §29（种子同源）→ §30（四步跑通）**；
> 2. **本文件**（CAPE 接线要用的接口面 + 三个模数的账）；
> 3. 才去看源码。
> 旧交接单 `HANDOFF-FusePIR四步.md` 保留：它里面有"那三条把 bug 钉错方向的硬结果"的完整教训。
>
> 长期规矩（用户 2026-10-15 立）：**上下文一开始压缩就立刻写交接单 + 提示词**，
> 交接单写进工作区文件（聊天会被压掉），要点同步进 `MAP.md`。

---

## 0. 一句话现状

**✅ A2 接线已跑通（2026-10-15 第五轮）**：A2 里那 4 处调用全部接上并实测，
`cape/CapeA2Wire.java` 是 A2 侧唯一的调用方，`probe/CapeA2WireTest.java` **exit 0**。
技术账见 **MAP §32**（本轮新增）。

```powershell
# 判据（随时回归）
.\run-mpc4j.ps1 -Class com.fusepir.probe.CapeA2WireTest 16 4096 16 18         # → exit 0（A2 接线）
.\run-mpc4j.ps1 -Class com.fusepir.probe.ScoreMulDomainTest 4096              # → exit 0（含缺陷断言）
.\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirFourStepTest 16 4096 16 18    # → exit 0（A1 四步）
.\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirAnswerBisectTest 16 4096 16 18 # → ⚠️ 见 §0.2：Q1.3b 不过
```

四个入口都在 `fusepir/FusePirFourStep.java`：`setup` / `query` / `answer` / `decode`。
**四个签名一行未改**（MAP §27.1）：本轮所有新增都是**加法式重载**。

### 0.1 这一轮真正新学到的东西（三件，都是实测）

1. **"打分直接吃 `resp_anc`" 不是免费的**：`bfvDefault(4096)` 下 `RingPack` 产物的噪声预算
   只有 **2 bit**，一次 `CtCtMul` 要 **~26 bit** ⇒ 得分解出来是均匀随机值。
   放宽系数模数到 `3×60`（`SecLevelType.NONE`）后 Pack 产物 **50 bit**、`q^BF × Pack`
   **逐槽完全正确**。⇒ A2 那条路必须传 `coeffBits`。
2. **判定规则要改**：`K > ones` 只够读**单个**字段；打分把桥的残差在 **τ 个字段上累加**
   （上界 `τ·ones/2`）⇒ 要 **`K > τ·ones`**（本组 `K=128`），判定 = `round(s_j/K) == τ`，
   **不是** `s_j == K·τ`（实测 K=17 时命中候选得 172、`K·τ = 170`）。
3. **§30.2 的归因被推翻**：掩码那堵墙也是**噪声预算**（同一实验：`bfvDefault` 下 0/4096；
   `q=3×60` 下 4096/4096、余 25 bit）。另外：`tRing ≠ K·T`（`tRing = 18T−17`，`K = ⌊tRing/T⌋`）。

### 0.2 ✅ `FusePirAnswerBisectTest` 的 Q1.3b 已修（一条**非确定性**断言）

它原来同时要求"与错 100 格的差 > #ones"（认残差）和"逐位精确等于 `p[5]`"（不认残差）
—— 自相矛盾，残差非 0 就红。而残差**每次运行都不同**（`m.encrypt` 每次重新随机化 `a`）：
三次运行 r=5 分别读回 6 / 5 / 8。修法：后半改成 `|got − p[5]| ≤ ones`，
"与错 100 格的差 ≫ ones"原样保留。**现在四个探针全 exit 0**。详见 MAP §32.6。


---

## 1. 环境与命令（照抄，别踩）

```powershell
cd E:\学习\密码赛\coding\rgsw-lab
.\run-mpc4j.ps1 -Class <全限定类名> [args...]
```

* JDK：`D:\Java\jdk`（脚本自己找 `javac`）。
* **⚠️ `run-mpc4j.ps1` 每次启动都 `Remove-Item mpc4j-out`** ⇒ 同一时刻只能跑一个。
* **⚠️ javac 的错误信息在本机是 GBK**，经 PowerShell 回来是乱码：
  **先看它报的行号，再用 `read` 读那一行** —— 比去解码错误文本快得多。
* **禁止**对 UTF-8 源码用 `Get-Content -Raw` / `Set-Content`（历史 mojibake 事故）。
* `Start-Process` 被沙箱拒绝；`Remove-Item` 可以用。子代理要用 `mpc4j-out-xx` 这类独立目录。
* 仓库根是 **`E:\学习\密码赛\coding`**（`.git` 在那里）。⚠️ 但**本轮大量探针文件未被 git 跟踪**，
  所以 `git` 不是安全网（见 §6 的事故）。
* 修改源码**优先用 `edit`（按唯一片段替换）**，不要"读整份→拼列表→整份写回"。

---

## 2. CAPE 要调 FusePIR 的 4 处（逐字来自 A2 原文，MAP §27.1）

```
A2 SETUP  11: (pp_F, st^F_S, sk) ← FusePIR.Setup(1^λ, DB^CAPE)      → FusePirFourStep.setup(...)
A2 QUERY   1: (q_anc, st^anc_C) ← FusePIR.Query(pp_F, sk, K_1)       → fp.query(K_1, seed)
A2 ANSWER  2: resp_anc ← FusePIR.Answer(st_S, q_anc)                 → fp.answer(q)
A2 ANSWER  3: Parse {(ct_{v_j}, ct^BF_j)}_{j=1}^m from resp_anc     → resp.valueCt(j) / resp.bloomCt(j)
A2 DECODE  2: V_{K_1} ← FusePIR.Decode(sk, st^anc_C, resp_anc)       → fp.decode(q.stC(), resp)
```

另外两处**已经存在**、不要重造：`pp_C ← pp_F.extendBloom(…)`（A2 SETUP 12）、
`st^F_S` 直接当 `st_S`（A2 SETUP 13）。

### 2.1 现在可用的公开面（**实测签名**，照这个调）

`FusePirFourStep`（实例）：

| 成员 | 说明 |
|---|---|
| `setup(Db db, int ringDim, int d, int lBf, long rhoH, long seed0)` | A2 SETUP 11。`Db.synthetic(nkw, mCount, withBloom, lBf, seed)` 可造演示库 |
| `query(String anchor, long seed)` → `Query` | `q.qCol()` / `q.qRow()` / `q.colIdx()` / `q.rowIdx()` / `q.stC()` |
| `answer(Query q)` → `Resp` | A2 ANSWER 2 |
| `decode(FusePirClientState stC, Resp resp)` → `long[]` 或 `null`(⊥) | A2 DECODE 2 |
| `pp()` / `stS()` / `ring()` / `bPay()` / `lBf()` / `mCount()` / `db()` | 状态与参数 |
| **`ringModulus()`** | **应答通道明文模数 `tRing`（见 §3，接线必须用它，不是 `T`）** |
| **`scale()`** | **精度倍率 K**：槽里存的是 `K·field` |
| `T`（静态常量） | **字段域**模数 = `FusePirParams.NATIVE_PLAINTEXT_MODULUS` = 65537 |
| `payloadTruth()` / `bffArray()` / `positions()` | 诊断用（**里面是 `K·field`**） |
| `answerSamples(q)` / `answerRnsSamples(q)` | 诊断用（Z_t / RNS 级样本） |
| `rotateRowsByComposedBits(m, src, slot, gk)`（静态） | §4.2 的"2 的幂组合"行内旋转 |
| `requirePositionsMatch(pp, keywords, pos)`（静态） | 建表↔pp 同源守卫（建库时会自动调） |
| `ringModulusFor(n, ones, base, digits)`（静态） | 选 `tRing`（素数搜索） |

`Resp`（`fp.answer(q)` 的产物）：

| 成员 | 说明 |
|---|---|
| `valueCt(int j)` | 把第 j 个候选的**值**转到槽 0（系数形态密文） |
| `bloomCt(int j)` | 把第 j 个候选的 **Bloom 段**转到槽 `[0,ℓ_BF)`。**⚠️ 不再掩码**（§6-②） |
| `valueSlot(j)` / `bloomSlotBase(j)` | 槽号（本组参数：值槽 `4/23/42`，段起点 `5/24/43`） |
| `packed()` → `Packed`；`packedSlots()` / `packedCoeff()` | 整条打包密文 / 槽值 / 系数形态 |
| `decodeSlots(ct)` | **槽值**（未除 K —— 接 CAPE 打分要用这个） |
| `decodeFields(ct)` | **字段域**（已除 K —— 判"载荷对不对"要用这个） |
| `galoisKeys()` | 与 `valueCt`/`bloomCt` **同一把**旋转密钥 |
| `scale()` / `mCount()` / `lBf()` | 精度倍率 / m / ℓ_BF |

打包件本身：`FusePirPackSlot.Packed` 有 `ct()`、`highestSlot()`、`bPay()`、`fpSlots()`、`segBase()`…

---

## 3. ⚠️⚠️ 三个模数的账（**本轮最大的新事实，接线第一件要记住的事**）

> 📌 **2026-10-15 第五轮更新**：本节原文写着 "`tRing = K·T`"，**那是简化说法**：
> `tRing` 是"最小的 `≡1 (mod 2N)` 且落在搜索下界之上的素数"，`K := ⌊tRing/T⌋`。
> 本组 `tRing = 1179649 = 18T − 17`，而 `17T = 1114129`（差 65520）。
> 存的是 `K·field`、除的也是 `K`，所以**算术不受影响**，但引用时别写成等式。

| 模数 | 值（本组参数） | 谁用它 |
|---|---|---|
| **字段域 `T`** | **65537** | 论文的 `t`：`fpDigits` 的 limb 宽度、`perValue`、`B_pay=61`、段起点 `[5,24,43]`、`parsePayload`、指纹比对 |
| **应答通道 `tRing`** | **`K·T`**（实测 `K=17` ⇒ 1179649） | **FusePIR 的环上下文**、`D`/`P_{c,b}`、`q^col`、盲旋转、`Pack`、**应答密文**、**CAPE 的打分** |
| native 载荷通道 | `2^32` | `CapeDemoService` / native 那条路，**本轮不动、也别混** |

**为什么会有两个**：`q_R→Z_t` 桥逐分量舍入的残差 `|E| ≤ ones/2` **与明文模数无关**，
所以换大 `t` 救不了；唯一解法是**字段乘 K 倍精度存放**，客户端解码时除以 K 一次舍入。
`K > ones`（`ones` = `s_L` 汉明重量）是硬要求。详见 MAP §30.1。

**⇒ 接线时的三条硬约束**（第五轮补了第 ④⑤ 两条，**它们是"能不能跑通"的那两条**）：

0. **打分那一步要两个参数旋钮**（实测，MAP §32.1/§32.2）：
   ① **系数模数 `3×60`**（`SecLevelType.NONE`）：`bfvDefault(4096)` 的 Pack 产物只有 **2 bit**
   噪声预算，一次 `CtCtMul` 要 **~26 bit** ⇒ 得分是随机值；`3×60` 下 Pack 产物 **50 bit**、
   `q^BF × Pack` **逐槽完全正确**。② **`K = 128 > τ·ones`**：`K > ones` 只够读**单个**字段，
   打分把残差在 **τ 个字段上累加**（上界 `τ·ones/2`）⇒ 要 `K > τ·ones`。
   ⇒ A2 那条路必须调 `setup(..., coeffBits, minScaleK)`（8 参重载，原 6 参签名没动）。

1. **CAPE 的打分必须整体搬到 `tRing`**：`BloomScoring.bloomScoreReaching(m, gk, q, cand, highest)`、
   `BatchEncoder`、`galoisKeysFor(m)` 都要用 **`fp.ring()`**（`tRing`），
   而**不是** 65537、也不是 `CapeBloomScore.DEFAULT_T = 2^32`。
   混用的症状要么是 `NTT form mismatch` / `plainModulus` 校验抛，要么**静默算错分**。
2. **槽里的数是 `K·field`**：bloom 位是 `0 / K`，不是 `0/1`。
   ⇒ 同态内积 `⟨B_qry, b_v⟩` 得到的是 **K × (匹配位数) + 桥的残差**（`|Σ E| ≤ τ·ones/2`），
   所以①**判定阈值要乘 K**，②**判定规则是 `round(s_j/K) == τ`，不是等号**
   （实测 K=17 时命中候选得 172 而 `K·τ = 170`）。**别把 `0/K` 当成 `0/1` 直接比**。
3. **`bloomCt(j)` 现在不掩码**：它只把段转到槽 `[0,ℓ_BF)`，**段外仍有载荷杂质**。
   这是刻意的（§6-②）：**"段外置零"由 CAPE 的 `q^BF` 承担** —— 客户端的 BF 查询向量
   在段外本来就是 0，`CtCtMul` 的积在段外也是 0，折叠因此不带杂质。
   ⇒ **接线时必须保证 `q^BF` 的段外确实为 0**（这正是本轮改动的代价）。

---

## 4. 折叠轮数：**不要用论文形状的 5 轮**（MAP §19.3）

`BloomScoring.foldSlots` 的前提是"支撑落在 `[0, ℓ_BF)`"，而 **`Pack` 的产物天然违反它**
（Bloom 位散布在 `[0, B_pay)`）。`B_pay = 61` ⇒ 最高参与槽 60 ⇒ **要 6 轮**（够到 `[0,64)`），
论文形状的 5 轮只够到 `[0,32)` ⇒ **静默漏算、分值偏小 ⇒ 本该接受的候选被拒**。

**⇒ 打分一律走 `BloomScoring.bloomScoreReaching(m, gk, q, cand, highestSlotInclusive)`**
（`FusePirPackSlot.scoreWithLayout` 已经把它绑成"唯一走法"）；
`CapeBloomScore` 那条 5 轮的路径只对**它自己造的 BF 向量**是对的 ——
**产物是 `Pack` 的那一刻就必须换。**

---

## 5. 已经实测的结论（**别重查，别重做**）

| # | 结论 | 判据/出处 |
|---|---|---|
| 1 | ANSWER 5/6/11 的算术**完全正确** | P4.0a 算术层 **61/61**（无容差）、P4.0c 落点搜索**唯一**组合 = 每路 `+P[r_a]` |
| 2 | "0/61"的根因是**位置函数种子不同源**（`BffEncode` 用 seed0 / `pp` 用 rhoH），**已修 + 有守卫** | MAP §29；`requirePositionsMatch` 建库时自动抛 |
| 3 | 桥的残差**与明文模数无关**，必须靠 K 倍精度 | MAP §30.1 |
| 4 | **槽掩码乘打包件不可用**（0/4096）：不是噪声，是**稠密明文的系数域乘积越界**；`×常数明文` 却完好 | `P5.0g` 缺陷断言 + `P5.0f` 正对照 |
| 5 | §4.2 的"2 的幂组合"旋转**精确**：往返 4096/4096；值槽 `4/23/42` 对齐 3/3 | `P5.0a/0d/0e` |
| 6 | `SampleExtract` **维数盲**，必须显式截到 `d` | MAP §26 / `toTruncatedZLwe` |
| 7 | `t=2^32` 上**不存在**槽位选择子（数学上不可能）；`t=65537` 可批处理 | MAP §18.2 |
| 8 | `CapeDemoService` 默认走的是**旧几何** `buildTables`，而 `bffPositions` 那条论文几何在 `buildTablesPaper` 里 —— 是"**未接线**"不是"没实现" | MAP §20 Tier C |

---

## 6. 已知陷阱（踩过的，按疼痛度排）

**① 两个模数混淆（本轮踩了三次，每次症状都不一样）**

| 坑 | 症状 |
|---|---|
| 建表 `BffEncode.encode(..., payload, T, ...)`：**表 D 的算术模数**也是 `tRing` | 大字段被取模毁掉，相位全错但每一步单独看都对（P2 掉到 0/16） |
| 判据的参考系：`bffArray()` 里是 `K·field`，不能与"除过 K"的相位比 | 显示 0/61，其实只差一个 K 倍 |
| `divideScale` **不能整体按中心代表折叠** | `K·field` 可超 `tRing/2` ⇒ 大的正字段被当负数。**只有大指纹 limb 错、小字段全对**、偏差是常数 |

**② `Resp.bloomCt` 的掩码**：见 §3-3。上一轮我把它归因成"噪声预算"，**那个归因是错的**
（更正写在 MAP §30.2）。**任何对打包密文做"稠密明文掩码"的想法都会撞同一堵墙。**

**③ 一次自伤事故（流程，不是代码）**：本轮用 PowerShell 整文件回写时脚本写错，
把 `probe/FusePirFourStepTest.java` 从 730 行截断成 248 行；该文件**未被 git 跟踪** ⇒ 只能按记录重建。
⇒ **整文件回写前先备份；改源码优先 `edit`。**

**④ 老陷阱（保留）**：`Plaintext.isNttForm()` 在本移植里**默认 true**，不能当"我准备的是系数形态"的判据；
`multiplyPlain` 要求两侧同形态；`NttTables` 第一参是 `log2(N)`；
手工 `SecretKey` 要覆盖**全部声明素数**且 `parmsId` 用 `m.sk.parmsId()`；
`prim` 不能依赖 `fusepir`（分层图 `prim ← bloom ← bff ← fusepir ← cape`）。

---

## 7. 纪律

* **每个断言配正/负对照**；**先跑再下结论**；**不许把"跑通"说成"端点正确"**。
* 报错时给**行号 + 原始输出**（javac 的乱码先看行号）。
* **不要动 `CapeDemoService` / native 路径**（本轮一行未改，保持这样）。
* `run-mpc4j.ps1` 每次清空 `mpc4j-out` ⇒ 不要并发跑。
* 想把"刻意期望错的缺陷断言"留下来（本项目已有先例，MAP §19.3）：照 `P5.0g` 那样写，
  并说明**它为什么必须错**、以及修好之后它会变红。

---

## 8. 建议的接线顺序（每步都能单独判）

1. **A2 SETUP 11/12/13**：`FusePirFourStep.setup` 造 `(pp_F, st^F_S)`；`pp_C = pp_F.extendBloom(...)`；
   `st_S = st^F_S`。判据：`pp_C` 的 Bloom 段与 `pp_F` 的字段布局一致。
2. **A2 QUERY 1**：`fp.query(K_1, seed)` → `q_anc`。判据：`q.colIdx()/rowIdx()` 与 `h_a(K_1)` 一致（探针 P3 已有）。
3. **A2 ANSWER 2 + 3**：`fp.answer(q_anc)`；`resp.valueCt(j)` / `resp.bloomCt(j)`。
   判据：先用 `decodeFields` 对**字段域真值**（探针 P5.1/P5.2 同款），再进 CAPE 打分。
4. **打分（真正的接线点）**：把 CAPE 的打分整体搬到 **`fp.ring()`（tRing）**，
   用 `bloomScoreReaching(…, packed.highestSlot())`，**阈值乘 K**。
   **先做一条只含"命中/不命中"两个候选的正负对照**，再上真数据。
5. **A2 DECODE 2**：`fp.decode(q.stC(), resp)`。判据：值集合正确 + **负对照**（换关键词 ⇒ ⊥）。
6. **端到端**：CAPE 的 `V_{K_1}` 与明文侧真值比；负对照必留。

**每一步跑完都回归那两个探针**（它们是这条链的地基）。

---

## 9. 可复制的开新对话提示词

```
继续 E:\学习\密码赛 里的工作。**A2 接线已经跑通（MAP §32）**，本轮不要再做一遍接线，
去处理 MAP §32.5 那张"未闭合项"表（或用户指定的下一件事）。先说结论再动手，不要重新发散。

【背景】工作目录 coding\rgsw-lab；仓库根在 coding\（.git 在那里，但很多探针未入库 ⇒ git 不是安全网）。
技术账在 src\main\java\com\fusepir\MAP.md —— 按顺序读 §27（四步入口）→ §29（种子同源）→ §30（四步跑通）→ **§32（A2 接线，本轮）**；
交接单在 coding\rgsw-lab\HANDOFF-CAPE接线.md（用它，别从源码重新推导）。

【现状：四个探针全 exit 0】
  .\run-mpc4j.ps1 -Class com.fusepir.probe.CapeA2WireTest 16 4096 16 18          # A2 接线（P1–P6）
  .\run-mpc4j.ps1 -Class com.fusepir.probe.ScoreMulDomainTest 4096               # 隔离实验（含缺陷断言）
  .\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirFourStepTest 16 4096 16 18     # A1 四步
  .\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirAnswerBisectTest 16 4096 16 18 # 二分辨识
A2 侧唯一的调用方是 cape/CapeA2Wire.java；四步入口在 fusepir/FusePirFourStep.java（签名一行未改）。

【已经接好的（别重做）】
  A2 SETUP 11 → FusePirFourStep.setup（8 参重载，见下）；SETUP 12 → pp_F.extendBloom（原有）；
  SETUP 13 → st^F_S 直传；QUERY 1-3 → query（含 b_qry 段外为 0 + τ + 守卫）；
  ANSWER 2 → answer；ANSWER 3 → resp.valueCt(j)/bloomCt(j)；ANSWER 4-6 → 打分；DECODE 2 → decode。

【接线绕不过去的两条（本轮实测，MAP §32.1/§32.2）】
  ① 打分的候选是 Pack 产物 ⇒ 噪声预算不够：bfvDefault(4096) 下 Pack 只有 **2 bit**、一次
     CtCtMul 要 **~26 bit** ⇒ 得分是随机值。必须传 coeffBits = {60,60,60}（SecLevelType.NONE，
     **玩具参数、不是 128-bit**）⇒ Pack 50 bit、q^BF × Pack 逐槽正确。
  ② K > ones 只够读**单个**字段；打分要在 **τ 个字段**上累加桥残差（上界 τ·ones/2）
     ⇒ 要 **K > τ·ones**（本组 τ=10、ones=11 ⇒ K=128）；判定 = round(s_j/K) == τ（**不是等号**）。
     query() 里有守卫：τ·ones ≥ K 直接抛。

【三个模数，别混（§3 已更正一处）】
  字段域 T = 65537：limb 宽度、perValue、B_pay=61、段起点 [5,24,43]、parsePayload、指纹比对。
  应答通道 tRing = 8404993（**A2 这条路**；K = ⌊tRing/T⌋ = 128）：环上下文 / D·P_{c,b} / q^col /
    盲旋转 / Pack / 应答密文 / **CAPE 的打分**。⚠️ 纯 A1 那条路仍是 tRing=1179649、K=17。
    ⚠️ "tRing = K·T" 是**简化说法**：tRing 是"最小的 ≡1 (mod 2N) 且落在搜索下界之上的素数"。
  native 载荷通道 2^32：CapeDemoService 那条，**不要动、也不要混**。
  ③ Resp.bloomCt(j) **不掩码**（只旋转），段外置零由 CAPE 的 q^BF 承担 ⇒ 必须保证 q^BF 段外为 0
    （本轮实测破约的代价：6 轮得分 = τ + v₃，而 5 轮会把杂质静默丢掉）。

【已经被实测否掉的（别重查，别重做）】
  · "0/61 是盲旋转错" —— 错。根因是建表位置函数与 pp 的 ρ_H 不同源（已修 + 有守卫 requirePositionsMatch）；
  · **"掩码乘打包件失败与噪声无关、是系数域乘积越界" —— 本轮推翻**：那堵墙就是**噪声预算**
    （bfvDefault 下 0/4096、掩码后 0 bit；q=3×60 下 4096/4096、余 25 bit。见 MAP §32.1）；
  · "桥的残差换个更大的 t 就能消" —— 错，残差与明文模数无关，必须靠 K 倍精度（现在还要 K > τ·ones）；
  · "延迟重线性化能省预算" —— 错：multiply 那一步就吃光，且 size-3 密文不能旋转；
  · "自定义系数模数能随便放宽" —— 默认被安全标准拒（isParametersSet=false），只能显式 SecLevelType.NONE；
  · t=2^32 上做槽位选择子 —— 数学上不可能（MAP §18.2）；
  · CapeDemoService 默认走的是旧几何 buildTables，论文几何在 buildTablesPaper 里 —— 那是"未接线"。

【纪律】每个断言配正/负对照；先跑再下结论；不许把"跑通"说成"端点正确"；
一条断言里**不能**既有"认残差的容差"又有"逐位精确"（那样的判据是掷骰子，见 §32.6）；
报错给行号+原始输出（javac 的乱码在本机是 GBK，先看行号再读那一行）；
**不要动 CapeDemoService / native 路径**；run-mpc4j.ps1 每次清空 mpc4j-out，不要并发跑；
改源码优先用 edit 按片段替换，**不要整文件回写**（本轮因此截断过一个 730 行的探针，且它未被 git 跟踪）。
```
