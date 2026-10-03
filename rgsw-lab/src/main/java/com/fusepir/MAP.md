# 实现说明（按论文结构）—— 哪些实现了、在哪、哪些没有

> **日期**：2026-10-14 深夜（拆包 + 按步拆分之后）
> **对应论文**：Algorithm 1 = FusePIR（SETUP / QUERY / ANSWER / DECODE），
> Algorithm 2 = CAPE（SETUP / QUERY / ANSWER / DECODE）
> **本文件的位置**：`coding/rgsw-lab/src/main/java/com/fusepir/MAP.md`
> （源码树根 —— 打开 `com/fusepir/` 第一眼就能看到）

## 📍 路径约定（本文件所有位置的读法）

| 写法 | 实际完整路径 |
|---|---|
| `bff/BffSetup.java:44` | `coding/rgsw-lab/src/main/java/com/fusepir/bff/BffSetup.java` 第 44 行 |
| `cape/CapeAnswer.java:90` | `coding/rgsw-lab/src/main/java/com/fusepir/cape/CapeAnswer.java` 第 90 行 |
| C++ `rgsw_blindrotate.cpp:543` | `coding/native-jni/src/main/cpp/rgsw_blindrotate.cpp` 第 543 行 |
| `common/BfGen.java` | `coding/common/src/main/java/com/fusepir/common/BfGen.java`（**独立模块**，两方共用） |

**源码根**：`coding/rgsw-lab/src/main/java/com/fusepir/`
**native 根**：`coding/native-jni/src/main/cpp/`

---

> ## ⚠️ 本文件对应的代码状态（如实说）
>
> * 拆包与按步拆分**已完成**，`javac` **0 error**（每步都单独验过）。
> * **验收套件没有在重构之后重跑** —— 用户明确要求先不跑测试。
>   所以"重构没改行为"目前**只有编译期证据，运行期证据还没有**。
> * 两类改动要分清：
>   * **纯搬移/改名**：`CapeClientQuery → CapeQuery`、`NativeCapeAnswer → FusePirAnswer`、
>     `CapeAlgorithm2Diag.answer → CapeAnswer`、`…decode → CapeDecode`、
>     BFF 闭式 → `BffSetup`、`keywordHash` → `BffEncode`。
>   * **去重**：`cellsPerCol` / `C` 这两条算式此前在 **3 个地方各写一遍**
>     （`CapeDemoData`、`CapeQuery.build`、`CapeQuery.buildIndicesOnly`），
>     现在统一走 `fusepir/FusePirSetup`；`keywordHash` 此前在服务端与客户端
>     **各有一份逐字重复**的实现，现在只有 `bff/BffEncode` 一份。
>     ⇒ 这两处**是语义等价的重构，但确实动了代码**，需要跑一遍验收才能确认。

---

## 0. 目录结构

2026-10-14 之前，`com.fusepir.rgsw` 是**一个平铺的包，87 个类** ——
"Algorithm 2 的 ANSWER 在哪"在文件树里看不出来。现在按论文分层、并把步骤拆成文件
（`coding/rgsw-lab/split-packages.ps1` 是一键重构脚本，可复核）：

| 包 | 完整路径 | 数 | 放什么 |
|---|---|---|---|
| `com.fusepir.prim` | `coding/rgsw-lab/src/main/java/com/fusepir/prim/` | 9 | 底层原语：RLWE / LWE / RGSW / CMUX / 盲旋转 / EXPAND / Ring Packing |
| `com.fusepir.bloom` | `…/com/fusepir/bloom/` | 1 | 加密 Bloom 得分（`BF.Gen` 本身在 `common/` 模块） |
| `com.fusepir.bff` | `…/com/fusepir/bff/` | 3 | BFF：`BffSetup`（参数）+ `BffEncode`（位置）+ `CapeDemoData`（表构造） |
| `com.fusepir.fusepir` | `…/com/fusepir/fusepir/` | 5 | FusePIR 四步：`FusePirSetup` / `FusePirQuery`※ / `FusePirAnswer` / `FusePirDecode` |
| `com.fusepir.cape` | `…/com/fusepir/cape/` | 9 | CAPE 四步：`CapeSetup` / `CapeQuery` / `CapeAnswer` / `CapeDecode` + 打分信道与服务 |
| `com.fusepir.demo` | `…/com/fusepir/demo/` | 2 | 数据集工具、JSON、一键演示 |
| `com.fusepir.probe` | `…/com/fusepir/probe/` | 61 | 探针 / 诊断 / 基准 / 验收测试 |
| `com.fusepir.legacy` | `…/com/fusepir/legacy/` | 7 | 已废弃的路线 C（自研 RLWE），**不参与编译** |

※ `FusePirQuery` 目前**还没有独立文件** —— 位置与行选择子的构造仍在 `cape/CapeQuery` 里，
见 §7「还差的东西」。

---

## 0.5　一页速查：论文每一步 → 状态 → 位置

| 论文 | 步骤 | 状态 | 位置（完整路径见上表 📍） |
|---|---|---|---|
| **底层** | `RGSW.Enc(μ)` | ✅ | C++ `rgsw_blindrotate.cpp:337` `build_rgsw_constant` |
| | 外积 `RGSW ⊡ RLWE` | ✅ | C++ `rgsw_blindrotate.cpp:419` `external_product` |
| | `CMUX` | ✅ | C++ `rgsw_blindrotate.cpp:487` `cmux` |
| | 乘单项式 `ct·X^k` | ✅ | C++ `rgsw_blindrotate.cpp:473` `multiply_power_of_x` |
| | **`BlindRotate`** | ✅ | C++ `rgsw_blindrotate.cpp:494` `blind_rotate`；Java 对照 `prim/BlindRotateOps.java`、`prim/BlindRotateComplete.java` |
| | 参数上下文 / 密钥 | ✅ | C++ `rgsw_blindrotate.cpp:727` `nativeCreateContext`；`prim/Mpc4jRgsw.java` |
| | `LWE↔RLWE` 桥 / Ring Packing | ⚠️ 原型，未接主路径 | `prim/LweRlweBridge.java`、`prim/LweRlweConversion.java`、`prim/LweToRgswOps.java`、`prim/RingPack.java` |
| **Bloom** | `BF.Gen(0,S)` | ✅ | `common/BfGen.java` |
| | SETUP：`S_v`/`m_K`/`b_v` | ✅ | `bloom/BloomSetup.java:96`/`:57`+`:76`/`:130` |
| | ANSWER：槽位编码 | ✅ 已收敛为 1 份 | `bloom/BloomChannel.java:113` `toSlotVector` |
| | `q^BF = RLWE.Enc(b_qry)` | ✅ | `bloom/BloomChannel.java:143` `encryptQuery`、`:153` `encryptQueryWire` |
| | `ct_score = CtCtMul(q^BF, ct^BF_j)` | ✅ | `bloom/BloomScoring.java:105` `bloomScore` |
| | 折叠 `Σ_r CtRotate(ct, 2^r)` | ✅ **论文行是 floor 笔误**，我们 ⌈·⌉；**另有第二种入口**（候选是 Pack 产物时用） | `bloom/BloomScoring.java:156` `foldSlots`（⌈log2 ℓ_BF⌉ 轮）；`foldAllSlots`（折满 N/2，等价对照）；**`bloomScoreReaching`/`foldSlotsReaching`（按最高参与槽取轮数，§19.3/§19.4）** |
| | `s_j = Dec(ct_score,j)` | ✅ | `bloom/BloomScoring.java:248` `decodeScore` |
| **BFF** | `BFF.Setup(n,3)`：`s`、`L_BFF` 闭式 | ✅（仅对照，**我们不使用**） | `bff/BffSetup.java:124` `paperS`、`:147` `paperLBff` |
| | `BFF.Setup` 的 `fp` / `D` 形状 | ✅ | `bff/BffSetup.java:88` `fp`、`:111` `newD` |
| | `BFF.Encode`：位置函数 `H`（唯一实现） | ✅ **`h_a` 已实现**；**论文几何路径上是活的**（2026-10-15 更正：本行原写"⚠️ 无 `h_a`，用线性探测"，是旧口径） | `bff/BffHash.java`：`hashGen(L_BFF,s,k,ρ_H)` → `HashGen.positions(...)`。⚠️ 建表侧 **`CapeDemoData:453` 在 `buildTablesPaper`（`:399`）里** ⇒ 论文几何走真 `h_a`；**旧几何 `buildTables`（`:185`，`CapeDemoService` 默认仍调它）仍走替代品**（同一个未接线问题，见 §14.5/§15.7） |
| | `BFF.Encode`：摆放 + 表 `D` + 分享 | ⚠️ 形态不同（k 路 = 同一列{k} 个相邻行） | `bff/BffEncode.java:137` `place`、`:195` `randomizeD`、`:219` `writeD`、`:276` `splitShares` |
| **FusePIR** | SETUP：网格 `(R,C)`、`cellsPerCol` | ⚠️ 推导顺序与论文相反 | `fusepir/FusePirSetup.java:46` `cellsPerCol`、`:56` `columns`、`:65` `span` |
| | SETUP：载荷布局 `B_pay`/偏移 | ✅ 布局公式唯一实现 | `fusepir/FusePirSetup.java` 的 `perValue`/`payloadBpay`/`valueOffset`/`bloomOffset` |
| | SETUP：`P_{c,b}(X)` | ⚠️ | `bff/CapeDemoData.java`（表构造，属 demo 资产） |
| | QUERY：位置 `u_a = h_a(K)` | ✅ **不是缺口了**（2026-10-15 更正：原写 ❌ 真缺口） | `bff/BffHash.positions`；`fusepir/FusePirParams.java:296` `bffPositions(rhoH,hg)` 把 `kw → h_a(K)` 装进 `pp`；`probe/FusePirStateTest:185` 断言 `pp` 的 `H` 与 `BffHash.positions` 逐位同一份 |
| | QUERY：`q^col` 选择子 | ✅ **P1-1 已完成** | `cape/CapeQuery.java:257` `encryptColumnSelectors`；native `rgsw_blindrotate.cpp:1363` `nativeEncryptSealedColumns` |
| | QUERY：`q^row = LWE.Enc_{s_L}(r_a)` | ⚠️ **无噪声** + `s_L` 必须等于 `s_R` | `cape/CapeQuery.java`（`q.beta[a] = (sum + rowIdx[a]) % twoN`） |
| | ANSWER：列选择→盲旋转→提取→三路相加 | ✅ | C++ `rgsw_blindrotate.cpp:543` `cape_answer_core`；入口 `nativeCapeAnswer:1614` / `nativeCapeAnswerSealed:1937` / `nativeCapeAnswerSealedC:1981` |
| | ANSWER：**`resp ← Pack(...)`（L13）** | ⚠️ **原语有且已验；缺适配器与调用方**（2026-10-15 更正：原写 ❌ 没有实现） | `prim/RingPack.pack`；实测见 **§18/§19**。⚠️ 收的是明文 `(as,bs)` 而非 `{ct_{pay,b}}`，且**零个协议调用方** |
| | DECODE：载荷切分 `Recover (f,m,v…)` | ✅ | `fusepir/FusePirDecode.java:57` `decodePayload` |
| | DECODE：`fp(K)` | ✅ **40-bit，非 `hashCode`**（2026-10-15 更正：原写"用 String.hashCode"） | `fusepir/FusePirDecode.java:155` `fpOf` 委托到 `bff/BffSetup.fp`（`oracle40`，`FP_SEED=20261015`） |
| **CAPE** | SETUP：`ℓ_BF`、`G`、`b_v`、`DB^CAPE` | ✅ | 见 `cape/CapeSetup.java` 的对照表（实现散在 `common/BfGen` 与 `bff/CapeDemoData`） |
| | SETUP：`B_pay = 2+m(1+ℓ_BF)` | ⚠️ **这是我们的推断**（论文没重述） | `cape/CapeSetup.java:57` `bPay`（转发到 `FusePirSetup.payloadBpay`） |
| | SETUP：打分信道（论文里没有这一步） | ⚠️ 口径差：**两个 `t`、两把 sk** | `bloom/BloomChannel.java:81` `setup` |
| | QUERY：`b_qry`、`τ` | ✅ | `cape/CapeQuery.java:96` `build`（`τ` 只在客户端） |
| | QUERY：`q^BF ← RLWE.Enc(b_qry)` | ✅ | `bloom/BloomChannel.java:153` `encryptQueryWire` |
| | QUERY：`q ← (q_anc, q^BF)` | ✅ | `cape/CapeQuery.java:379` `toJson` |
| | ANSWER：`resp_anc ← FusePIR.Answer(st_S, q_anc)` | ✅ | `cape/CapeDemoService.java:309` `runQueryCapeSealed` → `:509` `runAnchorNative` |
| | ANSWER：`Parse {(c_{v_j}, ct^BF_j)} from resp_anc`（L3） | ❌ **做不到**（需要 Pack） | 我们是**重新加密**（D2，调用点 `cape/CapeBloomScore.encryptCandidateBloom`） |
| | ANSWER：`ct_score,j = CtCtMul + 折叠`（L4-7） | ✅ | `bloom/BloomScoring.java:105` `bloomScore`；调用点 `cape/CapeBloomScore.score` |
| | ANSWER：`resp ← ({(c_{v_j}, ct_score,j)})`（L8） | ⚠️ | `cape/CapeDemoService.java:284` `answerCape`；响应字段 `payloadPlain`（**明文**）+ 每候选 `ctScoreBytes`（真密文） |
| | DECODE：`V_{K_1} ← FusePIR.Decode` | ✅ | `cape/CapeDecode.java:158` → `fusepir/FusePirDecode.java:57` |
| | DECODE：`f ≠ fp(K) ⇒ ⊥` | ✅ | `cape/CapeDecode.java:81` `decode` / `:112` `decodeWire` |
| | DECODE：`s_j = τ ⇒ R ∪ {v_j}` | ✅ | 同上 |

**一句话**：**算法骨架全在**；`Pack` 那一层**原语已有且已验，缺的是适配器与调用方**（§18/§19）；
另外三处形态差（独立 `s_L`、`q^row` 无噪声、两方密钥隔离）是结构性的。
**完整的缺口总账见 §20。**

> **`bloom/` 与 `bff/` 这一层现在是什么状态**（本轮结论，明细见 §11）：
> - `bloom/` —— **契约完整，缺口 0**。论文里属于 Bloom 的每一行都有唯一实现，
>   `cape/` 里只剩调用（§11.1 逐行核过）。
> - `bff/` —— **`BFF.Setup` / `BFF.Encode` 的数据结构侧完整**（`H`、`fp`、`D`、摆放、
>   三路分享、填充自检各自唯一一份），**但差两条真缺口**：`h_a`（A1 QUERY 3）
>   与 `select R, C`（A1 SETUP 4）。这两条**会改变几何**（`L_BFF` 130 → 155、`C` 26 → 10），
>   所以是**决定**而不是机械补齐 —— 见 §11.3 ①②。
>   第三条 `D[u] ← 0, u ∈ [L_BFF, RC)` 在**我们这组定义下是空操作**，不是缺口（§11.3 ③）。

---

## 1. 底层原语 —— `prim/`（+ native C++）

**完整路径**：`coding/rgsw-lab/src/main/java/com/fusepir/prim/`
（真正的实现在 `coding/native-jni/src/main/cpp/rgsw_blindrotate.cpp`）

| 论文里的东西 | 状态 | 位置 |
|---|---|---|
| 参数上下文（`N, t, q`）+ 密钥生成 | ✅ | C++ `rgsw_blindrotate.cpp:727` `nativeCreateContext`；Java `prim/Mpc4jRgsw.java` |
| `RGSW.Enc_s(μ)`（自举密钥） | ✅ | C++ `:337` `build_rgsw_constant` |
| 外积 / `CMUX` / 乘单项式 | ✅ | C++ `:419` / `:487` / `:473` |
| **`BlindRotate(q^row, Acc)`** | ✅ | C++ `:494` `blind_rotate`；Java 对照 `prim/BlindRotateOps.java`、`prim/BlindRotateComplete.java` |
| gadget 分解 | ✅ | C++ `external_product` 内；对照物 `prim/Mpc4jRgsw.java`（快 / BigInteger 慢两条） |
| `EXPAND`（SealPIR §3.3） | ⚠️ **未被主路径调用** | `prim/ExpandOps.java` |
| LWE 域列选择 | ⚠️ 实验结论 | `prim/LweColumnMath.java` |
| `LWE↔RLWE` 桥 / Ring Packing | ⚠️ **原型，未接主路径** | `prim/LweRlweBridge.java`、`LweRlweConversion.java`、`LweToRgswOps.java`、`RingPack.java` |
| native ANSWER 入口 | ✅ | `fusepir/FusePirAnswer.java:59` `run`（原 `prim/NativeCapeAnswer`，已按步搬到 `fusepir/`） |

---

## 2. Bloom —— `bloom/`

**完整路径**：`coding/rgsw-lab/src/main/java/com/fusepir/bloom/`

> 本轮把 Bloom 从 `cape/CapeBloomScore` 里拆出来，**4 个文件**，`cape/` 侧只留调用。
> 完整的「论文行 → 函数 → 调用方」表在 **§11.1**。

| 文件 | 行数 | 负责什么 |
|---|---|---|
| `bloom/BloomSetup.java` | 99 | `S_v`、`m_K`、`b_v` —— **SETUP 侧的纯逻辑，无同态** |
| `bloom/BloomChannel.java` | 127 | 打分信道的**密钥/编码原语**：`Scorer`、`setup`、`toSlotVector`/`padToSlots`（槽位编码，**唯一实现**）、`encryptQuery`/`encryptQueryWire`、`decryptSlots` |
| `bloom/BloomScoring.java` | 340 | QUERY/ANSWER 侧的同态运算：`encryptBloomVector`、`bloomScore`、`foldSlots`/`foldAllSlots`、`galoisKeysFor`、`decodeScore` |
| `bloom/ScorerWire.java` | 133 | 打分信道的**线格式**（`q^BF` 与密钥的序列化） |

| 论文里的东西 | 状态 | 位置 |
|---|---|---|
| `BF.Gen(0,S)` / `b_v` / `b_qry` | ✅ | `coding/common/src/main/java/com/fusepir/common/BfGen.java`（**独立模块**：客户端算 `b_qry`、服务端算 `b_v`，必须同一份实现） |
| A2 SETUP 3-5　`S_v` / `m_K` / `b_v` | ✅ | `bloom/BloomSetup.java:96` / `:57`+`:76` / `:130` |
| A2 QUERY 3　`τ ← ‖b_qry‖₁` | ✅ | `common/…/BfGen.java` 的 `hammingWeight` |
| ANSWER 2　槽位编码（**4 份重复已收敛为 1 份**） | ✅ | `bloom/BloomChannel.java:113` `toSlotVector` / `:132` `padToSlots` |
| ANSWER 3　`q^BF ← RLWE.Enc(b_qry)` | ✅ | `bloom/BloomChannel.java:143` `encryptQuery`、`:153` `encryptQueryWire` |
| ANSWER 4　`ct_score ← CtCtMul(q^BF, ct^BF_j)` | ✅ | `bloom/BloomScoring.java:105` `bloomScore`（→ `:122` 论文形状的重载） |
| ANSWER 5　折叠 | ✅ | `bloom/BloomScoring.java:155` `foldSlots` = **`⌈log2 ℓ_BF⌉` 轮**（论文这一行的 floor 是笔误，见 §10.3 ①）；`:192` `foldAllSlots` 是折满 `N/2` 的等价对照 |
| ANSWER 6　`s_j ← Dec(ct_score)` | ✅ | `bloom/BloomScoring.java:248` `decodeScore` |
| 打分信道线格式 | ✅ | `bloom/ScorerWire.java`（原 `cape/CapeScorerWire` 已删） |

**Bloom 侧缺口：无**（§11.1 逐行核过）。

---

## 3. BFF —— `bff/`

**完整路径**：`coding/rgsw-lab/src/main/java/com/fusepir/bff/`

> 本轮把 BFF 收敛到 **3 个文件**。完整的「论文行 → 函数 → 调用方」表在 **§11.2**，
> 三个缺口的性质判定在 **§11.3**。

| 文件 | 行数 | 负责什么 |
|---|---|---|
| `bff/BffSetup.java` | 163 | `BFF.Setup`：段大小 `s` 与 `L_BFF` 的**论文闭式**、指纹 `fp`、`D` 的形状 `newD` |
| `bff/BffEncode.java` | 296 | `BFF.Encode`：公开哈希 `H`（`keywordHash`/`mix`）、摆放 `place`、`randomizeD`/`writeD`/`checkDataRadius`、k 路分享 `splitShares` |
| `bff/CapeDemoData.java` | 561 | **样例数据库的装载与建表**（JSON 解析、`colOf`/`rowOf` 表、验算）——是 demo 资产，不是协议层 |

| 步骤 | 状态 | 位置 |
|---|---|---|
| `BFF.Setup(n,3)`：`s`、`L_BFF` 闭式 | ✅ 但**仅作对照** | `bff/BffSetup.java:124` `paperS`、`:147` `paperLBff` |
| `BFF.Setup(n,3)` 的产物 / `fp` / `D` 形状 | ✅ | `bff/BffSetup.java:76` `setup`、`:88` `fp`、`:111` `newD` |
| `BFF.Encode`：位置函数 `H`（**唯一**实现） | ✅ | `bff/BffEncode.java:66` `keywordHash`、`:92` `mix` |
| `BFF.Encode`：摆放 `place` | ✅ | `bff/BffEncode.java:137` |
| 表 `D` 的填充 | ✅ | `bff/BffEncode.java:195` `randomizeD`、`:219` `writeD`、`:247` `checkDataRadius` |
| 3 路加性分享 | ✅ | `bff/BffEncode.java:276` `splitShares` |
| A1 QUERY 3　`u_a ← h_a(K)` | ❌ **缺口（真）** | 见 §11.3 ① |
| A1 SETUP 4　`select R, C` | ❌ **缺口（真，且循环依赖）** | 见 §11.3 ② |
| A1 SETUP 9-11　尾部补零 | ✅ **空操作** | 我们 `L_BFF ≡ RC`，见 §11.3 ③ |
| `P_{c,b}`（列选择子 / 行掩码） | ✅ 在 `fusepir/` | 按 A1 它属于 FusePIR 的 ANSWER，不属于 BFF |

**⚠️ 三处形态差**
1. **`h_i` 没实现**：论文一个关键词有 `k=3` 个**分散**位置；我们是**同一列的 3 个相邻行**。
   ⇒ 我们的"BFF"实际是**槽表 + 线性探测**，3 路拆分只是加性分享，**不带过滤语义**。
2. **推导顺序反了**：论文 `Setup → L_BFF → 选 (R,C)`；我们**先按 n 定 `C`**，
   再声明 `L_BFF = cellsPerCol·C`。⇒ **我们的 `L_BFF`（130）不是论文的 `L_BFF`（闭式 155）**。
3. **代价**：3 条路列号相同 ⇒ `Acc_{a,b}` 对 a=0,1,2 是同一个值，同一份列选择算了 3 遍
   （白做约 5–6.5%）。**不建议顺手优化** —— 那会离论文更远。

---

## 4. FusePIR 四步（Algorithm 1）—— `fusepir/`

**完整路径**：`coding/rgsw-lab/src/main/java/com/fusepir/fusepir/`

### SETUP
| 论文 | 状态 | 位置 |
|---|---|---|
| L4 `Select R, C such that RC ≥ L_BFF, R ≤ N` | ⚠️ | `fusepir/FusePirSetup.java:46` `cellsPerCol`、`:56` `columns`、`:65` `span` |
| L5-7 `y ← fp(K_i) ‖ m_i ‖ v…` | ✅ | `bff/CapeDemoData.java`（`payload` 构造） |
| L8 `BFF.Encode` | ⚠️ | 见 §3 |
| L9-16 `P_{c,b}(X) = Σ_r D[r+cR][b]·X^r` | ⚠️ | `bff/CapeDemoData.java:353`。⚠️ 行下标是 `rowOf+a`，**不是论文的 `r+cR`** |
| — | ✅ | `FusePirSetup` 同时**消掉了三处重复**的网格算式 |

### QUERY
| 论文 | 状态 | 位置 |
|---|---|---|
| L3 `u_a ← h_a(K)`、`r_a`、`c_a` | ⚠️ 公式是我们的网格式 | `cape/CapeQuery.java:222`/`:246` |
| L5 `q^col = RLWE.Enc_{s_R}(e_{c_a})` | ✅ **P1-1** | `cape/CapeQuery.java:257` → C++ `:1363` `nativeEncryptSealedColumns` |
| L5 `q^row = LWE.Enc_{s_L}(r_a)` | ⚠️ `Δ=1, e=0`；且 **`s_L` 必须逐位等于 `s_R`** | `cape/CapeQuery.java`（`beta` 构造） |
| — | ❌ **没有独立文件** | 见 §7 |

### ANSWER
| 论文 | 状态 | 位置 |
|---|---|---|
| L4-7 列选择 / 盲旋转 / 提取 | ✅ | C++ `rgsw_blindrotate.cpp:543` `cape_answer_core` |
| L10-11 三路 `CtCtAdd` | ✅ | 同上（`sumCt[b]`） |
| **L13 `resp ← Pack({ct_{pay,b}})`** | ❌ **没有实现** | **没有文件** |
| 三个 native 入口 | — | `nativeCapeAnswer:1614`（基线）、`nativeCapeAnswerSealed:1937`、`nativeCapeAnswerSealedC:1981`（P1-1） |
| — | ✅ | `fusepir/FusePirAnswer.java:59` `run`（一次 JNI 调用跑完） |

### DECODE
| 论文 | 状态 | 位置 |
|---|---|---|
| L2-4 `y[β] ← Dec_{s_R}(ct_{pay,β})` | ⚠️ **回环里由服务端做** | C++ `cape_answer_core` 末尾用 `c->decryptor` ⇒ 响应字段是明文 |
| L5 `Recover (f,m,v…)` | ✅ | `fusepir/FusePirDecode.java:57` `decodePayload` |
| L6 `f ≠ fp(K) ⇒ ⊥` | ✅ | `cape/CapeDecode.java:81`/`:112`（判定在 CAPE 层） |

---

## 5. CAPE 四步（Algorithm 2）—— `cape/`

**完整路径**：`coding/rgsw-lab/src/main/java/com/fusepir/cape/`

### SETUP —— `cape/CapeSetup.java`
| 论文 | 状态 | 位置 |
|---|---|---|
| L1 `ℓ_BF, G` | ✅ | 数据集 meta + `common/BfGen.java` |
| L2 `m` | ✅ | `bff/CapeDemoData` 的 `meta.maxValues` |
| L3-6 `b_v ← BF.Gen(0,S_v)` | ✅ | `bff/CapeDemoData.java`（载荷构造时逐值算） |
| L7-10 `DB^CAPE` | ✅ | 同上（值占 `1+ℓ_BF` 项） |
| L11 `FusePIR.Setup` | ✅ | `bff/CapeDemoData` |
| `B_pay = 2+m(1+ℓ_BF)` | ⚠️ **推断，非原文** | `cape/CapeSetup.java:57` `bPay`（转发到 `FusePirSetup.payloadBpay`） |
| 打分信道（论文没有） | ⚠️ 两个 `t` | `bloom/BloomChannel.java:81` `setup`（线格式 `bloom/ScorerWire`） |
| — | — | `cape/CapeSetup.java` 本身只放**入口与口径说明**，不复制运算 |

### QUERY —— `cape/CapeQuery.java`
| 论文 | 状态 | 位置 |
|---|---|---|
| L1 `q_anc ← FusePIR.Query(...)` | ⚠️ | `:96` `build`（位置与选择子在同一类里，见 §7） |
| L2-3 `b_qry`、`τ` | ✅ | `:96`；`τ` **只在客户端** |
| L4 `q^BF ← RLWE.Enc(b_qry)` | ✅ | `bloom/BloomChannel.java:153` `encryptQueryWire` |
| L5-6 `q ← (q_anc, q^BF)` | ✅ | `:379` `toJson`（`colSel`/`colIdx` 互斥发出） |

### ANSWER —— `cape/CapeAnswer.java` + `cape/CapeDemoService.java`
| 论文 | 状态 | 位置 |
|---|---|---|
| L2 `resp_anc ← FusePIR.Answer(st_S, q_anc)` | ✅ | `CapeDemoService.java:309` `runQueryCapeSealed` → `:509` `runAnchorNative` |
| L3 `Parse {(c_{v_j}, ct^BF_j)}` | ❌ **需要 Pack** | 我们重新加密（D2） |
| L4-7 `ct_score,j` | ✅ | `cape/CapeAnswer.java:90` `answer` → `bloom/BloomScoring.java:105` `bloomScore` |
| L8 `resp` | ⚠️ | `CapeDemoService.java:284` `answerCape`；`payloadPlain` **是明文** |

### DECODE —— `cape/CapeDecode.java`
| 论文 | 状态 | 位置 |
|---|---|---|
| L2 `V_{K_1} ← FusePIR.Decode` | ✅ | `:158` → `fusepir/FusePirDecode.java:57` |
| L3-4 `V = ⊥ ⇒ ⊥` | ✅ | `:81` `decode` / `:112` `decodeWire`（负对照 N2） |
| L8-9 `s_j ← Dec`；`s_j = τ ⇒ 收` | ✅ | 同上（负对照 N1/N1b/N3） |

**两条 DECODE 入口刻意不合并**：`decode` 吃进程内 `Ciphertext`（快，但绕过"字节过线"）；
`decodeWire` 从**字节** load 再解密 —— 只有后者能让"服务器回的字节被破坏"这类负对照有意义。

---

## 6. ❌ **没有实现的**（不要找文件，它们不存在）

| 论文位置 | 缺什么 | 为什么没做 |
|---|---|---|
| **A1 ANSWER 13**：`resp ← Pack({ct_{pay,b}})` | **原语已实现并验过；缺的是"收密文"的适配器 + 任何调用方** | ⚠️ **2026-10-15 更正**：本行原写"`Pack` 整个没有 / 唯一完全没做的一步"，**不准**。真实现是 `prim/RingPack.pack`（真 ring packing，`PackGoalCheck:151` 自己就这么写）。**准确说法**：它收明文 `(as,bs)`，**不是** `{ct_{pay,b}}` 这组密文，且**零个协议调用方**。新实测：搬运在 `B_pay=61`/16-bit limb 上逐槽精确、可算性已界定、折叠轮数已修（**§18/§19**）。⚠️ 原写的"≈12 GB 切换密钥"也偏了：实测 **8.0 GB**（`n=N`）/ **16 MB**（`n=d=16`），且**真正的墙是模数不是体积**（§18.2） |
| **BFF 的 `h_i`** | 3 个分散位置 | 我们用"同一列 3 个相邻行"代替 ⇒ BFF 退化成槽表。**缺口性质见 §11.3 ①** |
| **BFF 的 `select R, C`** | `R` 的选取策略 | 论文只写约束 `RC ≥ L_BFF, R ≤ N`，**没给策略**；而我们的 `L_BFF` 又依赖 `R` ⇒ **循环依赖**，见 §11.3 ② |
| **独立的 `s_L`** | 第二把密钥 | 净旋转 `= Σa_i(s_R,i−s_L,i) − r_a`，差 1 位就偏 5767 行 ⇒ **与当前盲旋转口径不兼容** |
| **`q^row` 的噪声 `Δ·m + e`** | P1-2 | 判据已算出（`Δ/√d > 6σ`，`R < N/(6σ√d)`），**前置是先定 `R`，而论文没给 `R`** |
| **两方密钥隔离** | —— | 单 JVM 回环。⚠️ P1-1 后仍有一条同源边界：**选择子必须与「解码者」同一把秘密** |
| `RgswBaseNoise`（`probe/RgswBaseSweep.java` 的 javadoc 提到） | —— | **从来没有这个类**，是 javadoc 笔误（已就地更正） |

---

## 7. ⚠️ 还差的东西（下一步）

> **本轮已完成**：`bloom/` 与 `bff/` 的拆分与去重（Bloom 侧缺口归零，见 §11.1）；
> 槽位编码 4 份 → 1 份；`keywordHash` 明文哈希 2 份 → 1 份（含 `CapeDemoData` 里那个转发）；
> `CapeScorerWire` → `bloom/ScorerWire`；`FusePirSetup` 的 4 个布局公式（24 处重复调用点收敛）。
> 重构后**离线验收全绿**（§8 前 5 条；后 3 条需要服务在跑，按"先不用总体链接"未跑）。

| 项 | 现状 | 建议 |
|---|---|---|
| **BFF 的 `h_a` 与 `select R, C`** | 两个真缺口，**且会改变几何**（`L_BFF` 130 → 闭式 155、`C` 26 → 10） | **这是一个决定，不是机械修复**：见 §11.3 ①②。真做了就要重验「假阴性 0」和全部探针 |
| **`fusepir/FusePirQuery.java` 还不存在** | 位置公式与 `q^col`/`q^row` 构造都在 `cape/CapeQuery.java` | 抽一个 `FusePirQuery`，让 `CapeQuery` 只做 A2 的那两步（`b_qry`/`τ`、`q^BF`）。**这一步要动 `Sealed` 的形状**（约 10 个调用点直接读它的字段），风险高于前面几次，所以单独一轮做 |
| **`CapeDemoData` 仍是 1 个大类（561 行）** | 同时装：JSON 解析、DB 加载、BFF.Encode 的表构造、`Tables` holder | 可把"表构造"抽到 `bff/BffEncode` 的第二个方法。**同样是改逻辑归属，建议单独一轮** |
| **`probe/` 里还有 4 份 `S_v` 与 2 份 `τ`** | `CapeAnswerFull:65`、`CapeColumnPacked:87`、`CapeEndToEnd4:177`、`CapeEndToEndNative:90`（`S_v`）；`CapeEndToEndNative`、`CapeQFairBench`（`τ`） | 探针是**一次性诊断件**，重复不构成生产风险；要不要收敛由你定 |
| **验收套件未在重构后全部重跑** | 离线 5 条已全绿 | 服务那 3 条按"先不用总体链接"暂不跑 |

---

## 8. 验收命令（包名已变：`rgsw` → 分层）

```powershell
cd coding\rgsw-lab

# 离线
.\run-mpc4j.ps1 -Class com.fusepir.probe.CapeBffParamDiag
.\run-mpc4j.ps1 -Class com.fusepir.bloom.BloomScoring 8192
.\run-mpc4j.ps1 -Class com.fusepir.probe.CapeTableDiag "E:\学习\密码赛\coding\cape-demo\db\keywords.json" 8192
.\run-mpc4j.ps1 -Class com.fusepir.cape.CapeBloomScore 8192 18
.\run-mpc4j.ps1 -Class com.fusepir.probe.CapeWireFormatProbe 8192 18

# 需要服务在跑
.\run-mpc4j.ps1 -Class com.fusepir.probe.CapeDefaultPathTest 8756
.\run-mpc4j.ps1 -Class com.fusepir.probe.CapeAlgorithm2Diag 8756
.\run-mpc4j.ps1 -Class com.fusepir.probe.CapeColumnSelWireTest 8756

# 服务（包名也变了）
$env:DSH_JVM_OPTS = "-Dcape.selftest=true -Dcape.web=E:\学习\密码赛\coding\cape-demo\web"
.\run-mpc4j.ps1 -Class com.fusepir.cape.CapeDemoService 8756 8192 16 "E:\学习\密码赛\coding\cape-demo\db\keywords.json"
```

---

## 9. Algorithm 1（FusePIR）原文 + BFF / Bloom 逐行对照

> **来源**：用户 2026-10-14 深夜提供的全文转录。
> ⚠️ 用户**贴了两遍同一份 Algorithm 1**（内容逐字相同），这里按一份收录。
> Algorithm 2 的原文见本文件 §5 的引用。
>
> **对照只问一件事：这一行需要 BFF 或 Bloom 的哪个函数？我们有没有？**

```
Algorithm 1  FusePIR
SETUP(1^λ, DB = {K_i ↦ V_{K_i} = {v_{i,1},…,v_{i,m_i}}}_{i=1}^n)
 1: (D, H, fp) ← BFF.Setup(n, 3).
 2: L_BFF ← |D|,  m ← max_{i∈[n]} |V_{K_i}|.
 3: Select public parameters (N, d, t, q), and generate HE keys sk = (s_L, s_R).
 4: Select R, C such that RC ≥ L_BFF, R ≤ N.
 5: for i = 1 to n do
 6:     Pad V_{K_i} to m values and set
        y_{K_i} ← fp(K_i) ‖ m_i ‖ v_{i,1} ‖ ··· ‖ v_{i,m} ∈ Z_t^{B_pay}
 7: end for
 8: (D, H) ← BFF.Encode(D, H, {(K_i, y_{K_i})}_{i=1}^n).
 9: for u = L_BFF to RC − 1 do
10:     D[u] ← 0 ∈ Z_t^{B_pay}.
11: end for
12: for c = 0 to C − 1 do
13:     for b = 1 to B_pay do
14:         P_{c,b}(X) ← Σ_{r=0}^{R−1} D[r + cR][b]·X^r.
15:     end for
16: end for
17: pp ← (H, fp, R, C, N, d, t, q).
18: st_S ← ({P_{c,b}}_{c,b}, pp).
19: return (pp, st_S, sk).

QUERY(pp, sk, K)
1: q ← [].
2: for a = 0 to 2 do
3:     u_a ← h_a(K),  r_a ← u_a mod R,  c_a ← ⌊u_a/R⌋.
4:     e_{c_a} ← (0,…,0,1,0,…,0) ∈ {0,1}^C, with the 1 at index c_a.
5:     q_a = (q_a^col, q_a^row) = (RLWE.Enc_{s_R}(e_{c_a}), LWE.Enc_{s_L}(r_a)).
6: end for
7: q := (q_0, q_1, q_2),  st_C ← K.
8: return (q, st_C).

ANSWER(st_S, q)
 1: Parse st_S = ({P_{c,b}}_{c,b}, pp).
 2: for a = 0 to 2 do
 3:     Parse (q_a^col, q_a^row) from q.
 4:     for b = 1 to B_pay do
 5:         Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul(q_a^col[c], P_{c,b}(X)).
 6:         Acc'_{a,b} ← BlindRotate(q_a^row, Acc_{a,b}).
 7:         ct_{a,b} ← SampleExtract_0(Acc'_{a,b}).
 8:     end for
 9: end for
10: for b = 1 to B_pay do
11:     ct_{pay,b} ← CtCtAdd(CtCtAdd(ct_{0,b}, ct_{1,b}), ct_{2,b}).
12: end for
13: resp ← Pack({ct_{pay,b}}_{b=1}^{B_pay}).
14: return resp.

DECODE(sk, st_C, resp)
1: K ← st_C.
2: for each packed ciphertext ct_{pay,β} ∈ resp do
3:     y[β] ← Dec_{s_R}(ct_{pay,β}).
4: end for
5: Recover (f, m_K, v_1, …, v_m) ← y.
6: if f ≠ fp(K) then
7:     return ⊥.
8: end if
9: return {v_1, …, v_{m_K}}.
```

### 9.1 结论先说：**Algorithm 1 里没有 Bloom**

Algorithm 1 的 "BFF" 是 **Binary Fuse Filter**（位置/桶结构）；
`BF.Gen` / `b_v`（Bloom **Filter**）只出现在 **Algorithm 2 的 SETUP**。
两者缩写像，**完全无关**。所以：

* 拿 Algorithm 1 对照，**不会**新增任何 `bloom/` 函数；
* `bloom/` 该照 **Algorithm 2** 的 ANSWER 4-7 对照（已做完：`encryptBloomVector` /
  `bloomScore` / `foldSlots` / `foldAllSlots` / `decodeScore` / `galoisKeysFor`）。
  **唯一的缺口是 `Pack`** —— 没有它，`ct^{BF}_j` 无法从协议里产生（D2）。

### 9.2 BFF 逐行对照

| 行 | 论文要求 | 状态 | 位置 / 说明 |
|---|---|---|---|
| L1 | `(D, H, fp) ← BFF.Setup(n, 3)` | ⚠️ **三件套齐了，但顺序反了** | `BffSetup.setup(n,k)`（`s`/`L_BFF`）、`BffSetup.newD(lBff,bPay)`（**D 的形状**）、`BffEncode.keywordHash`（**H**）、`BffSetup.fp`（**fp**） |
| L2 | `L_BFF ← |D|`；`m ← max_i |V_{K_i}|` | ⚠️ | `BffSetup.Params.lBff`；`m` 取 `meta.maxValues`。⚠️ **我们的 `L_BFF` 依赖 R**（`= cellsPerCol·C`），而论文的 `R` 依赖 `L_BFF` ⇒ **循环依赖**，见 L4 |
| L4 | `Select R, C such that RC ≥ L_BFF, R ≤ N` | ❌ **没有这个函数** | 我们是反着走：`C = ⌈n/cellsPerCol⌉` 再得 `L_BFF`。**要按论文做，必须先定 `R` 的选取策略 —— 而论文没给 `R`**（这正是 P1-2 卡住的那个缺口）。⇒ **需要实现，但前置是一个设计决定** |
| L6 | `y ← fp(K_i) ‖ m_i ‖ v_1 ‖ ··· ‖ v_m` | ✅ **本轮补的函数** | `FusePirSetup.perValue/payloadBpay/valueOffset/bloomOffset`。⚠️ 此前这组算式在**全项目 24 处**各写一遍（构造侧 + 解析侧 + 探针），**本轮收口成一份** |
| L8 | `(D, H) ← BFF.Encode(D, H, {(K_i, y_{K_i})})` | ✅ | `BffEncode.place(...)`（摆放 + 三条自检）、`BffEncode.splitShares(...)`（k 路分享） |
| **L9-11** | `for u = L_BFF to RC−1: D[u] ← 0` | ❌ **没有这个函数** | 我们既不选 `(R,C)`，也就没有 `RC` 这个上界。**补上 L4 之后这条才有意义** |
| L12-16 | `P_{c,b}(X) ← Σ_r D[r + cR][b]·X^r` | ⚠️ | `bff/CapeDemoData` 写表。⚠️ 行下标是 `rowOf + a`，**不是论文的 `r + cR`** |
| QUERY L3 | `u_a ← h_a(K)`；`r_a = u_a mod R`；`c_a = ⌊u_a/R⌋` | ⚠️ | `BffEncode.keywordHash` 给**一个**位置（论文 k=3 个分散位置）；`colOf/rowOf` 公式是我们的网格式 |
| QUERY L4 | `e_{c_a} ← one-hot ∈ {0,1}^C` | ⚠️ 无独立函数 | 内联在 `CapeQuery.encryptColumnSelectors` 里（`e[a*C+cc] = (cc==colIdx[a])?1:0`）。**可以抽成一个 `oneHot(C, c_a)`** —— 但它是 QUERY 的，不是 BFF/Bloom 的 |

### 9.3 本轮为此实现的函数（都是 Algorithm 1 直接要求的）

| 新函数 | 对应行 | 为什么需要 |
|---|---|---|
| `BffSetup.newD(lBff, bPay)` | L1 的 `D` | `BFF.Setup` 的产物里有 `D`，此前我们只给了 `s`/`L_BFF`，**没给 D 的形状**。顺带把 `D` 的形状钉死为 `[L_BFF][B_pay]`（**不是** `[n][B_pay]`） |
| `BffSetup.setup(n, k)` → `Params` | L1 | 把 `(s, L_BFF)` 作为一次调用的产物返回（此前是两条裸公式） |
| `BffSetup.fp(K, t)` | L1 的 `fp` | 指纹函数有了单一入口（此前 `inField` 在 `CapeDemoData` 里） |
| `BffEncode.place(...)` | L8 | 摆放 + 三条自检（含**新增的 `k ≤ maxValues`**，见 §6） |
| `BffEncode.splitShares(...)` | L8 | k 路加性分享（`Σ_a D[u_a] = y_K` 的前提） |
| `FusePirSetup.perValue/payloadBpay/valueOffset/bloomOffset` | L6 | `y` 的布局。**收口 24 处重复** —— 这是本轮最有价值的一处 |

### 9.4 仍然缺的（Algorithm 1 要求、我们确实没有）

| 行 | 缺什么 | 前置 |
|---|---|---|
| **L4** | `Select R, C such that RC ≥ L_BFF, R ≤ N` | ✅ **已决定**：`R = C = √L_BFF = 16`（用户 2026-10-14 决定，§12.7）。**不再是缺口** |
| **L9-11** | `D[u] ← 0` for `u ∈ [L_BFF, RC)` | ✅ **在我们这组定义下是空操作**，不是缺口（§11.3 ③） |
| **ANSWER L13** | `Pack` | ⚠️ **原语已实现并验过**；缺"收密文"的适配器 + 调用方。**实测见 §18/§19**。⚠️ 原写"架构决定：切换密钥 ≈ 12 GB"**已更正**：真的成本是 **8.0 GB**（`n=N`）/ **16 MB**（`n=d=16`），而**不可逾越的那一条是 `t=2^32` 上不存在槽位选择子**（§18.2），所以 `Pack` 只能闭在 65537 通道 |
| **QUERY L5 的 `LWE.Enc_{s_L}(r_a)`** | 带噪声的 LWE 加密 | ⚠️ **仍缺**（P1-2）：`q.beta[a] = (sum + rowIdx[a]) % twoN` 无噪声。解药已找到：`coding/lwe-java/…/cape/he/LWE.java:101 encrypt(LWESecretKey,long)` **自带 `Δ=q/t` 与噪声**（§17.3） |
| **QUERY L3 的 `h_a`** | 3 个分散位置 | ✅ **已有**：`bff/BffHash.positions`，且是活路径（`FusePirParams.bffPositions` → `pp`）——**不再是缺口** |
---

## 10. Algorithm 2（CAPE）原文 + **Bloom / BFF** 逐行对照

> **来源**：用户 2026-10-14 深夜提供的全文转录（这一份是干净的，只贴了一遍）。
> Algorithm 1 的原文见本文件 §9。
>
> **这一节才是 Bloom 的归属地** —— Algorithm 1 里的 "BFF" 是 Binary Fuse Filter，
> 而 **Bloom Filter（`BF.Gen` / `b_v`）只在 Algorithm 2 里出现**（见 §9.1）。

```
Algorithm 2  CAPE
SETUP(1^λ, DB = {K_i ↦ V_{K_i} = {v_{i,1},…,v_{i,m_i}}}_{i=1}^n)
 1: Select public Bloom-filter parameters ℓ_BF and G = {g_1,…,g_h}.
 2: m ← max_{i∈[n]} |V_{K_i}|.
 3: for each v ∈ ∪_{i=1}^n V_{K_i} do
 4:     S_v ← {K_i : v ∈ V_{K_i}}.
 5:     b_v ← BF.Gen(0, S_v).
 6: end for
 7: for i = 1 to n do
 8:     V^CAPE_{K_i} ← {(v_{i,j}, b_{v_{i,j}})}_{j=1}^{m_i}
 9: end for
10: DB^CAPE ← {K_i ↦ V^CAPE_{K_i}}_{i=1}^n.
11: (pp_F, st^F_S, sk) ← FusePIR.Setup(1^λ, DB^CAPE).
12: pp ← (pp_F, ℓ_BF, G, m).
13: st_S ← st^F_S.
14: return (pp, st_S, sk).

QUERY(pp, sk, K = (K_1,…,K_Q))
1: (q_anc, st^anc_C) ← FusePIR.Query(pp_F, sk, K_1).
2: b_qry ← BF.Gen(0, {K_2,…,K_Q}).
3: τ ← ‖b_qry‖₁.
4: q^BF ← RLWE.Enc_{s_R}(b_qry).
5: q ← (q_anc, q^BF).
6: st_C ← (st^anc_C, τ).
7: return (q, st_C).

ANSWER(st_S, q)
1: Parse (q_anc, q^BF) from q.
2: resp_anc ← FusePIR.Answer(st_S, q_anc).
3: Parse {(ct_{v_j}, ct^BF_j)}_{j=1}^m from resp_anc.
4: ct_score,j ← CtCtMul(q^BF, ct^BF_j).
5: for r = 0 to log2 ℓ_BF − 1 do
6:     ct_score,j ← CtCtAdd(ct_score,j, CtRotate(ct_score,j, 2^r)).
7: end for
8: resp ← {ct_{v_j}, ct_score,j}_{j=1}^m.
9: return resp.

DECODE(sk, st_C, resp)
 1: Parse (st^anc_C, τ) from st_C, (resp_anc, {ct_score,j}_{j=1}^m) from resp.
 2: V_{K_1} ← FusePIR.Decode(sk, st^anc_C, resp_anc).
 3: if V_{K_1} = ⊥ then
 4:     return ⊥.
 5: end if
 6: R ← ∅.
 7: for j = 1 to |V_{K_1}| do
 8:     s_j ← Dec_{s_R}(ct_score,j).
 9:     if s_j = τ then
10:         R ← R ∪ {v_j}.
11:     end if
12: end for
13: return R.
```

### 10.1 结论：**BFF 在 Algorithm 2 里没有新增需求**

Algorithm 2 里唯一碰到 BFF 的地方是 SETUP 11（`FusePIR.Setup(1^λ, DB^CAPE)`）——
它把加宽后的 `DB^CAPE` 交给 FusePIR，**BFF 的全部需求仍在 Algorithm 1**（§9 已逐行对照）。
⇒ **拿 Algorithm 2 对照，不需要新增任何 `bff/` 函数。**

### 10.2 Bloom 逐行对照（这才是本算法的主场）

| 行 | 论文要求 | 状态 | 位置 / 说明 |
|---|---|---|---|
| SETUP 1 | `Select public Bloom-filter parameters ℓ_BF and G = {g_1..g_h}` | ✅ | `common/BfGen.choose(maxSetSize, ε_BF, n)` —— 由 ε_BF 反选 ℓ_BF 与 h |
| SETUP 3-4 | `S_v ← {K_i : v ∈ V_{K_i}}` | ⚠️ **两份实现** | `bff/CapeDemoData`（`kwOfValue`）与 `cape/CapeQueryDecode`（`kwOfValue`）**各写一遍**。**见 §10.4** |
| SETUP 5 | `b_v ← BF.Gen(0, S_v)` | ✅ | `BfGen.bits(Collection<String>)` / `bitsAsLong` |
| SETUP 7-10 | `V^CAPE_{K_i} ← {(v, b_v)}`；`DB^CAPE` | ✅ | `bff/CapeDemoData` 建载荷时逐值写入 |
| SETUP 11 | `FusePIR.Setup(DB^CAPE)` | ✅ | `bff/CapeDemoData` + `bff/BffEncode` |
| SETUP 12 | `pp ← (pp_F, ℓ_BF, G, m)` | ✅ | 数据集 meta |
| QUERY 2 | `b_qry ← BF.Gen(0,{K_2..K_Q})` | ✅ | `cape/CapeQuery`（`bf.bits(others)`） |
| **QUERY 3** | **`τ ← ‖b_qry‖₁`** | ✅ **本轮补的函数** | **`BfGen.hammingWeight(boolean[])`**。⚠️ 这条算式此前在**全项目 10 处**各写一遍（循环变量有的叫 `b` 有的叫 `bit`）；本轮收口 **8 处**，**剩 2 处未动**：`probe/CapeEndToEndNative`、`probe/CapeQFairBench`（按你的要求先只登记不改动） |
| QUERY 4 | `q^BF ← RLWE.Enc_{s_R}(b_qry)` | ✅ | **`bloom/BloomChannel.encryptQuery` / `encryptQueryWire`**（本轮已从 `cape/` 搬出） |
| **ANSWER 3** | **`Parse {(ct_{v_j}, ct^BF_j)}_{j=1}^m from resp_anc`** | ❌ **做不到** | 需要 **`Pack`**。我们的替代**本轮有了名字**：`cape/CapeBloomScore.encryptCandidateBloom(sc, bits, lBf)`（它把"这是一处替代"标在调用点上，而不是让它看起来像论文本来就这么做）。**这就是 D2** |
| ANSWER 4-7 | `ct_score,j ← CtCtMul(q^BF, ct^BF_j)` + 折叠 | ✅ | `bloom/BloomScoring.bloomScore(..., lBf)` → `foldSlots`（⌈log2 ℓ_BF⌉ 轮，见 §6 与 `foldSlots` 的注释） |
| ANSWER 8 | `resp ← {ct_{v_j}, ct_score,j}_{j=1}^m` | ⚠️ | 我们发 `payloadPlain`（**明文**，不是 `ct_{v_j}`）+ 每候选 `ctScoreBytes`（真密文）。**见 §10.3 的第二条** |
| DECODE 1-2 | `Parse (resp_anc, {ct_score,j}) from resp`；`V_{K_1} ← FusePIR.Decode(sk, st^anc_C, resp_anc)` | ⚠️ | `cape/CapeDecode.decodePayload` → `fusepir/FusePirDecode.decodePayload`（布局已收口到 `FusePirSetup.valueOffset`，见 §9.3） |
| DECODE 3-4 | `V_{K_1} = ⊥ ⇒ ⊥` | ✅ | `cape/CapeDecode`（负对照 N2） |
| DECODE 8-9 | `s_j ← Dec_{s_R}(ct_score,j)`；`s_j = τ ⇒ R ∪ {v_j}` | ✅ | `cape/CapeDecode`（负对照 N1/N1b/N3） |
| DECODE 6/13 | `R ← ∅` / `return R` | ✅ | 同上 |

### 10.3 ⚠️ 这一份原文暴露的**两处论文自身写得不严**（都要记，别当成我们的 bug）

**① ANSWER 5 的 `log2 ℓ_BF` 应为 `⌈log2 ℓ_BF⌉`。**
原文就是 `for r = 0 to log2 ℓ_BF − 1`，用的是 **floor**。
`ℓ_BF = 18` 时 `log2(18) = 4.17` ⇒ 只折 4 轮 ⇒ 只覆盖槽 `[0,16)`，
**漏掉槽 16、17** ⇒ `s_j` 偏小 2 ⇒ 本该接受的候选被拒。
**照抄这一行会算错。** 我们的 `foldSlots` 用的是 ⌈·⌉（见 §6 与 `bloom/BloomScoring.foldSlots` 的注释）。

**② ANSWER 8 的 `resp` 字段清单不完整。**
ANSWER 8 写的是 `resp ← {ct_{v_j}, ct_score,j}_{j=1}^m`（**没有 `resp_anc`**），
但 DECODE 1 要从 `resp` 里 **parse 出 `resp_anc`**，DECODE 2 又用它算 `V_{K_1}`，
而 DECODE 7 的循环上界 `|V_{K_1}|` 就来自它。
⇒ **`resp` 必须也带上 `resp_anc`**（或带上足够的 `ct_{v_j}` 让客户端重建）。

> 另一条相关的观察：`{(ct_{v_j}, ct^BF_j)}_{j=1}^m` 里**没有 `f`（指纹）与 `m_K`（候选数）**
> —— 它们是载荷系数 0 与 1。所以 `Pack` 的输出必须**同时**能让客户端拿到
> `f`/`m_K`（否则 `FusePIR.Decode` 第 6 行的 `f ≠ fp(K)` 无从判起）。
> ⇒ **`Pack` 必须做"结构性打包"，不只是压缩**：它要产出
> **每个候选两条密文**（`ct_{v_j}` 与 `ct^BF_j`，共 2m 条，其中 `ct^BF_j` 必须是
> ℓ_BF 槽位密文，才喂得进 `CtCtMul(q^BF, ·)`），**外加**指纹与候选数那可解的部分。
> 这比之前"Pack 就是把 B_pay 条压成几条"的说法精确得多。

### 10.4 对照后**需要实现、但按你的要求先只登记不改动**的

| # | 项 | 现状 | 说明 |
|---|---|---|---|
| 1 | **`S_v` 的两份实现**（SETUP 3-4） | `bff/CapeDemoData` 的 `kwOfValue`（`Map<Integer,Set_>`）与 `cape/CapeQueryDecode` 的 `kwOfValue`（`Map<Integer,Set<String>>`）**各写一遍** | 论文里 `S_v` 只定义一次。两份实现的危险是**它们可以悄悄不一致**（比如一边 TreeSet 一边 HashSet、一边含空值一边不含），而后果是 `b_v` 算错 → 假阴性 → **违背论文"假阴性必须为 0"的前提**。⇒ 该抽成一个共享函数。<b>注意层次：`bff` 不能依赖 `cape`（`cape` 已经依赖 `bff`），所以正确的落点是把它从 `CapeDemoData` 里拿出去 —— 也就是 §7 那条"CapeDemoData 仍是 1 个大类"的同一件事。** |
| 2 | **`Pack`**（ANSWER 3 / A1 ANSWER 13） | 完全没做，用 `encryptCandidateBloom` 重新加密代替 | 架构决定（切换密钥 ≈ 12 GB）。本轮把它的**输出形状**钉清楚了，见 §10.3 ② |
| 3 | **`ct_{v_j}` 作为密文返回**（ANSWER 8） | 我们发的是**明文** `payloadPlain` | 真修要发 B_pay 条密文（≈ 30.9 MB/响应），**要等 Pack 的决定** |

---

## 11. `bloom/` 与 `bff/` 的**对外契约表**（"上层只许调用，不许自己实现"）

### 11.0 这一节在回答什么问题

`bloom/` 和 `bff/` 必须**把论文里属于 Bloom 与 BFF 的全部函数都实现掉**，
让 `fusepir/` 与 `cape/` 里剩下的只是**调用**。所以这一节按「论文行 → 函数 → 谁调用」列表，
**并明确标出还没实现的那些行**——标出来的就是缺口，不要靠读代码猜。

层次（箭头 = 依赖方向，**不许有环**）：

```
prim/  ←  bloom/  ←  bff/  ←  fusepir/  ←  cape/
                              ↑
                     common/BfGen（独立模块，client 与 server 共用）
```

`bff` 依赖 `bloom` 是**不可避免**的：载荷 `y_{K_i}` 里的 Bloom 位串由 Bloom 侧定义。
反过来 `bloom` **不能**依赖 `bff` —— `BloomSetup.valueToKeywords` 只需要 `kwToValues`，
不需要任何 BFF 概念，这条已经成立。

### 11.1 Bloom —— 论文行 → 函数 → 调用方

| 论文行 | 函数 | 文件 | 调用方 |
|---|---|---|---|
| A2 SETUP 3　`S_v`（值 → 关键词集） | `BloomSetup.valueToKeywords` | `bloom/BloomSetup.java` | `bff/CapeDemoData`、`cape/CapeDemoService` |
| A2 SETUP 4　`m_K`（关键词 → 候选值数） | `BloomSetup.maxValues` + `BloomSetup.reconcile` | `bloom/BloomSetup.java` | `bff/CapeDemoData`（`reconcile` 在 DB 与 meta 不一致时**抛异常**） |
| A2 SETUP 3-5　`b_v`（值 → ℓ_BF 位串） | `BloomSetup.valueBloomBits` | `bloom/BloomSetup.java` | `bff/CapeDemoData` |
| A2 QUERY 2　`b_qry` | —（客户端直接由 `S_{K}` 算出，无独立函数） | — | `cape/CapeQuery` |
| A2 QUERY 3　`τ ← ‖b_qry‖₁` | `BfGen.hammingWeight` | `common/…/BfGen.java` | `cape/CapeQuery` |
| ANSWER 2　槽位编码 `b ← (b[0], …, b[ℓ_BF−1], ␣…)` | `BloomChannel.toSlotVector` / `padToSlots` | `bloom/BloomChannel.java` | `bloom/BloomChannel.encryptQuery`、`cape/CapeQuery` |
| ANSWER 3　`q^BF ← RLWE.Enc(b_qry)` | `BloomChannel.encryptQuery` / `encryptQueryWire` | `bloom/BloomChannel.java` | `cape/CapeQuery.build` |
| ANSWER 4　`ct_score,j ← CtCtMul(q^BF, ct^BF_j)` | `BloomScoring.bloomScore` | `bloom/BloomScoring.java` | `cape/CapeBloomScore.score` |
| ANSWER 5　**折叠**（`⌈log2 ℓ_BF⌉` 轮，见 §10.3 ①） | `BloomScoring.foldSlots` / `foldAllSlots` | `bloom/BloomScoring.java` | `BloomScoring.bloomScore` |
| ANSWER 6　`s_j ← Dec(ct_score,j)` | `BloomScoring.decodeScore` | `bloom/BloomScoring.java` | `cape/CapeBloomScore.score` |
| ANSWER 3　`b_v` 摆成密文槽向量 | `BloomScoring.encryptBloomVector` | `bloom/BloomScoring.java` | `cape/CapeBloomScore.encryptCandidateBloom` |
| 打分信道的 Setup（密钥 / Galois 键） | `BloomChannel.Scorer`、`BloomChannel.setup`、`BloomScoring.galoisKeysFor` | `bloom/BloomChannel.java`、`bloom/BloomScoring.java` | `cape/CapeSetup`、`cape/CapeDemoService` |
| 打分信道**线格式** | `ScorerWire.serialize/deserialize/serializeKey/deserializeKey/bytesToWire/…` | `bloom/ScorerWire.java` | `cape/CapeQuery`（HTTP）、`cape/CapeDemoService` |

**Bloom 侧缺口：无。** 上面每一行都有唯一实现，且 `cape/` 里已经只剩调用
（`CapeBloomScore` 保留的只有「按候选分组载荷 + 塑形响应」——那是 CAPE 的职责，
不是 Bloom 的）。

### 11.2 BFF —— 论文行 → 函数 → 调用方

> ⚠️ **本小节 2026-10-14 深夜第二次修订**：原文（CAPE 附录 Alg 3）已全文收进 **§12**，
> 参数证据收进 **§13**。修订推翻了我此前在这个位置写的**两条判断**，见 §11.3。

| 论文行 | 函数 | 文件 | 状态 |
|---|---|---|---|
| A3 SETUP 2/5　段大小 `s` | `BffSetup.paperS(k, n)` | `bff/BffSetup.java` | ✅ 与原文逐字一致 |
| A3 SETUP 3/6　`L_BFF` 闭式 | `BffSetup.paperLBff(k, n, useCeil)` | `bff/BffSetup.java` | ⚠️ **两篇出处不一致**（CAPE 用 `⌈·⌉`、ChalametPIR 用 `⌊·⌋`），见 §12.3 |
| A3 SETUP 8-9　`ρ_H`、`H = {h_j} ← BFF.HashGen(ρ_H, L_BFF, s, k)` | **`BffHash.allocate` + `BffHash.positions`** | `bff/BffHash.java` | ✅ **本轮实现**（按四份参考实现，见 §12.4） |
| A3 SETUP 10　`fp_{ρ_fp} : K → {0,1}^μ`（μ = 40） | `BffSetup.fp` | `bff/BffSetup.java` | ⚠️ D7：我们 32-bit `hashCode`，论文 40-bit |
| A3 SETUP 11-12　`D[u] ← ⊥` | `BffSetup.newD(lBff, bPay)` | `bff/BffSetup.java` | ✅ |
| A3 MAPPINGSTEP 1-9　按 `h_0(K)` 排序、建 `T[u]` | `BffMapping.mappingStep` | `bff/BffMapping.java` | ✅ **本轮实现** |
| A3 MAPPINGSTEP 10-33　剥皮取 `S`，含**回推单例**与 `\|S\| ≠ n ⇒ fail` | 同上 | `bff/BffMapping.java` | ✅ **本轮实现**（第 24 行的回推是散文补的，伪代码漏了 —— 见该类注释） |
| A3 ENCODE 2-3　mapping 失败 ⇒ **换新种子重来** | `BffEncode.encode` 的重试循环 | `bff/BffEncode.java` | ✅ **本轮实现**（`attempts` 如实报出） |
| A3 ENCODE 5-6　`D[u] ←$ Z_t^B` | `BffEncode.encode` | `bff/BffEncode.java` | ✅ |
| A3 ENCODE 8-17　LIFO 写 `D[p] ← y_K − Σ_{j≠p} D[h_j(K)]` | `BffEncode.encode` | `bff/BffEncode.java` | ✅ **本轮实现**。⚠️ 旧的 `splitShares`（随机拆 k 路）**保不了**"每槽一写"，只在旧几何下靠断言挡住 |
| A3 CHECK / RECONSTRUCT | `BffEncode.reconstruct` | `bff/BffEncode.java` | ✅ 并有探针逐个关键词验 |
| A1 SETUP 4　`select R, C s.t. RC ≥ L_BFF, R ≤ N` | `BffSetup.layout` / `selectRC` / `fromBff` | `bff/BffSetup.java` | ⚠️ **策略是我们的**（论文只给约束），见 §12.7 |
| A1 SETUP 9-11　`D[u] ← 0, u ∈ [L_BFF, RC)` | `BffEncode.zeroTail` + `encode` 里的分配 | `bff/BffEncode.java` | ✅ **本轮实现**。⚠️ 默认 `R` 策略下 `tail = 0`（空循环），见 §12.7 |
| A1 QUERY 3　`u_a ← h_a(K)`；`r_a = u_a mod R`；`c_a = ⌊u_a/R⌋` | `BffHash.positions` + `Layout.r` | `bff/BffHash.java` | ✅ **本轮实现**（`c_a`/`r_a` 的导出在探针里反查验过） |
| A1 SETUP 14　`P_{c,b}(X) ← Σ_r D[r+cR][b]·X^r` | `BffEncode.embed` | `bff/BffEncode.java` | ✅ **本轮实现** |
| 旧几何的一套（`place`/`randomizeD`/`writeD`/`splitShares`/`keywordHash`） | —— | `bff/BffEncode.java` | ⚠️ **保留但已非默认路径**：旧 demo 仍经过它们，等接线时替换 |

### 11.3 BFF 缺口（第三次修订 —— 前两次我各错了一条）

**① `h_a` —— 已实现（`bff/BffHash.java`），并顺带推翻了两条判断。**
A1 QUERY 3 的 `h_a` 由 A3 SETUP 9 的 `BFF.HashGen` 给出，定义在 BFF 原论文/参考实现里。
落地后验到：**`h_a` 三个位置全部在值域内、互异、且落在 k 个连续段**；
用真实 `h_a` 时**剥皮 1 个种子就成功**（中性夹具要 10 个种子 —— 这个对比就是分段余量的证据）。
细节与两条被推翻的判断见 §12.4。

**② `select R, C` —— 已实现，但策略是我们定的。**
⚠️ **更正**：此前我写"我们的 `L_BFF` 依赖 `R`、论文的 `R` 依赖 `L_BFF` ⇒ 循环依赖"。
**在论文的路径上不存在循环** —— `L_BFF` 只含 `n`，与 `R` 无关。
循环是**我们自己**那套 `L_BFF = cellsPerCol·C` 造成的自造问题。
论文的 `R ≤ N` 是唯一约束，策略见 §12.7。

**③ `D[u] ← 0, u ∈ [L_BFF, RC)` —— 已实现；而且它到底是不是"空操作"取决于 `R`。**
⚠️ **更正**：此前我说它是"空操作"，理由是 `L_BFF ≡ RC`。
**那个理由是错的** —— 我把 `cellsPerCol·C = 5·26 = 130` 当成了 `R·C = 16·26 = 416`。
它是**假恒等式**。
现在的正确说法分两种：
- 论文几何 + 默认 `R` 策略（`R = L_BFF = 256`）⇒ `RC = L_BFF` ⇒ **空循环**；
- 论文几何 + `R = N` ⇒ `RC = 8192 ≫ 256` ⇒ **尾部 7936 个槽，必须清零**。
两种都实现了（`zeroTail`），由 `R` 决定走哪种。

### 11.4 为何"随机化 + 覆写"不等于论文的 `BFF.Encode`

论文的 `ENCODE` 是 **LIFO 逆序回填**：剥皮栈 `S` 里最后被剥出的键
对应的槽是"当时唯一的占位者"，所以它在**回填时最先写**，且写的时候
它那 k−1 个伙伴槽**已经写过**了；于是 `D[p] = y_K − Σ_{j≠p} D[h_j(K)]` 里的每个
`D[h_j(K)]` 都是**终值**。剥皮的单调性保证这一性质。

我们的"随机拆 k 路 + 全部覆写"在**算术结果上等价**
（`Σ_a share_a = y_K`），但**不保证**论文那条"每个槽只被写一次"的性质 ——
在"一个槽被两个关键词共用"的情况下：
- 论文：剥皮保证不会发生（每个键有一个独占的写槽）；
- 我们：靠 `place` 的"cell 不碰撞"断言挡住，而那条断言是旧的 1 位置几何的产物。

⇒ 换成论文几何后，**必须**改成真正的 MAPPINGSTEP + LIFO 回填，
否则 `Σ_a D[h_a(K)] = y_K` 不再有保证（会出现静默假阴性）。

---

## 12. Algorithm 3（BinaryFuseFilter）原文 —— BFF 的**权威定义**

> **来源**：`coding/pdf-extract/out_cape.txt`（用户提供的 CAPE PDF 抽出文本），
> 第 1770-1930 行附录 A + 第 2372-2475 行（ChalametPIR 附录 B，用户先前提供）。
> 这一段是 `BFF.Setup` / `BFF.Encode` 的**定义处** ——
> Algorithm 1 只是**调用** `BFF.Setup(n,3)` / `BFF.Encode(...)`。

### 12.1 CAPE 附录 Algorithm 3（`out_cape.txt:1883-2011`）

```
Algorithm 3  BinaryFuseFilter
SETUP(n, k, B, t, µ)
 1: if k = 3 then
 2:     s ← 2^⌊log_3.33(n) + 2.25⌋.
 3:     L_BFF ← max( ⌈(0.875 + 0.25·max{1, log10(n/6)})·n⌉ , ⌈1.125n⌉ ).
 4: elseif k = 4 then
 5:     s ← 2^⌊log_2.91(n) − 0.5⌋.
 6:     L_BFF ← max( ⌈(0.77 + 0.305·max{1, log10(n/(6·10^5))})·n⌉ , ⌈1.075n⌉ ).
 7: endif
 8: Sample independent public seeds ρ_H, ρ_fp ←$ {0,1}^λ.
 9: Derive H = {h_j : K → [L_BFF]}_{j=0}^{k−1} ← BFF.HashGen(ρ_H, L_BFF, s, k).
10: Derive a fingerprint function fp_{ρ_fp} : K → {0,1}^µ.
11: for u = 0 to L_BFF − 1 do
12:     D[u] ← ⊥.
13: end for
14: return (D, H, fp_{ρ_fp}, L_BFF, s).

MAPPINGSTEP({K_i}_{i=1}^n, H, L_BFF)
 1: Order K_1, …, K_n by h_0(K_i) and denote the resulting sequence by L.
 2: for u = 0 to L_BFF − 1 do
 3:     T[u] ← ∅.
 4: end for
 5: for each K ∈ L do
 6:     for j = 0 to k − 1 do
 7:         T[h_j(K)] ← T[h_j(K)] ∪ {K}.
 8:     end for
 9: end for
10: Initialize an empty stack Q and an empty stack S.
11: for u = 0 to L_BFF − 1 do
12:     if |T[u]| = 1 then
13:         Push u into Q.
14:     end if
15: end for
16: while Q ≠ ∅ do
17:     Pop a location u from Q.
18:     if |T[u]| = 1 then
19:         K ← the unique keyword in T[u].
20:         Push (K, u) onto S.
21:         for j = 0 to k − 1 do
22:             v ← h_j(K).
23:             T[v] ← T[v] \ {K}.
24:             if |T[v]| = 1 then
25:                 Push v into Q.
26:             end if
27:         end for
28:     end if
29: end while
30: if |S| ≠ n then
31:     return fail.
32: end if
33: return S.

ENCODE(D, H, {(K_i, y_{K_i})}_{i=1}^n)
 1: S ← MappingStep({K_i}, H, L_BFF).
 2: if S = fail then
 3:     return fail.
 4: end if
 5: for u = 0 to L_BFF − 1 do
 6:     D[u] ←$ Z_t^B.
 7: end for
 8: while S ≠ ∅ do
 9:     Pop (K, p) from S.
10:     Retrieve the payload y_K associated with K.
11:     D[p] ← y_K.
12:     for j = 0 to k − 1 do
13:         if h_j(K) ≠ p then
14:             D[p] ← D[p] − D[h_j(K)]  (mod t).
15:         end if
16:     end for
17: end while
18: return D.

CHECK(D, H, K)
 1: for j = 0 to k − 1 do
 2:     d_j ← D[h_j(K)].
 3: end for
 4: return (d_0, …, d_{k−1}).

RECONSTRUCT(D, H, K)
 5: (d_0, …, d_{k−1}) ← Check(D, H, K).
 6: y ← 0^B.
 7: for j = 0 to k − 1 do
 8:     y ← y + d_j  (mod t).
 9: end for
10: return y.
```

### 12.2 CAPE 正文对 BFF 的**散文描述**（`out_cape.txt:1770-1805`，逐字）

- `"During setup, the parameter s determines the segment size of the BFF layout.
  The position functions generated by BFF.HashGen map each keyword to
  **k distinct locations distributed across k consecutive segments**."`
- `"The concrete finite-size choices of s and L_BFF follow the parameterization
  of BFF used in ChalametPIR [8]. For large n, the resulting array lengths
  approach 1.125n and 1.075n for k = 3 and k = 4, respectively."`
- `"The seeds ρ_H and ρ_fp are sampled independently. The former determines the
  BFF locations, whereas the latter is used to detect queries for keywords that
  were not encoded."`
- `"The temporary set T[u] contains all remaining keys mapped to location u.
  Whenever T[u] contains exactly one key K, location u is designated as the write
  location of K. The pair (K, u) is recorded in S, and K is removed from all of
  its k locations. **This may create new singleton locations, which are added to Q.**
  The mapping succeeds if all n keys are eventually placed in S."`
- `"If the mapping fails, the current construction attempt is discarded, and
  **Setup is repeated with a fresh position-function seed**."`
- `"The Encode procedure first invokes MappingStep to obtain the peeling stack S.
  … After a successful mapping, **all array entries are initialized uniformly in Z_t^B**.
  The procedure then processes S in last-in-first-out order."`

### 12.3 两篇在 `L_BFF` 上**确实不一致**（不是我们的问题）

| 出处 | 形状 |
|---|---|
| **CAPE** 附录 Alg 3 L3 | `max( ⌈(0.875+0.25·max{1,log10(n/6)})·n⌉ , ⌈1.125n⌉ )` |
| **ChalametPIR** 附录 B Alg 1 L3 | `N = ⌊c·m⌋`, `c = max( ⌊(0.875+0.25·max{1,log10(m/6)})·m⌋ , ⌊1.125m⌋ )` |

`n = 128` 时：**CAPE 给 155，ChalametPIR 给 154**。差 1。
我们的 `BffSetup.paperLBff(k, n, useCeil)` 把两者都留着，`useCeil` 就是开关。

### 12.4 ✅ 已解决：读法 B 正确，ChalametPIR Alg 1 L9 的字面公式是错的

**溯源结果**（完整报告：`coding/docs/reports/BFF位置函数溯源-HashGen原始定义-2026-10-14.md`）：

**BFF 原论文（Graf & Lemire 2022, arXiv:2201.01174 / JEA 27）只给结构约束，不给闭式：**
> *"Pick hash functions h0, h1, h2 from U to array locations in H so that
> h0(x), h1(x), h2(x) occupy **three distinct and consecutive segments**."*

**四份参考实现逐字一致**（C `FastFilter/xor_singleheader`、Java `XorBinaryFuse8`、
Rust `xorf`、**以及 ChalametPIR 自己的参考实现 `itzmeanjan/ChalametPIR`**）：

```c
h0 = mulhi(hash, SegmentCountLength)
h1 = (h0 + SegmentLength) ^ ((hash >> 18) & SegmentLengthMask)
h2 = (h1 + SegmentLength) ^ ( hash        & SegmentLengthMask)
```

⇒ **段号随 `a` 前进**（读法 B）。读法 A（ChalametPIR Alg 1 L9 字面）被三条独立证据否定：
① 与 BFF 原论文的 "distinct and consecutive" 冲突；
② 与 ChalametPIR **自己的**参考实现冲突；
③ 若 k 个位置同段，剥皮的机制就不成立。
（诚实边界：没有拿到 ChalametPIR 论文 PDF 的原始排版，所以只能断定
"字面读法与两处权威来源冲突，因此照字面实现是错的"，不能断定它是排版问题还是真错。）

### 12.5 ✅ 已实现：`bff/BffHash.java`

| 论文行 | 函数 |
|---|---|
| A3 SETUP 2/5　`s` | `BffHash.allocate(n,k).segmentLength`（= `BffSetup.paperS`，两者一致） |
| A3 SETUP 9　`HashGen(ρ_H, L_BFF, s, k)` | `BffHash.allocate` + `BffHash.positions(K, ρ_H, bp, k)` |
| A3 SETUP 10　`fp` | `BffSetup.fp`（μ=40 → 我们 32，D7） |

### 12.6 ⚠️⚠️ **论文的 `L_BFF` 闭式与它自己委托的 `HashGen` 互相不自洽**

`n = 128`、`k = 3`，**三个长度全都不一样**：

| 数 | 值 | 含义 |
|---|---|---|
| CAPE Alg 3 L3 闭式 | **155** | CAPE 自己写的 `L_BFF`（ChalametPIR 的 `⌊⌋` 版是 154） |
| `segmentCountLength` | **128** | `h_0` 的取值模数（只决定落到哪个段） |
| `arrayLength` | **256** | `h_a` 的**值域** `[0,256)` ⇒ `D` 最少要这么长 |

**两条硬冲突**（`probe/BffLayerTest` 里做成了可执行检查，都 PASS 即"冲突成立"）：
1. `155 < 256` ⇒ **`L_BFF = 155` 装不下 `h_a`**（`h_2` 能到 255）。
2. `155` 写不成 `(segmentCount + k − 1)·s` 的形状（`155/64 − 2 = 0.42` 不是整数）
   ⇒ **CAPE 给的 `(L_BFF, s) = (155, 64)` 根本描述不出一个 BFF 布局。**

**第三条独立矛盾**：CAPE Alg 3 L3 的公式在 `n = 10^6` 给 **2.18·n**，
而 CAPE 正文自称 *"the resulting array lengths **approach 1.125n**"*。
BFF 原论文表 1 写的是 `0.875 + 0.25·max(1, log(10^6)/log(n))`，在 `n=10^6` 正好给 **1.125**。
⇒ **CAPE 正文描述的是 BFF 原论文的公式，Alg 3 里那条 `log10(n/6)` 是抄错的。**

**我们的取舍**：按 CAPE 正文的指示
*"The concrete finite-size choices of s and L_BFF **follow the parameterization of
BFF used in ChalametPIR**"* —— 它**委托**给 BFF 的参数化，
所以 `BffSetup.fromBff(...)` 用 `BffHash.allocate(...).arrayLength = 256` 作为 `L_BFF`，
而不是 Alg 3 L3 的 155。**155 这个值仍然保留在 `BffSetup.paperLBff` 里**，
并在探针里与 128 / 256 一起打印，便于随时对照。

### 12.7 ✅ `R` 已定：**`R = C = √L_BFF`**（用户 2026-10-14 决定）

`A1 SETUP 4` 只写 `RC ≥ L_BFF, R ≤ N`，**没有给策略**。定为：

```
R = 2^⌊log2 √L_BFF⌋        （不超过 √L_BFF 的最大 2 的幂）
C = ⌈ L_BFF / R ⌉
```

**为什么根号开在 `L_BFF` 上、而不是 `N` 上**：
FusePIR 属于 SealPIR/OnionPIR 一系，那一系的经典做法是把数据库切成
**`√D × √D` 的方格**、查询发 `√D` 条密文。FusePIR 的 `R×C` + `C` 条列选择子
**就是这个结构**，作用在 **BFF 数组（长度 `L_BFF`）** 上。
⇒ 同一条思路给的根号是 `√L_BFF`。
⚠️ **论文里没有任何式子把 `R` 与 `N` 挂钩** —— 唯一提到 `N` 的地方就是上界 `R ≤ N`。
`R = √N` 可以跑（`√8192 ≈ 90`）但**没有依据**，而且 `√N ≈ 90 < L_BFF = 256`，
落进 `C > 1` 那侧却并不是最平衡的点。 ⇒ **不取 `√N`。**

**三条依据**：
1. `R` 取 2 的幂 —— FusePIR-C 附录 B：*"the row bits drive the bitwise evaluation of
   BlindRotate"*，且 `ℓ_r = ⌈log2 R⌉` 是**位长**，只有 2 的幂时按位分解无损。
2. 根号开在 `L_BFF` 上（上面那段）。
3. `R` 与 `C` 是同一个代价的两头：`C` ⇒ `C` 次 `CtPtMul` + `C` 条上传密文；
   `R` ⇒ `ℓ_r = ⌈log2 R⌉` 轮盲旋转。方格把两者平衡。

**实测（`probe/BffLayerTest`，30/30 通过）**：

| 路径 | `L_BFF` | `s` | `R` | `C` | `RC` | `tail` | `ℓ_r` |
|---|---|---|---|---|---|---|---|
| **BFF 参数化（默认）** | 256 | 64 | **16** | **16** | 256 | 0 | 4 |
| CAPE Alg3 闭式（仅对照） | 155 | 64 | 8 | 20 | 160 | 5 | 3 |
| 强制 `R = N` | 256 | 64 | 8192 | 1 | 8192 | **8037** | 13 |

**论文评估的全部三档规模都验过**（`n ∈ {128,256,512}`，`probe/BffLayerTest` 各 30/30 通过）：

| `n` | `s` | `segmentCount` | `segmentCountLength` | `L_BFF` | `R` | `C` | `RC` | `tail` |
|---|---|---|---|---|---|---|---|---|
| 128 | 64 | 2 | 128 | **256** | 16 | 16 | 256 | 0 |
| 256 | 64 | 4 | 256 | **384** | 16 | 24 | 384 | 0 |
| 512 | 128 | 4 | 512 | **768** | 16 | 48 | 768 | 0 |

`R = 16` 在三档相同（`2^⌊log2 √L_BFF⌋`：`√256=16`、`√384≈19.6→16`、`√768≈27.7→16`），
且三档都 `R | L_BFF` ⇒ `tail = 0`。**真实 `h_a` 下剥皮都在 1 个种子内成功。**

位置怎么落到 `(c, r)` 上的实例（关键词 #0，`u = 102 / 144 / 234`）：

| `(R, C)` | `u_0=102` | `u_1=144` | `u_2=234` |
|---|---|---|---|
| **`R=16, C=16`** | `(c=6, r=6)` | `(c=9, r=0)` | `(c=14, r=10)` |
| `R=64, C=4` | `(1, 38)` | `(2, 16)` | `(3, 42)` |
| `R=256, C=1` | `(0, 102)` | `(0, 144)` | `(0, 234)` |

⇒ `C = 1` 时三条路**都在第 0 列**，列选择子是 `RLWE.Enc([1])`，
**"同态选列"那一半完全空转**。取方格布局就是为了让这一半真的在挑（本例挑 16 列里的第 6/9/14 列）。
这也把 P1-1（列选择子密文化）留在默认路径上。

**⚠️ 这条策略的副作用**：`L_BFF` 是 2 的幂时 `R | L_BFF` ⇒ **`RC = L_BFF` ⇒ `tail = 0`
⇒ `A1 SETUP 9-11` 是空循环**。这是合法的（论文只要求 `RC ≥ L_BFF`）。
要让那一步真的清槽，只能 `R > L_BFF`，而那时 `C = 1`
—— **二者在 `L_BFF` 为 2 的幂时互斥**（`tail = 0 ⟺ R | L_BFF`，`C > 1 ⟺ R < L_BFF`）。
探针里用 `forceR = N` 把这个非空尾部逼出来验过（8037 个槽，`zeroTail` 全部清 0）。

**⚠️ 与论文自己那组实测的差**：论文在 `n ∈ {128,256,512}` 上是 **`C = 1`**（§13.3），
我们取方格布局 ⇒ `C = 16`。**两者都满足论文给出的唯一约束**；
我们取方格是因为它让"同态选列"真的在做事。**这是我们主动选的一条偏离，如实登记。**

---

## 13. 论文的数值参数（逐条抄自原文，附行号）

> 来源同 §12。**这一节只抄论文写了的东西**；论文没写的明确标 "未给出"。

### 13.1 HE 参数（`out_cape.txt:1152-1161`，逐字）

```
1152: Our implementation uses Microsoft SEAL [40] with the BFV
1153: homomorphic encryption scheme. We set the plaintext modu-
1154: lus to t = 65537 and use the default configuration in SEAL to
1155: achieve 128-bit security. The degree of the polynomial mod-
1156: ulus is N = 16384. The BFF uses three hash positions per
1157: keyword and the fingerprint length is 40 bits.
```

| 参数 | 论文 | 我们 | 差 |
|---|---|---|---|
| 方案 | Microsoft SEAL / **BFV** | SEAL(BFV) 打分信道 + 自建 RGSW native 信道 | 结构差 D11（两个 `t`） |
| `t` | **65537** | native 信道 `2^32`；打分信道 65537 | ⚠️ D11 |
| 安全 | 128-bit，「SEAL 默认配置」 | 自定 | 未核 |
| `N` | **16384** | **8192** | ⚠️ 差一倍（见 §13.4） |
| BFF 位置数 | **3** | 3（但形态不对，见 §11.3 ①） | ⚠️ |
| 指纹长度 | **40 bit** | 32 bit（`String.hashCode`） | ⚠️ D7 |
| `ε_BF` | **2^−20** | 2^−6 | ⚠️ D5c（已登记） |

**未给出**：log q / 系数模数链、LWE 维数 `d` 的数值、`B_pay` 的数值与定义、
`ℓ(n, ε_BF)` 的展开式、Bloom 哈希个数 `h` 的数值。原文第 157 行明说
*"parameters and ciphertext dimensions are omitted"*。

### 13.2 论文实验规模（`out_cape.txt:1179-1180`、`1217-1219`）

- 单关键词：`n ∈ {128, 256, 512}`、`m ∈ {2^13, 2^14, 2^15}`、值长 16/64/256/1024 bit。
- 合取：`n ∈ {128, 256, 512}`、`m ∈ {2^9, 2^10, 2^11}`、`Q ∈ {3,5,10,20,30}`、值长 16 bit。

⇒ **论文自己就在 n = 128 这一档做实验**，与我们的 demo 同一规模。

### 13.3 ⭐ 证据：论文那组实验里 **`C = 1`**

三条独立证据：

**① 每查询 3 条 RLWE 密文**（`out_cape.txt:2278-2279`，安全性证明逐字）：
```
2278: Hence, the only challenge-dependent part of the adversary's
2279: view is the collection of the 3ℓ RLWE ciphertexts and the 3ℓ
2280: LWE ciphertexts contained in the challenge queries.
```
`ℓ` 是 ℓ-query 实验里的**查询次数** ⇒ **每查询 3 条 RLWE + 3 条 LWE**。
A1 ANSWER 5 是 `Σ_{c=0}^{C−1} CtPtMul(q_a^col[c], P_{c,b})`，`q_a^col` 是 **C 条**密文的向量；
乘上 3 个 BFF 位置 ⇒ 每查询 `3C` 条 RLWE。`3C = 3` ⇒ **`C = 1`**。

**② 查询大小 2304.97 KiB 正好是 3 条 SEAL 密文**（`out_cape.txt:1211`）：
SEAL 序列化时每个系数按**一个 `uint64` × 模数个数**存。
`N = 16384` + **3 个 60-bit 素数**（`log q = 180`）⇒ 单条
`2 × 16384 × 3 × 8 = 786432 B = 768 KiB`。
`2304.97 KiB ÷ 768 KiB = 3.0013` ⇒ **3 条**。
（旁证：MMK 的查询大小是 **768.25 KiB** = 正好 1 条；MMK 只发 1 条。）

**③ 查询大小与 `n`、`m` 无关**（Table 2 里全部 2304.97 KiB）：
`n` 从 128 涨到 512、`m` 从 2^13 涨到 2^15，`C` 不变 ⇒ `C = 1` 在三档都成立。

⇒ **`R` 只需满足 `R ≥ L_BFF`**（这样 `C = ⌈L_BFF/R⌉ = 1`）。
论文的 `R ≤ N` 上界（`N = 16384`）非常宽松，说明论文在这个规模上
**根本没触发多列**，`R` 的具体取值对他们也不敏感。

> ⚠️ **一条与之张力相反的线索，必须一起记**：同一条证明接着说
> *"We first replace, one at a time, each RLWE encryption RLWE.Enc(e_{c(r,0)})
> with RLWE.Enc(e_{c(r,1)})"* —— 若 `C = 1` 则 `e_{c_a}` 恒为 `[1]`，
> 这步 hybrid 就是空的，证明会退化。**⇒ 论文在这一点上内部不自洽**
> （要么 `C > 1` 与查询大小矛盾，要么这句 hybrid 写法不严谨）。
> **这是论文的问题，不是我们的 bug**；我们按 ①②③ 这三条**可算**的证据取 `C = 1`，
> 并把这条张力登记在这里。

### 13.4 我们与论文的参数差（要一起说的）

| 项 | 论文 | 我们 | 影响 |
|---|---|---|---|
| `N` | 16384 | 8192 | native 上下文、RGSW 键、密文大小全部差一倍。**改它要重跑全部性能数字** |
| `m`（每关键词值数） | 2^9…2^15 | **3** | 我们的 demo 是**迷你实例**：`B_pay = 60`（论文推断下会是 2+m(1+ℓ_BF)，m=512 时上千） |
| `ℓ_V` | 16 bit | 值 id 为小整数 | demo 简化 |
| 响应大小 | CAPE 3/6/12 MiB（∝ m，与 n、Q 无关，`out_cape.txt:1444-1462`） | `B_pay` 条密文 | ⚠️ 论文响应**只随 m 增长**，这给 `Pack` 的输出规模提供了硬约束（§10.3 ② 那条推断可以据此收紧） |
---

## 14. ✅ 论文几何已接进 FusePIR/CAPE（2026-10-14 深夜，本轮）

### 14.1 新老几何的对照（这是本轮改动的全部内容）

| | 旧几何（仍在，作对照） | **新几何（论文几何，默认路径）** |
|---|---|---|
| 位置函数 | `BffEncode.keywordHash`：哈希 + **线性探测**，**1 个位置** | **`BffHash.positions`**：`h_a`，**k 个分散位置** |
| `u → (列, 行)` | `c = u / cellsPerCol`、`r = (u % cellsPerCol)·maxValues + a` | **`c = ⌊u/R⌋`、`r = u mod R`** |
| k 路 | 一个 cell 的 **k 个连续行** | 三个**独立的 `h_a` 位置** |
| `L_BFF` | `cellsPerCol·C = 130`（几何副产品） | **256** = `(segmentCount+k−1)·s`（BFF 参数化） |
| `R` / `C` | `R = 16`（环内行数）、`C = 26` | **`R = 16`、`C = 16`**（`R = C = √L_BFF`） |
| 写表 | 随机拆 k 路 + 全部覆写 | **剥皮 MAPPINGSTEP + LIFO 回填** |
| 表形状 | `[26][59][8192]` = 12 M long | **`[16][59][8192]` = 7 M long** |
| `dataRadius` | 15 = `(cellsPerCol−1)·maxValues + k` | **16 = `R`** |
| 尾部补零 | 空区间（Σ 见 §11.3③） | `RC = L_BFF` ⇒ 也是空（`R \| L_BFF`） |

### 14.2 新增的代码

| 文件 | 内容 |
|---|---|
| `bff/BffHash.java` | `allocate()` + `h_a` |
| `bff/BffMapping.java` | MAPPINGSTEP |
| `bff/BffEncode.java` | `encode`（LIFO 回填 + 换种子重试）、`zeroTail`、`embed`、`reconstruct` |
| `bff/BffSetup.java` | `Layout`、`layout`（方格策略）、`selectRC`、`fromBff` |
| `bff/CapeDemoData.java` | **`buildTablesPaper(ringDim, k, t, seed, forceR, hashSeed)`** + 抽出的 `buildPayload`（两条几何共用 A1 SETUP 6） |
| `cape/CapeQuery.java` | **`buildPaper(...)`** + `buildWithIndices(...)`：把"几何→索引"与"索引→密文"拆开，**两条几何共用同一份密文构造** |
| `bff/CapeDemoData.Tables` | 新增 `pos[kwCount][k]`、`layout`、`colRow(i, a)` |

**native 侧一行未改** —— `nativeCapeAnswer(ctx, d, C, k, bPay, flat, cIdx, rIdx)` 的 `cIdx`/`rIdx` 本来就是**按路**传的数组，两套几何只是喂不同的值。

### 14.3 验收（全部离线，**不含任何 HTTP 往返**）

| 探针 | 结果 | 验的是 |
|---|---|---|
| `probe/BffLayerTest 128 8192` | **30/30 PASS** | A3 MAPPINGSTEP/ENCODE/CHECK/RECONSTRUCT、A1 SETUP 4/9-11/12-16、`h_a` 三条性质 |
| `probe/BffLayerTest 256 8192` | **30/30 PASS** | 同上（论文第二档规模） |
| `probe/BffLayerTest 512 8192` | **30/30 PASS** | 同上（论文第三档规模） |
| `probe/CapePaperGeometryTest <db> 8192` | **15/15 PASS** | 建表 + 跨端索引一致性 + **旧几何分支的等价性回归** |
| `probe/CapePaperNativeTest <db> 8192 16 2` | **3/3 PASS** | **真实盲旋转**下的密文侧假阴性 0 |
| `bloom/BloomScoring 8192` | PASS | Bloom 侧（与几何无关） |
| `probe/CapeBffParamDiag` / `CapeTableDiag` | ALL PASS | 旧几何未回归（旧路径仍可用） |

关键数字：
* **`Σ_a P_{c_a,b}[r_a] = y_K[b]` 对 128 关键词 × 59 载荷位 = 7552 项全部成立**（明文侧）
* `CapeQuery.buildPaper` 的 `(c_a, r_a)` 与建表的 `colRow` 对 **128 关键词 × 3 路 = 384 项**逐位一致
* **`CapeQuery.build` 重构后与旧建表逐位一致**（128 × 3 = 384 项）——
  这条是必需的，因为服务默认路径用的就是它，而"编译通过"**不是**等价性的证据（见 §14.6）
* **真实盲旋转**：2 个关键词载荷 **0/59 失配**；两条负对照（行号挪一格 / 列号挪一格）都是 **59/59 失配**
* 负对照：改一个被读到的系数 → 3 个关键词失配；用错的行/列公式反算 → **128/128 全失配**
* 负对照：回填顺序从 LIFO 改成正序 → **125/128 全失配**（LIFO 是语义不是风格）

### 14.4 ⚠️ 被推翻的旧数字（要一起说）

| 项 | 旧值 | 新值 | 说明 |
|---|---|---|---|
| `C` | 26 | **16** | 列选择子密文数 3×26=78 → **3×16=48** |
| 查询里列选择子部分 | ≈ **41 MB** | ≈ **25 MB** | 按 N=8192、每条 524,401 字节实测推算 |
| 表大小 | 12 M long | **7 M long** | `[26]` → `[16]` |
| `L_BFF` | 130 | **256** | 定义整个换了（几何副产品 → BFF 参数化） |
| `dataRadius` | 15 | **16** | |
| 单关键词的落点 | 1 个 cell 的连续 3 行 | **3 个分散位置** | |
| `CapeBffParamDiag` 的断言「k 个位置 = 同一列的连续 3 行」 | ✓ | **只在旧几何成立** | 该断言现在描述的是旧路径；新路径见 §12.7 |

**仍然有效、未被推翻的**：`BloomScoring`（与几何无关）、`CapeWireFormatProbe` 的线格式、
`s_L == s_R` 这条硬约束（§P1-1）、Bloom 侧的全部结论。

### 14.5 范围与接线状态（2026-10-14 深夜，按用户指示收窄）

⚠️ **本轮的交付范围是 `bloom/` 与 `bff/`**（"我要 bff 和 bloom 完全满足后续 FusePIR 和 CAPE 的调用"）。
我一度把 `CapeDemoService` 的默认路径也切了 —— **那是 CAPE 侧的行为改动，不在这一步，已完全回退**：

| 文件 | 状态 |
|---|---|
| `cape/CapeDemoService.java` | **已回退**，运行行为与改动前**完全一致**（仍走旧几何、仍用 `tb.colOf/rowOf`）。核验：3 对 `cIdx[a]=tb.colOf[…]` / `rIdx[a]=tb.rowOf[…]+a` 齐全，全文无 `colRow`/`paperGeometry`/`buildTablesPaper` 痕迹 |
| `cape/CapeQuery.java` | ⚠️ **唯一保留的 `cape/` 改动**，且**不改变行为**：`build(...)` 只是被拆成"先算几何 → 再交给 `buildWithIndices`"，逐位等价；另外**新增** `buildPaper(...)`。保留它的理由：它是"bff 完全满足下游调用"这条要求的**调用方证据**，而且由 `CapePaperGeometryTest` 正面验过（不是没人跑的死代码）。⚠️ 那个"逐位等价"的声明**不是靠看代码断言的** —— `CapePaperGeometryTest` §旧几何分支把 128 关键词 × 3 路逐个与旧建表的 `(colOf, rowOf+a)` 对过（**384 项全等**，负对照 R 16→8 能检出）。**若你希望 cape/ 一行都不动，说一声我就回退。** |

**⏳ 明确没跑的**（按"先不用跑全连接"）：

1. `CapeDemoService` **没起过**，`-Dcape.selftest=true` 没跑，`/api/query-sealed` 没打过 ——
   下面所有验证里**不包含任何 HTTP 往返**。
2. 服务侧探针未重跑：`CapeDefaultPathTest`、`CapeAlgorithm2Diag`、`CapeColumnSelWireTest`。
3. `CapeQuery.buildIndicesOnly`（跨进程格式探针用）仍用旧公式。

### 14.6 ⚠️ 本轮我自己造成的一个 bug（必须记）

回退 `CapeDemoService` 时发现：我用 `[regex]::Replace` 做批量替换，
替换串里的 `$1cIdx[a] = cr[0];` 被 .NET 的替换语法解析错，
**把 `cIdx[a] = cr[0];` 与 `rIdx[a] = cr[1];` 两行静默吃掉了**，只剩 `int[] cr = …` 一行。

**而代码照样编译通过** —— 因为 `cIdx`/`rIdx` 本来就先 `new long[K]`（全 0），
少两行赋值只是让它们保持全 0，于是 native ANSWER 会**三路都读槽 0** ⇒ 静默错误答案。

* 影响范围：**零**。服务从未启动，`CapePaperNativeTest` 自己构造 `cIdx/rIdx`，
  所以没有任何已跑的验证被污染。
* 已经修好（三处按原样还原），并且**加了一条机械核验**：
  `cIdx 赋值 3 处 / rIdx 赋值 3 处` 必须成对。

**教训（与前面几次同类）**：`[regex]::Replace` 的**替换串**不是字面量，
`$` 有特殊含义；批量改代码要么用字面量 `.Replace()`，要么改完**逐处核对**。
而且"编译 0 错误"**不是**批量改动正确的证据 —— 这次它掩盖了两行丢失。

### 14.7 实测对照（同机、同数据集）

| | 旧几何 | 新几何（论文） |
|---|---|---|
| `L_BFF` | 130 | **256** |
| `R` / `C` | 16 / **26** | 16 / **16** |
| 表大小 | `26×59×8192` = **95.9 MB** | `16×59×8192` = **59.0 MB** |
| **ANSWER 一次** | **77,775 ms**（439.41 ms/unit） | **76,165 ms**（平均，C=16） |
| 载荷失配 | 0/59 | **0/59** |

⇒ **换几何没有解决速度问题**：`C` 从 26 降到 16，ANSWER 只快了约 2–6%，
因为瓶颈在**盲旋转**（约 400 ms/unit × 177 unit），不在 `CtPtMul`。这与 P1-1 的结论一致。

⚠️ 两次实测的 `t` **不同**（旧探针硬编码 `65537`，新路径用 DB 里的 `2^32`），
所以这个百分比只能当**指示性**数字，不是严格控制变量下的对照。
---

## 15. `bloom/` 与 `bff/` 完整性审计（2026-10-14 深夜，回答"是否完整"）

> **问题**：`bloom/` 和 `bff/` 是不是都完整了？
> **答案**：**查完之后不能说"完整"。** 审计翻出 4 类问题，其中 1 类是**真的没做到"完全满足调用"**。
> 下面每条都是 grep 出来的，不是印象。

### 15.1 审计方法

对 `bloom/` 与 `bff/` 的**每一个公开函数**做调用点统计
（`\bfn\s*\(`，排除 javadoc 行与函数定义行）。
⚠️ 第一遍我用了**限定名**（如 `BffSetup.fp(`），同文件内的非限定调用匹配不到，
得到一堆假阳性（`oracleHash`、`foldSlots`、`foldAllSlots`、`mappingStep` 都被误判成死代码）。
**改用裸函数名重查才是对的。**

### 15.2 查出来的 4 类问题（都已修）

| # | 问题 | 性质 |
|---|---|---|
| 1 | **`BffSetup.fp` 是死代码（0 个调用方）**，而 `fp` 这个算式在项目里写了 **4 遍**：`BffSetup.fp`、`CapeDemoData.buildPayload`（`inField(kw.hashCode(), t)`）、`FusePirDecode.fpOf`（同式）、`CapeDemoService:1081`（同式）。**`fp` 是 A1 SETUP 1 的 `(D, H, fp) ← BFF.Setup(n,3)` 三个产物之一，属于 BFF 层** —— 所以"下游绕过 bff 自己算"正是"bff 没完全满足调用"的直接证据 | ❌ **真问题，已修**：三处改为调 `BffSetup.fp`（唯一实现） |
| 2 | **`BffSetup.newD` 是死代码**（`BffEncode.encode` 自己 `new long[rc][bPay]`）。而且**它的 javadoc 是错的**：写着形状是 `[L_BFF][B_pay]`，但 A1 SETUP 9-11 要写 `D[u], u ∈ [L_BFF, RC)` ⇒ 论文里 `D` 就是 `[RC][B_pay]` 长，按 `[L_BFF]` 分配那一步会直接越界 | ❌ **真问题，已修**：`encode` 改调 `newD`；javadoc 更正为 `[RC][B_pay]` |
| 3 | **`BffSetup.setup` 是死代码**（0 调用方）。它是 `A3 SETUP 1-2` 的入口 `(s, L_BFF) ← BFF.Setup(n,3)` | ⚠️ 已修：`selectRC` 改为经 `setup` 取值；另加 `setup(n,k,useCeil)` 重载 |
| 4 | **三处 javadoc 与代码矛盾**：`bff/BffEncode` 类注释与 `bff/BffSetup` 类注释都写 *"`h_i` 没有实现"*（**已经实现了**，在 `BffHash.positions`）；`bloom/BloomSetup` 类注释写 *"`S_v` 有两份独立实现"*（**已收敛成一份**，`CapeQueryDecode` 现在调 `BloomSetup.valueToKeywords`） | ❌ **注释撒谎，已改** |

### 15.3 复查结果：bff/bloom 里已无死代码

修完之后对 16 个关键函数重查，**全部有 ≥1 个调用方**：
`fp`(24)、`newD`(1)、`setup`(11)、`oracleHash`(1)、`mix`(2)、`foldSlots`(2)、
`foldAllSlots`(2)、`layout`(6)、`fromBff`(1)、`selectRC`(2)、`embed`(2)、`zeroTail`(2)、
`reconstruct`(4)、`encode`(17)、`positions`(8)、`allocate`(4)。

**回归**：`fp` 的改动直接动载荷内容，所以重跑了全部探针 ——
`BffLayerTest 128` 30/30、`CapePaperGeometryTest` 15/15、`CapeTableDiag` 15/15
（**假阴性 0、假阳性率仍 0.0344**，与改动前逐位相同 ⇒ 纯重构）、
`BloomScoring` 8/8、`CapeBffParamDiag` 16/16。全部 exit=0。

### 15.4 ⚠️ 仍然**不**完整的地方（这些不是代码缺失，是别的东西）

"函数齐了 + 都有人调" ≠ "完全符合论文"。下面这些要一起说：

| # | 项 | 性质 |
|---|---|---|
| A | **`fp` 是 32-bit `String.hashCode`，论文是 40-bit** | **保真度缺口**（D7）。函数在、被调用、行为正确，但**取值域不对**。改它要动 `t` 相关的对齐，是独立一轮 |
| B | **`h_a` 按 BFF 参考实现落地，不是 CAPE 所引 ChalametPIR 的字面公式** | 因为那条字面公式把 k 个位置放同一段，与 BFF 原论文 + ChalametPIR 自己的参考实现都矛盾（§12.4） |
| C | **`L_BFF` 用 BFF 参数化（256），不是 CAPE Alg3 闭式（155）** | 因为 155 与 `HashGen` 互不自洽（§12.6） |
| D | **`R` 的策略是我们的（`R = C = √L_BFF`）** | 论文只给约束、没给策略（§12.7） |
| E | **`bff/` 里同时存在两套几何** | 旧的那套（`keywordHash`/`place`/`splitShares`/`writeD`/`randomizeD`）**仍有调用方** —— 只经 `CapeDemoData.buildTables`（旧几何对照路径）。不是缺口，但"bff 里有两套写法"本身是维护风险 |
| F | **`bff/CapeDemoData` 仍是 615 行的单类** | 混了 JSON 解析 + DB 装载 + 建表（两套几何各一份入口）。MAP §7 已记 |
| G | **`probe/` 下还有几份自己写的 `S_v` / `b_v` / 指纹副本** | 一次性诊断件，不在生产路径上（`CapeAnswerFull:65`、`CapeColumnPacked:87`、`CapeEndToEnd4:177`、`CapeEndToEndNative:90`） |
| H | **`Pack` 仍然没有**（A1 ANSWER 13） | 所以 A2 ANSWER 3 要的 `ct^BF_j` 无法从协议里产生（D2）。**范围在 `fusepir/`/`cape/`，不是 bloom/bff 的缺口** |
### 15.5 ✅ 状态更新（2026-10-14 深夜第二轮：A 已做、E 已做、F 未做）

用户指示"完成它两（A + E/F），不用跑全连接，更新 MAP 中 bloom 与 bff 状态"。实际结果：

#### ✅ A：`fp` 从 32-bit 改成论文的 **40-bit**（D7 已消除）

**关键约束（实测确认）**：论文 §5.1 是 `μ = 40`，而**论文自己的 `t = 65537` 只有 16 bit/槽**
—— 40 bit **装不进一个 `Z_t` 槽**。所以 `y = fp ‖ m ‖ v…` 里那个 `fp`
必然是 `⌈40/⌊log2 t⌋⌉` 个槽。我们此前推的 `B_pay = 2 + m·perValue`
里的那个 `2` 就是把 40-bit `fp` 当成了 1 个槽 —— **论文从未写过 `B_pay` 的算式**，所以这是我们该修的推断。

| `t` | 每槽 | `fpSlots` |
|---|---|---|
| 我们的 native `2^32` | 32 bit | **2** |
| 论文的 `65537` | 16 bit | **3** |

新增/改动的 API：
* `FusePirSetup.FP_BITS`(40)、`slotBits(t)`、`fpSlots(t)`、`countOffset(fpSlots)`
* `payloadBpay(fpSlots, m, perValue)`、`valueOffset(fpSlots, j, perValue)`、`bloomOffset(...)`
  —— **三个签名都加了 `fpSlots`**，于是 18 个调用点**全部编译报错**（这正是我要的：编译期暴露，不静默）
* `BffSetup.fp(String)`（40-bit）、`fpDigits(kw, t, fpSlots)`、`fpFromDigits(y, off, fpSlots, t)`、
  `FP_SEED`（**与 `ρ_H` 独立的指纹种子**，对齐正文 *"seeds ρ_H and ρ_fp are sampled independently"*）
* `FusePirDecode.fpOf(kw)`、`fingerprintOk(kw, y, t)`（A1 DECODE 6 的 ⊥ 判据）、`nativeFieldModulus()`
* `CapeBloomScore.score(..., fpSlots)` 重载（候选数下标随 `fpSlots` 走）

**验收**（`probe/CapePaperGeometryTest` 新增 `fingerprint40Section`，总计 **22/22**，exit=0）：
* `t=2^32 ⇒ fpSlots=2`；`t=65537 ⇒ fpSlots=3`（与论文一致）
* **拆—拼往返**：128 个关键词的 40-bit 指纹都能从载荷拼回
* 指纹最大值 ≥ `2^32` —— **确实用到了 32 bit 以上的位**（32-bit 版做不到）
* ★ 正确的关键词：`fingerprintOk` 对全部 128 个通过（假阴性 0）
* **[负对照]** 用错的关键词去校验 ⇒ **128/128 全被拒**
* **[负对照]** 把指纹槽改 1 ⇒ 校验失败（不是恒真）

**被推翻的数字**：`B_pay` **59 → 60**（多一个指纹槽）。
响应大小、`ANSWER` 时间相应 +1/60 ≈ +1.7%（未实测，服务没跑）。

#### ✅ E：旧几何已从 `BffEncode` 搬出

`bff/BffEncode.java` **只留论文路径**（`checkDataRadius` + `PositionFn`/`Table`/`encode`/`embed`/`zeroTail`/`reconstruct`），
旧几何那套（`keywordHash`/`mix`/`Placement`/`place`/`splitShares`/`randomizeD`/`writeD`）搬到
**`bff/BffEncodeLegacy.java`**。

⚠️ **为什么是"搬"而不是"删"**：回退后的 `CapeDemoService` 与 `CapeQuery.build(...)`
**仍在用旧几何**（MAP §14.5）。删掉会让服务直接编译不过。
所以做成"搬到明确命名的地方" —— `bff/` 的默认表面只剩论文路径，
旧路径的存在一眼可见。**等服务默认路径切到论文几何后，这个文件可以整个删除。**

#### ❌ F：`CapeDemoData` **没有拆**

它现在 **748 行**（比之前的 615 行还长，因为 `buildPayload` 加了指纹拆槽与往返自检）。
仍混着：JSON 解析 + DB 装载 + **两套几何的建表入口**（`buildTables` / `buildTablesPaper`）+ `Tables` holder。
**这是本轮没做完的一项**，如实登记。

#### 回归（全部离线，无 HTTP 往返）

| 探针 | 结果 |
|---|---|
| `BffLayerTest 128 8192` | 30/30 exit=0 |
| `CapePaperGeometryTest` | **22/22** exit=0（含新增的 40-bit 指纹节） |
| `CapeTableDiag` | 15/15 exit=0 |
| `CapeBffParamDiag` | 16/16 exit=0 |
| `BloomScoring 8192` | 8/8 exit=0 |
| `CapeBloomScore 8192 18` | 15/15 exit=0 |
| `CapeWireFormatProbe 8192 18` | 9/9 exit=0 |

**过程中修掉的一处真 bug**：`CapeTableDiag` 里候选数下标**硬编码成 `pay[1]`**、
值起始**硬编码成 `2 + v*(1+lBf)`**。`fpSlots` 变成 2 之后这两处会**静默读错槽**
（`pay[1]` 变成指纹的第 2 位）⇒ 该探针报"**假阴性 = 298**"。
已改为走 `FusePirSetup.countOffset/valueOffset`。
**这正是 `fpSlots` 加进签名要防的事** —— 但只防住了走布局函数的地方，硬编码的那些得靠跑探针抓。

#### ⚠️ 一个**未查清**的现象（如实登记，没有解释）

`CapeTableDiag` 的**实测**假阳性率**不变**（0.0344，与 40-bit 改动前逐位相同），
但它同时打印的**理论值 `mean((k_v/ℓ)^h)` 从 0.0164 变成了 0.0221**。
我**还没查清**为什么 —— 理论上 Bloom 那条链路与指纹无关。
已记为待查项，不当作"没发生"。
### 15.6 ⚠️ 第三轮复查：**A 原来只做了一半**（2026-10-14 深夜）

用户问"BFF 完善了吗"，我按惯例先查再答 —— 结果查出 **4 处生产侧消费方还在按旧的 1 槽布局读载荷**。

#### 问题：40-bit 指纹改完之后，读的那一侧没跟着改

| 文件 | 旧代码 | 后果 |
|---|---|---|
| `cape/CapeBloomScore.fingerprintOf(payload)` | `return payload[0]` | 只拿到 40-bit 指纹的**低 32 位** ⇒ `f ≠ fp(K)` **恒成立** ⇒ **所有查询都返回 ⊥** |
| `cape/CapeAnswer:97` | `(int) payload[1]` | 候选数变成指纹的**第 2 位**（一个巨大的数）⇒ `Math.min(cnt, maxValues)` 恒为 `maxValues`，看起来"还能跑" |
| `cape/CapeDemoService:1081` | `CapeDemoData.inField(kw.hashCode(), t)` | 期望指纹是**旧的 32-bit 值** ⇒ P0-4 校验恒 FAIL |
| `cape/CapeAnswer.answer(...)` | 无 `t` 参数 | 拿不到 `fpSlots`，无法定位槽 |

**这四处都不是编译错误**（`payload[0]`/`payload[1]` 语法上完全合法），
所以"编译 0 错误 + 探针全绿"**完全掩盖了它们** —— 因为跑的那 7 个离线探针里，
没有一个走 `CapeAnswer.answer(...)` 这条路（它只被 `CapeDemoService` 用）。

⇒ **教训**：改一个**跨层的数据布局**（这里是载荷的槽布局）时，
"改了定义方 + 调用方能编过" 只覆盖了**走布局函数**的那部分；
**硬编码下标的地方是编不过也测不到的盲区**。
本轮这类盲区一共 6 处（`CapeTableDiag` 2 处 + 上面 4 处）。

#### 已修

* `CapeBloomScore.fingerprintOf(long[] payload, long t)` —— 用 `BffSetup.fpFromDigits` 拼回 40-bit
* `CapeBloomScore.valueCountOf(long[] payload, long t)` —— 走 `FusePirSetup.countOffset`
* `CapeAnswer.answer(..., long t)` —— 新增 `t` 参数；`CapeDemoService` 传 `t`
* `CapeDemoService` 的期望指纹改为 `BffSetup.fp(query.get(0))`（bff 层唯一实现）
* 删掉两个**死代码**：`CapeDemoData.inField`（无调用方）、
  `BffSetup.fp(String, long)`（40-bit 上线后无调用方）；"静默回绕"那段警告挪到
  `BffSetup.oracle40` 的注释里

#### 回归

`BffLayerTest` 30/30、`CapePaperGeometryTest` 22/22、`CapeTableDiag` 15/15、
`CapeBloomScore` 15/15、`CapeBffParamDiag` 16/16、`BloomScoring` 8/8、
`CapeWireFormatProbe` 9/9 —— **全部 exit=0**（仍未跑全连接）。

⚠️ **但这四条修改所在的路径（`CapeAnswer.answer` → `CapeDemoService`）
在离线探针里覆盖不到，只有跑服务才会走到** —— 按用户指示没跑。
所以对它们我只能说"改对了、编过了"，**不能说"验过了"**。

#### 当前 bff/ 的完成度（诚实版）

| 维度 | 状态 |
|---|---|
| 论文要求的函数**齐全** | ✅ `BFF.Setup`(s/L_BFF/D/H/fp)、`MAPPINGSTEP`、`ENCODE`(LIFO+重试)、`CHECK/RECONSTRUCT`、`select R,C`、尾部补零 —— 全在 `bff/` |
| 每个函数**都有调用方** | ✅ 复查过（裸函数名逐个查，避免上一轮的假阳性） |
| **`fp` 40-bit**（D7） | ✅ 已修（拆槽 + 往返 + ⊥ 判据 + 2 条负对照） |
| 旧几何**已移出默认表面** | ✅ 搬到 `bff/BffEncodeLegacy`（**没删**，因为回退后的服务仍在用） |
| **无死代码** | ✅ 本轮的 2 处已删 |
| `h_a` 按**参考实现**而非所引字面公式 | ⚠️ 见 §12.4 —— 那条公式可被证伪 |
| `L_BFF` 用 BFF 参数化而非 CAPE 闭式 | ⚠️ 见 §12.6 —— 闭式与 `HashGen` 互不自洽 |
| `R` 的策略是我们的 | ⚠️ 见 §12.7 —— 论文只给约束 |
| **`CapeDemoData` 未拆（F）** | ❌ **仍 747 行**，混 JSON 解析 + DB 装载 + 两套几何建表入口 |
| 服务侧那 4 处修改**未实测** | ⚠️ 见上 |
### 15.7 第四轮：按伪代码补齐函数（子代理系统清点 + 已修项）

用户指示："根据论文以及伪代码完成各个调用所需的函数包括未完成的 bff，先不用连接 FusePIR 和 CAPE"。
我开了一个子代理做 **Algorithm 1/2/3 + Alg 4(FusePIR-C) + Alg 5(CAPE-C) 逐行 → Java 函数** 的清点
（用**裸函数名** grep 查调用点，避免限定名的假阳性）。

#### ✅ 本轮修掉（都是子代理查出来或我自查出来的）

| # | 问题 | 修法 |
|---|---|---|
| 1 | **`BFF` 的 `Check` 没有独立过程** —— 论文里 `Check(D,H,K)`（取 `d_j←D[h_j(K)]`）与 `Reconstruct`（求和）是**两个**过程，此前被压成一个 `reconstruct` | 新增 `BffEncode.check(d, posOf, k, bPay)` 返回 `(d_0..d_{k−1})` 并做范围自检；`reconstruct` 委托它 |
| 2 | **`BffHash.allocate` 把 `3.33/2.25` 写死、与 `k` 无关** ⇒ `k=4` 会静默拿到 `k=3` 的段长，而 `paperS(4,n)` 用 `2.91/−0.5`（两个口径不一致且都不报错） | `allocate` 现在调 `BffSetup.paperS(k,n)`；**且 `k≠3` 直接拒绝** —— k=4 的容量常量（0.77/0.305）我们没对着参考实现核过，编一个"看起来合理"的数比报错危险 |
| 3 | **`HashGen` 缺伪代码的原签名** —— 伪代码是 `HashGen(ρ_H, L_BFF, s, k)`，(L_BFF, s) 是**入参**；此前只有 `positions(…, BffParams, k)`（参数从 n 推出来） | 新增 `BffHash.hashGen(lBff, s, k)`：反解 `segmentCount = L_BFF/s − (k−1)` 并校验，**描述不出布局的组合在调用点就被拒**（如 CAPE 的 `(155, 64)`）；`BffLayerTest` 里配了负/正对照 |
| 4 | **我这轮自己造的死代码 3 处**（`BffParams.hashGen()`、`BffSetup.setup(n,k)` 2 参重载、`positions(List,seed,HashGen)`） | 前两个改为**被生产路径调用**（`CapeDemoData` 现在走 `bp.hashGen()`）；2 参重载**删除** |
| 5 | `BffSetup` 的 javadoc 指向**已搬走**的 `BffEncode#keywordHash`，以及**已退役**的 `FusePirSetup#span`（旧几何） | 已改指 `BffEncodeLegacy#keywordHash` / `fromBff`，并注明旧几何口径已退役 |

回归：`BffLayerTest` n=128 **32/32**、n=512 **32/32**、`CapePaperGeometryTest` 22/22、
`CapeTableDiag` 15/15、`CapeBffParamDiag` 16/16、`BloomScoring` 8/8、`CapeBloomScore` 15/15、
`CapeWireFormatProbe` 9/9 —— **全部 exit=0**。

#### ⚠️ 子代理清点出的**仍未完成**项（按"是否卡住调用方"排序）

**Tier 1 — 真的卡住调用方（伪代码那一行写不出来）**

1. **`Pack({ct_{pay,b}})`**（A1 ANSWER 13 `out_cape.txt:901`；A2 ANSWER 3 `:1043`）。
   ⚠️ **且 §6:294 "Pack 整个没有 / 没有文件" 这个说法不准**：
   `prim/RingPack.pack(...)`（`:154`）是一个**真的 ring packing** 原语且被验过
   （`probe/PackGoalCheck:151` 明说"论文的 Pack 已经另起一个类实现并验证了"），
   但它收的是**明文 LWE 分量** `(as, bs)`，不是 `{ct_{pay,b}}` 这组密文，
   而且**没有任何协议代码调它**。所以准确说法是：
   *"ring-packing 原语有了；缺的是收 ANSWER 那组密文的 `Pack`，以及任何调用方"*。
   ⚠️ 另外 `probe/SampleToPackLink:125` 实测 `|residual|` 最大 ≈30（位值是 1）
   ⇒ 就算套上适配器，A2 的 `s_j = τ` **精确相等**判据在那条路上也不成立。
2. **`BFF.Check`** —— ✅ 本轮已加（见上表 #1）。
3. **Algorithm 4/5（FusePIR-C / CAPE-C）整条查询压缩链没有实现**：
   `PRG(ρ,a,j)`（`:2044-2046`、`:2121`）、`bin_ℓ(x)`（`:2042`）、`ℓ_c=⌈log2 C⌉, ℓ_r=⌈log2 R⌉`（`:2034-2038`）
   都**没有**任何对应函数，`PRG` 这个词只出现在注释里；
   而且**根本没有 `FusePIR-C` / `CAPE-C` 类**（Alg 5 是 100% 委托）。
   ⇒ 这两个算法的 QUERY 完全写不出来。
4. **Alg 4 的原语有、但没有任何协议调用方**：`LweToRgswOps.convert`（`:59`，5 个参数、没有 `z̃` 对象）
   与 `ExpandOps.expand`（`:86`）都只被自己的 `main` 或探针调用。
   Alg 4 SETUP L2 *"Generate the public evaluation material required by LWEtoRGSW"*（`:2031`）**没有实现**；
   `probe/CapeBkCompressed:37` 还记着 Java 侧位提取 **4/4 失败**。
5. **没有名为 `CtPtMul` / `CtCtMul` / `CtCtAdd` / `CtRotate` / `SampleExtract_0` 的函数**：
   ANSWER 4-11（`:878-900`）与 A2 ANSWER 4-7（`:1050-1053`）在 Java 侧只有**内联**实现，
   或者只在 C++（`cape_answer_core`）里。
6. **没有 `pp` / `st_S` / `st_C` 类型**，没有 `(s_L,s_R)` 密钥对生成
   （`CapeQuery:227-229` 记着 `s_L` 必须与 bootstrap key 的比特逐位相同 ⇒ 两把密钥的结构没实现），
   没有 `ρ_H`/`ρ_fp` 的**采样**（`ρ_H` 是调用方给的 `seed0`，`ρ_fp` 是硬常量 `BffSetup.FP_SEED`）。

**Tier 2 — 不卡（存在，只是参数表不同）**：`BFF.Setup/Encode/MappingStep/Reconstruct`、
`BffSetup.layout/zeroTail/embed/newD`、`BF.Gen`、`BloomChannel.encryptQuery`、
`FusePirDecode.decodePayload/fingerprintOk`、`sampleExtract`、`BlindRotateOps.blindRotate`。

**Tier 3 — 死代码（子代理逐个裸名核过，我尚未处理）**：
`CapeQuery.toSlots`、`CapeBloomScore.toWire`、`CapeBloomScore.plainScore`、`CapeDecode.decode`（12 个调用方全走 `decodeWire`）、
`Mpc4jRgsw.addInplace`/`subInplace`、**整个类 `cape/CapeSetup.java`**（唯一成员 `bPay` 0 调用）、
**整个类 `cape/CapeQueryDecode.java`**（只被 docs 与 `split-packages.ps1` 提到）。

#### ⚠️ MAP 里**已知与本轮代码不符**、但还没逐行改的行（诚实登记，别当已改）

`§11.2:635`（D7 仍写 32-bit，**已过时**，见 §15.5A）、`§11.2:636`（参数名写 `lBff`，实为 `rc`）、
`§11.2:642`（CHECK/RECONSTRUCT 合并说 —— 本轮已拆开，此行要更新）、
`§11.2:645`（把字段 `Layout.r` 说成函数）、`§11.2:647`（"旧几何已非默认路径"**低估**了：
`CapeDemoService:117` 仍在调旧几何的 `buildTables`，与 §14.5 自相矛盾）、
`§11.1:607/613/618`（三处**调用方归属写错**：`S_v` 的第二个调用方是孤儿类 `CapeQueryDecode`；
`BloomChannel.encryptQuery` 的调用方是 `CapeDemoService` 不是 `CapeQuery`；
`CapeSetup` 根本没调过 scorer setup —— 它是死类）、
`§11.3③:668`（写 `R = L_BFF = 256`，与 §12.7 的 `R=16` 矛盾）、
`§12.5:847`（"`allocate` 的 `segmentLength` = `paperS`，两者一致" **只在 k=3 成立** —— 本轮已修代码）、
`§6:294-296`（Pack/h_i/循环依赖三行的旧口径）。
### 15.8 第五轮：伪代码点名的同态运算收成函数（范围：**只要 CAPE/FusePIR 所需的**）

用户指示收窄范围："只要 CAPE 和 FusePIR 所需的函数就行，别的不用"。
所以本轮**不做** FusePIR-C/CAPE-C（Alg 4/5）、不做 ChameletPIR 延伸、不做与本条无关的整理。

#### 新增 `prim/CtOps.java` —— 伪代码点名、而 Java 侧此前**一个都没有**的那些运算

审计的发现是：论文里 `CtCtAdd` / `CtCtMul` / `CtRotate` / `CtPtMul` / `SampleExtract_0`
**都有名字**，而我们的 Java 树里全是内联展开（或只在 C++ 的 `cape_answer_core` 里）。
后果不是"跑不动"，而是**没法把伪代码的一行对上代码的一处**；更糟的是
**`relinearize` 忘了写不会有任何报错**（密文维度涨上去，后面才炸或悄悄错）。

| 论文行 | 函数 | 调用点 | 状态 |
|---|---|---|---|
| A2 ANSWER 4 `CtCtMul(q^BF, ct^BF_j)` | `CtOps.ctCtMul`（**强制含 relinearize**） | `BloomScoring:107,123` | ✅ 活 |
| A2 ANSWER 5 `CtRotate(ct, 2^r)` | `CtOps.ctRotateRows` | `BloomScoring:172,193` | ✅ 活 |
| A2 ANSWER 5 / A1 ANSWER 11 `CtCtAdd` | `CtOps.ctCtAddInplace` | `BloomScoring:173,194,200` | ✅ 活 |
| **A1 ANSWER 5** `CtPtMul(q^col[c], P_{c,b})` | `CtOps.ctPtMul` | **0** | ⚠️ 无调用方，**已如实标注** |
| **A1 ANSWER 7** `SampleExtract_0(Acc)` | `CtOps.sampleExtract0` | **0** | ⚠️ 无调用方，**已如实标注** |

**两个"无调用方"的说明（不是遗漏）**：我们这条路径的 ANSWER 4-8 **整个在 native/C++**
（`rgsw_blindrotate.cpp:543` `cape_answer_core`）。留着这两个函数的理由是
**伪代码点名要求它们**，且一旦要在 Java 侧写 ANSWER 5/7，它们是唯一正确的入口。
两条都写进了各自的 javadoc（"目前没有 Java 调用方"），不是偷偷留死代码。

⚠️ `sampleExtract0` 的**类型映射要一起说**：论文的 `SampleExtract_0` 交出一条 **LWE 密文**，
而我们的 `LweRlweBridge.sampleExtract` 返回的是 **LWE 样本**（`long[][]`）。
本函数如实转发那个类型 —— 硬包成 `Ciphertext` 只会骗人。

⚠️ `ctPtMul` **没有做明文长度自检**：本库的 `Plaintext` 没有公开的长度读取方法
（只有 `reserve/resize/set` 与构造器）。**这是已知边界，不是"检查过了"** —— 已写在 javadoc 里。

#### 自己加的又删掉的（记下来，因为这是第三次踩同一个坑）

我先写了 `ctCtAdd` 的**值形态**、以及 `zeroPlaintext`/`checkPlaintext` 两个工具，
随后核调用点发现 **三者都没有调用方** ⇒ 全部删除。
项目已经因为"加了没人调的函数"被审计抓过两次（`BffSetup.fp`、我这轮的 `BffParams.hashGen()`），
所以这次是核完就删，不留。

#### 回归（全离线，无 HTTP 往返）

`BloomScoring` 8/8、`CapeBloomScore` 15/15、`CapeWireFormatProbe` 9/9、
`BffLayerTest` n=128 **32/32**、n=512 **32/32**、`CapePaperGeometryTest` 22/22、
`CapeTableDiag` 15/15、`CapeBffParamDiag` 16/16 —— **合计 149 项 PASS / 0 FAIL，全部 exit=0**。

⚠️ 替换是**逐字等价**的（原写法 `ev.multiply(...)` + `ev.relinearizeInplace(...)` /
`shifted.copyFrom(acc)` + `ev.rotateRowsInplace(...)` / `ev.addInplace(...)`），
且**没有改变分配次数**（原来每轮也新建一条 `shifted`），所以性能不受影响 ——
这一点是刻意的：折叠要跑 `⌈log2 ℓ_BF⌉` 轮，值形态会引入每轮一次分配。
---

## 16. `Pack` 的实测结论（2026-10-14 深夜，**决定性负结果**）

> 这一节的全部数字都是**真 SEAL 4.0.0 native 上实测**出来的，不是读代码推的。
> 完整报告：`E:\学习\密码赛\refs\packlwe-master-实测报告.md`（在 `coding/` 之外，不动仓库）。

### 16.1 ⚠️ 更正一条归因（我此前说错了）

代理⑤ 在 **MPC4J Java SEAL 移植版**上发现：`packFromSample` 只对"一条密文里一个位置"精确，
堆叠 6 个位置 6/6 全错且**不抛异常**，两条各自正确的密文相加连位置 0 都坏。
我当时归因为"**这套 Java 移植版对稠密打包是坏的**"。

**这个归因是错的。** 代理③ 在**真 SEAL 4.0.0 native** 上复刻了同一构造：
- 单位置：**8/8 精确**（与 Java 侧逐位一致）——说明移植层没错；
- **4 个各自精确的单位置密文相加 → 0/4 正确**。

**代数原因**：`packFromSample` 的 `c1` 是**稠密**向量、项是模 q 的均匀大数（~2^27）；
相加后 `⟨c1,s⟩` 按 `N·q` 量级增长，远超 `Δ = q/t` ⇒ **解密必然读出垃圾**。
⇒ 这是**那个构造本身的性质，与库无关**。
**结论：`packFromSample` 这条路线从候选里划掉**，理由 = "该构造 c1 稠密，相加爆噪声"。

（顺带确认：`packFromSample` 回卷时的**二次取负是必要的** —— 不做那步 8/8 全错；
`sampleExtract` 的符号约定自逆。这条已写在 Java 侧注释里，现在有 native 对照了。）

### 16.2 `packlwe-master` 的 `doPackingLWEs` **不成立**（结构性）

| 实测 | 结果 |
|---|---|
| 输入侧 4094/4094 单独解密 | ✅ 全对 |
| 合并：4094 条 → 1 条 | ❌ **只有 12/4094 条消息存活**，**全程无异常**（与 Java 侧同一"静默失败"症状） |
| 墙钟 | 1.95 s（N=4096, t=2^32, q=109 bit） |
| 单元脉冲 | input 0 → `0:512`；**input 1..4093 全部湮灭**（k=1..8 均如此） |
| 扫 67 种合并参数（e∈{1..63 奇}∪{N+1,2N+1} × 左右移 × s∈{1,2,4,N/4,N/2}） | **满足"两条消息都存活"的配置 = 0 个** |

**根因是结构性的**：`src/packfunc.cpp:214` 用
`apply_galois_inplace(ct_even, depth + 1, galois)` —— 指数是 `2,4,8,…,4097`，**全是偶指数**。
SEAL 拒绝偶指数作 galois element；而实测自同构规则是 `ψ_e(X^k) = X^{e·k mod 2N}`，
可用 `e` **全是奇数** ⇒ `e·k` 与 `k` **同奇偶**；`NegacyclicRightShiftInplace` 也保奇偶。
⇒ **系数永远跨不过"偶 → 奇"**，而稠密打包恰恰需要连续系数（含奇数位）。**不可修。**

**换 `t` 救不了**：`t=270337` 与 `t=2^32` 下**一样坏**（都只救回 2/8）。

**但它"与 `t` 无关"这一点是真的**（这条本身有用）：`BatchEncoder` 在 `packfunc.cpp` 里出现 **0 次**，
明文在 `packfunc.cpp:77` 逐系数手写；实测 `t=2^32` 时 `new BatchEncoder` 抛
"not valid for batching"，而 `doPackingLWEs` 照跑完。

### 16.3 ⭐ `Pack` 唯一还有实证支持的路：**修好的"移位 + 相加"**

实测证明：**新鲜密文**的移位相加**是干净的**（`7@0 + 9@0` → `0:14  1:9`，无污染）。
坏的只是 `ψ_e` 的**指数选择**。

受 §16.2 的奇偶障碍限制，系数布局**大概只能做到"间隔 2 的格"= N/2 = 2048 条消息/密文**。
而 CAPE 要的是 **`B_pay = 60` 条 → 1 条** ⇒ **2048 ≥ 60，可能已经够用，不必改任何参数**。

**⇒ 这是现在最该先算清的点**，且不再是"读代码能解决"的：
*待答问题*：在 `t = 2^32` / BFV / q = 109 bit / N = 4096 下，
间隔 2 的格能否把 **60** 条消息全部正确装进 **1** 个密文并全部解出？
（代理试过的修复版：移位量改 `N/depth`、指数改 `2·(N/depth)+1`、两种方向、样本换新鲜密文 —— **都没成功**，
最好结果是全部塌到系数 0。所以"修好的版本存在"这一点**尚未被证实**。）

另外两条候选（代价更大）：
1. **改到可 batching 的 `t`**（`t ≡ 1 mod 2N`，如 65537/270337），直接用 SEAL 的 slot 置换。
   代价：与现有 `t = 2^32` 载荷信道**不兼容**（D11 那两个 `t` 会变成三个）。
2. **RGSW/CMux 逐位合成**：语义绝对安全，代价 `O(N)` 次 CMux。

### 16.4 shipped 源码的硬伤（记下来，别再被它浪费时间）

| 位置 | 问题 |
|---|---|
| `include/common.h:12` | `typedef unsigned long size_t;` —— 与真 `size_t` 冲突（几百处 ambiguous），Win64 上还是错的 32 位，并让 `packfunc.cpp:18` 的定义与 `packlwes_head.h:8` 的声明不一致 |
| `src/packfunc.cpp:285/287` | `dobumblebeepack` 用了**未声明**的 `num_ct` ⇒ **硬编译错误**；上游**从未编译过它**（`pack_test.cpp:17` 里那行是注释掉的） |
| `src/packfunc.cpp:64-68` | 取模硬编码 `PLAIN_MODULUS` 而非 `plain_modulus()`；且 `for (auto v : vec)` 是**按值拷贝** ⇒ 整个归约**完全无效** |
| `src/testfunc.cpp:133-215` | `packlwes_test()` **不做任何断言**，只 `print_matrix` 打印首尾各 4 个系数；`packfunc.cpp:175-182` 把 `pod_matrix` 改成了消息本身 ⇒ `:172` 加密出的 `ct_for_padding` **带着消息**，padding 从未生效 |
| 仓库根 `origin.cpp` | 是旧版 packfunc（283 行，`doPackingLWEs` 只有 4 参） |
| 仓库自带 `bin/packlwes_test` | **Linux ELF**，本机跑不了；`CMakeLists.txt:11` 要求 SEAL **4.1** |

### 16.5 环境与可复用产物（**下一轮别再重新踩**）

- **SEAL：本机只有 `E:\学习\密码赛\tools\SEAL-4.0.0\`（源码 v4.0.0）。**
  `%TEMP%\dsh-*` **不存在**；`third_party\` 只有 bkpir-main；`coding\native-jni\lib` 只有 DLL 产物。
  （我此前会话记录里"SEAL 暂存在 `%TEMP%\dsh-*`"**已经过时**。）
- 手写构建产物：**`refs\ascii\sealbuild\lib\libseal.a`**（36 `.cpp` + 3 `.c`，编译 20.8 s）。
- 可复用脚本（都在 `coding/` 之外）：
  `refs\build_seal_manual.py`（手写构建 SEAL）、`refs\ldlink.py`（直接调 ld 链接）、
  `refs\build_packlwe.py`、`refs\build_dense_native.py`、`refs\pl_diff.py`（比对脚手架），
  以及 `refs\packlwe_dense.cpp` / `refs\dense_pack_native.cpp`。
- ⚠️ **沙箱踩坑（重要）**：
  1. **非 ASCII 绝对路径传不进 `ld.exe`/`g++` 驱动** —— g++ 链接完全不可用；
     必须 `cwd` 是 ASCII 且**全用相对路径**直接调 `ld`。
  2. **`-DXXX=OFF` 不等于未定义** —— SEAL 的 `gcc.h:22` 用 `#ifdef` 判，写 `=OFF` 反而算"已定义"。
  3. `-Iinc` 这种**裸相对路径无效**，要写 `-Isealbuild/inc`。
  4. **输出路径含中文也会崩**，产物必须放**纯 ASCII** 目录。
  5. cmake 的 compiler-id 探测在本沙箱以 `0xC0000409` 崩 —— 所以用手写构建，别用 cmake。
---

## 17. 全仓对账：我此前报的"缺口"有 15/19 其实存在（2026-10-14 深夜）

> 起因：用户问"查查还有什么是实现了你却以为还缺的"。
> 方法：一个只读代理把 19 条"缺口"逐条去**全部模块**里搜（不只 `rgsw-lab`），
> 每条给"**有没有 + 在哪（file:line+签名）+ 是不是当前口径 + 有没有接线 + 能不能直接用**"。
> **结果：19 条里 15 条存在、3 条"结论对但理由错"、只有 1 条真的没有。**

### 17.1 ⚠️ 我为什么错（流程缺陷，不是一次性失误）

1. **我引用了 `MAP.md` 里我自己写进去的"过期行登记表"所列举的行。** 那张表在
   `§15.7`（本文件 `:1387-1398`），标题就是*"⚠️ MAP 里已知与本轮代码不符、但还没逐行改的行
   （诚实登记，别当已改）"*，里面**逐条列出了** `§6:294-296（Pack/h_i/循环依赖三行的旧口径）`、
   `§6:294 "Pack 整个没有"这个说法不准`、以及"没有名为 CtPtMul/CtCtMul/… 的函数"那一行。
   **⇒ 我答"FusePIR 还差什么"时引的就是这几行。** 登记了却不遵守，登记就没有意义。
2. **我信任了一份校正前的报告。** `docs/reports/逐子程序核对-我们的实现是否符合论文算法-2026-10-13.md:182-184`
   把 `CtCtMul`/`CtRotate`/`resp` 三行标 ❌，而**同一份文件 `:59` 逐字引用了
   `lwe-java/cape/he/LWE.java`** —— 我据它得出"`LWE.Enc` 没有函数"。
3. **我只看 `rgsw-lab/`。** 仓库还有 `lwe-java/`、`rlwe-java/`、`tiny-cape/`、
   `cape-fusepir-database-handoff/`（41 文件）四个模块，我一次都没打开。
   还有 `docs/` 里**正是我需要的"哪份实现是默认"的文档**：`默认实现一览.md`、
   `QUERY_DECODE_编排说明.md`、`HE_三层调用说明汇总.md`、`RLWE路线审计.md` —— **一份没读**。

**⇒ 规则（写下来当约束用）**：判"缺"之前必须
**(a) 跨全部模块搜；(b) 判它是不是当前口径（参数是否与主路径一致）；
(c) 判有没有接线；(d) 只信 `§15.7` 那张登记表之外的行 —— 表内的行一律不许引用。**

### 17.2 ⚠️⚠️ 最要紧的一条：**两份 BFF 位置函数实测不一致**

代理把两份**都忠实重实现**（先复现 handoff 的冻结测试向量以证明转写无误）再比对：

| `n=128` | 位置 |
|---|---|
| `bff/BffHash`（**现行**） | **[87, 140, 225]** |
| `cape-fusepir-database-handoff/…/BffHashGen`（**旧**） | **[2, 85, 143]** |

**不一致。** 分歧点四条：段长 **2.25**（论文 Table 1 + C/Rust 实现，四份来源）vs **2.11**
（正是 `BffHash:160-161` **刻意否定**掉的 Java `XorBinaryFuse8` 变体）；oracle
`SHA-256(ρ_H‖0x00‖K)` vs `murmur3`；`h_0` 用 64 位 `unsignedMultiplyHigh` vs 取高 32 位比对；
`L_BFF = (segmentCount+k−1)·s` vs `(segmentCount+2)·s`。

**今天不致命，但只是"碰巧"**：`grep com.fusepir.database` 在 `rgsw-lab` 里 **0 命中**
⇒ handoff 那条链是**被意外隔离的，不是设计隔离的**。而它产出**约 5.2 GB 的磁盘 BFF 表**，
`HANDOFF.md:41` 明说那张表是**服务端资产**。
**⇒ 主路径哪天去读那个目录，每一次查找都会静默落空** —— 正是本项目反复踩到的假阴性类别。
**这是整份对账里唯一有"可复现不一致 + 静默失败 + 实体数据挂着"三件套的项。**

**建议动作**：`BffHashGen` 对到 `BffHash`（纯 n 上的数学，无密码学依赖），或退役 handoff 的 BFF 链；
**在做完之前，任何人不得把那张磁盘表接进主路径。**

### 17.3 我说成"缺"的东西（按重要性）

| 我说"没有" | 实际 | 影响 |
|---|---|---|
| `LWE.Enc` | ✅ `lwe-java/src/main/java/cape/he/LWE.java:101` `encrypt(LWESecretKey, long)`，**带 Δ=q/t 与噪声** | **这是项目自己的 #1 缺陷 P0-1 的解药**（`缺陷总表.md:59`：把通用 LWE 密文直接喂盲旋转，旋转量变成 `Δr = 256r`）。我说"没有函数"**把修法藏起来了** |
| `CtCtMul` / `CtRotate` / `CtCtAdd` | ✅ `prim/CtOps.java`，且**全都在默认打分路径上是活的**（`BloomScoring:108,124,172,193,173,194,200`） | 信了我就去**重写已经跑通、且带 relinearize 的代码** —— 最容易真引出 bug 的一条 |
| Java 侧 ANSWER 5-7 | ✅ `probe/CapeEndToEnd4:485-489/383/385/391` 有完整 Java 实现并跑通 | Java 化是**接线**，不是重写 |
| `(s_L, s_R)`"结构性不可能" | ⚠️ **结论对、理由错**：`Mpc4jRgsw(..., SecretKey)` 证明两把密钥**可构造**；真阻碍是**旋转恒等式**且已量化（`CapeDSemanticsProbe:212/217/219`：差 1 位 ⇒ 行偏 **5767**） | 不是"不可能"，是"已量化代价 + 有书面决定的架构选择" |
| `oneHot` / `u→(c_a,r_a)` / 单一 `FusePIR.Query` / 两个 `Parse` | ✅ 全在 `fusepir/FusePirQuery.java:369,414` 与 `FusePirAnswer.paths:183`，**现行且活的**，带着本仓库最好的防御性断言 | 信了我会**第三次**重写那段"已改正过两次"的代码 |
| **"CAPE 从未端到端跑通"** | ❌ **这句话是错的**：`CapeEndToEnd4` 与 HTTP 默认路径**都端到端跑过**，各有验收命令 | 可信度风险。**站得住的措辞是 `缺陷总表.md:35-37`**：*"Algorithm 2 的增量已实现并通过端到端断言；但索引无噪声、候选密文未从检索密文导出、单 JVM 密钥未隔离这三条 P0 仍未修 ⇒ 完整、具查询隐私、按论文参数工作的 CAPE 尚未实现"* |
| `tiny-cape/CapeEndToEnd` | ⚠️ N=8/t=17/q=97，**服务器被直接告知 `(r*,c*)`**（无密文列选择）、当场解密、打分是明文整数点积 | **不得当"端到端 CAPE"引用**。但它**独立确认了 Pack 的缩放墙**（`tiny-cape/README.md:102`：q=97 时 `Δ·N·t/2 > q/2` 让槽掩码乘法不可能）—— 与 `SampleToPackLink` 实测的 ≈30 是同一堵墙、不同参数点 |

**我说对的**：`FusePIR-C`/`CAPE-C`（算法 4/5）**确实整个没有** —— 唯一一条准确的"缺"。
**`Pack`**：算法层我说错（四份实现，`RingPack` 是真 ring packing，`README.md:315` 有 **6/6** 验收行）；
**协议层我说对**（无调用方），但**理由从"没写"变成"已实测的架构决定"**。

### 17.4 数字与文档缺陷（与代码无关，但会误导人）

* **`B_pay` = 60**（native `t=2^32`）/ **61**（scoring `t=65537`）；
  而 **59 还印在三处**：`README.md:469`、`缺陷总表.md`、`keywords.json` 的 `"bPay":59`
  （那个字段**没人读**，`CapeDemoData:188,403` 会重算）。⇒ 纯文档缺陷。
* **主路径参数全部核对无误**（代理实测）：N=8192、t=2^32/65537、ℓ_BF=18、k=3、
  L_BFF=256、R=16、C=16、`tail=0`；`n=256/512` ⇒ L_BFF=384/C=24 与 768/C=48。
* `MAP.md` 的 `L_BFF`/`h_a`/`Pack`/`FusePirQuery` 几行与工作树矛盾（见 §15.7 那张表）。

### 17.5 真正还开着的工程项：**只有两个**

1. **P0-1**：把 `cape.he.LWE.encrypt` 接进盲旋转、去掉 `Δ=256` 的缩放
   （`缺陷总表.md:59`，🔴 最大的一条）。
2. **A1 ANSWER 13 的 `Pack`**：`RingPack` + 一个收 `{ct_{pay,b}}` 的适配器，
   或 §16.3 那个"间隔 2 的格能否装下 60 条"的实验 —— **容量上 2048 ≥ 60，但没人证过**。
   ⚠️ **这一条在 §18 里已经被大幅收窄**：`Pack` **能**闭合，但**只能闭在 65537 那条通道上**；
   在 `t=2^32` 上是**可证的数学不可能**。**读 §18，不要只读这一行。**

---

## 18. `Pack`（A1 ANSWER 13）的最终裁决：**能闭合，但只能闭在 65537 那条通道上**

（2026-10-15；`RingPack` 自检重跑 + 代理 `0deb4da0` 复核 + 我逐条复核代理结论）

### 18.0 结论先行

1. `RingPack` 是**真的 ring packing**，算术核心在**项目尺度上逐槽位精确**
   （我本机重跑 N=8192 / t=65537 / nLwe=32 ⇒ **7/7 全 PASS，exit 0**）。
2. 但它在 **`t = 2^32` 上不可能存在** —— 不是"没实现"，是**数学上不存在**（§18.2）。
3. 而这条墙**只挡住 native 载荷通道**；`Pack` 与 `BloomScoring` 共用的那条 65537 打分通道
   **本来就满足条件**，且 `RingPack.main` 的 P2 已经在喂**打包产物**（而不是新加密的密文）（§18.1）。
4. ⇒ **A1 ANSWER 13 在我们的 65537 通道上可闭合；在 2^32 native 通道上永久关闭。**
   这又是一条**独立**支持 D11 双-t 设计的理由。

### 18.1 我独立复核的（不是转述）

命令 `.\run-mpc4j.ps1 -Class com.fusepir.prim.RingPack 8192 32` ⇒ exit 0，`P1…P5b` + `P6.1…P6.7` 全 PASS。

```
[setup] 交换密钥 96 条（32×3），构造 882–924 ms
        体积约 48.0 MB（每条 512 KB）
```

⇒ **524,288 B/密文**，与 `[params] … 工作层=4(174 bit)` 自洽：`2 × 4 × 8192 × 8 = 524,288`。
**整张交换密钥成本表因此可以自己算，不必信任何人**（§18.4）。

**P2 就是"打包产物 → 槽位域 SIMD 内积"这条链**：`RingPack.java:592` 的 `score(...)`
收的是 `Ciphertext packed`，内部 `transformFromNttInplace` 之后**直接喂**
`BloomScoring.bloomScore(m, gk, qBF, packedCoeff)`；调用点 `:286`（P2）与 `:459`（P4 扫描），
`P3` 是"查询平移一格后得分必须变"的负对照。

### 18.2 为什么 `t = 2^32` 上**不存在**槽位选择子（我重推过）

设 `E(X) = Σ v_j X^j`，槽位点 `x_i = ω^{2i+1}`（`ω` 为 2N 次本原单位根，`ω^N = −1`）。

1. `E(x_i) − E(x_0) = (x_i − x_0)·G(x_i)`，`G ∈ Z[X]`（因式分解恒等式）。
2. `ω` 是**奇数**（`Z_{2^32}` 的单位）⇒ 每个 `x_i = ω^奇` 与 `ω` **同余 mod 4**
   （`ω≡1` 则全 `≡1`；`ω≡3` 则奇次幂仍 `≡3`）⇒ `x_i − x_0 ≡ 0 (mod 4)`。
3. ⇒ **任意 `E`、任意 `i` 都有 `E(x_i) ≡ E(x_0) (mod 4)`。**
4. 选择子要 `E(x_i)=1` 且 `E(x_j)=0`；但由 3，`E(x_i)=1 ⇒ E(x_j) ≡ 1 (mod 4) ⇒ E(x_j) ≠ 0`。
   **矛盾。对一切 N ≥ 2 成立。**

一句话根因：**`Z_{2^k}[X]/(X^N+1)` 不是 N 个 `Z_{2^k}` 的积环**
（Vandermonde 行列式 `Π_{i<j}(x_j − x_i)` 的每个因子都是偶数 ⇒ 行列式非单位），
所以它**没有幂等基**，也就没有"槽"这个概念 —— **连"换一种槽的定义"这条路也一起断了。**

代理的穷举把这个定理钉住了：`N=4, k=5` 遍历 `(2^5)^4 = 1,048,576` 个系数向量、
`k=6` 遍历 `16,777,216` 个，**均无选择子**；同一套代码在 `t=65537` 与 `t=536903681` 上**找得到**。
（N=8192 本身搜不了：`(2^32)^8192`。）

> 顺带钉掉一个诱人的错直觉：`Z_{2^k}[X]/(X^N+1) ≅ (Z_{2^k})^N` 是**假的**。
> 上面那句"Vandermonde 非单位"就是它的反证。

### 18.3 我**纠正代理报告**的三处（重要 —— 否则会把已成的事当缺口）

| 代理的说法 | 实际 | 若不纠正的后果 |
|---|---|---|
| *"喂 `packed`（而非新加密密文）进 `BloomScoring` 是**下一个待跑的实验**"* | ❌ **已经是 `RingPack.main` 的 P2，而且 PASS**（`:286` + `:592`，配 P3 负对照） | 会去重跑一件**已经跑通**的事；还会误以为 A1 的"一个打包密文 → SIMD 内积"这条链**没闭合** |
| *"`PackGoalCheck` 那句『实测 6/6』是过期的，`main` 只有 5 项"* | ❌ 实测 **6 条 report**（P1/P2/P3/P4/P5a/P5b），**"6/6" 是准的** | 会去"修"一句没写错的验收行 |
| *"打包通道**必须**挪到 ~30 bit 素数"* | ⚠️ **不是必须**：`65537` 在 N=8192 **和** N=16384 上都可批处理（`65537−1 = 65536 = 4·16384`），而 `BloomScoring` 每个入口都硬依赖 `BatchEncoder`（`encryptBloomVector:74`、`decodeScore:249`） | 会去动一条**本来不需要动**的模数决策。30 bit 素数买到的是**槽位余量**，不是可行性 |

代理**说对的**（我复核确认）：`CapeAnswerHomomorphic:135` 确实把 `vBf` **重新加密**成 `candBF`
再去 `:138` 打分，`:102` 打的包**根本没进打分** ⇒ 那条链在该探针里**是断的**；
`RingPack.main` 建的是 `t=65537` 而非 `2^32`（`RingPack.java:242`）。
代理另一条也准：`PackGoalCheck` 的 ❌ 裁决块与它下面的 ✅ 块**互相打脸**，
只读 ✅ 就会得出"Pack 已完成"的错结论 —— **以 ❌ 裁决块为准**（它针对的是
`LweRlweBridge.packFromSample` 那条**系数域**路线，那条路线确实不是论文的 Pack）。

### 18.4 交换密钥成本（实测，不是估计）

每条 RLWE 密文 **524,288 B**（N=8192、工作层 4）。

| 配置 | 条数 = `nLwe × digits` | 字节 |
|---|---|---|
| N=8192, t=2^32, base=2^16, digits=2, **`nLwe = N`**（论文的 LWE-in-RLWE 假设） | 16,384 | **8.0 GB** |
| N=8192, t=2^32, base=2^16, digits=2, **`nLwe = d = 16`**（小独立 `s_L`） | 32 | **16 MB** |
| N=8192, t=65537, base=2^8, digits=3（原型自身配置，即 6/6 那套） | 24,576 | 12.0 GB |
| N=16384, t=2^32, base=2^16, digits=2, `nLwe = N` | 32,768 | **64.0 GB** |
| N=16384, t=2^32, base=2^16, digits=2, `nLwe = d = 16` | 32 | 64 MB |

⇒ **512× 的差**。⚠️ `RingPack.java:52-54` 那句"N=16384 时约 16 GB"**低估**：
按 2 个多项式分量算是 64–96 GB。

**但这里有个对我们有利的不对称**：盲旋转那边的 LWE 秘密**只有 `d = 16` 位**
（`CapeQuery.java:374` `Integer.getInteger("cape.d", 16)`；`CapeDemoService:132` 用它建 bootstrap key），
所以 `s_L` **已经**可以是独立小秘密；**只有 Pack 的交换密钥**需要整个环秘密 ——
因为 `SampleExtract_0` 出来的是**环秘密下**的 N 维 LWE 样本。

### 18.5 `Pack` 与两条通道的对齐（这条决定 ANSWER 13 能不能闭）

| 通道 | `t` | `slotBits` | `fpSlots` | `B_pay` | 能否 `Pack` |
|---|---|---|---|---|---|
| native 载荷（D11 加的那条） | `2^32` | 32 | 2 | **60** | ❌ **不可能**（§18.2） |
| 打分（论文自身的 t） | `65537` | 16 | 3 | **61** | ✅ **已跑通**（P2/P4/P5） |

> ⚠️ **2026-10-15 加注（很容易误读，务必一起看）**：上表第一行的 `t=2^32` 是
> **CAPE 演示服务**那条载荷通道，**不是 FusePIR 的**。
> FusePIR 自己的应答通道明文模数是
> `FusePirParams.NATIVE_PLAINTEXT_MODULUS = 65537`（`:281`，`FusePirAnswer:364` 强制对账）
> ⇒ **`Pack`（A1 ANSWER 13）没有任何模数障碍**，它在 `N=8192` 与 `N=16384` 上都可批处理。
> §18.2 那条墙只挡 `2^32` 那条通道。**适配器已实现并验收，见 §23.2。**

`FusePirSetup.slotBits(65537) = 16`、`fpSlots(65537) = 3` ⇒ `payloadBpay = 3+1+m·perValue = 61`
（`FusePirSetup:111-146`）。**每槽 ≤ 2^16 < 65537，物理上放得下** ——
§15 那条"40 bit 指纹连论文自己的 t 也放不进一个槽"的观察，反过来正是 Pack 可行的原因。

### 18.6 我这次改的代码（唯一一处）

**`RingPack.pack` 会静默截断高位。** `pack` 对每条 `a_j` 只迭代 `digits` 次
`digit = remaining % base; remaining /= base`，循环结束后**直接丢掉 `remaining`**。
若 `base^digits < t`，所有 `a_j ≥ base^digits` 的**高位被无声丢弃** ——
产物仍是一条"看起来正常"的密文，只是相位错了。

- `t=65537` + 原型自带的 `base=2^8, digits=3`：覆盖 `2^24 > t` ✅（**这就是 6/6 成立的原因**）
- `t=2^32` + 同一套 gadget：只覆盖 `1/256` ⇒ **几乎每条 `a_j` 都被截断**
- 要上 `t=2^32` 必须 `base=2^16, digits=2`（恰好覆盖 `2^32`，且 `base ≤ t/2` 仍在明文窗口内）

**动作**：新增 `requireGadgetCovers(t, base, digits)`（`RingPack.java:215`），
`pack` 第一行调用（`:156`），不满足直接抛。**并配 7 条子检查**
（`P6.1–P6.7`，`RingPack.java:367-381`），**逐条打印**而不是用一个布尔量兜住 ——
其中 `P6.2` 是 `2^8·2 = 65536 < 65537`（**只差 1** 的边界，必须拦），
`P6.5/P6.6` 是 `t=2^32` 的一负一正，**`P6.7` 真调 `pack`** 验证守卫确实被接线（防"守卫写在旁边没人用"）。

> **过程记录（值得留）**：P6 第一版我用一个 `boolean` 把 6 个子项 `&=` 起来 ⇒
> 只报一行 "FAIL"、**不知哪条错**，第一次跑就是这么糊过去的；
> 拆成逐条 `sub(...)` 后立刻定位到"`Mpc4jRgsw(1024, 2^32, …)` 建不出来
> （`plainModulus is not smaller than coeff_modulus`）"——
> 顺带发现**守卫根本不需要一个密码学上下文**，于是把它重构成纯函数 `(t, base, digits)`。
> **"一个布尔量兜住 N 个子项"正是本项目反复踩的假通过类别。**

### 18.7 仍然开着的（诚实清单）

1. **P2 打的是 1-bit 消息。** 真实载荷是 `B_pay = 61` 个 **16-bit limb** 落进 61 个槽，
   再走 `qBF × packed → 折 ℓ_BF` 那套。**没跑过。** 这是下一条要做的实验。
   ⇒ ⚠️ **已在 §19 跑掉，结论见那里（搬运精确；但折叠轮数不能按 ℓ_BF 取）。**
2. **`65537` 的 BFV 噪声余量够不够撑完整条链**：P5b 的余量（最大偏差 66 vs `t/2 = 32768`，
   要求 ≥ 8×）是**打包构造明文侧**的余量，**不是** `ct×ct + relinearize + 5 轮折叠`之后的。
3. **适配器没写**：`{ct_{pay,b}} → 一个打包密文`。
   （`FusePirPack` 是 R1 的**系数域**变体，60→60，**无压缩**。）
4. **"自己写 Lagrange 选择子"这条路未验证、不得当后备**：代理实测它**复现不出 `BatchEncoder` 的编码**
   （`t=536903681` 下 NTT 域 8192/8192 全不匹配；对常数密文选槽 0 解出 **0** 而不是 12345）。
   选择子**存在性**的穷举证据成立，但**手写那条实现不成立** ⇒ **一律用 `BatchEncoder`**。
5. 若将来真需要 >16 bit 的槽：`t = 536903681 = 41·2^14 + 1`（30 bit 素数，`≡ 1 mod 2N`）
   可 `BatchEncoder`（代理实测 8 槽 0 错）。但 **BFV 噪声随 t 增长**，
   大 t **不是白送的** —— 别把它当"更多余量"。

### 18.8 ⚠️ 顺带发现：**两份 Pack/LWE-桥权威文档正文被损坏**（**已修**，见下）

查 `LWE_RLWE打包_RingPack_调研.md` 的 §五之三 时，`grep Pack` **0 命中**。
按字节查下去：

| 文件 | 字符数 | 小写 `c` | 小写 `o` |
|---|---|---|---|
| `rgsw-lab/LWE_RLWE打包_RingPack_调研.md` | 12,338 | **0** | 305 |
| `rgsw-lab/LWE_RLWE桥_调用说明.md` | 6,554 | **0** | 180 |

**结论：这两份文件的正文里每一个小写 `c` 都被写成了 `o`**（大写 `C` 未受影响、中文未受影响）。
证据：`RingPack` 0 次 / `RingPaok` 9 次；`BloomScoring` 0 / `BloomSooring` 4；
`scaleToT` 0 / `soaleToT` 1；`SampleToPackLink` 0 / `SampleToPaokLink` 2；
首行标题字节为 `… Ring Pao`（本应 `Ring Pack`）。
**注意文件名本身是好的**（`…_RingPack_调研.md`），所以只看目录列表发现不了。

**危害（正是本项目最怕的静默类别）**：
* 在这两份**权威文档**里搜 `Pack` / `packFromSample` / `BloomScoring` / `scaleToT` / `PackGoalCheck`
  **一律 0 命中** ⇒ 读者会得出"这些文档根本没讨论 Pack"的错结论，
  于是**再写一遍已经写过的调研**（本项目已经重复踩过好几次）。
* 本次代理引用的"调研 §四""§五之三"就是这两份文件；它把 `RingPaok` 读成 `RingPack` 是对的，
  但**下一个人不一定会**。

**成因：未定。** 明确**排除**了 §14.6 那类编码往返（那类会产生替换符 `�`，这里没有）；
变换是精确的 `c → o`，与"替换串里 `$1` 后面直接跟 `c` 被当成分组引用"这种*正则替换事故*
同属一类（见 `README.md` 附录 A 第 16 条）。**但这是推测，不是结论。**

**修复状态：已修（2026-10-15）。** 反向映射在一般情形下**不可逆**，所以用的是
**受控词表**：把文档里含 `o` 的 token 逐个枚举"哪些 `o` 本来是 `c`"，候选必须
**在代码库里真的存在**才采纳（唯一候选才替换）。两个必须的前提是
"排除损坏形态自身"（损坏形态会串进别的文档，否则自己匹配自己）与"大小写精确"。

| | 文件 1 `LWE_RLWE打包_RingPack_调研.md` | 文件 2 `LWE_RLWE桥_调用说明.md` |
|---|---|---|
| 小写 `c` | **0 → 139**（我补 12 后为 **151**） | **0 → 106** |
| 小写 `o` | 305 → 178（我补后 **166**） | 180 → 86 |
| 行数 | 323 → 327（+4 行告示） | 212 → 216（+4 行告示） |
| 中文字符数 | **2988，逐字未变** | **1347，逐字未变** |

**验证（我自己按字节重跑，不采信代理自述）**：`RingPack` 9 / `RingPaok` 0；
`BloomScoring` 4 / `BloomSooring` 0；`packFromSample` 3 / `paokFromSample` 0；
首行标题 `# LWE → RLWE 打包（Ring Packing）调研` 完好；
**总量守恒**：`305 = 178 + 115 + 12`、`180 = 86 + 42 + 52` 两边都对上。

⚠️ **代理自述与文件实况不符一处（已由我纠正）**：它的替换表宣称
`switoh → switch`、`switohing → switching`、`web_fetoh → web_fetch`、
`BatohEnoder → BatchEncoder` 都已复原，但按 token 扫描**这四类 12 处仍原样留在文件 1 里**。
是它的"事故回滚"过程把它们倒回去了。⇒ **代理的"已完成"清单必须按文件实况复核，不能采信自述。**
我已补齐：`BatchEncoder` ×3、`switch`/`switching` ×5、`web_fetch` ×3、`mismatch` ×1。
补齐后文件 1 再没有任何含 `oh` 的 token。

⚠️ **差点把告示本身改坏**：`Paok` 与 `Sooring` 在每份文件里各只出现 **1** 次，
而那 1 次**正是告示里的示例**（"`Paok` → `Pack`"）。机械化替换会把它变成
"`Pack` → `Pack`"。⇒ **给文档加"损坏示例"告示之后，同名字符串就不再是纯损坏标记了。**

⚠️ **代理另一处判断是错的**：它把文件 2 的 `BFF` 报成"应为 `BFV`"。**实际 `BFF` 是对的** ——
那一句讲的是 Binary Fuse Filter 的重建性质 `Σ_a D[h_a(K)] = y_K`。**未改**。

**仍然不可信的部分（已由每份文件第 2–5 行的告示声明）**：
英文散文里的词形（真正的 `o` 与被损坏的 `c` 无法自动区分），以及**不在替换表里**的任何标识符。
**中文结论、以及替换表里那些对得上代码的标识符，现在可用。**
文件 1 还留着一处被截断的引文片段 `the RLWE c…`（字符已复原，原词不可知）。

**还有一处未解、且不属本损坏类别**：文件 1 的 HERMES 引用写成
`https://askoryp.to/t/resource-topic-2023-1244-…/20474`，**实测 `askoryp.to` 解析不了**
（`getaddrinfo ENOTFOUND`）。它**不是** `c→o` 的产物（反推只会得到 `askcryp`，不是已知站点），
所以要么是别的损坏、要么作者本来就写错了。**未改、未猜** —— 记在这里等人核对。
（同一张表里 `web_fetch` 被限制那条也保留：本环境确实没能读到原文。）

---

## 19. 真实载荷过 `Pack` 的实测（A1 ANSWER 13 的最后一块判据）

（2026-10-15；新探针 `probe/PackLimbPayloadTest.java`）

跑法：`.\run-mpc4j.ps1 -Class com.fusepir.probe.PackLimbPayloadTest 8192 16`
⇒ **exit 0，13 项全达成**，其中 2 项是**刻意期望"错"的缺陷断言**。

参数：`N=8192`、`t=65537`、`ℓ_BF=18`、`m=3`、`fpSlots=3`、`perValue=19`、**`B_pay=61`**、`nLwe=16`。

**探针用的载荷槽布局**（由 `FusePirSetup` 的算式算出，探针里不手写下标）：

```
[fp 0..2] [m_i 3] [v_0 4][bv_0 5..22] [v_1 23][bv_1 24..41] [v_2 42][bv_2 43..60]
```

⇒ **三个 Bloom 段的起点是 5 / 24 / 43** —— 这个数字是 §19.4 那条缺陷的全部原因。

### 19.1 判据一（搬运）：61 个 16-bit limb 逐槽精确 ✅

* `P0.1–P0.4`：`fpSlots(65537)=3`、`perValue(18)=19`、`B_pay=61` —— 把 §18.5 那张表变成断言。
* **`P1.1`：61 个 limb 错 0 个，未写入的槽非零 0 个。** 值取 `{30000, 31000, t−1}`，
  **含最大可表示 limb `t−1 = 65536`**。
* `P1.2`：40-bit 指纹（三段 `[41719, 59681, 94]`）经 Pack 往返一致。

⇒ **§18.7 第 1 条（"真实载荷没跑过"）关闭。**
`Pack` 在 65537 通道上对**完整 `B_pay = 61` 的 16-bit limb 载荷**是**逐槽精确**的，
且不是"恰好一个比特对"—— 61 个槽全中、尾部不泄漏。

### 19.2 判据二（可算性）：**只有二进制段能进同态内积** ✅

`P8`：查询在三个**值**槽 `{4, 23, 42}` 上各置 1 ⇒ 真值 `30000+31000+65536 = 126536`，
解出 **`60999` = 126536 mod 65537**。

**这条的判据必须两个一起看**：`P1.1` 已证明**每个 limb 单独搬运是精确的** ⇒
结论只能是 **"单个 limb 没问题、求和有问题"**，**不能**缩成"16-bit 不能打包"。
`t = 65537` 只装得下权重为 `w`、每个值 `≤ t/(2w)` 的和；
`w = 18`（ℓ_BF 全命中）时上界只有 **1820**。

⇒ 载荷的槽**分两类**，这条区分必须写进 A1 ANSWER 13 的契约：

| 类别 | 槽（本例） | 能否进 `CtCtMul` 内积 |
|---|---|---|
| **被搬运**的 limb（fp / `m_i` / 值，可达 `t−1`） | `0..4`、`23`、`42` | ❌ 求和会回绕 |
| **可算**的二进制段（`bv`，0/1） | `5..22`、`24..41`、`43..60` | ✅ |

### 19.3 判据三（**新缺陷**）：论文形状的折叠**够不着** Pack 的落点 🔴

`BloomScoring.foldSlots` 的正确性前提是"支撑落在 `[0, ℓ_BF)`"——`BloomChannel.padToSlots`
造的候选满足它。**但 `Pack` 的产物天然违反**：Bloom 位散布在整个 `[0, B_pay)` 上。

`ℓ_BF = 18` ⇒ `⌈log2 18⌉ = 5` 轮 ⇒ **只够到 `[0, 32)`**。实测：

| 段 | 命中位在槽 | 5 轮折叠得分 | 真值 | 判据 |
|---|---|---|---|---|
| 0 | 20..22 ⊂ [0,32) | **3** | 3 | `P2` ✅ 正对照 |
| 0（不命中查询） | — | **0** | 0 | `P3` ✅ 负对照（证明分数随查询变） |
| 1 | **39..41 ≥ 32** | **0** ❌ | 3 | `P4` **缺陷断言复现** |
| 2 | **58..60 ≥ 32** | **0** ❌ | 3 | `P6` **缺陷断言复现** |

**正确的轮数** = `⌈log2(最高参与槽 + 1)⌉`：`B_pay = 61` ⇒ 最高参与槽 60 ⇒ **6 轮**（够到 `[0,64)`）。
`P9` 实测 **6 轮**，严格介于论文形状的 **5 轮**与折满的 **13 轮**之间。

**这是"漏算"不是"算错"**：分值偏小 ⇒ **本该接受的候选被拒**，
与 `foldSlots` 注释里已经登记过的那类静默失败同族。
`P5b`/`P7b` 是**参数活性负对照**：把最高参与槽谎报成 31 ⇒ 必须重现漏算。
若这两条也得 3，说明新入口的参数是摆设 —— 它们通过了，所以参数确实在起作用。

### 19.4 我加的 API（本轮第二处代码改动）

* `BloomScoring.bloomScoreReaching(m, gk, q, cand, highestSlotInclusive)`（`:214`）
* `BloomScoring.foldSlotsReaching(m, gk, ct, highestSlotInclusive)`（`:228`）
  —— 实现在 `foldSlots` 之上（传 `最高参与槽 + 1`，恰好等价于"够到该槽"）
* `foldSlots`（`:156`）的注释里补了**"候选是 Pack 产物时不满足前提、会静默漏算"**的警告。

⚠️ **必须说清的边界：这是"潜在缺陷"，不是"现行缺陷"。**
`cape/CapeBloomScore.java:200` 走的确实是 5 轮那条，但它的**候选是 `BloomChannel` 造的
BF 向量**（支撑在 `[0, ℓ_BF)`）⇒ **现行打分路径是对的，不要误报成线上 bug**。
这个漏算**只在 `Pack` 产物成为候选的那一刻发作** —— 也就是 A1 ANSWER 13 接线的那一步。
**所以：接线时必须走 `bloomScoreReaching`，否则答案会静默偏小。**

### 19.5 回归

`BloomScoring`(8 PASS) / `CapeBloomScore`(15 PASS) / `CapeWireFormatProbe`(9 PASS) /
`PackGoalCheck`(exit 0，刻意 4 条"未达成") —— **全部 exit 0，无回归**。

### 19.6 §18.7 清单的更新

| # | 原状态 | 现状态 |
|---|---|---|
| 1 | P2 打的是 1-bit 消息，真实载荷没跑过 | ✅ **关闭**（§19.1：61 个 16-bit limb 逐槽精确） |
| 2 | 65537 的 BFV 噪声余量够不够撑完整条链 | ⚠️ **仍未验**，但**多了一档可用轮数**：6 轮比折满少 7 轮（噪声少 2^7 倍）。仍缺"Pack 产物 → `CtCtMul` + relinearize + 6 轮折叠"的实测余量 |
| 3 | `Pack` 的适配器（`{ct_{pay,b}}` → 一个打包密文）没写 | ❌ **仍未写** |
| 4 | 自写 Lagrange 选择子不得当后备 | 不变（`BatchEncoder` 唯一可用） |
| 5 | >16 bit 槽需 30 bit 素数 | 不变；**注意 §19.2 让它更不紧迫**：可算槽只需装 0/1 |

**⇒ A1 ANSWER 13 现在的诚实状态**：**搬运**✅、**二进制段打分**✅（前提是轮数取对）、
**适配器**❌、**打包产物进 `ct×ct` 的噪声余量**❌未测。
不是"能闭合了"，而是"**只剩两件，且都不再是原理性问题**"。

---

## 20. FusePIR（Algorithm 1）缺口总账（2026-10-15，逐条按代码核过）

回答"FusePIR 还缺什么"。**分四类**，因为"缺"有三种不同的意思：
写不出来 / 写得出但语义不对 / 曾经缺但现在有了 / 按你的决定不做。

### Tier A —— **真的写不出来**（只有 2 条，其中 1 条是你决定不做的）

| # | 缺口 | 现状（按代码核） | 卡住谁 |
|---|---|---|---|
| **A1** | **`Pack` 的适配器**：`{ct_{pay,b}}` → 一个打包密文 | `prim/RingPack.pack` 收的是**明文** LWE 分量 `(as, bs)`，不是那组密文。调用点只有 `probe/CapeAnswerHomomorphic:102`、`probe/PackLimbPayloadTest:156`、`RingPack.main` —— **协议代码零调用** | A1 ANSWER 13；以及 A2 ANSWER 3 的 `Parse {(c_{v_j}, ct^BF_j)}`（D2 是它的症状） |
| **A2** | **Alg 4 / Alg 5（`FusePIR-C` / `CAPE-C`）整条查询压缩链** | `PRG(ρ,a,j)`（`:2044-2046`、`:2121`）、`bin_ℓ(x)`（`:2042`）、`ℓ_c=⌈log2 C⌉`/`ℓ_r=⌈log2 R⌉`（`:2034-2038`）**都没有对应函数**，`PRG` 只出现在注释里；**没有这两个类**；Alg 4 SETUP L2 的公开求值材料没实现；`probe/CapeBkCompressed:37` 记着 Java 侧位提取 **4/4 失败** | ⚠️ **§15.8 记着你已指示"本轮不做 Alg 4/5"** ⇒ 这是**"按决定不做"，不是"遗漏"**。列为缺口只为账目完整 |

**⇒ §0.5 速查表里 FusePIR 那 10 行，现在已无一行是 ❌**（`Pack` 那行是 ⚠️）；
A1 唯一"写不出来"的是 **`Pack` 的适配器**。

### Tier B —— **写得出，但语义不符**（不改就不算"按论文"）

| # | 缺口 | 现状 | 解药 / 前置 |
|---|---|---|---|
| **B1** | **`q^row` 没有噪声**（P1-2） | `cape/CapeQuery.java` 里 `q.beta[a] = (sum + rowIdx[a]) % twoN` —— 论文要 `LWE.Enc_{s_L}(r_a)`（`Δ·m + e`） | **解药已经找到**：`coding/lwe-java/…/cape/he/LWE.java:101 encrypt(LWESecretKey,long)` **自带 `Δ=q/t` 与噪声**（§17.3）。前置：先定 `R`（已定，§12.7） |
| **B2** | **独立的 `s_L` 不存在** | `s_L` 必须**逐位等于** `s_R`（`CapeQuery:227-229`），否则净旋转 `Σa_i(s_R,i−s_L,i)−r_a` 不对；`CapeDSemanticsProbe:212/217/219` 实测**差 1 位 ⇒ 行偏 5767** | **架构决定**（`README.md:146-155` 有书面决定与代价），不是机械修复 |
| **B3** | 🔴 **P0-1：`Δ = 256` 缩放** | 把通用 LWE 密文直接喂盲旋转 ⇒ 旋转量变成 `Δr = 256r`（`缺陷总表.md:59`，**全项目最大的一条**） | 与 B1 **同一剂解药**（`LWE.encrypt`）。**这是当前最值得做的一条** |
| **B4** | 两方密钥隔离 | 单 JVM 回环。P1-1 之后仍有一条同源边界：**选择子必须与"解码者"同一把秘密** | 工程项 |

### Tier C —— **已经好了，但历史上被写成"缺"**（⚠️ **别再去重做**）

| 曾被写成 | 实际 | 出处 |
|---|---|---|
| `h_a`（A1 QUERY 3）❌ 真缺口 | ✅ `bff/BffHash.positions`，**论文几何路径上是活的**：`FusePirParams.bffPositions` → `pp`；建表侧 `CapeDemoData:453`（在 `buildTablesPaper:399` 里）走它；`FusePirStateTest:185` 断言 `pp` 的 `H` 与它逐位一致。⚠️ **但旧几何 `buildTables:185` 仍用替代品，而 `CapeDemoService` 默认调的是旧的** ⇒ 是"未接线"，不是"没实现" | §0.5 / §9.4 已就地更正 |
| `fp(K)` 用 `String.hashCode`，非 40-bit | ✅ `FusePirDecode:155 fpOf → BffSetup.fp`（`oracle40`） | §0.5 已更正 |
| `Select R, C`（A1 SETUP 4）没策略 | ✅ 已决定 `R = C = √L_BFF = 16` | §12.7 |
| `D[u] ← 0, u ∈ [L_BFF, RC)` | ✅ 在我们这组定义下是**空操作** | §11.3 ③ |
| **`Pack` 整个没有** | ⚠️ **原语有且已验**（`RingPack`），缺的只是适配器与调用方 | §17.3 / §18 / §19 |
| `Pack` 切换密钥 ≈ 12 GB | ⚠️ 实测 **8.0 GB**（`n=N`）/ **16 MB**（`n=d=16`）；**真正的墙是模数**（`t=2^32` 上选择子不存在） | §18.2 / §18.4 |

**这六条是"我说成缺、其实有（或口径错）"的高危项**，属 §17.1 那类流程缺陷的延续。
⇒ **动手前先查本表**，否则会第三次重写同一段代码。

### Tier D —— 一句话

**FusePIR 只差两层**：① `Pack` 的适配器（约 2 天量级，且已无原理性障碍）；
② `q^row` 的噪声与 `Δ=256`（**同一剂解药**，即把 `cape.he.LWE.encrypt` 接进盲旋转，见 B3 —— 这是全项目最大的一条）。
**其余"缺"要么已有、要么是已量化的架构决定、要么是你决定不做的 Alg 4/5。**

---

## 21. 「盲旋转先不要噪声」这条决定的账目（2026-10-15）

**结论：可以，而且这已经就是现在实现的状态；但"不要噪声"省下的不是隐私，隐私卡在另一处。**

### 21.1 它不是新决定，也不是"先放着"这么轻

* `prim/BlindRotateOps.java:198-209` 的 javadoc 已经写明：
  {@code b = ⟨a,s⟩ + r mod 2N}（**Δ=1、无 {@code e}**）是**本项目的工程决定，不是论文原文**。
* `cape/CapeQuery.java:258` 写着"**按需求「盲旋转不要噪声」**"。
* ⚠️ **关键事实（决定了它不是开关）**：同一段 javadoc 记着实测
  ——「本实现的盲旋转对 {@code e} **零容忍**（实测 {@code e=±1} 就**整体推移一格、取到相邻记录**）」。
  ⇒ "加噪声"**不是加一项**，而是要连带做 CMUX 里的**舍入 / mod-switch**（即 Δ 尺度处理）。
  **那正是 P0-1「旋转量变成 {@code Δr = 256r}」的来处。**

### 21.2 ⚠️ 纠正一个直觉：**噪声不是隐私的解药**

* `cape/CapeQuery.java:461` —— `m.put("sBits", q.sBits);`，**明文秘密比特是上线的**；
  服务器侧还会解析并用它（`CapeDemoService.java:1711-1727`，随后喂进三个 native 入口）。
* ⇒ 服务器拿 `a` / `beta` / `sBits` **一步相减**就得到 `r_a`：
  {@code r_a = beta − ⟨a, sBits⟩ (mod 2N)}。**不需要任何密码学分析。**
* **而且加噪声也救不了**：只要 `sBits` 还在线上，服务器就会算
  {@code β − ⟨a,sBits⟩ = Δr + e}，**除以 Δ 一舍入就还原 `r`**。
  ⇒ **隐私这一条与噪声无关**，它卡在"sBits 上线"，要改的是盲旋转的**接口**
  （三个 native 入口都收 `sBits`），不是噪声项。

### 21.3 所以"先不要噪声"的真实账目

| | 付掉 | 换来 |
|---|---|---|
| 论文保真 | A1 QUERY 5 写的是 `LWE.Enc_{s_L}(r_a)`，我们不是 | —— |
| 可宣称的范围 | 不能引用 LWE 的安全性论证（`BlindRotateOps:206-207` 原文）；"按论文参数工作的 CAPE"仍不成立（`缺陷总表.md:35-37` 已这么写） | —— |
| 隐私 | **不额外付**（21.2：损失已由 `sBits` 上线造成，与噪声无关） | —— |
| 同态管线 | —— | ⭐ **ε=0 ⇒ 每一步都是精确的**：任何失败都是真 bug 而不是"余量不足"。**这对正在做的 `Pack` / 折叠轮数 / 适配器是最干净的正对照** |

### 21.4 若决定维持"不要噪声"，该做的三件事（都不是加噪声）

1. 🔴 **把 `sBits` 从出站报文里拿掉**（或明确标注"仅单进程回环，出站即失去查询隐私"）。
   `CapeQuery:427` 的表格把它解释成"**公开引导密钥材料** {@code bsk = {RGSW(s_i)}}" ——
   **这是把两样东西混了**：`bsk`（RGSW **加密**后的比特）确实可以公开，
   而 `sBits` 是**明文比特**，不是公开材料。这一条比噪声更值得先修。
2. **把「无噪声 ⇔ Δ=1 ⇔ 旋转量是明文单位」做成断言**：盲旋转入口应要求
   `β ∈ [0, 2N)`，一旦有人把 `LWE.encrypt`（带 `Δ=q/t` 与噪声）直接接进来就**炸**，
   而不是静默转 256 倍（P0-1 的形态）。**守卫比注释可靠**（同 §18.6 的 `requireGadgetCovers`）。
3. **别删已有的负对照**：`probe/CapeAlgorithm2Diag.java:174` 与
   `CapeDemoService.java:1149` 的 **N5**（"服务器能从 `(a,beta,sBits)` 一步还原 `r_a`"）
   是"已知未修"的**活证据**；删了就等于把这条缺陷变成静默的。

### 21.5 一句话

**"先不要噪声"是安全的、省事的、且对当前调试有利的选择**；
它**不新增隐私损失**（因为损失已经由 `sBits` 上线造成），
**但它不能当作隐私问题的"以后再说"** —— 那一项与环境噪声无关，
要么把 `sBits` 下架、要么如实声明"本实现不提供查询隐私"。

---

## 22. **不要噪声**的前提下，FusePIR 还缺什么（2026-10-15）

先按 `docs/缺陷总表.md` 逐条过（那是本项目**唯一**的问题清单），再把它与 Code 对照。
**"不要噪声"= 接受 `缺陷总表` 的 P0-1 后果 1（正确性只在 `e=0` 下成立），不动后果 2。**

### 22.1 ⚠️ 先纠正注册表里一条会误导人的话

`缺陷总表.md:195` 写：*"`r_a` 那一半仍然开着 …… ⇒ **只有 P1-2（索引噪声）才能关掉它**"*。

**在"噪声被推迟"的前提下这句变成了死路，而且它本身也不准**：

| 情形 | 结果 |
|---|---|
| `sBits` 上线（`CapeQuery:461`，现状）**且**加噪声 | ❌ **照样泄漏**。服务器算 `β − ⟨a,sBits⟩ = Δr + e`，**除以 Δ 再舍入就是 `r`** —— 这本来就是 LWE 解密，噪声在"服务器持有秘密"面前毫无作用 |
| 无噪声**且**不下发 `sBits` | ❌ **仍然泄漏**：`缺陷总表.md:61` 自己判过 —— `d=16`、`q_L=2N` 下拿 `(a,b)` 解方程即可恢复 `s`。⇒ 无噪声的 LWE **不是 LWE**，安全性论证整条断掉 |
| 加噪声**且**不下发 `sBits` | ✅ 这一种才关得掉（真两方部署的形态） |

**⇒ 结论：在"不要噪声"下，查询隐私是"不可达"，不是"以后再说"。**
这条必须如实声明，而不是留在注释里。`缺陷总表.md:35-37` 那句口径已经这么写，是对的。

### 22.2 不要噪声下仍然缺的（按"是否卡住调用方"排序）

| # | 缺口 | 现状（按代码 / 注册表） | 与噪声有关吗 |
|---|---|---|---|
| **1** | 🔴 **`Pack` 的适配器**（唯一"写不出来"的） | `RingPack.pack` 收 `(as,bs) ∈ Z_t`；真实 `ct_{pay,b}` 在 **`q_R`** 上（`Δ=q_R/t` 已缩放）⇒ 适配器必须**二选一**：(a) 缩放到 `Z_t`（引入残差 ≈30，`SampleToPackLink` / `RingPack` P5b 实测），或 (b) **按 `q_LWE` 重设计 gadget 与 `SwK`**（调研 §五之三的"正确做法"）。成本：(b) 在 `nLwe=N` 下 **8.0 GB**；要降到 **16 MB** 就得先做第 2 条 | ❌ 无关（是**模数**问题，不是噪声问题） |
| **2** | 🔴 **独立的 `s_L`**（`缺陷总表:204`，未修） | 净旋转 `= Σ a_i(s_R,i − s_L,i) − r_a`，要 `≡ −r_a` 须对所有 `a` 有 `Σ a_i(…) ≡ 0`；实测**差 1 位 ⇒ 行偏 5767**。注册表口径：**与 P1-2 卡在同一结构点** ⇒ 推迟噪声**不会**让这一条变简单 | ❌ 无关（旋转恒等式） |
| **3** | 🟠 **`Pack` 是 `ct^{BF}_j` 的来源 ⇒ P0-3 的另一半**（`缺陷总表:200-201`） | 响应字段 `ctPay` 名实不符（实际是**明文**载荷，已正名 `payloadPlain`）。真修要等 `Pack`；"发 `B_pay` 条密文"按实测单条 524,401 B 推算 ≈ **30.9 MB/响应**（**推算，未实测**） | ❌ 无关 |
| **4** | 🟠 **两方密钥隔离 / P0-4** | 单 JVM、同一 `Mpc4jRgsw` 持私钥。⚠️ `缺陷总表:198` 记着：**回环里 P1-1 关掉的是线路上的明文列号（数据流），不是密钥隔离** | ❌ 无关 |
| **5** | 🟠 **P1-1 的密钥切换未实现** | `LweRlweConversion:163` 强制 `d == N`（LWE-in-RLWE）；论文 §2.5 允许 `SampleExtract` 后切到后续计算用的 LWE 密钥，**该切换没有**。它同时决定第 1 条走 (b) 时是 8 GB 还是 16 MB | ❌ 无关 |
| **6** | 🟠 **P1-3 的第二半** | `RingPack 4096` 曾 P2/P3/P4 失败 ⇒ 用 `N=8192`（**我已验：8192 上 7/7 + 13/13 全过**，第一半实际已解）。**第二半仍成立**：自检用的是**合成** `Z_t` 样本，不是 `SampleExtract` 输出 —— **我 §19 的 13/13 同样是在合成样本上做的**，别把它读成"链路已通" | ❌ 无关 |
| **7** | 🟡 **P0-1 的修法②**（无噪声下唯一还行动的 P0-1 子项） | "盲旋转接口**显式拒绝**不匹配的编码"。因为一旦有人把 `LWE.encrypt`（带 `Δ=q/t` + `e`）直接接进来，旋转量会变成 `Δr = 256r` 而**静默算错** | ⚠️ 半相关：它就是为"以后加噪声"准备的绊线 |
| **8** | ⚪ **Alg 4 / 5（`FusePIR-C` / `CAPE-C`）** | `缺陷总表:247` 明写：本项目基准 = **Alg 2（CAPE）+ Alg 1（FusePIR）**，**不实现 C 变体** | — 属"不做"，不是缺 |

### 22.3 一句话

**不要噪声只把 P0-1 的"后果 1"从缺陷降级成"已声明的口径"**（`缺陷总表:255` 口径 1 本来就这么写），
**其余 7 条一条都没少**；其中 **①`Pack` 适配器的真障碍是模数、②独立 `s_L` 是旋转恒等式**，
两者都与噪声无关，而且它们**互相牵制**（`s_L` 独立 ⇒ 适配器成本从 8 GB 降到 16 MB）。

**并且：不要噪声让"查询隐私"从"待修"变成"不可达"**（§22.1），这一条要写进声明，不能只写在注释里。

---

## 23. 补缺口（2026-10-15）：`Pack` 槽位域适配器 + 盲旋转编码绊线

用户指示：**「先补缺口不用链接 FusePIR」**。所以本轮的产出**全部没有生产调用方**，
只有实现 + 自检；接线状态如实登记在每一条后面。

### 23.1 ⚠️ 先说一条我先搞错的事实：**A1 通道本来就是 65537**

`FusePirParams.NATIVE_PLAINTEXT_MODULUS = 65537`（`:281`，由 `FusePirAnswer:364` 强制对账）。

⇒ **`Pack` 在 FusePIR 通道上根本没有模数障碍** —— `65537 − 1 = 65536` 是
`2N = 16384`（N=8192）与 `32768`（N=16384，论文的 N）的整数倍，**两边都可批处理**。

**§18.2 那条"`t = 2^32` 上不存在槽位选择子"的墙，挡的是 CAPE 演示服务那条载荷通道（D11 的第二个 `t`），
不是 FusePIR。** 我此前在 §18.5 把两条通道并列时容易让读者以为 `Pack` 整体有问题 —— 已就地加注。

### 23.2 交付物一：`fusepir/FusePirPackSlot.java` —— 槽位域适配器（论文那一步）

与 `FusePirPack`（变体 R1，系数域，一条密文一个系数）**并列且分工明确**：
本类才是"A1 ANSWER 13 → A2 ANSWER 3 能 parse 出 `ct^{BF}_j`"的那条路。

**它把三条本来靠人记的契约绑成了类型**：

| 契约 | 为什么必须绑 |
|---|---|
| **槽位布局** | 由 `FusePirSetup` 的算式**自己算**（`fpSlots`/`perValue`/`payloadBpay`/`bloomOffset`），不接受调用方手写下标 —— 手写会让"构造侧拆、解析侧拼"对不上，症状是"某些字段恒为 0" |
| **最高参与槽** | `Packed.highestSlot()`。§19.3 的静默漏算根因就是"打包方知道、打分方不知道" |
| **折叠轮数** | **不暴露** `bloomScore(…, lBf)`，只给 `scoreWithLayout` —— 把正确的轮数变成**唯一走法** |

**自检 `probe/FusePirPackSlotTest`（N=8192、t=65537、ℓ_BF=18、m=3、B_pay=61）⇒ exit 0，4/4 全达成：**

| 项 | 结果 |
|---|---|
| `P0.1/0.2` | `65537` 在 **N=8192 与 N=16384** 上均可批处理 ✅ |
| `P0.3/0.5` | `[负对照]` `t=2^32` 必须被拒、`t=65539`（不满足 `t≡1 mod 2N`）必须被拒 ✅ |
| `P1.1` | **`B_pay = 61` 个字段逐槽精确，错 0 个**（含最大 limb `t−1 = 65536`）✅ |
| `P1.2` | 40-bit 指纹经适配器往返一致 ✅ |
| `P2` | `scoreWithLayout` 得 **3**（按最高参与槽 60 取 6 轮折叠）✅ |
| **`P3`** | ⚠️ **缺陷断言**：同一密文改用论文形状折叠（5 轮 ⇒ 够到槽 31）**必须漏算成 0** ⇒ 复现 ✅（这条是钉住"契约必需"的） |
| `P4.1–P4.5` | `a` 行不等长 / `b` 条数 ≠ `B_pay` / gadget 覆盖 `65536 < t` / 交换密钥行数不足 / **槽数 4096 ≠ 环维度 8192 的 BatchEncoder** ⇒ **全部抛** ✅ |

**成本（实测，本机）：** `nLwe=16`、`base=2^8`、`digits=3` ⇒ **48 条 × 524,288 B = 24.0 MB**。
（`base=2^16, digits=2` 时是 32 条 = 16 MB —— 与 §18.4 那张表同口径。）

**接线状态：❌ 零个生产调用方**（按指示）。调用点只有本探针。

### 23.3 交付物二：盲旋转入口的编码绊线（P0-1 修法②）

`prim/BlindRotateOps.java` 新增两个入口校验，并在 `blindRotateRow`（A1 ANSWER 6 的具名入口）里调用：

* **`requireIndexConvention(a, β, n)`** —— 值域绊线：所有分量必须落在 `[0, 2N)`。
* **`requireIndexModulus(qL, n)`** —— **完备版**：调用方**声明**模数，只有 `2N` 被接受。

⚠️ **覆盖率我分三种情形算清并实测了，不敢含糊**（`probe/BlindRotateIndexGuardTest`，exit 0）：

| 情形 | 命中 |
|---|---|
| **把通用 LWE 密文直接喂进来**（P0-1 的实际形态） | ✅ **64/64 命中** —— `a` 均匀于 `[0,q)`、`q ≈ 2^174 ≫ 2N` ⇒ 第一个分量就越界 |
| 只有 `β` 是 Δ 缩放的（`a` 已归约） | ⚠️ **192/256**，解析式：`Δ·r < 2N ⟺ r < 2N/Δ = 64` 那 64 个漏掉 |
| **`a` 与 `β` 都已预先 `mod 2N` 归约** | ❌ **0 命中，且原理上不可能命中** —— 值域与合法输入**完全一样**。**这是真实盲区，不是"覆盖率不够"** |

`P3.1` **刻意断言那条盲区必须放行**（免得读者以为值域检查是完备的），
`P3.2` 断言完备版 `requireIndexModulus` 能挡住同一输入。

**回归：** `BlindRotateOps`(4 PASS) / `HashGenRhoTest`(31 PASS，**其中 P-9 正是走 `blindRotateRow` 的合法调用**) /
`FusePirStateTest`(全部) / `FusePirAnswer`(1 PASS) —— **全部 exit 0，无回归**。
⇒ 守卫挡的是坏输入，**没有误伤**合法路径。

### 23.4 本轮**没有**补的（如实登记，别当作已补）

| 项 | 状态 |
|---|---|
| **RNS + `q_R → Z_t` 的转换** | ❌ **未做**。适配器要求输入**已在 `Z_t` 内**。真实链路上 `SampleExtract_0` 的输出在 `q_R` 上、且是 **RNS 形态**（`LweRlweBridge.sampleExtract` 返回 `[prime][…]`），这一层桥仍未搭 ⇒ **P1-3 第二半仍开**，`P0-3` 的另一半也仍开 |
| **独立 `s_L`** | ❌ **未做**（是旋转恒等式 + 架构决定，不是实现工作） |
| **两方密钥隔离（P0-4）** | ❌ 未做（要拆进程） |
| **Alg 4/5** | ❌ 按既有决定不做 |
| **LWE 密钥切换 N→d（P1-1）** | ✅ **已实现并独立验收**：`prim/LweKeySwitch.java` + `probe/LweKeySwitchTest`，**30/30、exit 0（我自己重跑过，不采信代理自述）**。见 **§24** |

---

## 24. 缺口 ③ 与 RNS 桥（2026-10-15）：`LweKeySwitch` + `rnsToT`

### 24.1 交付物三：`prim/LweKeySwitch.java`（P1-1 / 论文 §2.5）

**独立验收**：我自己跑 `run-lwe-keyswitch.ps1 -N 8192 -D 16` ⇒ **exit 0，30 PASS / 0 FAIL**
（不看代理给的那份日志）。维度网格 `(N,d) = (1024,4/16/64) (8192,4/16/64)` 六组**全部实建 + 往返 PASS**。

### 24.2 ⚠️ 我给子代理的任务书里有**符号矛盾**，它按可验证判据改对了

我同时写了三句：(a) ksk 载荷 `+B^k·s[j]`；(b) **加法**累加；(c) 要满足 `b' − ⟨a',s'⟩ ≡ b − ⟨a,s⟩`。
在 (c) 自己规定的相位约定下，(a)+(b) 推出的是 `b + ⟨a,s⟩` ⇒ 用 `b = ⟨a,s⟩ + m` 解出来是
`m + 2⟨a,s⟩`，**往返必失败。三句不能同时成立。**

代理保留 (a)、把 (b) 改成**减法累加**（BV 密钥切换 `c' = (0,b) − Σ a_{j,τ}·c̃_{j,τ}`），
并用**变异测试**证明判据有分辨力：换成字面加法版后同一探针 **20 PASS / 7 FAIL / exit 1**。
⇒ **这条我认，是我写的任务书错了，它的取舍是对的。**

### 24.3 ⚠️⚠️ 必须分开的两个"16 MB vs 8 GB"——**别混着引**

代理报告里用 `(N+1)/(d+1) = 481.9×` 去对应我说的"16 MB ↔ 8 GB"。**那是两把不同的钥匙**：

| 钥匙 | 条目形态 | 单条 | `nLwe = d = 16` | `nLwe = N = 8192` |
|---|---|---|---|---|
| **Pack 的交换密钥** `RingPack.switchingKey`（§18.4） | **RLWE 密文** | **524,288 B** | 32 条 = **16 MB** | 16,384 条 = **8.0 GB** |
| **`LweKeySwitch` 的 ksk**（本节） | **LWE 样本**（`d+1` 个 long） | `(d+1)×8 = 136 B` | 24,576 条 = **3.34 MB** | 算术外推 ≈ **1.6 GB**（`digits=3`） |

两组数**恰好都在 16 MB / 8 GB 附近纯属巧合**（比值分别是 `N/d = 512` 与 `(N+1)/(d+1) = 481.9`）。
**它们是不同对象的钥匙，服务于不同步骤，不得互换引用。** 已在表里分列。

### 24.4 交付物四（额外）：`FusePirPackSlot.rnsToT` —— RNS / `q_R → Z_t` 的桥

`probe/FusePirPackSlotRnsTest` 实测：
* **转换成立**：`β − ⟨a,s⟩` 与载荷一致，**最大偏差 39**（N=8192；理论 `std ≈ 20`，
  与 `SampleToPackLink` 的 ≈30 同量级）；符号约定（`a` 取反）由"秘密改 1 位 ⇒ 偏差爆炸"的负对照确认。
* 🔴 **本轮最重要的发现**：**真实 `SampleExtract_0` 的输出维数是 `N`，不是 16**
  （RNS 形状 `[4][8193]`）。⇒ **给这条链路配 Pack 的交换密钥就是 `nLwe = N`**：
  N=8192 ⇒ **12.0 GB**，本机装不下（加 `requireGadgetCovers` 之外的维数守卫**正确抛了**，探针 P2.2 断言过）。
  ⇒ **"RNS 桥"与"密钥切换 N→d"不是两件独立的事**：Pack 要吃真实样本且密钥不炸，
  必须**先**做密钥切换（③），这与论文的 `sk = (s_L, s_R)` 是同一件事。
* ⚠️ **低于移植下限时不要跑**：N=1024 上 `工作层=1(27 bit)` ⇒ `q ≈ 2^27`、`Δ = q/t ≈ 2^11`，
  Pack 装不下。**先前真跑过一次、P3a 解出垃圾（偏差 45575）——那种结果不能当作"Pack 失败/成功"**；
  已改成**显式跳过并说明理由**（`MIN_N_FOR_PACK = 4096`，依据是缺陷总表『口径 2』的硬约束）。

### 24.5 仍然没验的（不许当成已验证）

| 项 | 状态 |
|---|---|
| **③ 与 RNS 桥的组合**（先 `LweKeySwitch` 再 `Pack`） | ❌ **未验**。代理自己也写明："与 `LweRlweBridge` 的符号对接**只写进 Javadoc、没实际跑通**"。这是**下一步最该做的实验**：它一跑通，`nLwe=d=16`（Pack 的 SwK = 16 MB）这条路才第一次被证明成立 |
| **`nLwe = N` 的完整打包** | ❌ 未验（12 GB，本机装不下）。**不得**因此声称"N=8192 上的真实链路 Pack 通了" |
| 噪声/安全 | 代理声明：`LweKeySwitch` **无噪声**、**无安全性结论**、样本是合成的。**如实接受**，不引用安全性 |
| 独立 `s_L` / 两方隔离 / Alg 4-5 | 仍是"决定 / 不做"，不是"已补" |

---

## 25. 从工作区资料里补齐 FusePIR 缺口（2026-10-15）

用户指示："想办法补齐，从工作区中所有文章里找参考"。

### 25.1 找到的权威资料（此前**没有**被引到）

| 文件 | 为什么关键 |
|---|---|
| **`coding/docs/CAPE-数学规范-SETUP到ANSWER.md`**（621 行） | **本项目的数学规范**，§0.5 密钥 / §1.3 载荷展平 / §2.3 行选择子 / §3.2-3.8 ANSWER 逐步 / §五 正确性条件 C1-C9。**它自己声明"实现时唯一依据"** |
| **`coding/docs/reports/P1-2-行选择子加噪声-分析与判据-2026-10-14.md`**（123 行） | 噪声缺口的**完整判据 + 瓶颈 + 落地步骤**；本轮之前只被当成"未完成" |
| `Hao 等 - Practical Keyword PIR…`（FusePIR 源论文）· `Submission_usenix_232/`（CAPE）· `mpc4j/ae/2025_USEC_…` | 原始出处 |
| `coding/docs/论文原文-ANSWER摘录.md` · `默认实现一览.md` · `伪代码逐行复核-两处硬偏离` | 逐行对照类 |

### 25.2 ✅ 补齐：A1 SETUP 6 的两个缺失函数

`fusepir/FusePirSetup.java` 新增（依据 = 规范 §1.3 + §四）：

| 函数 | 对应伪代码 |
|---|---|
| `padValuesToM(values, m)` | SETUP 6 前半 `Pad V_{K_i} to m values`（**补 0**，长于 m 直接抛） |
| `assemblePayload(fpDigits, count, values, bloom, lBf)` | SETUP 6 后半 `y ← fp ‖ m_i ‖ v…` |
| `parsePayload(y, m, t, lBf)` → `Payload` | DECODE 5 `Recover (f, m_K, v_1…v_m) ← y`（严格互逆） |

**自检 `probe/FusePirPayloadLayoutTest` ⇒ exit 0，全部通过**（P1 pad 4 项、P2 下标 5 项、
P3 互逆 5 项、P4 坏输入 6 项 —— 含"补的是 0 不是复制"、`count` 越界、
Bloom 非二进制位、`y` 短于 `B_pay` 等负对照）。

⇒ 这一条同时消掉了 `probe/CoeffPackTest:481` 那份"与 `CapeDemoData.buildPayload` **同分布重写**"
的重复实现所暴露的缺口。**它不改变任何既有语义**（偏移仍走同一组函数）。

### 25.3 ⚠️⚠️ 三处"缺口"被参考资料**改判**

#### (1) `sk = (s_L, s_R)` **不是两把独立密钥** —— 规范 §0.5 说是"同源"

```
s_L = (s_L[0], …, s_L[d−1]) ∈ {0,1}^d          LWE 私钥
s_R(X) = Σ_{j<d} s_L[j]·X^j ∈ R_q              RLWE 私钥（同源）
```
规范原文：**"同源"是整条链能闭合的关键**；`s_R` 的第 `j` 个系数就是 `s_L[j]`；**全程只有一套秘密**。
C9：`d = LWE 维数 ≤ N`，注"`s_R` 按 `s_L` 铺开"。

🔴 **它直接改掉 §18.4/§24.4 的"8 GB"结论**：按规范，`s_R` **只在 `[0,d)` 上非零**
⇒ `SampleExtract_0` 出来的是 **`d` 维** LWE 样本；而规范 §3.6 的交换密钥是
`SwK[j][k] = RLWE(B^k · s_L[j])`、**`j ∈ [0,d)`** ⇒ **Pack 的密钥是 `d × digits` 条，不是 `N × digits` 条**。

**而本仓库两头不一致**：`cape.d` 默认 **16**（引导密钥与 `q^row` 用它），
但 `Mpc4jRgsw` 生成的是**全 N 系数**三元秘密（`缺陷总表:203` 的直方图写明"全 8192 系数"）
⇒ `SampleExtract` 得 N 维样本 ⇒ 交换密钥 12.0 GB。
**⇒ "8 GB"不是 Pack 的固有代价，是 `s_R` 的支撑没按规范收缩到 `[0,d)` 的后果。**
论文的 `d`：`P1-2` 报告 §4.3 写"**论文是 `d = 512`**" ⇒ 按规范应是 `512 × digits` 条。

⚠️ **安全注记（别把"16 MB"当好消息）**：若 `s` 的支撑是**已知**的 `d` 元子集，则
`c_0 + c_1·s = c_0 + Σ_{j<d} c_1[j]·s_j`，而 `c_1` 均匀 ⇒ **这恰好是一个 `d` 维 LWE 实例**。
⇒ **安全性完全由 `d` 决定；`d = 16` 是玩具**（16 个未知量，线性代数即可解）。
所以 Pack 的真实密钥成本是 `d × digits × 524,288 B`，**`d` 由安全级别定，不由我们定**。

#### (2) `LWE.Enc_{s_L}(r_a)` 的"带噪声"：**两份参考资料互相冲突**

| 出处 | 写法 |
|---|---|
| `P1-2` 报告 §一（引论文 §2.5） | `LWE.Enc` 里 `b = ⟨a,s⟩ + **Δ·m + e**`（**Δ + 噪声**） |
| `CAPE-数学规范` §2.3 | `β = ⟨a, s_L⟩ + r_a mod q_L`（**Δ=1、无 `e`**） |

⇒ 规范把论文的通用 `LWE.Enc` **简化**成了无噪声形式。**你选的"不要噪声"= 站在规范这一侧；
`缺陷总表` P0-1 站论文那一侧。这不是谁写错，是两处口径**并存**。**已登记，不擅自改判。**
⚠️ 规范 §2.3 还有一条与我们不同：`a ∈ Z_{q_L}^d`（模 `q_L`），我们用 `mod 2N`。

#### (3) ⭐ 噪声缺口（P1-2）**已有解，且在我们这组参数下可行**

`P1-2` §4.1-4.3 给了完整判据：`Δ/√d > 6σ`；容量约束 `Δ·R ≤ N` ⇒ **`R < N/(6σ√d)`**。
取 `σ = 3.2`：**`N=8192`、`R=16` ⇒ `Δ ≤ 512` ⇒ 临界 `d ≈ 711`；论文 `d = 512 < 711` ⇒ 可行**（余量 1.4×）。
§七 给了落地步骤（表加 `blockWidth`、客户端 `β = ⟨a,s⟩ + Δ·r_a + e`、按 §六 的"换旋钮"分法降规模测）。
§五 说当时**主动停止**的理由是：(a) 降规模方法错、(b) **前提"先定 `R`"未定**。
**⇒ 两条现在都不成立了**（`R = C = √L_BFF = 16` 已在 §12.7 定下）。
⇒ 这条从"结构缺口"降级为 **"有判据、可落地、只差一个实现决定"**。

### 25.4 参考资料另外暴露的三处**实现偏离**（新发现）

| 出处 | 规范说 | 我们做 | 影响 |
|---|---|---|---|
| 规范 §1.3 | `B_pay = β_fp + **2** + m·(1+ℓ_BF)`（"个数"拆 **2** 个 limb） | `fpSlots + **1** + …` | **差 1，两者不可能同时对**。⚠️ **未改** —— 改了会静默打破既有 DB、`CapeDemoData`、`CapeAlgorithm2Diag` 等**全部载荷消费者**。探针 `P5` **刻意断言该差异存在**（改了就会变红，提醒更新文档） |
| 规范 §3.6 | 分解是**平衡**的：`a_j = Σ d_k B^k`，`\|d_k\| ≤ B/2` | `RingPack.pack` 用 `digit = remaining % base ∈ [0,B)`（**非平衡**） | 平衡分解能省噪声 ⇒ **Pack 的一条可改进点**，且与 §19/§24 的噪声余量直接相关 |
| 规范 §3.2 | `Acc_c = CtExtract_0(CtRotate(q^col, −c))` 再与 `P_{c,b}` 相乘 | 直接 `CtPtMul(q^col[c], P_{c,b})` | 规范 §2.2 自己记了两种读法；与 D3"列选择子 = C 个独立密文"是同一处 |

### 25.5 结论：四个缺失函数的现状

| 缺口 | 现状 |
|---|---|
| SETUP 6 `Pad V_{K_i} to m` | ✅ **已补**（§25.2） |
| SETUP 6 `y_{K_i}` 装配 | ✅ **已补**（§25.2，含逆函数与互逆自检） |
| SETUP 3 `sk = (s_L, s_R)` | ⚠️ **改判**：不是"生成两把密钥"，而是"把 `s_R` 按 `s_L` 铺开"（§25.3(1)）。**这是实现工作**（`Mpc4jRgsw` 接受 `SecretKey`），且有量化收益（`N/d` 倍密钥） |
| QUERY 5 `LWE.Enc_{s_L}(r_a)` 带噪声 | ⚠️ **改判**：口径冲突（§25.3(2)）；且**判据已备、可行性已证**（§25.3(3)），只差"要不要做"的决定 |

---

## 26. ✅ 把 `s_L` 铺成 `s_R`（规范 §0.5）—— 实测落地，Pack 的密钥 **512×**

（2026-10-15，承接 §25.3(1)；用户"继续"）

### 26.1 交付物

* **`prim/LweRlweConversion.liftLweSecretToRlwe(m, sL)`** —— 构造
  `s_R(X) = Σ_{j<d} s_L[j]·X^j` 的 `SecretKey`（规范 §0.5 的"同源"）。
* **`probe/FusePirSecretLiftTest`** —— **exit 0，P1–P5 全达成**。

### 26.2 实测结果（N=8192、t=65537、d=16、ℓ_BF=18、B_pay=23）

| 项 | 结果 |
|---|---|
| **P1 现状** | 默认秘密 **非零 5375–5508 / 8192**、最高非零下标 **8191** ⇒ **不 ⊆ [0,d)** |
| **P2 铺开后** | 非零 **9** 个、最高下标 **15** ⇒ 支撑恰为 `[0,d)`；前 d 个系数**逐位 = `s_L`**；**密钥可用**（加密→解密往返 12345 正确）；且与默认密钥确实不同 |
| **P3 负对照** | `s_L` 长于 N / 含 2 / 为空 ⇒ **全部抛** |
| **P4.1 正例** | 铺开后 + **只带前 16 项** + **16 行**交换密钥 ⇒ 大值字段最大偏差 **1**（相对 0.002%） |
| **P4.2 负对照** | **全支撑**秘密 + 同样只带前 16 项 ⇒ **解错**（超容差）⇒ 证明"解得回来"是**铺开**带来的，不是碰巧 |
| **P5 成本** | **48 条 = 24.0 MB**（`nLwe=d=16`）vs **24,576 条 = 12,288 MB**（`nLwe=N=8192`）⇒ **512×** |

> ⇒ **§18.4/§24.4 那个"8–12 GB"现在有了完整的因果链**：
> 它**不是** Pack 的固有代价，而是 `s_R` 用了全 N 支撑（P1 实测 5375–5508 个非零）的后果；
> 按规范铺开之后就是 `d × digits` 条。

### 26.3 ⭐ 顺带发现：铺开**也把缩放残差压小了**（但不等于位精确）

`P4.1b`：位/小值字段 **14/20 个恰好相等，最大偏差 1**。
而 §24.4 在**全支撑**下实测的是**偏差 30–60、0 个恰好相等**。

**原因**：缩放残差是 `Σ_j δ_j·s_j`，**只累加在秘密的非零支撑上**。
全支撑 ⇒ ~5500 项 ⇒ `std ≈ 20`；铺开后 ⇒ `d=16` 项 ⇒ `std ≈ 1.3`。

⚠️ **但不要过度解读**（这条很容易被说成"位精确问题解决了"）：
* 残差随 **`√d`** 增长。论文的 `d = 512` ⇒ `std ≈ 5.3` ⇒ **又超过位值 1**；
* 所以铺开是**密钥体积的大胜**（512×）+ **残差的顺带收益**，
  **并不**使 `s_j == τ` 的精确判据成立。要那一条仍需 §25.3(3) 的块布局（`Δ/√d > 6σ`）。

### 26.4 ⚠️ 安全含义（必须与 512× 一起说）

若秘密的支撑是**已知**的 `d` 元子集，则 `c_0 + c_1·s = c_0 + Σ_{j<d} c_1[j]·s_j`，
而 `c_1` 均匀 ⇒ **这恰好是一个 `d` 维 LWE 实例**。
⇒ **安全性完全由 `d` 决定**：`d = 16` 只是玩具（16 个未知量，线性代数即可解）。
`d = 512`（论文实验值）时密钥是 `512 × 3 × 524,288 B ≈ 768 MB`。
**⇒ "24 MB"是 `d=16` 的数字，不能当作可用参数下的成本。**

### 26.5 本 Java 移植的**三个库事实**（踩坑记录，别再重踩）

| # | 事实 | 症状 |
|---|---|---|
| 1 | `SecretKey.data()` 必须覆盖**全部声明素数**（含最后一个 special prime），不是只覆盖 `workingPrimeCount` 个 | 否则 `ValCheck` 判 `secret key is not valid for encryption parameters` |
| 2 | **`NttTables` 的第一个参数是 `log2(N)`，不是 `N`** | 传 `N` 会建出长度 1 的表 ⇒ `NttHandler.transformToRev` 报 `Index 1 out of bounds for length 1` |
| 3 | `parmsId` 必须用**库自己那把密钥身上那个对象**（`m.sk.parmsId()`），不能用 `context.firstParmsId()` | 两者 `equals`/`==` 都为真，但 `ValCheck.isMetaDataValidFor` **仍然判 false**；换 `m.sk.parmsId()` 立刻通过 |

> 第 3 条尤其阴：`coeffCount` 对、`isNttForm` 对、`parmsId ==` 为真，**只有 metaValid 是 false**。
> 是靠直接调公开的 `ValCheck.isBufferValid/isMetaDataValidFor/isValidFor` 三项分别打印才定位到的
> —— **"问校验器哪一项不过"比猜快得多，这条方法值得留。**
> ⚠️ 本类里的 `m.sk` 是 `Mpc4jRgsw` 的公开字段，所以这条依赖是成立的。

### 26.6 状态

**这是"补齐"而不是"接线"**：`liftLweSecretToRlwe` 的调用方只有本探针；`Mpc4jRgsw` 与协议路径**一行未改**。

---

## 28. 📌 交接与长期规矩（2026-10-15）

> **规矩（用户 2026-10-15 立）**：**只要会话的上下文开始压缩（compaction），就立刻写好
> "交接单 + 开新对话提示词"**，不要等被切断再补。
> 交接单要**写进工作区文件**（聊天会被压缩掉），并在聊天里给一段可复制的提示词。
> 位置约定：`coding/rgsw-lab/HANDOFF-<主题>.md`。
> （试过写进 Hindsight，服务没起：`ECONNREFUSED 127.0.0.1:9077` ⇒ 以工作区文件为准。）

**当前交接单：`coding/rgsw-lab/HANDOFF-FusePIR四步.md`**（FusePIR 四步 / ANSWER 实现）。

**开工读序**：本文件 §18–§28 → 交接单 → 才看源码。

**本轮（§25–§27）留下的、交接单里逐条列了的要点**（细节见那两份，这里只留索引）：
`DB^CAPE` 加宽口径（`B_pay=61`）· `Pack` 在 A1 的 65537 上成立、在 CAPE 演示的 `2^32` 上不可能 ·
`sampleExtract` 维数盲必须截到 `d` · 铺开 `s_R` 使 Pack 密钥 512× · 四步的四个 CAPE 入口 ·
**唯一卡点 ANSWER 6（盲旋转）**，其三个假设已被实测否掉两个半。
**唯一的开新对话提示词在交接单 §7。**

---

## 27. FusePIR 四步做成 CAPE 可调用的入口（2026-10-15）—— 结构通、ANSWER 5-11 算术未通过

用户指示："我要这四步的调用函数，对应 CAPE 中需要对 FusePIR 的调用"，
随后"继续刚才对 FusePIR 四步的实现"。

### 27.1 CAPE 到底调用 FusePIR 的哪几处（逐字来自 A2 原文，MAP §10）

```
A2 SETUP  11: (pp_F, st^F_S, sk) ← FusePIR.Setup(1^λ, DB^CAPE).
A2 QUERY   1: (q_anc, st^anc_C) ← FusePIR.Query(pp_F, sk, K_1).
A2 ANSWER  2: resp_anc ← FusePIR.Answer(st_S, q_anc).
A2 ANSWER  3: Parse {(ct_{v_j}, ct^BF_j)}_{j=1}^m from resp_anc.   ← ★ 决定 resp 的类型
A2 DECODE  2: V_{K_1} ← FusePIR.Decode(sk, st^anc_C, resp_anc).
```
⇒ **四处**，`fusepir/FusePirFourStep.java` 就是按这四个签名写的
（`setup` / `query` / `answer` / `decode`），另有两条**已存在**的接线不重复造：
`pp_C ← pp_F.extendBloom(…)`（A2 SETUP 12）与 `st^F_S` 直接当 `st_S`（A2 SETUP 13）。

**⚠️ 两处按原文读出来的、容易把签名写错的地方：**
1. **A2 SETUP 11 传进去的是 `DB^CAPE`，不是原始 DB** —— A2 SETUP 3-10 先把每个值配成
   `(v, b_v)`，**然后**才调 `FusePIR.Setup` ⇒ A1 SETUP 6 的 `y` 在 CAPE 这条路上是
   `fp‖m_i‖v‖b_v‖…` ⇒ **`perValue = 1+ℓ_BF`、`B_pay = 61`**（与 §18.5 的 CAPE 列一致）。
   ⇒ 本类把"每个值带不带 Bloom 段"做成参数：{@code lBf=0} 就是纯 A1（A1 的 `y` 无 Bloom，§9.1）。
2. **A2 ANSWER 3 要"parse 出每个候选的 `(ct_{v_j}, ct^BF_j)`"** —— 槽位域 Pack 把它们放进
   **一条**密文的槽里 ⇒ "parse" 落成**槽对齐**（`Resp.valueCt(j)` / `Resp.bloomCt(j)`）。

### 27.2 已通过的（有断言）

| 项 | 结果 |
|---|---|
| **P1 Setup 形状** | `B_pay=61`（CAPE 加宽口径）、`R·C=48 ≥ L_BFF=48`、`st^F_S` 表宽 `=B_pay`；**铺开后的秘密非零 5 个、最高下标 13 < d=16** |
| **P2 明文侧重构** | **16/16** 个关键词满足 `Σ_a D[h_a(K)] = y_K` |
| **P3 Query 形状** | `(r_a,c_a)` 与 `h_a(K_1)` 一致、`recombine(R)` 回到 `u_a`、`q^row` 长 d、`q^col` 有 C 条、`st^anc_C` 只带关键词 |
| **P4 Answer 跑通** | **26–28 s**，产出 `packed(S, t=65537, N=4096, B_pay=61, lBf=18, 段起点=[5,24,43], 最高参与槽=60)` —— **布局与 §19 预测逐项相符** |

**⇒ `Pack` 那一层是忠实的**：P4.0 判出 ANSWER 的相位错误之后，**打包件解出来的值
（24245）与相位检查算出来的错误值完全相同** ⇒ 错在 ANSWER 5-11，不在 Pack。

### 27.3 ❌ 未通过的：ANSWER 5-11 的算术（这是当前唯一的 bug）

**P4.0（与 Pack 完全无关的判据）** `β − Σ_{k<d} a_k·s_L[k] mod t` 对每个字段比对真值：
**0/61 个字段相等**，例如字段 4 相位 24245 vs 真值 1007（偏差 23238）。
⇒ **列选择 / 盲旋转 / SampleExtract 这条链的算术不对**，与 Pack 无关。

**已排除的**：
* BFF 那一步（P2 通过 ⇒ `D` 与位置函数自洽）；
* Pack（上面那条"同一个错值"的对照）；
* 形态问题（`NTT form mismatch` 已修，见 27.4）；
* 维数问题（截断到 d 之后 Pack 不再要求 N 行密钥）。

**下一步该做的最小实验**（写在这是为了别再从头发散）：
在 `answerSamples` 里把 **列选择之后、盲旋转之前**的 `acc` 暴露出来，解密它的**整条多项式**，
断言它等于 `P_{c_a,b}`（逐系数）。这一条能把"列选择错"与"旋转落点错"分开。

### 27.3.1 ✅ 已做（2026-10-15）：三条硬结果把 bug 钉到 ANSWER 6

| 实验 | 结果 | 排除掉什么 |
|---|---|---|
| **P4.00** 解密列选择后的 `acc`，与 `P_{c_a,b}` 逐系数比 | **0 / 4096 个系数不符**（`c_a=3, b=4`） | ⇒ **ANSWER 5 完全正确**（含"不跳过零分量"的 D3 读法） |
| **P4.0b** 假设「常数项 = `Σ_a (−1)^{r_a+1}·D[u_a]`」 | **0 / 61 命中** ⇒ **假设被证伪** | ⇒ 旋转的**符号**不是 `X^{−r} = (−1)^r X^{N−r}` 那一种 |
| **P4.0c** 暴力搜「每路贡献 `±P[k]` 或 `0`」的全部组合（`(2R+1)^3 = 729`），要求**同时**解释全部 61 个字段 | **0 个组合成立** | ⇒ 落点**根本不是 `P` 的某个系数**（任何下标、任何符号都不行）⇒ **问题在"旋转量本身"，不在落点** |

三条合起来：**ANSWER 5 是对的；ANSWER 6 产生的相位不是 `P_{c_a,b}` 的任何系数**
（`P` 的支撑只有 `[0,R)=[0,4)`，所以"转到别的系数"最多给出 `±P[k]` 或 0 —— 实测否掉了）。

**⇒ 现在的怀疑集中在 `q_a^row` 的构造，而不是落点：**
1. **`β` 里用的秘密与 `bk` 里加密的秘密是否同一个**：`bk[i] = encryptRgswConstant(s_L[i])`
   （在 **`s_R`** 下加密 `s_L[i]`），而 `qRow` 用 `lweEncryptIndex(s_L, …)`。
   盲旋转累的是 `X^{Σ a_i·(bk 里那个比特)}` —— 两者必须逐位同源，
   而本仓库**反复**在这一点上出过事（`CapeQuery` 里那段最长的不变量注释、P1-1 的四轮教训）。
   本探针的 `Db.synthetic` + `liftLweSecretToRlwe` 路径**没有**像 `CapeQuery` 那样做同源性对账。
2. **`acc` 的形态标志不可靠**：`isNttForm()` 在本移植里默认 true（§27.4 #2），
   而 `blindRotate` 用 `multiplyPowerOfX` —— **对 NTT 形态的密文乘 `X^k` 是错的**
   （NTT 域的旋转不是乘单项式）。`columnSelect` 里那句
   `if (acc.isNttForm()) transformFromNttInplace(acc)` **可能根本没执行**。
   ⚠️ 这一条最像：P4.00 用 `decrypt`（它自己也查 `isNttForm`）验过，两边可能**同样地**被这个标志骗过。

**下一步（最小的那个）**：把 `acc` 的形态**显式**统一 —— 在做列选择时就保证交给盲旋转的是
**系数形态**（不要依赖 `isNttForm()`），然后重跑 P4.0。若还是不行，再查 `bk` 与 `qRow` 的同源性。

### 27.3.2 旧的怀疑（保留，已被 P4.0b/4.0c 部分否掉）
* **旋转方向**：规范 §3.3 明确写"常数项**不是** `P[r_a]`，而是 `±P[(−r_a) mod N]`；
  要直接得到 `P[r_a]` 须把旋转量写成 `X^{N−r_a}` 或让累加器初值带 `X^{+r_a}`"。
  而 `HashGenRhoTest` P-9 用同一个 `blindRotateRow` 得到的是 `P[r_a]` —— 两处口径需对齐；
* **列选择的形态**：`qCol` 加密的是**常数** `e[c]`，`ctPtMul` 在 NTT 形态下是**环乘**
  （不是槽位逐点乘）⇒ `e[c]·P_{c,b}` ✓ 这条推理成立，但**未经实测确认**。

### 27.4 途中修掉的三处（都是我自己写错的，记下来防复发）

| # | 错误 | 现象 / 修法 |
|---|---|---|
| 1 | 复用同一个 `Plaintext` 装 `P_{c,b}` | 第二轮起形态已被污染；改成每轮新建 |
| 2 | 用 `isNttForm()` 判断"我准备的是不是系数形态" | **本移植里 `new Plaintext(n)` 的 `isNttForm()` 默认就是 true** ⇒ 判据恒真、只会误导。已删掉该守卫并写清原因（与 §26.5 第 3 条同源） |
| 3 | `q^col` 的密文没转 NTT 形态 | `multiplyPlain` 要求**两侧同形态**；`Encryptor.encrypt` 给系数形态 ⇒ 抛 `NTT form mismatch`。改成**加密后立刻 `transformToNttInplace`**（一次/查询，而不是每次相乘都转） |

### 27.5 状态

**是"补齐 + 自检"，不是"接线"**：`FusePirFourStep` 没有生产调用方；
`CapeDemoService` / native 路径一行未改。
⇒ **结构（四个签名、DB^CAPE 加宽口径、A2 ANSWER 3 的 parse 形式）已经定下来并验过大半，
剩下的是 ANSWER 5-11 的一处算术。**
---

## 29. 🔴 ANSWER 6 的"0/61"**已定位并修掉**（2026-10-15）—— 根因是**位置函数种子不同源**，不是盲旋转

（本轮：`probe/FusePirAnswerBisectTest`（新，二分辨识）+ 修 `fusepir/FusePirFourStep.setup`）

### 29.0 结论先行

1. **ANSWER 5 / 6 从头到尾都是对的。** §27.3.1 那三条"硬结果"把 bug 钉在 ANSWER 6 上，
   **钉错了方向** —— 它们全都建立在同一个错误前提上（见 29.2）。
2. **真根因**：`FusePirFourStep.setup` 里建表用的位置函数种子与 `pp` 发布的 `ρ_H` **不是同一个**。
   症状 = 协议**每一步都对**，但查询读到**别的格子** ⇒ 相位判据 0/61。
3. 修法：`ρ_H` 同时当 `BffEncode.encode` 的首次尝试种子，`pp` 用**建表实际用的那个种子**
   `tab.seed`（重试成功时它是 `ρ_H + attempt − 1`），并加**建库时就会抛**的守卫
   `requirePositionsMatch`。

### 29.1 根因：两处种子差 1，而类型系统拦不住

| 位置 | 种子 |
|---|---|
| 建表（`BffEncode.encode:170`） | `seed0 + attempt − 1` = **20261016**（`seed0` 由探针传入） |
| 查询（`pp.h()`，`FusePirParams.bffPositions(su.rhoH, …)`） | **20261015**（`rhoH` 由探针传入） |

`BffHash.positions(K, seed, hg)` 的 `seed` 与 `hg.rhoH` 是**同一个量而该函数不校验一致**
（`BffHash.java:490` 原文警告）⇒ 两边取不同常量时**类型合法、编译通过、运行期完全静默**。

**实测证据（`probe/FusePirAnswerBisectTest` 的 Q2 组，修复前）**：

```
[info] 16/16 个关键词的两套位置**不一致**
[info] 锚关键词 kw-0003：建表 [6, 25, 40]；pp [15, 30, 36]
[info] 在 [20261012,20261020] 里搜到 1 个种子能复现建表位置：20261016
[达成] Q2.3 [正对照] 建表那套 u_a 的和 == 真值：61/61 个字段
[达成] Q2.4 [负对照] pp 那套 u_a 的和 == 真值：0/61 个字段
```

⇒ **"0/61"整个由种子不同源造成**，与列选择、旋转、形态都无关。

### 29.2 ⚠️ 为什么 §27.3.1 的三条硬结果会把人带偏

| 实验 | 它实际证明了什么 | 它**没有**证明什么 |
|---|---|---|
| P4.00（`acc` vs `P_{c_a,b}` 逐系数） | 列选择对 | —— |
| P4.0b（带符号和 0/61） | 带符号和不是答案 | 因为**真值那 61 个数取自建表格子**，而相位取自查询格子；两边不同 ⇒ 这一条本来就不可能命中 |
| **P4.0c（0/729 组合）** | **什么也没证明** | 它的候选列取自**建表**那套 `u`，相位来自**查询**那套 `u`；两列不同 ⇒ **组合空间里根本不含真解**。0/729 是**结构性的**，不是"落点不是 P 的系数" |

**教训（值得留档）**：一条判据只要**同时**用到"真值"与"被测物"，就必须先证明
**两者的输入同源**；否则它失败时给出的是"错的方向"，而不是"没有信息"。
本轮为此把探针改成**两层判据**（见 29.4）。

### 29.3 修法与守卫

* `BffEncode.encode(…, rhoH, …)` —— `ρ_H` 按 A3 SETUP 8 的定义就是位置函数种子（原先错传 `seed0`）。
* `pp` 用 `bp.hashGen(tab.seed)` + `bffPositions(tab.seed, …)`。
* 新增 **`FusePirFourStep.requirePositionsMatch(pp, keywords, tab.pos)`**：
  建库时逐关键词比对"查询侧 `pp.h()` 给出的位置"与"建表侧实际用的位置"，不等就抛。
  守卫自己也有正/负对照（`Q2.5`：拿错种子的 `pp` 必须抛、拿对的必须不抛）。
  （§18.6 那条纪律："守卫写在旁边没人用"等于没有守卫。）

### 29.4 修复后的实测（`FusePirFourStepTest`，N=4096、d=16、ℓ_BF=18、B_pay=61）

| 判据 | 修复前 | 修复后 |
|---|---|---|
| **P4.0a 算术层**（在 `Z_{q_R}` 上把相位算完、**只舍入一次**；无容差） | — | **61/61** ✅ |
| **P4.0b 交付层**（过 `rnsToT` 逐分量舍入） | **0/61**，最大偏差 **32378** | **61/61 在残差上界内**，最大偏差 **2**（精确命中 25–35/61，逐次运行不同） |
| P4.0b 正对照（不带符号的重构和） | — | **61/61** ✅ |
| P4.0b2 负对照（`(−1)^{r_a+1}` 带符号和） | — | **0/61** ✅（既证伪 §27.3.1 的符号假设） |
| **P4.0c 落点搜索** | 0/729（**结构性**，见 29.2） | **恰好 1 个组合**：`路0:+P[3] 路1:+P[2] 路2:+P[0]` = **每路 `+P[r_a]`**，与论文一致 ✅ |
| §4.1③ `β ≡ ⟨a,s_L⟩ + r_a (mod 2N)` | — | **3/3 路成立** ✅ |
| §4.1② `cmux` 分支方向 | — | `c=1` 返回**第二个**参数（旋转支）⇒ 方向正确，**不是 bug** ✅ |
| §4.1① P-9 配方搬进本管线（铺开秘密 + N=4096） | — | **6/6 个 `r_a` 命中**（4 个精确、2 个偏差 1 = 残差）✅ |

**⇒ 交接单 §4.1 的三步全部做完，结论是：三条嫌疑都不成立。**
P-9 配方在本管线上就是对的；`cmux` 方向是对的；`β` 恒等式成立。

### 29.5 新增的两层判据（`AnswerOps.phaseOfRns` + `FusePirFourStep.answerRnsSamples`）

`rnsToT` 把 `β` 与 `N` 个 `a_k` **各自**从 `q_R` 舍入到 `Z_t`，相位里因此多出
`Σ_k δ_k·s_k`（`δ_k ∈ (−½,½]`，上界 `#ones/2`）。**这是桥的固有残差，不是 ANSWER 的算术错**
（§24.4 / §26.3 已登记）。所以判据必须分两层：

| 层 | 入口 | 能不能要求精确相等 |
|---|---|---|
| **算术层** | `AnswerOps.phaseOfRns(m, rnsSample, sL)`（`Z_{q_R}` 上算完相位、**只舍入一次**） | ✅ **能**（这就是 P4.0a 的 61/61） |
| **交付层** | `FusePirFourStep.answerRnsSamples`（三路相加后的 RNS 样本，未经桥）→ `toTruncatedZLwe` | ❌ 不能，只能要求 `|偏差| ≤ #ones/2` |

**⚠️ 混着说就会把"桥的残差"误报成"盲旋转错" —— 本轮之前正是这么错的。**

### 29.6 这段代码里的一个陷阱（我自己写的，值得留）

`phaseOfRns` 第一版**忘了把 `a` 取反**（`FusePirPackSlot.rnsToT:368` 有 `.negate()`：
SEAL 的相位是 `c0 + c1·s`，而本项目约定 `b ≡ ⟨a,s⟩ + m`，所以样本里的 `a` 就是 `−c1`）。
漏掉这一次取反 ⇒ 相位差 `2·Σ c1_k s_k` ⇒ **每个字段都像随机数**（第一次跑 P4.0a 就是 0/61，
而**同一时刻交付层是 61/61** —— 两层判据并存才让这个自伤立刻现形）。

### 29.7 仍未闭合的，以及它们的**精确形态**

| # | 卡点 | 精确症状（实测） | 与 ANSWER 5-6 有关吗 |
|---|---|---|---|
| **①** | **`q_R→Z_t` 桥的缩放残差（±1..2）** | 小字段被污染：`m_i` 解出 `4`（真值 3）⇒ `parsePayload` 抛；`decode` 判 `⊥`；bloom 的 0/1 位变成 `−1/0/1/2` | ❌ **无关**（是桥，已登记 §24.4/§26.3） |
| **②** | **`Resp.bloomCt(j)` 的"掩码"那一步在打包件上不成立** | 掩码乘打包件 **0/4096**（解出均匀随机值 = 解密失败） | ❌ 无关（见 §29.8） |

### 29.8 §4.2 的结果：旋转**做成了**，它后面那一步另有问题

**§4.2 要求的"2 的幂组合"已实现并逐位验过**（`FusePirFourStep.rotateRowsByComposedBits`）：

| 判据 | 结果 |
|---|---|
| `P5.0a` 值槽 `4 / 23 / 42`（都不是 2 的幂）转到槽 0 == 打包件对应槽 | **3/3 个候选** ✅ |
| `P5.0c` 负对照：多转一格 ⇒ 必须对不上 | ✅ |
| `P5.0d` 正对照：转 `s0` 再按 `N/2−s0` 转回 ⇒ 逐位还原 | **4096/4096** ✅（⇒ 组合是精确的，不是近似） |
| `P5.0e` 只旋转（`base=5 = 4+1`）与打包件槽 `[5,11)` 逐位比 | **逐位相同** ✅ |

**但 `bloomCt` 在旋转之后还要"掩码"（只留槽 `[0,ℓ_BF)`），那一步把密文解坏了**
（`P5.0b` 0/3）。诊断过程（每一步都配正/负对照，全部实测）：

| 实验 | 结果 | 排除了什么 |
|---|---|---|
| 同一条稠密掩码 × **新加密**密文（连乘**两次**） | **4096/4096** | 掩码机构本身、明文编码、明文复用 |
| 打包件 × **常数**明文 1 | **4096/4096 还原** | 打包件"不可乘" |
| 打包件 × `RingPack.slotSelector`（单槽选择子） | **0/4096** | "只是 18 位掩码太大" |
| 结构：`size()` / `parmsId` / RNS 素数个数 | **两边完全相同** | 形态、层级、模数 |
| 系数↔NTT 往返、旋转 | 都精确 | 形态与旋转 |

⇒ **唯一剩下的解释是噪声预算**：槽掩码在**系数域稠密**（`l1 ≈ N·t/2`），
而本管线的 `m.encrypt` 出**无噪声**密文（所以新加密连乘两次都精确）；
`RingPack` 的产物是这条链上**第一条真带噪声的密文** ⇒ 一次稠密明文乘就过界。

**给 `ct^BF_j` 找出路的三个选项（未选，等决定）**：
① **不掩码**：只旋转，"置零"交给 CAPE 的 `q^BF`（客户端侧段外本来就是 0 ⇒ `CtCtMul` 的积在段外也是 0 ⇒ 折叠不带杂质）；
② 在 **`Pack` 之前**按候选分别掩码（那时还是理想 `Z_t` 样本、无噪声）；
③ 找出 `RingPack` 产物噪声的真正来处并压低它。

### 29.9 本轮改动的文件

| 文件 | 改动 |
|---|---|
| `fusepir/FusePirFourStep.java` | **修根因**（`rhoH` 当首次尝试种子 + `pp` 用 `tab.seed`）；新增 `requirePositionsMatch` 守卫、`rotateRowsByComposedBits`（§4.2）、`answerRnsSamples`、`packedSlots`/`packedCoeff`/`galoisKeys` 诊断；`bloomCt`/`maskFirstSlots` 写清实测警告 |
| `fusepir/AnswerOps.java` | 新增 `phaseOfRns`（算术层判据）、`sumPaths`；`addPaths` 改为两步的复合（不再各自实现一遍算术） |
| `fusepir/FusePirPackSlot.java` | `scaleToT` 由 private 改 public（让"只舍入一次"的判据复用同一口径，不许手抄公式） |
| `probe/FusePirAnswerBisectTest.java` | **新建**：Q1（旋转本身：P-9 配方 / cmux 方向 / β 恒等式）、Q2（真值同源）、Q3（解释 P4.0c 为何 0 命中） |
| `probe/FusePirFourStepTest.java` | P4.0 拆成算术层/交付层两层；P4.0b/4.0c 改用无残差的算术层相位；新增 P5.0a–P5.0g（§4.2 与掩码的诊断，含缺陷断言）；`decode` 经 `decodeSafe` 包一层，免得一次抛异常把 P5/P6/P7 全带走 |

**未动**：`CapeDemoService` / native 路径（一行未改）。
---

## 30. ✅ FusePIR 四步**跑通**（2026-10-15 第三轮）—— 两个卡点都清掉，用的是"K 倍精度"这条路

（本轮：改 `fusepir/FusePirFourStep.setup`/`answer`/`decode` + `fusepir/FusePirSetup` + `fusepir/FusePirPackSlot.pack`；
新建/重建 `probe/FusePirFourStepTest`。判据命令：`.\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirFourStepTest 16 4096 16 18`）

### 30.0 结论先行

**`FusePirFourStepTest` 现在 exit 0，全部判据达成**（P1/P2/P3/P4.00/P4.0d/P4.0a/P4.0b/P4.0b2/P4.0c/P4/P5/P6/P7）。

| 判据 | 结果 |
|---|---|
| **P4.0a 算术层相位**（Z_{q_R} 上算完、只舍入一次，无容差） | **61/61** ✅ |
| **P4.0b 交付层相位**（过桥 + 除 K） | **61/61，最大偏差 0** ✅ |
| P4.0c 落点搜索 | **恰好 1 个组合** = 每路 `+P[r_a]` ✅ |
| **P4 四步端到端**（SETUP→QUERY→ANSWER(真 Pack)→DECODE） | **恢复出 `[1007,1008,1009]`** ✅ |
| **P5 A2 ANSWER 3 的 parse**（值槽 + Bloom 段对齐 + 字段域取值） | **全绿**，含 P5.0c/0d/0f/0g 正负对照 ✅ |
| **P6 Decode** | ✅ |
| P7 负对照与 4 关键词抽查 | ✅ |

### 30.1 卡点 ①（`q_R→Z_t` 桥的缩放残差）—— 用 **K 倍精度**解决

`FusePirPackSlot.rnsToT` 逐分量把 `β` 与 `a_k` 从 Z_{q_R} 舍入到应答通道明文域，相位里多出
`E = Σ_k δ_k s_k`，**`|E| ≤ ones/2`（ones = 私钥汉明重量），且这个绝对误差与明文模数无关**
⇒ 换更大的 `t` 救不了它（这一点本轮专门确认过）。

**解法（本轮实现）**：把字段**乘上精度倍率 K** 存放，让残差落在"K 分之一"的余量里。

```
字段域 T = 65537（论文的 t，布局/limb/B_pay 全部按它算，所以 B_pay 仍是 61）
应答通道 tRing ≡ 1 (mod 2N)、素数、tRing = K·T，K > ones（本组实测 K = 17、ones = 11）
  setup   ：y 的每个字段写成 K·field；D 的算术模数也用 tRing（用 T 会把大字段取模毁掉）
  answer  ：Pack 在 tRing 上跑（槽位布局仍按 T 算 ⇒ FusePirPackSlot.pack 新增 tField 参数）
  decode  ：槽值除以 K（一次舍入）⇒ E 被完全吸收，field 精确
```

* `FusePirFourStep.ringModulusFor(n, ones, base, digits)`：在 `[tRing_min, base^digits)` 里搜
  `≡1 (mod 2N)` 的素数，找不到就**抛**并说明该调哪个旋钮（§18.6 的守卫纪律）。
* `FusePirSetup.assemblePayload(..., scale)` / `FusePirSetup.divideScale(y, K, tRing, T)`：一对互逆。
* ⚠️ **这条路只因为"盲旋转不要噪声"才免费**：BFV 噪声随 `t` 增长，有噪声时换大 `t` 会吃噪声余量。
  本实现 Δ=1、无噪声（§21 的工程决定）⇒ 精度可以这样买。

**途中踩的三个坑（都是"两个模数混淆"这一类静默错，值得留档）**：

| # | 坑 | 症状 |
|---|---|---|
| 1 | `BffEncode.encode(..., payload, T, ...)`：**建表 D 的算术模数**也必须换成 tRing | 表按 `mod T` 回填，`K·field > T` 被取模毁掉 ⇒ 相位全错但每一步单独看都对（P2 直接掉到 0/16） |
| 2 | **判据的参考系**：`bffArray()` 里存的是 `K·field`，不能与"除过 K"的相位比 | P4.0b/P4.0c 显示 0/61，其实只差一个 K 倍 |
| 3 | 🔴 `divideScale` **不能整体按中心代表折叠** | `K·field` 可以超过 `tRing/2`（`field > 32768` 时就会）⇒ 大的正字段被误判成负数。症状极隐蔽：**只有大的指纹 limb 错、小字段全对**，且偏差是个常数（实测 3854 ≈ T/K）。正确做法：只有"离 `tRing` 不到 K"的那一点才当负残差 |

### 30.2 卡点 ②（`Resp.bloomCt` 的掩码）—— **不是噪声，是"稠密明文的系数域乘积越界"**

§29.8 我把它归因成"噪声预算"，**那个归因是错的**（本轮更正）。真实判据：

* 槽掩码在**系数域是稠密的**（l1 ≈ N·t/2），一次明文乘会让消息多项式的**系数**超过 `t/2`；
* 一旦越界，取模后被 NTT **摊到每一个槽** ⇒ 解出来是均匀随机值；
* **与密文来源无关**，只与"乘数的系数域范数"和"被乘槽值的大小"有关。

实测（全部在探针里，配正/负对照，永久保留）：

| 实验 | 结果 | 说明 |
|---|---|---|
| 掩码 × 新加密密文（槽值小） | **4096/4096** | 机制没错 |
| 打包件 × **常数**明文 1（系数域稀疏） | **4096/4096 还原** | 打包件本身没问题 |
| 掩码 × 打包件（槽值可达 t−1） | **0/4096**（`P5.0g` 缺陷断言） | 越界 |
| 只旋转、不掩码 | **逐位相同**（`P5.0e`） | §4.2 的旋转部分是对的 |

**⇒ `bloomCt` 现在只旋转、不掩码**：段外置零交给 CAPE 的 `q^BF`（客户端侧段外本来就是 0，
`CtCtMul` 的积在段外也是 0 ⇒ 折叠不带杂质）。这条**改变了 `bloomCt` 的契约**，已写在它的 javadoc 里。

### 30.3 本轮改动的文件

| 文件 | 改动 |
|---|---|
| `fusepir/FusePirFourStep.java` | **应答通道明文模数 `tRing = K·T`**（`ringModulusFor` + 素数搜索）；`setup` 里顺序调整（s_L/tRing 先于装配 y）、`BffEncode` 用 tRing、`pp` 仍用 T；`answer` 传 `tField=T`；`decode` 加"除 K → 解析"；新增 `ringModulus()`/`scale()`；`Resp` 新增 `scale()`/`decodeFields()`/`packedSlots()`/`packedCoeff()`/`galoisKeys()`；`bloomCt` 去掉掩码；新增 `requirePositionsMatch`、`rotateRowsByComposedBits`、`answerRnsSamples` |
| `fusepir/FusePirSetup.java` | `assemblePayload(..., scale)` 重载 + `divideScale(y, K, tRing, T)`（含"只在 tRing 附近当负残差"的修正） |
| `fusepir/FusePirPackSlot.java` | `pack(..., long tField, ...)` 重载（槽位布局按字段域算，**不再按 m.t**）；`scaleToT` 转 public |
| `fusepir/AnswerOps.java` | `phaseOfRns`（算术层判据）、`sumPaths`；`addPaths` 改为两步复合 |
| `probe/FusePirAnswerBisectTest.java` | 二分辨识（Q1 旋转本身 / Q2 真值同源 / Q3 P4.0c 为何 0 命中）—— **全部达成** |
| `probe/FusePirFourStepTest.java` | P4.0 拆两层 + 参考系统一；P5.0a–P5.0g；`decodeSafe`；本轮**重建过一次**（见 §30.4） |

### 30.4 ⚠️ 一次自伤事故（必须留档）

本轮我用 PowerShell 改探针时写错了脚本（`WriteAllLines` 只写了前半段），**把
`probe/FusePirFourStepTest.java` 从 730 行截断成 248 行**；而该文件**未被 git 跟踪**
（`coding/.git` 里没有它）⇒ 无法回滚，只能按记录重建。

**教训**：①"整文件重写"型脚本必须先备份；②本项目大量探针**未入库**，`git` 并不是安全网；
③改源码优先用 `edit`（按唯一片段替换）而不是"读整份→拼列表→整份写回"。

**重建后已全绿（exit 0），且比截断前更整齐**（P4.0 的参考系统一了）—— 但这条流程缺陷本身要记。
---

## 31. 📌 CAPE 接线的硬约束 + 交接索引（2026-10-15 第四轮）

**当前交接单：`coding/rgsw-lab/HANDOFF-CAPE接线.md`**（主题：把 FusePIR 四步接进 CAPE）。
上一份 `HANDOFF-FusePIR四步.md` 保留（含"三条把 bug 钉错方向的硬结果"的教训）。
**开工读序：§27 → §29 → §30 → 交接单 → 才看源码。**

### 31.1 三个模数的账（**接线第一件要记住的事**）

| 模数 | 值 | 谁用 |
|---|---|---|
| **字段域 `T`** | **65537** | 论文的 `t`：limb 宽度、`perValue`、`B_pay=61`、段起点 `[5,24,43]`、`parsePayload`、指纹比对 |
| **应答通道 `tRing`** | **`K·T`**（实测 `K=17` ⇒ 1179649） | FusePIR 环上下文 / `D` / `P_{c,b}` / `q^col` / 盲旋转 / `Pack` / **应答密文** / **CAPE 的打分** |
| native 载荷 | `2^32` | `CapeDemoService` 那条，**不动、不混** |

### 31.2 五条硬约束

1. **CAPE 的打分整体搬到 `tRing`**：`BloomScoring` / `BatchEncoder` / `galoisKeysFor` 都用
   `fp.ring()`。用 65537 或 `CapeBloomScore.DEFAULT_T = 2^32` 会抛形态错、或**静默算错分**。
2. **槽里是 `K·field`**（bloom 位是 `0/K`）⇒ 同态内积是 `K × 匹配位数` ⇒ **阈值 τ 也要乘 K**。
3. **`Resp.bloomCt(j)` 不再掩码**（只旋转）：段外置零由 CAPE 的 `q^BF` 承担
   ⇒ **`q^BF` 段外必须为 0**。这是"稠密明文掩码乘打包件会解坏密文"（§30.2）的直接代价。
4. **折叠轮数走 `bloomScoreReaching(…, packed.highestSlot())`**：`B_pay=61` ⇒ 6 轮；
   论文形状的 5 轮只够到槽 31 ⇒ **静默漏算**（§19.3）。
5. **四个入口签名照 A2 原文，不要改**（§27.1）；`CapeDemoService` / native 路径**一行不动**。

### 31.3 接线时的诊断入口（都在 §30 实现好了）

`Resp.decodeSlots(ct)`（**槽值**，接打分用）/ `Resp.decodeFields(ct)`（**字段域**，判载荷用）/
`Resp.scale()` / `FusePirFourStep.ringModulus()` / `answerRnsSamples` / `AnswerOps.phaseOfRns`。
⚠️ 两个解码入口**不要混**：混了就是"差 K 倍"的静默错（§30.1 表里的第 2 条）。

### 31.4 未闭合项（如实登记）

| 项 | 状态 |
|---|---|
| `bloomCt` 去掩码后的契约变更 | ⚠️ **需要 CAPE 侧配合**（`q^BF` 段外为 0）；已在 `bloomCt` 的 javadoc 与交接单 §3-3 登记 |
| 打分段的端到端（真候选 + 阈值 τ） | ❌ **未做**，这是接线的本体 |
| `tRing` 对 BFV 噪声余量的影响 | ⚠️ 本实现无噪声（§21 的工程决定）⇒ 现在免费；**一旦加噪声，`K` 倍精度会吃噪声余量**，必须重算 |
| 大 `d`（论文 `d=512`）下的 `K` | ⚠️ `K > ones ≈ d/2` ⇒ `tRing` 需要更大的 gadget（`base=2^16, digits=2` 覆盖 2^32）；`ringModulusFor` 会在搜不到时**抛**并说明该调哪个旋钮 |

---
## 32. ✅ CAPE（A2）接线**跑通**（2026-10-15 第五轮）—— 但打分那一步要**两个参数旋钮**才成立

本轮：新建 `cape/CapeA2Wire.java`（A2 侧唯一的调用方）+ `probe/CapeA2WireTest.java`（验收）+
`probe/ScoreMulDomainTest.java`（隔离实验）。**判据命令**：

```powershell
.\run-mpc4j.ps1 -Class com.fusepir.probe.CapeA2WireTest 16 4096 16 18   # → exit 0
.\run-mpc4j.ps1 -Class com.fusepir.probe.ScoreMulDomainTest 4096        # → exit 0（含缺陷断言）
```

### 32.0 结论先行

1. **A2 里那 4 处调用全部接上并实测**：SETUP 11（`FusePirFourStep.setup`）→ SETUP 12
   （`pp_F.extendBloom`，原有）→ SETUP 13（`st_S ← st^F_S`，直传）→ QUERY 1-3 →
   ANSWER 2（`answer`）→ ANSWER 3（`valueCt(j)` / `bloomCt(j)`）→ 打分（ANSWER 4-6）→
   DECODE 2（`decode`）。**四个入口的签名一行未改**（§27.1 / §31.2-5）。
2. **"打分直接吃 `resp_anc`" 在本移植里不是免费的**：`CoeffModulus.bfvDefault(4096)` 下
   `RingPack` 产物的噪声预算只有 **2 bit**，而一次 `CtCtMul` 要 ~26 bit ⇒ 得分是均匀随机值。
   放宽系数模数到 `3×60`（`SecLevelType.NONE`）后 Pack 产物 **50 bit**、`q^BF × Pack`
   **逐槽完全正确**（0/4096 不符）。
3. **判定规则必须从"等号"改成"取整"**：`K > ones` 只够读**单个**字段；打分把桥的残差在
   `τ = ‖b_qry‖₁` 个字段上**累加**（上界 `τ·ones/2`）⇒ 要 `K > τ·ones`。本组 `K = 128 > 110`，
   判定 = `round(s_j/K) == τ`，**不是** `s_j == K·τ`（实测 K=17 时命中候选得 172、`K·τ = 170`）。
4. **§30.2 的归因被推翻（更正）**：掩码那堵墙也是**噪声预算**，不是"与噪声无关的系数域越界"。
   实测：`bfvDefault` 下 Pack 产物 2 bit、掩码后 **0 bit / 0-4096 槽对**；
   `q=3×60` 下掩码后 **4096/4096 槽对、余 25 bit**。两者的唯一差别就是预算。
5. **`tRing ≠ K·T`（文字更正）**：`tRing` 是"最小的 `≡1 (mod 2N)` 且不落在搜索下界之下的素数"，
   而 `K := ⌊tRing/T⌋`。本组 `tRing = 1179649 = 18T − 17`，而 `17T = 1114129`。
   MAP §30.1/§31.1 与交接单 §3 写的 "`tRing = K·T`" 是**简化说法**（不影响任何算术：
   存的是 `K·field`，除的也是 `K`）。

### 32.1 实测账（`probe/ScoreMulDomainTest`，N=4096）

| 参数 | 新加密 | `RingPack` 产物 | `q^BF × Pack` | 稠密掩码 × Pack |
|---|---|---|---|---|
| `bfvDefault(4096)`（工作 q = 72 bit） | 51 bit | **2 bit** | ❌ 4096/4096 槽不符 | ❌ 0/4096 |
| `q = 3×60`（工作 120 bit，`SEC_LEVEL_NONE`） | 99 bit | **50 bit** | ✅ 0/4096 槽不符 | ✅ 4096/4096（余 25 bit） |

* 一次 `CtCtMul` 的代价 ≈ **26 bit**（实测 51 → 25），与 `t` 基本无关；
* `Pack` 的代价 ≈ **49 bit**，且**与 limb 数几乎无关**（k=1 时 17 bit、k=61 时 14 bit）
  ⇒ 瓶颈是那些**稠密槽位选择子**（`multiplyPlain`，代价 ~`log2(N·t)`），不是 key switch 的条数；
* **延迟重线性化不是出路**：`multiply` 那一步就把预算吃光（实测 E2 = 0 bit），
  而且 size-3 密文**不能旋转**（`Evaluator` 抛 `encrypted size must be 2`）；
* **自定义系数模数默认被拒**（`isParametersSet=false`：*not compliant with
  HomomorphicEncryption.org security standard*），只能显式走 `SecLevelType.NONE`。

### 32.2 本条路的两个参数旋钮（**都是玩具参数，必须一起说**）

| 旋钮 | 值 | 为什么 |
|---|---|---|
| 系数模数 | `3×60 bit`（`Mpc4jRgsw` 新增的 6 参构造 + `FusePirFourStep.setup` 的 8 参重载） | 让 `Pack` 产物活得下一次 `CtCtMul`（2 bit → 50 bit） |
| 精度倍率 `K` | `128`（`> τ·ones = 110`，`ringModulusFor` 的新增 `minScaleK`） | 让判定与"τ 个字段的桥残差之和"可比 |

⚠️ `3×60` **不满足 128-bit 安全标准**（论文自己的参数集比这大得多）；纯 A1 的调用方
（6 参 `setup`）**仍是原来的合规参数**，行为一行未变。

### 32.3 本轮改动的文件

| 文件 | 改动 |
|---|---|
| `cape/CapeA2Wire.java` | **新建**：A2 的四个调用 + 打分 + 判定（`query`/`answer`/`decode`、`A2_COEFF_BITS`、`A2_MIN_SCALE_K`、`nearestFieldScore`、`queryVector`、`plainInner`）；`query()` 里有 `K > τ·ones` 守卫 |
| `fusepir/FusePirFourStep.java` | 两个**加法式**重载：`setup(..., coeffBits, minScaleK)`（原 6 参原样保留、委托）与 `ringModulusFor(..., minScaleK)`；`setup` 里的两处 `new Mpc4jRgsw` 改走新构造 |
| `prim/Mpc4jRgsw.java` | 新增 6 参构造（`coeffBits != null` 时用 `CoeffModulus.create` + `SecLevelType.NONE`）；原 4/5 参构造行为一行未变 |
| `probe/CapeA2WireTest.java` | **新建**：P1–P6，含"命中/漏位/换 q^BF/换 st^anc_C(⊥)/5 轮 vs 6 轮/破约"六组正负对照 |
| `probe/ScoreMulDomainTest.java` | **新建**：隔离实验 + 噪声阶梯 + **缺陷断言**（`bfvDefault` 下那一组刻意期望它错，放宽 q 后它会变红） |
| `probe/FusePirAnswerBisectTest.java` | 修一条**非确定性**断言：`Q1.3b` 原来同时要求"与错 100 格的差 > #ones"（认残差）和"逐位精确等于 `p[5]`"（不认残差）—— 自相矛盾，残差非零时就红（见 §32.6） |

**未动**：`CapeDemoService` / native 路径（一行未改）。

### 32.4 六个已实测、`CapeA2WireTest` 每次都会跑的判据

| 判据 | 结果 |
|---|---|
| P1 SETUP 11-13（`pp_C` 由 `pp_F` 加宽、`st_S` 直传、`B_pay` 三方一致） | ✅ |
| P2 QUERY 1-3（`q_anc` 形状、**`q^BF` 段外为 0**、`τ = ‖b_qry‖₁`、守卫） | ✅ |
| P3 ANSWER 2-6（**得分取整 == 明文内积**、`bloomCt` 的段外杂质实测） | ✅ 3/3 候选 |
| P4 DECODE（`V_{K_1}`、合取语义收下 `[1001]`、`⊥` 负对照、阈值不乘 K ⇒ 0 个） | ✅ |
| P5 折叠轮数（5 轮与 6 轮等价；**破约后给出不同的错值**） | ✅ |
| P6 三方对账（`payloadTruth` vs DB 0 处不符；`CtCtMul` 逐槽 0/4096 不符） | ✅ |

### 32.5 未闭合项（如实登记）

| 项 | 状态 |
|---|---|
| `3×60` 的参数是玩具 | ⚠️ 要让论文参数（大 q）成立，得换 native/更大的 N；本移植的 `bfvDefault(4096)` 装不下这一步 |
| 判定规则的偏差 | ⚠️ 论文是 `s_j == τ` 的**等号**；我们改成 `round(s_j/K) == τ`，因为桥的残差是**本实现的**（§24.4/§26.3），不是论文的 |
| `τ` 的上限 | ⚠️ `K > τ·ones` 且 `tRing = K·T < base^digits = 2^24` ⇒ 本组 `τ ≤ 23`；查询关键词集不能随便变大（有守卫会抛） |
| `bloomCt` 不掩码的契约 | ⚠️ 仍需要 CAPE 侧保证 `q^BF` 段外为 0（本轮实测了破约的代价：6 轮得分 = τ + v₃） |

### 32.6 ⚠️ 顺手查出的一条**非确定性**断言（`FusePirAnswerBisectTest` 的 Q1.3b）

回归时 `Q1.3b` 变红。它**不是**本轮改出来的（本轮对 A1 路径只有加法式重载，6 参 `setup`
与 4/5 参 `Mpc4jRgsw` 构造的行为逐位相同），而是**它自己写错了**：

```java
dev > ones && centered(got, t) == centered(p[5], t)   // 前半认残差、后半要求逐位精确
```

前半认了 `≤ #ones` 的残差，后半却要求"`got` 逐位等于 `p[5]`" —— 只要 `rnsToT` 的残差非 0
就必然红。**实测它是每次运行都不同的**（`m.encrypt` 每次重新随机化 `a`）：

| 同一条判据、三次运行 | r=5 读回 | 与 `p[5]=6` 的差 |
|---|---|---|
| 第一次 | 6 | 0（恰好过） |
| 第二次 | 5 | 1（红） |
| 第三次 | 8 | 2（红） |

⇒ 修法：后半改成 `|got − p[5]| ≤ ones`（"是 r=5 的答案，在残差内"），负对照要证的
"与错 100 格的差 ≫ ones" 原样保留（实测 98/101 ≫ 11）。
**教训**：一条断言里不能既有"认残差的容差"又有"逐位精确"，否则它是一条**掷骰子**的判据。

---
## 33. ✅ CAPE 接入前端（2026-10-15 第六轮）—— 页面改走**默认密文路径**，并修掉 3 条缺陷

### 33.0 结论先行

1. **CAPE（native 那条）本身能用**：服务自带进程内端到端自检 **9 PASS / 0 FAIL**
   （`Dec(ct_score) == τ`、指纹 ⊥、N1/N2/N3 负对照全绿），一次 ANSWER **75.1~75.8 s**
   （锚检索占 99%：75.0 s；同态打分 0.6 s）。
2. **但页面（前端）此前"不能用"**：它走的是**明文关键词**那条老路，且有一个
   **off-by-one** 让合取判定**永不命中**（实测池内组合返回 `hit=false`）。
   ⇒ 本轮把页面接到默认路径，并修掉这个 off-by-one。
3. **浏览器做不了 BFV**（加密 `b_qry` / 解密 `ct_score`）⇒ 新增两个**显式标注**的
   "客户端模拟器"出口，页面按 **seal → `/api/query` → decide** 三步走。
4. **单进程回环**必须与结论一起说：模拟器与服务端同 JVM、共享打分密钥 ⇒
   演示的是**协议形态与计时**，不是密钥分离。口径落在 `cape-demo/README.md`（已知边界）、
   `/api/state.protocol.clientSimulator`、`/api/client/decide` 响应的 `note`
   与线路面板的措辞里（⚠️ **页头不再写它** —— 用户 2026-10-15 要求把页头那段删掉）。

### 33.1 实测（2026-10-15，N=8192）

| 查询 | τ | 出站字段 | 体里含关键词 | 候选 `Dec(ct_score)` | 判定 |
|---|---|---|---|---|---|
| `Adam Sandler + family`（池内命中 1） | 5 | `[d,anchorColIdx,anchorRowIdx,qBFBytes]` | **无** | **5** / 3 / 2 | 收下 5706 ⇒ *Spanglish (2004)* ✓ |
| `anime + golf`（负对照） | 3 | 同上 | **无** | 2 / 1 / 1 | 一条都不收 ✓ |

服务端自检（`-Dcape.selftest=true`）：CAPE 端到端 **9/0**、sealed 合规路径 **4/0**（修前 3/1）、
P1-3 **7/0**、P1-1 **3/0**。

### 33.2 修掉的三条（都配了可跑判据，详见 `docs/缺陷总表.md` §四 2026-10-15）

| # | 缺陷 | 症状 / 判据 |
|---|---|---|
| 1 | **载荷读取 off-by-one**：40-bit 指纹上线后 `fpSlots` 由 1 变 2（`B_pay` 59→60），两处读取仍写 `payload[1]` 与 `2 + j·(1+ℓ_BF)` ⇒ 候选数读成**指纹高位 limb** | 修前 `valueCount=171`、`接受=[]`、sealed 自检 3 PASS/1 FAIL、页面 `hit=false`；修后 `valueCount=3`、`接受=[5706]`、4 PASS/0 FAIL、页面命中。⚠️ 它能藏住是因为"整条载荷逐位比照"那条**不按下标读**。已改走 `FusePirSetup.countOffset/valueOffset` |
| 2 | **`run-demo.ps1` 类名写错**（`com.fusepir.demo.CapeDemoService` 不存在，真名 `com.fusepir.cape.CapeDemoService`） | 一键启动永远 `service exited early`；全 classpath 无此类 |
| 3 | **判定入口在 `V_K1` 为空时掐连接**：我第一版用"读 JSON 解析结果"的入口去读**进程内**的 `long[]` 载荷 ⇒ `valueIds` 空、`ct_score` 3 条 ⇒ `decodeWire` 里 `valueIds.get(j)` 抛 `IndexOutOfBounds`（在它的 `try` 之外）⇒ `HttpServer` 掐掉连接，前端只看到"服务器关闭了连接" | 修前原始响应＝连接被关闭；加 try/catch 后立刻现形为 `{"ok":false,"error":"…IndexOutOfBoundsException: Index 0 out of bounds for length 0"}`。已改用 `FusePirDecode.decodePayloadCoefficients(payload, t)` + 两个出口都包 try/catch + `|V_K1| != |ct_score|` 时报错不猜 |

### 33.3 本轮改动的文件

| 文件 | 改动 |
|---|---|
| `cape/CapeDemoService.java` | ① 修两处载荷 off-by-one；② 新增 `/api/client/seal` 与 `/api/client/decide` 两个出口（+ `ClientSeal`/`CapeRespForClient` 两个内部留档类）；③ `runQueryCapeSealed` 在返回前留档客户端判定要用的三样；④ `/api/state.protocol` 增两条自述；⑤ 两个新出口包 try/catch |
| `cape-demo/web/index.html` | `doSearch()` 改成三步（seal → query → decide）；新增**线路面板**（客户端发了什么 / 服务器收到什么 / 谁判定）与**每候选得分**表；进度条刻度改读 `/api/state.expected.answerMs`（页头那段"走默认密文路径 + 单进程回环"的说明按用户要求已删） |
| `cape-demo/run-demo.ps1` | 类名改正（`com.fusepir.cape.CapeDemoService`）+ 就地写明这条坑 |
| `cape-demo/README.md` | 新增"页面走的是哪条路"（三步表 + 实测表 + 回环警告）、实测数据更新（ANSWER ≈75 s）、已知边界补"两方部署/payloadPlain"两行、文末登记本轮两条缺陷 |
| `docs/缺陷总表.md` | 新增"### 2026-10-15 本轮"（前端接入 + 3 条缺陷，含判据与修前/修后实测） |

**未动**：native C++（`blindrotate.dll` 一行未改）、A1/A2 的 MPC4J 纯 Java 那条路（§32）。

### 33.4 仍未闭合（如实登记）

| 项 | 状态 |
|---|---|
| **单进程回环** | ⚠️ 模拟器与服务端同 JVM、共享打分密钥 —— 演示"协议形态"，**不是**两方部署（与 `缺陷总表` 的 P0-4 同源） |
| `payloadPlain` 是**明文** | ⚠️ 候选 id 就在这份载荷里；真修要发 `B_pay` 条密文（按实测单条 524,401 字节推算 ≈30.9 MB/响应） |
| 41 MB 的列选择子流 | ⚠️ P1-1 那条读法的直接后果，未优化（见 `缺陷总表`） |
| 页码上的进度条刻度 | ⚠️ 已改成读 `/api/state.expected.answerMs`（不再写死 150 s） |

### 33.5 📌 查验单（给另一个 agent 用）

`coding/rgsw-lab/VERIFY-CAPE接线与前端.md` —— **逐条 claim + 怎么独立判定 + 什么算没通过**，
含 5 条**变异测试**（把缺陷放回去，看断言是否真的变红）与"我明确**没有**声称的"一节。
新会话要动这两块之前，先跑它一遍。
