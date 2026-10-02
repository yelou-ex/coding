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
| | `ct_score = CtCtMul(q^BF, ct^BF_j)` | ✅ | `bloom/BloomScoring.java:92` `bloomScore` |
| | 折叠 `Σ_r CtRotate(ct, 2^r)` | ⚠️ 机制同形、**轮数不同** | `bloom/BloomScoring.java:102` `foldAllSlots`（`rotateRows(1,2,4,…,N/4)` + 一次列旋转） |
| **BFF** | `BFF.Setup(n,3)`：`s`、`L_BFF` 闭式 | ✅（仅对照，**我们不使用**） | `bff/BffSetup.java:44` `paperS`、`:67` `paperLBff` |
| | `BFF.Encode`：位置函数 `H` | ⚠️ 无 `h_i`，用线性探测 | `bff/BffEncode.java:52` `keywordHash`、`:78` `mix` |
| | 表 `D` / 分享 | ⚠️ 形态不同 | `bff/CapeDemoData.java:298` 3 路 share、`:353` 表 `P_{c,b}` |
| **FusePIR** | SETUP：网格 `(R,C)`、`cellsPerCol` | ⚠️ 推导顺序与论文相反 | `fusepir/FusePirSetup.java:46` `cellsPerCol`、`:56` `columns`、`:65` `span` |
| | SETUP：`P_{c,b}(X)` | ⚠️ | `bff/CapeDemoData.java:353` |
| | QUERY：位置 `u_a = h_a(K)` | ⚠️ 一个位置 + 线性探测 | `bff/BffEncode.java:52`；调用点 `cape/CapeQuery.java:222/246` |
| | QUERY：`q^col` 选择子 | ✅ **P1-1 已完成** | `cape/CapeQuery.java:257` `encryptColumnSelectors`；native `rgsw_blindrotate.cpp:1363` `nativeEncryptSealedColumns` |
| | QUERY：`q^row = LWE.Enc_{s_L}(r_a)` | ⚠️ **无噪声** + `s_L` 必须等于 `s_R` | `cape/CapeQuery.java`（`q.beta[a] = (sum + rowIdx[a]) % twoN`） |
| | ANSWER：列选择→盲旋转→提取→三路相加 | ✅ | C++ `rgsw_blindrotate.cpp:543` `cape_answer_core`；入口 `nativeCapeAnswer:1614` / `nativeCapeAnswerSealed:1937` / `nativeCapeAnswerSealedC:1981` |
| | ANSWER：**`resp ← Pack(...)`（L13）** | ❌ **没有实现** | **没有文件** —— 见 §6 |
| | DECODE：载荷切分 `Recover (f,m,v…)` | ✅ | `fusepir/FusePirDecode.java:57` `decodePayload` |
| | DECODE：`fp(K)` | ⚠️ 用 `String.hashCode`，非论文 40-bit | `fusepir/FusePirDecode.java:91` `fpOf`；`bff/CapeDemoData.java:416` `inField` |
| **CAPE** | SETUP：`ℓ_BF`、`G`、`b_v`、`DB^CAPE` | ✅ | 见 `cape/CapeSetup.java` 的对照表（实现散在 `common/BfGen` 与 `bff/CapeDemoData`） |
| | SETUP：`B_pay = 2+m(1+ℓ_BF)` | ⚠️ **这是我们的推断**（论文没重述） | `cape/CapeSetup.java:54` `bPay` |
| | SETUP：打分信道（论文里没有这一步） | ⚠️ 口径差：**两个 `t`、两把 sk** | `cape/CapeBloomScore.java:168` `setup` |
| | QUERY：`b_qry`、`τ` | ✅ | `cape/CapeQuery.java:96` `build`（`τ` 只在客户端） |
| | QUERY：`q^BF ← RLWE.Enc(b_qry)` | ✅ | `cape/CapeBloomScore.java:220` `encryptQueryWire` |
| | QUERY：`q ← (q_anc, q^BF)` | ✅ | `cape/CapeQuery.java:379` `toJson` |
| | ANSWER：`resp_anc ← FusePIR.Answer(st_S, q_anc)` | ✅ | `cape/CapeDemoService.java:309` `runQueryCapeSealed` → `:509` `runAnchorNative` |
| | ANSWER：`Parse {(c_{v_j}, ct^BF_j)} from resp_anc`（L3） | ❌ **做不到**（需要 Pack） | 我们是**重新加密**（D2） |
| | ANSWER：`ct_score,j = CtCtMul + 折叠`（L4-7） | ✅ | `cape/CapeAnswer.java:90` `answer` → `bloom/BloomScoring.java:92` |
| | ANSWER：`resp ← ({(c_{v_j}, ct_score,j)})`（L8） | ⚠️ | `cape/CapeDemoService.java:284` `answerCape`；响应字段 `payloadPlain`（**明文**）+ 每候选 `ctScoreBytes`（真密文） |
| | DECODE：`V_{K_1} ← FusePIR.Decode` | ✅ | `cape/CapeDecode.java:158` → `fusepir/FusePirDecode.java:57` |
| | DECODE：`f ≠ fp(K) ⇒ ⊥` | ✅ | `cape/CapeDecode.java:81` `decode` / `:112` `decodeWire` |
| | DECODE：`s_j = τ ⇒ R ∪ {v_j}` | ✅ | 同上 |

**一句话**：**算法骨架全在，缺的是 `Pack` 那一层**；
另外三处形态差（`h_i`、独立 `s_L`、两方密钥隔离）是结构性的。

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

| 论文里的东西 | 状态 | 位置 |
|---|---|---|
| `BF.Gen(0,S)` / `b_v` / `b_qry` | ✅ | `coding/common/src/main/java/com/fusepir/common/BfGen.java`（**独立模块**：客户端算 `b_qry`、服务端算 `b_v`，必须同一份实现） |
| `ct_score ← CtCtMul(q^BF, ct^BF_j)` | ✅ | `bloom/BloomScoring.java:92` |
| 折叠 `Σ_r CtRotate(ct, 2^r)` | ⚠️ | `bloom/BloomScoring.java:102`。机制同形；**我们折满 `N/2` 槽 = 13 轮，论文 `⌈log2 ℓ_BF⌉ = 5` 轮**。等价条件 `ℓ_BF ≤ N/2` + 高位补零，已验过 |

---

## 3. BFF —— `bff/`

**完整路径**：`coding/rgsw-lab/src/main/java/com/fusepir/bff/`

| 步骤 | 状态 | 位置 |
|---|---|---|
| `BFF.Setup(n,3)`：`s`、`L_BFF` 闭式 | ✅ 但**仅作对照** | `bff/BffSetup.java:44` `paperS`、`:67` `paperLBff` |
| `BFF.Encode`：位置函数 `H` | ⚠️ **`h_i` 未实现** | `bff/BffEncode.java:52` `keywordHash`、`:78` `mix` |
| 表 `D`、3 路分享、`P_{c,b}` | ⚠️ 形态不同 | `bff/CapeDemoData.java:298`（share）、`:353`（表）、`:222`/`:246`（`colOf`/`rowOf`） |
| 填充 | ✅ | `bff/CapeDemoData.java` 的 `dataRadius` 自检；按附录 Alg 3 L6 对 `[0,L_BFF)` 均匀随机 |

**⚠️ 三处形态差**
1. **`h_i` 没实现**：论文一个关键词有 `k=3` 个**分散**位置；我们是**同一列的 3 个相邻行**。
   ⇒ 我们的"BFF"实际是**槽表 + 线性探测**，3 路拆分只是加性分享，**不带过滤语义**。
2. **推导顺序反了**：论文 `Setup → L_BFF → 选 (R,C)`；我们**先按 n 定 `C`**，
   再声明 `L_BFF = cellsPerCol·C`。
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
| `B_pay = 2+m(1+ℓ_BF)` | ⚠️ **推断，非原文** | `cape/CapeSetup.java:54` `bPay` |
| 打分信道（论文没有） | ⚠️ 两个 `t` | `cape/CapeBloomScore.java:168` `setup` |
| — | — | `cape/CapeSetup.java` 本身只放**入口与口径说明**，不复制运算 |

### QUERY —— `cape/CapeQuery.java`
| 论文 | 状态 | 位置 |
|---|---|---|
| L1 `q_anc ← FusePIR.Query(...)` | ⚠️ | `:96` `build`（位置与选择子在同一类里，见 §7） |
| L2-3 `b_qry`、`τ` | ✅ | `:96`；`τ` **只在客户端** |
| L4 `q^BF ← RLWE.Enc(b_qry)` | ✅ | `cape/CapeBloomScore.java:220` `encryptQueryWire` |
| L5-6 `q ← (q_anc, q^BF)` | ✅ | `:379` `toJson`（`colSel`/`colIdx` 互斥发出） |

### ANSWER —— `cape/CapeAnswer.java` + `cape/CapeDemoService.java`
| 论文 | 状态 | 位置 |
|---|---|---|
| L2 `resp_anc ← FusePIR.Answer(st_S, q_anc)` | ✅ | `CapeDemoService.java:309` `runQueryCapeSealed` → `:509` `runAnchorNative` |
| L3 `Parse {(c_{v_j}, ct^BF_j)}` | ❌ **需要 Pack** | 我们重新加密（D2） |
| L4-7 `ct_score,j` | ✅ | `cape/CapeAnswer.java:90` `answer` |
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
| **A1 ANSWER 13**：`resp ← Pack({ct_{pay,b}})` | **`Pack` 整个没有** | **唯一"完全没做"的一步**。它同时是 A2 ANSWER 3 能"解析出 `ct^BF_j`"的前提 ⇒ **D2 不是独立 bug，是 Pack 缺失的症状**。真做要 ≈**12 GB** 切换密钥（`n=N=8192`），是**架构决定** |
| **BFF 的 `h_i`** | 3 个分散位置 | 我们用"同一列 3 个相邻行"代替 ⇒ BFF 退化成槽表 |
| **独立的 `s_L`** | 第二把密钥 | 净旋转 `= Σa_i(s_R,i−s_L,i) − r_a`，差 1 位就偏 5767 行 ⇒ **与当前盲旋转口径不兼容** |
| **`q^row` 的噪声 `Δ·m + e`** | P1-2 | 判据已算出（`Δ/√d > 6σ`，`R < N/(6σ√d)`），**前置是先定 `R`，而论文没给 `R`** |
| **两方密钥隔离** | —— | 单 JVM 回环。⚠️ P1-1 后仍有一条同源边界：**选择子必须与「解码者」同一把秘密** |
| `RgswBaseNoise`（`probe/RgswBaseSweep.java` 的 javadoc 提到） | —— | **从来没有这个类**，是 javadoc 笔误（已就地更正） |

---

## 7. ⚠️ 还差的东西（下一步）

| 项 | 现状 | 建议 |
|---|---|---|
| **`fusepir/FusePirQuery.java` 还不存在** | 位置公式与 `q^col`/`q^row` 构造都在 `cape/CapeQuery.java` | 抽一个 `FusePirQuery`，让 `CapeQuery` 只做 A2 的那两步（`b_qry`/`τ`、`q^BF`）。**这一步要动 `Sealed` 的形状**（约 10 个调用点直接读它的字段），风险高于前面几次，所以单独一轮做 |
| **`CapeDemoData` 仍是 1 个大类（≈700 行）** | 同时装：JSON 解析、DB 加载、BFF.Encode 的表构造、`Tables` holder | 可把"表构造"（≈150 行）抽到 `bff/BffEncode` 的第二个方法。**同样是改逻辑归属，建议单独一轮** |
| **验收套件未在重构后重跑** | —— | §8 的命令可以直接跑 |

---

## 8. 验收命令（包名已变：`rgsw` → 分层）

```powershell
cd coding\rgsw-lab

# 离线
.\run-mpc4j.ps1 -Class com.fusepir.probe.CapeBffParamDiag
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
