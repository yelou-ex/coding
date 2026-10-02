# CAPE 复现规划书

> **本文件位置说明**：按你的要求放在 `coding/` 里。若你希望它归属 `docs/`（与其余文档一致），
> 移动后同步 `README.md` 的 §文档地图 即可 —— 我没有擅自移，因为你说的是"放到 @coding/"。
>
> **写于**：2026-10-14（承接同日的列选择二次纠正与逐子程序复核）
> **依据**：论文 `Submission_usenix_232.pdf`（标题 *"CAPE: Communication-Efficient Conjunctive
> Keyword PIR"*）的 Algorithm 1/2 与 §2.5 子程序定义**原文**；代码侧逐行读过
> `rgsw_blindrotate.cpp`、`Mpc4jRgsw`、`BloomScoring`、`RingPack`、`ExpandOps`、
> `LweRlweBridge`、`LweToRgswOps`。
>
> ⚠️ **本文不引用旧审计表**（`docs/reports/逐子程序核对…2026-10-13.md`）—— 它的行号、
> S5 的"补零"说法、Q3 的"与论文一致"都已失效。那份表需要按本文重写。

---

## 一、现状评估（先说清"到哪了"）

### 1.1 已经逐行对上的（这些是真的对，别重做）

| 论文 | 本实现 | 位置 |
|---|---|---|
| A1 SETUP 14：`P_{c,b}(X) ← Σ_r D[r+cR][b]·X^r`（行=幂次） | `p[cc][b][rr]`，列主序 | `CapeDemoData` P 构造段 |
| A1 QUERY 4-5：`e` one-hot、`q^col`、`q^row` | 形态一致（C 个常数编码密文 + `ct×pt`） | `rgsw_blindrotate.cpp:1355-1379` |
| A1 ANSWER 5：`Σ_c CtPtMul(q^col[c], P_{c,b})` | `multiply_plain(sel[cc], tabNtt[cc][b])` 累加 | 同上 |
| A1 ANSWER 6：`BlindRotate(q^row, Acc)` | `blind_rotate`：`cur ← CMUX(bk[i], cur, cur·X^{a_i})`，再 `X^{−β}`；净旋转 `= X^{−r}` ⇒ `p_r` 到常数位 | `rgsw_blindrotate.cpp:494-512` |
| A1 ANSWER 7：`SampleExtract_0` | 密文域三路相加后一次取样（线性，等价） | `1371-1375` |
| A2 QUERY 2-3：`b_qry ← BF.Gen(0,{K₂..K_Q})`、`τ ← ‖b_qry‖₁` | 完全一致（含"排除 anchor"） | `CapeDemoService` |
| §2.5 `SampleExtract_j` | `b = c0[j]`、`a_k = c1[(j−k) mod N]`（过 `X^N` 取负）+ `q_R→q_L` | `LweRlweBridge.sampleExtract` |
| §2.5 `Pack` | 差 b → 取负 → `slotSelector(槽)` 逐条相加 | `RingPack.pack` |
| SealPIR `EXPAND` | `e_j = N/2^j + 1`、倍增递归、`α = C⁻¹ mod t` 折进表 | `ExpandOps` |

**⇒ Algorithm 1（FusePIR）的骨架是通的，端到端能跑（≈36.5 s / 177 单元 / `payloadMismatch=0`）。**

### 1.2 CAPE 的定义性缺口（缺了它就不是 CAPE）

| 缺口 | 论文位置 | 现状 |
|---|---|---|
| **G1 加密 Bloom 打分** | A2 ANSWER 4-7：`ct_score,j ← CtCtMul(q_BF, ct_{B^F_j})`，再 `for r=0..log₂ℓ_BF−1: ct_score,j ← CtCtAdd(ct_score,j, CtRotate(ct_score,j, 2^r))` | **子程序有**（`BloomScoring.bloomScore` + `foldAllSlots`，`ℓ_BF = N/2` 时与论文精确对齐）、**但主路径一次都没调用** |
| **G2 每候选项的密文分数** | A2 ANSWER 8：`resp ← ({ct_{v_j}, ct_score,j})` | 不存在。我们返回**扁平 `long[] rec`**（B_pay 个系数），**没有"按候选分组"的中间表示** |
| **G3 `s_j == τ` 判定** | A2 DECODE 8-9：`s_j ← Dec(ct_score,j)`；`if s_j = τ then R ← R ∪ {v_j}` | 不存在。现在是**明文合取** `boolean conj`（`CapeDemoService:295-301`） |
| **G4 `f ≠ fp(K) ⇒ ⊥`** | A2 DECODE 3-4 / A1 DECODE 6 | `fp = rec[0]` **只用于上报**，不据此拒绝 |

### 1.3 形态对但语义不对（最危险：自检会全绿）

| 项 | 论文 | 我方 | 后果 |
|---|---|---|---|
| **S1 列选择子由谁加密** | 客户端发 `RLWE.Enc(e)`（C 个独立密文） | **服务器** `encryptor->encrypt_symmetric(p, sel[cc])` 自造，`colIdx` 明文传输 | 形态对（C 个常数编码密文 + `ct×pt`），但附录 D.2 的 *"a column selector is indistinguishable by RLWE IND-CPA security"* **不成立** |
| **S2 行选择子无噪声** | `b = ⟨a,s⟩ + Δ·m + e` | `b = ⟨a,s⟩ + r`（`Δ=1, e=0`） | **安全归约不成立**；且 `BlindRotateOps.blindRotate` 对 `e=±1` 实测**零容忍** |
| **S3 `d` 的语义** | `LWE.Enc` 里 `a ∈ Z_q^d` 的维数 | SEAL **三值 {-1,0,1}** 秘密的**前 d 个系数**，且 `v=−1 → 0`（`secret_bits:412`） | `d` 语义偏离；约 **2/3 的轮是恒等** |
| **S4 服务端知道 anchor 与 `b_qry`** | 两者都由客户端产生 | 服务器收明文关键词 → 自查 `kwIndex` → 自算 `bloomBits(others)` | 隐私模型与论文不同 |

### 1.4 口径差（结论必须带着说）

| 参数 | 论文 | 现网 | 后果 |
|---|---|---|---|
| `ε_BF` | 2⁻²⁰ | **2⁻⁶** | 实测（全部 16256 个有序关键词对）**假阴性 0**（论文论证前提，必须为 0）、**假阳性率 3.44%** vs 模型 1.64% ⇒ 约 **1/29** 的查询多返回一个假阳性值 |
| `N` / `d` | 16384 / 512 | **8192 / 16** | 不能声称论文配置已复现 |
| `ℓ_BF` | `ℓ(n, ε_BF)`，未给值 | **18** | 见上 |
| `B_pay` | `2+m`（m 最大 2¹¹） | **59** | 量级差很大 |
| 性能 | Table 3 的 `Time(s)` | **≈36.5 s** | ⚠️ 论文那列是**等值 3.00 的模型输出、不是实测**；且我们这 36.5 s **不含** G1 那部分 ⇒ **两边不可直接比** |

---

## 二、总体目标与"完成的定义"

**目标**：实现论文 **Algorithm 2（CAPE）**，即在现有 FusePIR 骨架上补齐
**加密 Bloom 打分（G1）+ 每候选密文分数（G2）+ `s_j = τ` 判定（G3）**，
并让 **S1/S2** 的语义与论文一致。

**"复现完成"的验收定义（四条全中才算）**：

1. `CapeTableDiag` 全部断言通过（含**假阴性必须为 0**）；
2. 端到端返回 `hit/integrity/payloadMismatch=0`，且**判定走的是 `Dec(ct_score)==τ`**，
   **不是**明文合取（用一条负对照证明：把 `ct_score` 破坏掉，判定必须失败）；
3. **隐私断言**：出站 JSON 里不含关键词、不含 `τ`、不含 `b_qry`，
   **且列选择子是密文**（不是 `colIdx` 明文）——见 `CapeSealedFlowTest` 的字段白名单断言；
4. 性能与口径差**写进文档**，不声称"达到论文速度"。

**明确不在范围内**：CAPE-C / FusePIR-C（查询压缩变体）。本项目基准是 CAPE；
`LweToRgswOps` 因此**不在关键路径**，也**不能**拿它当标准 CAPE 盲旋转的正确性证据
（`docs/缺陷总表.md` 的 `CAPE-CRYPTO-08`）。

---

## 三、任务表（按优先级；每项都有验收与回滚）

> 记号：**P0** = 不解决就不能声称实现 CAPE；**P1** = 语义/安全；**P2** = 性能。
> 「依赖」指需要外部产物，见 `沙箱受限清单-需要人工获取.md`。

### P0-1　把 Bloom 打分接进主路径（G1 + G2）

| | |
|---|---|
| **论文依据** | A2 ANSWER 4-7；§2.5 的 `CtCtMul` 定义 |
| **现状** | `BloomScoring` 已实现并自检通过，但**未被任何服务代码调用**（实测搜不到） |
| **做法** | ① 载荷仍存 Bloom 位（位置不动）；② 服务端按候选 j 取出其 Bloom 段，经 `RingPack` 打成**一个** RLWE（每位一槽）；③ `bloomScore(qBF, ct_BF_j)` 得密文分数；④ 响应结构改成 `({ct_v_j}, ct_score,j)` |
| **⚠️ 必须先核** | `foldAllSlots` 折**全部 N 个系数**，论文折 **ℓ_BF 项**。两者相等 ⟺ 下标 ≥ ℓ_BF 的项贡献为 0（由 `b_qry` 补零保证）⇒ **要求 `ℓ_BF ≤ N/2`**。**先用 `ℓ_BF < N/2` 造一条测试**验证这一点（现在的自检只测了 `ℓ_BF = N/2`，覆盖不到） |
| **验收** | 密文分数解密后 `== τ`（命中）/ `< τ`（漏位），且 **`ℓ_BF` 取 18（< N/2）时也成立** |
| **回滚** | 新增独立出口，不动 `/api/query` |

### P0-2　`resp` 改成"每候选一组"（G2）

| | |
|---|---|
| **论文依据** | A2 ANSWER 8 |
| **现状** | 返回扁平 `long[]`；Bloom 位是**载荷的一部分**，不是独立的 `ct_{B^F_j}` |
| **做法** | 定义响应结构 `{ value_j, ct_BF_j, ct_score_j }`；`value_j` 仍可来自解密（论文 DECODE 1 步也用 `FusePIR.Decode`） |
| **验收** | 响应里**每个候选都带自己的 `ct_score`**；能对单条候选独立判定 |

### P0-3　判定改为 `Dec(ct_score) == τ`（G3）

| | |
|---|---|
| **论文依据** | A2 DECODE 7-10 |
| **现状** | 明文合取 `boolean conj`（`CapeDemoService:295-301`） |
| **做法** | 客户端侧解密 `ct_score`，与本地 `τ` 比；相等则收 |
| **验收（关键）** | **负对照**：故意破坏 `ct_score`（如置零）⇒ 判定必须**失败**。**没有这条，不能排除"判定根本没做"** |
| **注意** | 这条是 CAPE 与 BKPIR 的核心区别所在（论文 §1 原文："BKPIR incurs prohibitively high communication overhead, requiring the client to communicate the entire database for each query"） |

### P0-4　`f ≠ fp(K) ⇒ ⊥`（G4）

| | |
|---|---|
| **论文依据** | A2 DECODE 3-4 / A1 DECODE 6 |
| **现状** | `fp` 只上报，不拒绝 |
| **做法** | 指纹不等时返回 ⊥（现在的"全 59 系数逐位相等"比 40-bit 指纹强得多，可保留为额外自检） |
| **验收** | 故意用错关键词 ⇒ 必须返回 ⊥ |

### P1-1　列选择子改由客户端加密（S1）

| | |
|---|---|
| **论文依据** | A1 QUERY 4-5 + 附录 D.2；附录开头 *"Instead of directly sending the RLWE one-hot column selectors …"* |
| **现状** | 服务器自造 + `colIdx` 明文传输 |
| **做法** | 客户端加密 C 个常数编码密文（`e[c]` 放**常数项**，不是第 c 个系数），走字节序列化给服务端；服务端加载后 `ct×pt` 累加 |
| **现成证据** | `CapeColumnSelectBaseline` 已证明这条路数学正确（N=4096 与 N=8192 全部断言通过，含两条负对照）。**注意该探针把表列也加密了（`ct×ct`）**；论文里表是**明文**多项式，真实形态是 `ct×pt`，更省 |
| **验收** | 出站 JSON 的字段白名单断言通过（不含 `colIdx` 明文）；`CapeColumnSelectBaseline` 的形态在服务里复现 |

### P1-2　行选择子加噪声（S2）

| | |
|---|---|
| **论文依据** | §2.5 `LWE.Enc`；A1 QUERY 5 |
| **现状** | `b = ⟨a,s⟩ + r`，`Δ=1, e=0` |
| **难点** | `BlindRotateOps` 对 `e=±1` **实测零容忍**（整体推偏一格）⇒ 加噪声前必须先解决"相位含噪时如何正确舍入" |
| **做法（待定，三条记录在 README §3.6）** | (a) 引噪声但改舍入；(b) 保持无噪声并把这条写死为工程决定；(c) 用更宽的 Δ |
| **验收** | 加噪后盲旋转命中率仍为 1（或在文档里明确记为**已知偏离**，不再声称满足 LWE 安全模型） |

### P1-3　`d` 语义对齐（S3）

| | |
|---|---|
| **现状** | `secret_bits` 取 SEAL 三值秘密前 `d` 个系数，`v=−1 → 0` ⇒ 约 2/3 轮恒等 |
| **两条路** | (a) 换成"LWE-in-RLWE"：把 `s ∈ Z_q^d` 真正作为多项式放进 RLWE 密钥（`LweToRgswOps` 的自检里已有这个做法）；(b) 保持现状但把 `d` 的语义与"约 2/3 轮恒等"写进文档 |
| **验收** | 文档里 `d` 的定义与代码一致；若走 (a)，`LweToRgswOps` 的验收 0/1/2 需通过 |

### P2-1　NFLlib 替换 SEAL 的标量 NTT（C2）

**依赖 A1**（需你放源码，见 `沙箱受限清单-需要人工获取.md`）。完整计划已在
`docs/reports/C2-NFLlib替换SEAL的NTT-实施计划-2026-10-13.md`：明文 NTT 占一次 CMUX 的 **41.2%**，
OnionPIR 报告 NFLlib 比 SEAL 快 **2–3×** ⇒ 建模 ANSWER 37.3 s → **29.7 s（2×）/ 27.1 s（3×）**。
**第一步不是集成，是先量"纯 NTT"占那 41.2% 的多少**（换 NFLlib 只能加速
`evaluator.cpp:2121` 那一行，不含 plain-lift），这一步决定模型要打几折。

### P2-2　口径差的收窄（可选，成本高）

`ε_BF: 2⁻⁶ → 更小` 会让 `ℓ_BF` 增大 ⇒ `B_pay = 2 + m·(1+ℓ_BF)` 线性增长 ⇒ **直接放大工作量**。
需要先算清"把假阳性压到可忽略"要付多少代价，再决定做不做。

---

## 四、硬约束（不要碰）

| 约束 | 说明 |
|---|---|
| **不改变原论文的算法** | 参数与实现可自选，但**必须记录在案**（这是项目既定约束） |
| **`ℓ_BF ≤ N/2`** | 槽域打分的容量上限（一个槽域密文装 `N/2` 个槽） |
| **`base < 2t`** | 平衡分解的位必须落在 `[0, t)` 内 ⇒ gadget 基上限由 `t` 定。这是 `t=2³² / base=2³²` 的由来 |
| **`N ≥ 4096`** | 密钥切换需 ≥2 个工作素数；`bfvDefault(2048)` 只给 1 个。这是这套 Java 移植的硬约束 |
| **不改这三个文件** | `CapeEndToEnd4.java`、`CapeEndToEndNative.java`、`NativeCapeAnswer.java`（用户明确要求保留原样） |
| **只做本地提交** | commit 由我做，**推送由你自己做**（见 `SYNC.md`） |

---

## 五、验收命令（每项都要能跑出"通过/不通过"）

```powershell
cd coding\rgsw-lab

# 几何 + 合取恰好性（假阴性必须为 0）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeTableDiag "E:\学习\密码赛\coding\cape-demo\db\keywords.json" 8192

# 列选择基准形态（C 个独立密文 + 常数编码 + 两条负对照）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeColumnSelectBaseline 8192 26 15

# 出站隐私（字段白名单；服务需 -Dcape.sealed=true）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeSealedFlowTest 8756

# 出站 bf 可反解的演示（说明为什么 bf 默认不发）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeBfLeakProbe
```

端到端（另开窗口起服务）：

```powershell
cd coding
$env:DSH_JVM_OPTS = '-Dcape.web=E:\学习\密码赛\coding\cape-demo\web'
.\rgsw-lab\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeDemoService 8756 8192 16 "E:\学习\密码赛\coding\cape-demo\db\keywords.json"
# 另一窗口：POST /api/query  {"keywords":["Adam Sandler","family"]}
# 期望：hit=true  payloadMismatch=0  约 36.5 s
```

---

## 六、依赖的外部产物

见 `沙箱受限清单-需要人工获取.md`。**推进 P0/P1 不需要任何外部产物**；
只有 **P2-1（NFLlib）** 需要你放源码。

---

## 七、必须一起说的口径差（任何结论都要带）

1. 本项目的 36.5 s **不含** G1 那部分 ⇒ 与论文 Table 3 **不可直接比**；
   而论文 Table 3 的 `Time(s)` 列是**等值 3.00 的模型输出、不是实测**。
2. `ε_BF = 2⁻⁶`（论文 2⁻²⁰）⇒ **假阳性率 3.44%**，约 **1/29** 查询多返回一个值；
   但**假阴性 = 0**（论文论证前提，已实测）。
3. `N=8192 / d=16 / B_pay=59` 相对论文（16384 / 512 / 2+m）**有明显量级差**。
4. 单进程回环 demo：同一 JVM 持密钥又跑查询 ⇒ **隐私性质无法在两方进程间验证**。
5. `LweToRgswOps` 不在关键路径，**不能**当标准 CAPE 盲旋转的正确性证据。

---

## 八、建议的推进顺序

```
P0-4 (⊥，最便宜) → P0-3 (判定改密文) → P0-1 + P0-2 (打分 + 响应结构，绑定做)
   → P1-1 (列选择子改客户端加密，有现成探针可抄)
   → P1-3 (d 语义，改文档或改实现二选一)
   → P1-2 (行选择子噪声，最难，可能只能记为已知偏离)
   → P2-1 (NFLlib，等源码)
```

**先把 P0 做完**：那四件合起来才是"Algorithm 2 的增量"，
做完之前**不能声称实现了论文的 CAPE**——现在只能声称"FusePIR 检索骨架 + 明文合取判定"。
