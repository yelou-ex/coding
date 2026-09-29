# CAPE QUERY + DECODE 编排 —— 说明与实测

> 补齐 README 整改项 **A2 / A3 / A5**。类：`CapeQueryDecode.java`
> 记录日期：2026-09-28

---

## 一、补齐了什么

原来链路两端是空的，本次接上：

```
SETUP   已有：BFF 编码 → 二维布局 P_{c,b}(X) → 盲旋转密钥
QUERY   ★ 本次：客户端构造查询 + 逐位 RGSW 自举密钥 + 行索引密文 + Bloom 查询向量
ANSWER  已有：列选择 → 盲旋转 → BFF 三路相加
DECODE  ★ 本次：解密 → 读字段 → Bloom 合取判定 → 输出结果集
        ★ 本次：与明文答案集对账 + 负对照
```

跑法：

```powershell
$root = "D:\DFY-ws\cape"; $jdk = "D:\Java\jdk-25\bin"
$cp = "$root\lib\mpc4j-crypto-fhe-seal.jar;" +
      ((Get-ChildItem "$root\lib\deps" -Filter *.jar | ForEach-Object { $_.FullName }) -join ';')
& "$jdk\java.exe" -Xmx8g -cp "$root\rgsw-lab\mpc4j-out;$cp" com.fusepir.rgsw.CapeQueryDecode 2048 64
```

---

## 二、实测：**全流程跑通**

```
--- 1. SETUP ---
    K_1 → [11, 22]
    K_2 → [11]
    K_3 → [33]
    值 → 关联关键字：  v=11 ← [K_1, K_2]   v=22 ← [K_1]   v=33 ← [K_3]
    Bloom（ℓ_BF=2）：  b_{11}=[1,1]   b_{22}=[0,1]   b_{33}=[0,1]
    B_pay = 8（m=2, ℓ_BF=2）
    payload_1 = [70, 2, 11, 1, 1, 22, 0, 1]

--- 2. QUERY（客户端）---
    查询 = [K_1, K_2]（合取）
    锚关键词 K_1 的 BFF 位置 = [0, 1, 2]
    b_qry = [1, 1]，τ = |b_qry|₁ = 2

--- 3. ANSWER（服务器，看不到 r*）---
    盲旋转 3 路 × 8 字段 = 24 次

--- 4. DECODE（客户端）---
    重建 payload = [70, 2, 11, 1, 1, 22, 0, 1]   ← 与原始完全一致
    [PASS] 4.1 BFF 三路重建 == 原始 payload
    恢复的值 v = 11，其 Bloom = [1, 1]
    ⟨b_qry, b_v⟩ = 2 = τ → 命中
    [PASS] 4.3 Bloom 合取判定命中
    明文答案集（同时属于 [K_1, K_2] 的值）= [11]
    [PASS] 4.4 恢复的值 ∈ 明文答案集
    负对照：b_{v=33}=[0,1] → ⟨·, b_v⟩ = 1 ≠ 2 → 不命中（正确）

=== QUERY + DECODE 打通 ===
```

---

## 三、参数扫描：**最快能实现的参数**

用 `CapeQueryDecode`（每轮 24 次盲旋转，d=16）实测：

| N | 工作素数 | 结果 | 端到端耗时 | 说明 |
|---|---|---|---|---|
| **1024** | **1** | ❌ **0/3** | 0.9 s | **硬下限**：单素数上下文不支持密钥切换 → `keyswitching is not supported by the context` |
| **2048** | 2 | ✅ 3/3 | **1.7 s** | **最快的可用点** |
| 4096 | 2 (72 bit) | ✅ 3/3 | 4.9 s | |
| 8192 | 4 (174 bit) | ✅ 3/3 | 30.4 s | lou 的 `RingPack` 也要求 N ≥ 8192 |
| 16384 | — | 未跑 | 估算 ~2 min | 论文参数 |

### 结论：**推荐 N = 2048（开发/验证）、N = 8192（含 Bloom 打分的完整链路）**

理由：

1. **N = 1024 不可用** —— `Mpc4jRgsw` 用 `CoeffModulus.bfvDefault(n)`，
   该函数对 N ≤ 1024 只给 1 个素数，而**重线性化需要 ≥ 2 个工作素数**（BFV 要把最后一个留给 `q_last`）。
   实测报错：`keyswitching is not supported by the context`。

2. **N = 2048 是最快的可用点** —— 1.7 s 跑完整条 QUERY→ANSWER→DECODE，
   24 次盲旋转 + 3 路 BFF 重建 + Bloom 判定全对。开发期用这个迭代最快。

3. **N = 4096 是"够用"的折中** —— 4.9 s，且是 `BloomScoring` 已验证通过的点。

4. **N = 8192 是完整链路的最小点** —— lou 的 `RingPack` 实测
   "N=4096 打包能过、但打分侧（多一次 CtCtMul + 重线性化 + 折叠）噪声崩，
   N=8192 起步（4 个工作素数 / 174 bit）"。

> ⚠️ **两套 N 的用途不同，别混用**：
> 本类（QUERY/DECODE，走**盲旋转**）N=2048 就够；
> **Bloom 打分**（`BloomScoring`/`RingPack`）要 N ≥ 4096，建议 8192。

---

## 四、本验证版的三处简化（都写进注释了）

| # | 简化 | 论文做法 | 影响 |
|---|---|---|---|
| 1 | **列选择直接传明文列坐标** | 客户端送**加密 one-hot** 列选择器（RLWE 密文，one-hot 每一位是明文多项式的系数） | 只影响**隐私**（服务端知道了目标列），不影响**正确性**。README §1.2 已纠正语义为 `CtPtMul`（密文×明文） |
| 2 | **BFF 位置由位置池连续分配** | `MappingStep` 的剥离（peeling）算法 | 正确性等价（Σ_{a} D[u_a] = payload 严格成立），只多了内存占用 |
| 3 | **每个字段一条多项式（R=n, C=1）** | R×C 二维布局 + 列选择 | 结构等价；论文的列打包是为了省通信量 |

> 这三处都是为了"先让原理跑通"，都可以在保持接口不变的前提下逐步替换。

---

## 五、与 tiny-cape 的关系

| | tiny-cape（N=8, q=97） | 本类（N=2048+，SEAL/MPC4J） |
|---|---|---|
| 目的 | **可手工逐位验算** | **在真实参数上跑通** |
| 依赖 | 零依赖纯 JDK | MPC4J（需 JDK 25） |
| 盲旋转 | ✅ 整条多项式对拍通过 | ✅ 3 路 × 8 字段全对 |
| QUERY/DECODE | 内联在 `CapeEndToEnd` | ✅ **本类** |
| Bloom 打分 | ❌ q=97 容量不够 | ✅ `BloomScoring` |

两者**互相印证**：tiny-cape 证明代数关系，本类证明工程可实现性。

---

## 六、还剩什么

| 项 | 状态 |
|---|---|
| QUERY 客户端逻辑 | ✅ 本次完成 |
| DECODE 编排 | ✅ 本次完成 |
| 端到端（同一套数据跑通四步） | ✅ 本次完成 |
| 参数收敛（三套 N → 一套） | 🟡 **建议：开发用 2048，完整链路用 8192** |
| 加密列选择器 | ✅ 已在 `CapeColumnSelectionIndependent` 实现（CAPE 原版：one-hot 整体密文）。更省的紧凑坐标形态属 **CAPE-C**，本项目不做 |
| 真实 LWE 噪声 | ❌ 未做（`lweEncryptIndex` 是 Δ=1 无噪声约定，见其注释） |
| `SampleExtract`（tiny-cape 层） | ❌ 未对齐（不影响本类，本类用 `LweRlweBridge.sampleExtract`） |
