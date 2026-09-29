# 知识库 · CAPE 明文侧（BFF / Bloom / Pack）

> 用途：写正式代码前的**规范化参考**。每条都标注了「论文怎么写」vs「本仓库代码实际怎么做」，
> 不一致的地方**以代码为准**，并给出理由。
>
> 最后核对：2026-09-27（对 `origin/main` = `4448d39`）

---

## 目录

| 文件 | 内容 |
|---|---|
| `CAPE-Bloom过滤器存储与提取.md` | **原始设计说明**（外部提供，讲 BFF 一位一系数、SampleExtract 取标量、Pack 进槽位） |
| `代码对照-存储与提取.md` | **与代码逐条核对**：框架一致，但发现 3 处必须按代码修正的地方 |
| 本文 | 索引 + 速查 |

---

## 一、一句话结论

**Bloom 过滤器始终是"切开存储"的：每位一个独立字段、每位一个多项式、每位一个系数。**

```
明文阶段（数据库编码）
  每个关键词 payload = [指纹 | 值个数 | (值, Bloom位…)…]
  → BFF 一维数组
  → 重排为 R×C
  → 每个字段 b × 每列 c 构造一个多项式 P_{c,b}(X) = Σ_r D[r,c,b]·X^r
  → Bloom 位 i 存在 P_{c, b(i)}(X) 的第 r 个系数上

密文阶段（服务器检索）
  列选择 CtPtMul → 盲旋转 → SampleExtract_0    对每个字段各做一次
  → 得到 B_pay 个 LWE 密文（每个加密一个字段/一个 Bloom 位）
  → 三路 BFF 相加：ct_pay,b = ct_0,b + ct_1,b + ct_2,b

Pack 阶段
  Pack({ct_pay,b}) → RLWE 密文
  → 每个字段占一个【槽位】（不是系数！见对照文件第 3 条）

CAPE 过滤阶段
  CtCtMul(q^BF, ct_j^BF) → 逐槽位乘法
  + CtRotate/CtCtAdd 折叠 → 内积 s_j
```

**为什么必须切开**：若整个 Bloom 塞进一个系数，`CtCtMul` 会做大整数乘法、产生进位，破坏按位逻辑。
只有每位独立占一个位置，才能在槽位层面做内积。

---

## 二、速查：payload 字段布局（**按代码，不是按论文**）

```
payloadLength = 3 + 2 + m · (2 + ℓ_BF)          m = 每个关键词的 value 数上界（填充到 m）
                                    ↑      ↑
                            值的 2 个 limb   Bloom 的 ℓ_BF 位
```

| 下标 | 内容 | 位数 |
|---|---|---|
| `0,1,2` | 指纹 `fp`（3 个 16-bit limb） | **48 bit** |
| `3` | 值个数 `m_K` 高 16 位 | 16 |
| `4` | 值个数 `m_K` 低 16 位 | 16 |
| `5 + j·(2+ℓ_BF) + 0` | 第 `j` 个 value `v_j` 高 16 位 | 16 |
| `5 + j·(2+ℓ_BF) + 1` | `v_j` 低 16 位 | 16 |
| `5 + j·(2+ℓ_BF) + 2 + i` | **Bloom 位 `b_{v_j}[i]`** | **1** |

**Bloom 位的字段号**：`b(i, j) = 5 + j·(2+ℓ_BF) + 2 + i`
**Bloom 位的系数位置**：`D[r, c, b(i,j)]` 存在 `P_{c, b(i,j)}(X)` 的**第 r 个系数**上

---

## 三、⚠️ 与原设计说明的 3 处不一致（**写代码时以本节为准**）

| # | 原说明 | 代码实际 | 为什么要按代码 |
|---|---|---|---|
| 1 | 指纹 40 bit（`B_0` 一个字段） | **48 bit = 3 个 16-bit limb**（下标 0/1/2），**且一个字段占一个多项式** | 因为每个字段要单独放一个多项式、且值必须落在 `Z_t` 可表达窗口内（t=65537，16-bit limb 天然安全） |
| 2 | `u = r·C + c` | **`slot = row + column·rows`**（列优先） | 两者只是行列编排不同**都可行**，但两边必须用同一个。代码用列优先，落盘顺序 `[column][payloadBlock][row]` |
| 3 | Pack 后字段落在**系数**（表格里写"系数索引 0..5"） | Pack 后字段落在**槽位** | **这条最关键**：`CtCtMul` 只有槽位域才是逐位相乘，系数域下是卷积。lou 的 `RingPack` 就是为修这个而写的 |

> 补充：原说明写 `L_BFF = R×C`，代码里是 **`R×C ≥ L_BFF`**（多余槽位补 0）。

---

## 四、写代码时的 5 个硬约束

| # | 约束 | 出处 |
|---|---|---|
| 1 | **`ℓ_BF ≤ N`** —— 一个 value 的 Bloom 必须装进一个槽位 | `BloomParameters.choose(maxSetSize, target, maxLength= N)` |
| 2 | **R ≤ N** —— `P_{c,b}(X)` 的次数是 `R−1` | `rows = min(N, ceil(√L_BFF))` |
| 3 | **位位置只依赖关键词** —— `B(K)`，不含 value | README 第 11 项；已由 `BloomConjunctionCheck` 钉死 |
| 4 | **每个字段一个多项式** —— 不能把一个 payload 塞进一个多项式 | 否则 SampleExtract 只能取到一个标量 |
| 5 | **值/指纹用 16-bit limb** | payload 字段必须落在 `Z_t` 的 fast plain lift 窗口（±t/2） |

---

## 五、代码入口索引

| 环节 | 类 / 方法 |
|---|---|
| payload 布局与填充 | `PayloadBlockProvider.fill(keyword, offset, length, output)` |
| payload 总长 | `PayloadBlockProvider` → `payloadLength = 3 + 2 + m·(2+ℓ_BF)` |
| Bloom 位推导 | `BloomParameters.bits(String keyword)` / `bits(Collection<String>)` |
| Bloom 参数选择 | `BloomParameters.choose(maxSetSize, target, maxLength)` |
| 共用入口 | `CapeParameters.bloomParameters(maxSetSize)` |
| R×C 布局 | `BffMatrixLayout.of(bff, parameters)`；`coefficient(column, payloadBlock, row)` |
| 落盘 | `DiskBffEncoder`（顺序 `[column][payloadBlock][row]`，大端 int32） |
| 明文端到端查询 | `PlaintextFusePirQuery.query(keyword)` |
| **密文侧打分** | `rgsw-lab/BloomScoring.java`（槽位域 `CtCtMul` + 折叠） |
| **域裁决实验** | `rgsw-lab/BloomInnerProductProbe.java`（**需传 N ≥ 8192**，默认 2048 会因单素数抛异常） |
| **多条 LWE → 一个 RLWE** | `rgsw-lab/RingPack.java` |
| BFF 列选择 / 盲旋转 / 提取 | `AnswerPathMini`、`BlindRotateOps`、`LweRlweBridge` |

> ⚠️ `BloomInnerProductProbe` 默认 `N=2048`，而 N=2048 只有 1 个工作素数、
> 重线性化需要密钥切换 → 抛 `keyswitching is not supported by the context`。
> **跑法：显式传参 `... BloomInnerProductProbe 8192`**（本机已验证，结论见对照文件）。

---

## 六、待办（按 README 的整改编号）

| 项 | 内容 | 状态 |
|---|---|---|
| A1 | Bloom 位位置只依赖关键词 | ✅ 已完成（PR #2） |
| A4 | Bloom 打分 `CtCtMul` + `Σ CtRotate` | ✅ 已完成（`BloomScoring` 5/5） |
| — | Pack（真正的 Ring Packing） | ✅ 已完成（`RingPack` 6/6，N=8192） |
| A2/A3 | 客户端 QUERY 逻辑 + 列选择接通 | ❌ **未做** |
| A5 | DECODE 编排 | ❌ 未做 |
| — | `PlaintextFusePirQuery` 用 Bloom 做合取判定 | ❌ 未接（现在只读 value 列） |
| — | 产品化列打包（`P_{c,b}(X)` 接进 ANSWER） | ❌ 未接 |

---

## 七、参数提醒（两套，别混用）

| 用途 | 预设 | N | 位置 |
|---|---|---|---|
| **明文侧**（BFF / Bloom 编码） | `CapeParameters.testMinimal()` | 4096 | 现在 `defaults()` 就是它 |
| **密文侧**（RingPack + 打分） | — | **8192 起步** | 4096 时打分侧噪声崩（多一次 CtCtMul + 重线性化 + 折叠） |
| 出论文数字 | `CapeParameters.paperAligned()` | 16384 | — |

> 另：重线性化需要 **≥ 2 个工作素数**；N=2048 只有 1 个，会抛
> `keyswitching is not supported by the context`。
