# Bloom 过滤器适配论文 + 参数最小化（2026-09-19）

> 两项改动：**① 修好 Bloom 位位置（论文对齐）**；**② 参数全面最小化**（本阶段只验证原理能否跑通）。

---

## 一、改了什么

### ① Bloom 位位置：只依赖关键词（论文对齐）

**原来的错**（`PayloadBlockProvider.java:69`）：

```java
byte[] digest = digest(keyword + ":" + value);   // ← value 混进了哈希
```

**现在**：位位置由 `BloomParameters.bits(keyword)` 统一推导，**只依赖关键词**。

```java
// BloomParameters.java
public boolean[] bits(String keyword) { ... }              // B(K)
public boolean[] bits(Collection<String> keywords) { ... } // 一个 value 的 b_v
```

**为什么这是必须的**（CAPE §4.1 的合取判定）：

| 谁 | 手里有什么 | 能算什么 |
|---|---|---|
| 客户端 | 只有关键词 `K_2..K_Q` | `B(K_i)` —— **算不出** `B(K_i : v)` |
| 服务端 | value `v` 及其关联关键词 | `b_v = Σ B(K')` |

两边必须用**同一个 `B(K)`**。原来 value 混进哈希后，同一个关键词在不同 value 下落在不同位，
客户端的 `b_qry` 与服务端的 `b_v` 位位置永远对不上，**内积恒为 0，合取判定永远失败**
（README 第 11 项记录的实质错误）。

**顺带**：`CapeParameters.bloomParameters(maxSetSize)` 成为**唯一入口**，
服务端与客户端调同一个方法，避免两边各写一份而漂移。

### ② 参数最小化

| 项 | 原来 | 现在 | 说明 |
|---|---|---|---|
| 默认预设 | `paperAligned()` | **`testMinimal()`** | 本阶段目标是跑通，不是出数字 |
| N（环维度） | 16384 | **4096** | 同时也是 Bloom 长度上限 ℓ ≤ N |
| ε_BF | 2⁻²⁰ | **2⁻⁶** | ℓ 随 −log(ε) 增长，压太低会撞 ℓ ≤ N |
| 指纹位数 | 40 | **16** | 只用于"查错返回 ⊥"，测试够用 |
| 数据集 | 全量 1475 | **支持抽样**（如 32、128） | 载荷长度 ∝ m，而真实 m=131 |
| t = 65537 | — | **不动** | 它同时是 fast plain lift 窗口（±t/2），换了会掩盖 gadget 切段约束 |
| k = 3 | — | **不动** | BFF 三位置结构是必须验证的 |

**新增 API**：
```java
CapeParameters.paperAligned()          // 出论文数字用
CapeParameters.testMinimal()           // 跑通用（现在是 defaults()）
CapeParameters.defaults()              // → testMinimal()
capeParameters.bloomParameters(max)    // 服务端/客户端共用的唯一入口

MovieLensTagLoader.load(path, 32)      // 前 32 个关键词（字典序，可复现）
DatabaseInitializerMain <csv> [paper|test] [maxKeywords]
DiskBffEncodeMain <csv> <dir> [block] [keywordLimit]     # 或 CAPE_PRESET=paper
```

> **为什么数据集也要缩**：`payloadLength = 3 + 2 + m·(2+ℓ_BF)`，
> 其中 `m = maxKeywords 里单个关键词关联 value 数的上界`。真实 MovieLens small 的
> `m = 131`，于是**每个关键词都要填充到 131 个 value**（即使平均只有 2.42 个）。
> 这才是规模的主要来源，光缩 Bloom 不够。

---

## 二、实测规模对比（MovieLens small）

| 配置 | h | ℓ_BF | Bpay | L_BFF | 表系数 | 占用 | 编码耗时 |
|---|---|---|---|---|---|---|---|
| **paper + 全量** | 16 | 5075 | 665092 | 2048 | 1,362,108,416 | **5196 MB** | （未跑，太大） |
| test + 全量 | 6 | 1498 | 196505 | 2048 | 402,442,240 | 1535 MB | — |
| test + 128 关键词 | 6 | 113 | 4260 | 256 | 1,090,560 | 4.2 MB | — |
| **test + 32 关键词** | 6 | 35 | 597 | 64 | **38,208** | **0.1 MB** | **0.1 s** |

**关键**：`test + 32 关键词` 让整条链路从 GB 级降到 **149 KB 磁盘 / 0.1 秒**，
而且**结构完全不变**（k=3 位置、分段 BFF、指纹校验、ℓ ≤ N 都保留）。

---

## 三、验证结果（本机实测）

### 新增：`BloomConjunctionCheck` —— 合取判定的验收测试

```
[params] N=4096, k=3, 指纹=16 bit, ε_BF=2^-6, t=65537
[bloom] maxSetSize=3 -> h=6, lBF=26 bits (上限 N=4096) OK

--- 1) 真命中必须全部召回（漏判 = 正确性问题）---
      [sci-fi, action]                真命中=[2, 3]      判定命中=[2, 3]
      [sci-fi, comedy]                真命中=[1]         判定命中=[1]
      [action, comedy, drama]         真命中=[]          判定命中=[]
      [sci-fi, documentary]           真命中=[5]         判定命中=[5]
      [action, documentary]           真命中=[7]         判定命中=[7]
      [comedy, documentary]           真命中=[9]         判定命中=[9]
      [drama, documentary]            真命中=[8]         判定命中=[8]
      [sci-fi, action, drama]         真命中=[3]         判定命中=[3]
  [PASS] 真命中全部召回            共 11 个真命中，漏判 0 个

--- 2) 假阳性（ε_BF 的固有性质，不是 bug）---
  [PASS] 单关键词假阳性率与 ε_BF 同量级
--- 3) 位位置只依赖关键词 ---
  [PASS] B(K) 与 value 无关，且 value 的 Bloom 恰含其关键词的位
      检查 72 个 (value, keyword) 组合，全部一致

=== Bloom 合取判定全部通过 ===
```

**验收标准说明**（测试里写清了）：
- **必须召回全部真命中** —— 一个都不能漏（这是正确性）
- **假阳性受 ε_BF 控制** —— Bloom 的固有性质，不是 bug。
  ε_BF 越小假阳性越少，但 ℓ_BF 变大（受 ℓ ≤ N 约束）。
  合取 Q 个关键词时需**同时**误命中，约 `ε_BF^(Q-1)`，所以合取反而更准。

### 回归：原有测试仍全过

```
ArithmeticBffSelfTestMain  T1–T5 全过（Setup/Encode/Check/Reconstruct 闭环）
```

### 端到端明文查询（首次跑通）

之前因 5.2 GB 跑不了，现在 149 KB、0.1 秒：

```
DiskBffEncodeMain <tags.csv> <dir> 2048 32
  → L_BFF=64 Bpay=597 R=8 C=8 blocks=1 (0.1 s)
  → 产物：bff-block-00000.bin 149.2 KB + .sha256 + bff-manifest.json

PlaintextFusePirQueryMain <dir>
  1970s             → 候选 value = [1635, 3556, 6327]   ✓ 与数据库一致
  1980s             → 候选 value = [1777, 2145]         ✓
  1900s             → 候选 value = [918]                ✓
  no-such-keyword   → 结果 = ⊥                          ✓
```

manifest 里现在带上正确的 Bloom 参数（跨语言对齐用）：
```json
"bloomHashCount": 6,
"bloomLength": 35,
```

---

## 四、还差什么（Bloom 相关）

| 项 | 状态 |
|---|---|
| ② 服务端 Bloom 生成（位位置只依赖关键词） | ✅ **本次修好并验证** |
| ③ 客户端侧 `BF.Gen`（共用同一份） | ✅ 已具备 —— `BloomParameters.bits(String)` 就是客户端要用的 |
| ④ **密文侧打分** `CtCtMul` + `Σ CtRotate(·,2^r)` | ❌ **仍未写**（算子齐，编排缺。README 整改项 A4 / R4） |
| ⑤ `PlaintextFusePirQuery` 用 Bloom 做合取判定 | ❌ 仍未接（现在只读 value 列表，Bloom 位取回就丢） |

> 本次修的是**前提**：位位置对了，④⑤ 才有可能对。建议下一步接 ④。

---

## 五、注意 / 影响面

1. **`CapeParameters.defaults()` 语义变了** —— 现在返回**最小测试参数**。
   任何依赖"默认 = 论文参数"的地方会跟着变小。要论文参数请显式 `paperAligned()`。
2. **`DiskBffEncoder` 的 manifest 格式没变**，只是数值变小。
3. **哈希规则变了**（位位置不再含 value）—— 之前生成的 BFF 数据**与新代码不兼容**，
   需要重新编码。恰好原先也没生成过完整数据（太大），所以无实际影响。
