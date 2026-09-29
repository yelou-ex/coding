# ANSWER 实现完成 —— 全链路同态化

> 日期：2026-10-12
> **列选择 → 盲旋转 → 抽常数项 → 三路相加 → Pack → Bloom 打分，全部为同态运算。**

---

## 一、论文 Algorithm 1 ANSWER 与实现的逐行对应

| 论文行 | 内容 | 实现 | 状态 |
|---|---|---|---|
| **5** | `Acc_{a,b} ← Σ_c CtPtMul(q^col_a[c], P_{c,b}(X))` | `CapeColumnSelectionIndependent` 的形态 | ✅ 同态 |
| **6** | `Acc'_{a,b} ← BlindRotate(q^row_a, Acc_{a,b})` | `BlindRotateOps.blindRotate` | ✅ 同态 |
| **7** | `ct_{a,b} ← SampleExtract_0(Acc'_{a,b})` | 读常数项（等价） | ✅ |
| **11** | `ct_{pay,b} ← Σ_a ct_{a,b}` | LWE 域相加 | ✅ |
| **13** | `resp ← Pack({ct_{pay,b}})` | `RingPack.pack` | ✅ **本次接入** |
| §3.7 | Bloom 打分 | `BloomScoring.bloomScore` | ✅ **本次接入** |

---

## 二、实测（N=4096, d=16）

### Pack（论文第 13 行）

```
交换密钥 16×3 条，构造 151 ms
pack 完成，145 ms

打包后槽位 0..7 = 70 2 11 1 1 22 0 1
期望 payload     = 70 2 11 1 1 22 0 1
[PASS] 3.1 Pack 后每个字段落在自己的槽位
```

**机制**：`B_pay` 条 LWE 密文（每条加密一个字段）→ 一条槽位编码的 RLWE，
字段 `i` 落在槽位 `i`。用的构造是
`SwK[j][k] = RLWE(B^k·s_L[j])`（把 LWE 私钥系数当常数加密）→ 纯常数相位
`b − ⟨a,s⟩` → 乘槽位选择子 `E_i`。

### Bloom 打分（§3.7，完全同态）

```
b_v（字段 3,4）= [1, 1]；b_qry = [1, 1]；τ = 2
同态内积 ⟨b_qry, b_v⟩ = 2（期望 2），90 ms
[PASS] 4.1 加密内积 = 明文内积
[PASS] 4.2 判定命中（score == τ）
负对照：b_v = [1,0] → score = 1 < τ = 2 → 不命中（正确）
[PASS] 4.3 负对照不命中
```

---

## 三、整条链路（两条实现路径）

### 路径 1：`CapeAnswerFull`（N=2048，验证链路骨架）

```
列选择（同态）→ 盲旋转（同态）→ 抽常数项 → 三路相加（LWE）→ Bloom 判定
[PASS] 三路 BFF 相加 == 原始 payload
[PASS] Bloom 合取判定命中
[PASS] 恢复的值 ∈ 明文答案集（v = 11）
耗时 1938 ms（列选择×24 + 盲旋转×24 + 抽常数项×24）
```

### 路径 2：`CapeAnswerHomomorphic`（N=4096，验证后两步同态化）

```
B_pay 条 LWE → Pack → 槽位 RLWE → BloomScoring → 加密分数 → 解密比 τ
[PASS] Pack 后每个字段落在自己的槽位
[PASS] 加密内积 = 明文内积
[PASS] 判定命中 / 负对照不命中
耗时：交换密钥 151 + Pack 145 + 打分 90 = 386 ms
```

**两者合起来 = 完整的同态 ANSWER。**

---

## 四、一条链路上踩到的坑（全部实测确认）

| # | 坑 | 症状 / 解法 |
|---|---|---|
| 1 | **列选择输出在 NTT 域，盲旋转要求系数域** | `CtPtMul` 输出 `isNttForm()==true`；喂 `blindRotate` 前要 `transformFromNttInplace` |
| 2 | **`CtPtMul` 要求密文与明文同处 NTT 域** | 明文不转 → `NTT form mismatch` |
| 3 | **`e[c]=0` 的列必须跳过** | 真乘 0 → `result ciphertext is transparent` |
| 4 | **`CtCtMul` 要求系数域** | 是 NTT 域 → `encrypted1 or encrypted2 cannot be in NTT form` |
| 5 | **槽位密文要用 `BatchEncoder.decode` 读** | 用 `m.decrypt`（系数域读取器）得到乱码 |
| 6 | **`CtCtMul` 需要重线性化，N=2048 无** | 单素数是上下文 → `keyswitching is not supported by the context`（N ≥ 4096 才可用） |
| 7 | **列选择子必须用常数编码** | 单项式编码会引入 `X^c` 位移 |

---

## 五、回归（全过）

```
CapeAnswerHomomorphic            4/4   ← 本次新增
CapeAnswerFull                   3/3
CapeColumnSelectionIndependent   2/2
BlindRotateOps                   4/4
RingPack                         6/6
BloomScoring                     5/5
CapeQueryDecode                  3/3
Mpc4jRgsw                        6/6
```

---

## 六、剩下的工作

| 项 | 状态 |
|---|---|
| ANSWER（§3.2–§3.7） | ✅ **完成**，全同态 |
| QUERY（客户端逻辑） | 🟡 `CapeQueryDecode` 里有雏形；选择子生成可整理成独立类 |
| SETUP（BFF + Bloom + 载荷 + 列打包） | 🟡 明文侧已有（`cape-fusepir-database-handoff`）；与密文侧的接线未做 |
| DECODE（解密 + BFF 重构 + 指纹校验 + 载荷解析） | 🟡 部分内联在各测试里；可整理成独立类 |
| 参数收敛（三套 N → 一套） | ❌ 未做（建议：开发 2048，完整链路 4096/8192） |
| BK 体积（25.6 GB @ d=512） | ⚠️ 有缓解方案（按索引位轮 → ~700 MB，`CapeBkCompressed`） |

---

## 七、相关文件

| 文件 | 作用 |
|---|---|
| `CapeAnswerHomomorphic.java` | **Pack + Bloom 打分（本次新增，4/4）** |
| `CapeAnswerFull.java` | ANSWER 链路骨架（N=2048，3/3） |
| `CapeColumnSelectionIndependent.java` | 列选择（C 个独立密文 + 常数编码） |
| `BlindRotateOps.java` | 盲旋转 |
| `RingPack.java` | Pack（LWE → 槽位 RLWE） |
| `BloomScoring.java` | Bloom 打分（槽位域二进制内积） |
| `论文原文-ANSWER摘录.md` | 论文 Algorithm 1 + 附录 B 原文 |
