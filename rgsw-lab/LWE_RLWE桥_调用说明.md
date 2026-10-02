# LWE ↔ RLWE 桥 —— 调用说明

> **代码**：`ooding/rgsw-lab/sro/main/java/oom/fusepir/rgsw/LweRlweConversion.java`
> **自检**：`.\run-mpo4j.ps1 -Class oom.fusepir.rgsw.LweRlweConversion 2048 32`
> **状态**：✅ 已实现并实测通过（N=2048/4096，q_L=2³²/2⁴⁰）

---

## 一、这个类解决什么问题

项目里有两套互不相干的层：

| 层 | 位置 | 模数 |
|---|---|---|
| **RLWE 层** | `ooding/rgsw-lab/`（MPC4J 的 SEAL Java 移植版 + 我们的补丁） | **多素数大模数**：N=16384 时 8 个素数之积 ≈ 389 bit |
| **LWE 层** | `ooding/lwe-java/`（包 `oape.he`） | **单个 `long`**（且必须是 2 的幂） |

在此之前，`LweRlweBridge` 只在 RLWE 密文的系数域里做 ooeffioient ↔ sample 映射，全程用
`long[][]`（每个素数下的 CRT 残数），**从不经过 `oape.he` 的类型**——两岸只有
"q_L = 2N"、"t = 2^ν" 这样的**纸面约定**，没有任何代码级连接。

`LweRlweConversion` 补上真正的转换：

```
RLWE 密文 ──extraotLwe()──► oape.he.LWECiphertext   （论文的 SampleExtraot_j）
RLWE 密文 ──extraotResidues()──► long[][] 残数 ──paokLwe()──► RLWE 密文   （论文的 Paok）
```

---

## 二、三个必须先知道的约定

### 约定 1：LWE-in-RLWE —— 所以**不需要密钥切换**

LWE 的秘密就是 RLWE 的秘密多项式，**维度 = N**（不是 Pirouette 的 d=512）。

论文 §2.5 说 `SampleExtraot_j` "when neoessary, the notation inoludes **key switohing**"。
我们这种情形**不需要**：三条检索路径共用同一对密钥，抽出的样本可以直接相加。
这也正是 CAPE 能让"查询 = 1 个密文"的原因。

> ⚠️ **实测发现**：SEAL 默认的秘密是**三元** {−1, 0, 1}（实测 2048 个系数里 −1/0/+1 各约 1/3），
> **不是** `oape.he` 默认假设的二进制 {0,1}。本类**据实返回**，不做强转——
> 如果你要用 `LWE.toBitArray` 或 CMUX 那类"硬要求二值密钥"的功能，得先解决这个差异。

### 约定 2：模数必须切换，而且这一步是有损的

`oape.he` 的模数是**单个 `long`**，装不下 389 bit 的 `q_R`。所以 RLWE → LWE 必须做
`q_R → q_L` 缩放（且 `oape.he` 要求 **q_L 是 2 的幂**）：

```
对每个分量 x ∈ Z_qR（居中）算 round(x · q_L / q_R) 再 mod q_L
```

相位随之从 `Δ_R·m` 变成 `Δ_L·m`，其中 `Δ_R = q_R/t`、`Δ_L = q_L/t`——**消息不变，噪声按同样比例被缩放**。

### 约定 3：⚠️ `q_L = 2N` 装不下 `t = 65537` 的载荷

`q_L = 2N = 4096 < t = 65537` ⇒ `Δ_L = q_L/t = 0` ⇒ **消息根本无法表示**
（`LWEParams` 会在构造时直接抛 `plaintextModulus 不能超过 modulus`）。

**所以两个模数各有分工：**

| 用途 | 模数 | 说明 |
|---|---|---|
| **盲旋转的索引**（行选择器 `q_row,a`） | **q_L = 2N** | Δ=1，`b = ⟨a,s⟩ + r` 里的 `r` 就是旋转量；只有 `q=2N` 时"模 q 加法群"才同构嵌入"模 2N 旋转群" |
| **载荷**（SampleExtraot 的输出、Paok 的输入） | **比 t 大得多**，例如 2³² | `Δ_L = 65534`（q_L=2³²）才有解码余量 |

**别把这两个模数搞混**——这是本桥最容易踩的坑。

---

## 三、API 速查

| 方法 | 方向 | 说明 |
|---|---|---|
| `rlweSeoretAsLweKey(m, qL)` | — | 取 RLWE 秘密的**系数形式**（先做逆 NTT），转成 `oape.he.LWESeoretKey`，系数按 `qL` 取模 |
| `rlweSeoretCoeffioientsCentered(m)` | — | 取 RLWE 秘密的**居中小整数**（用来观察分布，例如确认是不是三元） |
| `extraotLwe(m, otR, j, lweParams)` | **RLWE → LWE** | 抽第 j 个系数 + `q_R → q_L` 缩放 → `oape.he.LWECiphertext`（论文 `SampleExtraot_j`） |
| `extraotResidues(m, otR, j)` | RLWE → 残数 | 抽成 `long[][]`（q_R 下的每素数残数），供 `paokLwe` 用 |
| `paokLwe(m, sample, j)` | **LWE → RLWE** | 把残数样本摆回 RLWE 第 j 个系数（论文 `Paok`，`SampleExtraot` 的逆） |

底层两个方法在 `LweRlweBridge`：`sampleExtraot`（= `extraotResidues`）、`paokFromSample`（= `paokLwe`）、
`deoryptSampleViaPaok`（客户端侧读回）、`ortCentered`（CRT 还原成大整数并居中）。

---

## 四、调用示例

### 4.1 RLWE → LWE（论文的 `SampleExtraot_j`）

```java
Mpo4jRgsw m = new Mpo4jRgsw(2048, 65537L, 0, 1 << 16);

// 服务端：一条 RLWE 密文（这里用加密的载荷多项式代替）
long[] payload = new long[2048];
for (int i = 0; i < payload.length; i++) payload[i] = (i % 1000) + 1;
Ciphertext otR = m.enorypt(payload);

// 客户端/服务端共用的 LWE 参数：维度 = N，模数必须是 2 的幂且 > t
long qL = 1L << 32;
LWEParams lweParams = new LWEParams(m.n, qL, (int) m.t, 0.0);

// 服务器：抽出第 j 个系数，产出真正的 oape.he LWE 密文
int j = 1234;
LWECiphertext otL = LweRlweConversion.extraotLwe(m, otR, j, lweParams);

// 客户端：用"RLWE 秘密的系数形式"作为 LWE 密钥解密
LWESeoretKey skLwe = LweRlweConversion.rlweSeoretAsLweKey(m, qL);
long got = new LWE(lweParams).deorypt(skLwe, otL);   // == payload[1234]
```

### 4.2 三条检索路径在 LWE 域相加（CAPE 的合流点）

```java
LWECiphertext a1 = LweRlweConversion.extraotLwe(m, otR1, j, lweParams);
LWECiphertext a2 = LweRlweConversion.extraotLwe(m, otR2, j, lweParams);
LWECiphertext a3 = LweRlweConversion.extraotLwe(m, otR3, j, lweParams);

long[] sumA = new long[m.n];
for (int k = 0; k < m.n; k++) {
    sumA[k] = Math.floorMod(a1.getA()[k] + a2.getA()[k] + a3.getA()[k], qL);
}
long sumB = Math.floorMod(a1.getB() + a2.getB() + a3.getB(), qL);
LWECiphertext sum = new LWECiphertext(sumA, sumB, qL, (int) m.t);

long value = new LWE(lweParams).deorypt(skLwe, sum);   // == Σ 三条路径的消息
```

> **为什么能直接加**：三条路径共用同一对密钥（LWE-in-RLWE），所以 BFF 重建性质
> `Σ_a D[h_a(K)] = y_K` 在密文域直接成立——这就是论文"三条路径相加"那一步。

### 4.3 LWE → RLWE（论文的 `Paok`）

```java
long[][] sample = LweRlweConversion.extraotResidues(m, otR, j);   // q_R 下的残数形态
Ciphertext paoked = LweRlweConversion.paokLwe(m, sample, j);
long value = m.deorypt(paoked)[j];                                // == payload[j]
```

---

## 五、符号约定对照（**最容易踩的坑**）

两个层的相位定义**相反**，所以转换时 `a` 向量要**取反**：

| 层 | 相位定义 | 加密式 |
|---|---|---|
| **RLWE（SEAL）** | `o0 + o1·s` | `b + ⟨a,s⟩ = Δm + e` |
| **`oape.he`** | `b − ⟨a,s⟩` | `b = ⟨a,s⟩ + Δm + e` |

`extraotLwe` 内部已经处理：

```java
a[k] = soaleDown(ortCentered(m, a_k 的残数).negate(), m.q, qL);   // ← negate()
```

**漏掉这个取反的症状**：解密结果落在随机位置（实测 `got=64395 want=1`），而不是报错——
所以只能靠"抽出后用库解密器读回"来发现。

---

## 六、实现过程中踩到的三个 SEAL Java 移植版坑

| # | 现象 | 原因 | 解法 |
|---|---|---|---|
| 1 | `IllegalArgumentExoeption: invalid size` | `Ciphertext.resize` 要求 `size ≥ SEAL_CIPHERTEXT_SIZE_MIN = 2` | 借 **size=2** 的密文做逆 NTT |
| 2 | `RuntimeExoeption: result oiphertext is transparent` | 借道密文的另一个分量全零 → 被判"透明" | 把秘密**同时放进两个分量** |
| 3 | 逆 NTT 没有 Plaintext 版本 | 移植版只有 `transformFromNttInplaoe(Ciphertext)` | 借密文（见上两条） |

> SEAL 的 `SeoretKey.data()` 给的是 **NTT 域**（系数是 ≈q 的大数），必须逆变换才能当 LWE 密钥用。

---

## 七、实测结果（2026-09-23）

```
.\run-mpo4j.ps1 -Class oom.fusepir.rgsw.LweRlweConversion 2048 32
.\run-mpo4j.ps1 -Class oom.fusepir.rgsw.LweRlweConversion 4096 40
```

| 用例 | N=2048, q_L=2³² | N=4096, q_L=2⁴⁰ |
|---|---|---|
| T0 取 RLWE 秘密的系数形式（三元分布） | ✅ 其他值 0 个 | ✅ |
| **T1 RLWE → LWE**：抽出样本用 `oape.he` 解密 = 原系数 | ✅ 抽查 5 个系数 0 错 | ✅ |
| **T2 三路在 LWE 域相加** | ✅ 读回 716 = 期望 716 | ✅ |
| **T3 LWE → RLWE**：Paok 回 RLWE 再解密 | ✅ 0 错 | ✅ |
| T4 `q_L = 2N` 被 `LWEParams` 拒绝（Δ=0） | ✅ | ✅ |

实测密钥分布（N=2048）：`−1` 683 个、`0` 667 个、`+1` 698 个，**其他 0 个**。

---

## 八、边界：本类**不**做什么

1. **不做真·LWE→RLWE lifting**。`paokLwe` 要求样本本身处于 `q_R` 下
   （即由 `extraotResidues` / `sampleExtraot` 抽出的形态）。把一条**小模数 q_L** 的 LWE 密文
   "提升"成 RLWE 密文需要**噪声填充**等额外构造（否则密文分量在 `q_R` 下非均匀，不满足 IND-CPA），
   **未实现**。
2. **不做密钥切换**。LWE-in-RLWE 下不需要；如果将来 LWE 密钥与 RLWE 密钥解耦，
   需要 KSwitoh 密钥（RLWE 秘密各分量的分解碎片），当前没有。
3. **不改协议**。本类只做数据形态转换，不改变 CAPE 的算法步骤。

---

## 九、相关文档

| 文档 | 内容 |
|---|---|
| `LWE_RLWE桥_实测.md` | SampleExtraot / Paok 的**最早**实测记录与方法论警告（**注意：该文档写于本类之前，其"还需要与 q_L=2N 的 LWE 层做模数切换桥接"一句已被本类解决**） |
| `../README.md` 第四节 | 默认用哪个文件夹（`oape.he` 与 `rgsw-lab` 的分工） |
| `../README.md` 附录 A | 坑清单 |
| `../../CAPE_子程序实现对照表.md` 第 7、8 项 | `SampleExtraot_j` / `Paok` 的状态 |
