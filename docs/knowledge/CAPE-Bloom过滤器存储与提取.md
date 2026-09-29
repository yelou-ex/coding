# CAPE 中 Bloom 过滤器在 R×C 矩阵中的存储与提取

你的问题非常精准，直指 CAPE 从数据库编码到服务器检索的完整链条。下面我分三步讲清楚：**初始 R×C 矩阵怎么存**、**SampleExtract 怎么取**、**Bloom 过滤器位在哪个环节进入 RLWE 多项式**。

---

## 1. 初始 R×C 矩阵的存储布局

### 1.1 BFF 数组的一维结构

回顾论文 Section 2.4，算术 BFF 是一个一维数组：

\[
\mathbf{D} \in (\mathbb{Z}_t^B)^{L_{\text{BFF}}}
\]

每个位置 \(u \in [0, L_{\text{BFF}}-1]\) 存储一个 **payload 向量** \(\mathbf{y}_{K_i} \in \mathbb{Z}_t^B\)。

在 CAPE 中，每个关键字 \(K_i\) 的 payload 被展平为一个固定长度的标量序列：

\[
\text{Payload}_i = [\underbrace{\text{fp}}_{B_0},\; \underbrace{m_{K_i}}_{B_1},\; \underbrace{v_1}_{B_2},\; \underbrace{b_{v_1}[0]}_{B_3},\; \underbrace{b_{v_1}[1]}_{B_4},\; \dots,\; \underbrace{b_{v_1}[\ell_{\text{BF}}-1]}_{B_{2+\ell_{\text{BF}}}},\; \underbrace{v_2}_{B_{3+\ell_{\text{BF}}}},\; \dots]
\]

**关键点**：Bloom 过滤器的每一位 \(b_{v_j}[i]\) 是这个序列中的一个**独立标量**，占据一个独立的字段位置 \(B_{2+j(\ell_{\text{BF}}+1)+i}\)。

### 1.2 二维布局 R×C

论文 Section 3.1 写道：

> *"We further represent the array into a two-dimensional layout and pack each column into polynomial coefficients."*

一维 BFF 数组被重新排列成 \(R \times C\) 矩阵，其中：

\[
L_{\text{BFF}} = R \times C
\]

BFF 位置 \(u = r \cdot C + c\) 对应矩阵条目 \((r, c)\)，即第 \(r\) 行、第 \(c\) 列。

### 1.3 每个字段的多项式编码

由于 payload 有 \(B_{\text{pay}}\) 个字段，服务器为**每个字段 \(b\)** 和**每一列 \(c\)** 构造一个多项式：

\[
P_{c,b}(X) = \sum_{r=0}^{R-1} D[r, c, b] \cdot X^r
\]

其中 \(D[r, c, b]\) 是矩阵条目 \((r, c)\) 的 payload 的第 \(b\) 个字段的值。

**举例**：假设 \(R = 4\)，\(C = 2\)，\(B_{\text{pay}} = 6\)（指纹、数量、值 \(v_1\)、Bloom 位 0、Bloom 位 1、Bloom 位 2）。

- \(P_{0,0}(X) = D[0,0,0] + D[1,0,0]X + D[2,0,0]X^2 + D[3,0,0]X^3\) — 第 0 列所有行的指纹
- \(P_{0,1}(X) = D[0,0,1] + D[1,0,1]X + \dots\) — 第 0 列所有行的数量
- \(P_{0,2}(X) = D[0,0,2] + D[1,0,2]X + \dots\) — 第 0 列所有行的 \(v_1\)
- \(P_{0,3}(X) = D[0,0,3] + D[1,0,3]X + \dots\) — 第 0 列所有行的 Bloom 位 0
- \(P_{0,4}(X) = D[0,0,4] + D[1,0,4]X + \dots\) — 第 0 列所有行的 Bloom 位 1
- \(P_{0,5}(X) = D[0,0,5] + D[1,0,5]X + \dots\) — 第 0 列所有行的 Bloom 位 2

**Bloom 过滤器的每一位，在初始 R×C 矩阵中，是以「多项式的系数」形式存储的。** 具体来说，Bloom 位 \(i\) 对应字段 \(b = B_3 + i\)，它的值 \(D[r, c, B_3+i]\) 存储在多项式 \(P_{c, B_3+i}(X)\) 的第 \(r\) 个系数上。

---

## 2. SampleExtract 如何提取目标 Bloom 位

回顾 Algorithm 1 的 ANSWER 阶段：

```text
2: for a = 0 to 2 do
3:     Parse (q, qow) from q.
4:     for b = 1 to B_pay do
5:         Acc_{a,b} ← ∑_{c=0}^{C-1} CtPtMul(q_a^col[c], P_{c,b}(X))
6:         Acc_{a,b} ← BlindRotate(q_a^row, Acc_{a,b})
7:         ct_{a,b} ← SampleExtract_0(Acc_{a,b})
8:     end for
9: end for
```

### 2.1 第 5 行：列选择

\(q_a^{\text{col}}[c]\) 是加密的列选择器（RLWE 一热编码），只有目标列 \(c^*\) 对应 1，其余为 0。

\[
\sum_{c=0}^{C-1} q_a^{\text{col}}[c] \cdot P_{c,b}(X) = P_{c^*, b}(X)
\]

结果是一个 RLWE 密文，其明文多项式是 \(P_{c^*, b}(X)\)，系数为：

\[
P_{c^*, b}(X) = D[0, c^*, b] + D[1, c^*, b]X + \dots + D[R-1, c^*, b]X^{R-1}
\]

### 2.2 第 6 行：盲旋转选行

\(q_a^{\text{row}}\) 是加密的行索引 \(r^*\)。盲旋转执行：

\[
\text{Acc}_{a,b} \leftarrow \text{BlindRotate}(q_a^{\text{row}}, \text{Acc}_{a,b})
\]

数学效果：把多项式 \(P_{c^*, b}(X)\) 旋转 \(X^{-r^*}\)，使得第 \(r^*\) 个系数 \(D[r^*, c^*, b]\) 移动到常数项：

\[
P_{c^*, b}(X) \cdot X^{-r^*} = D[r^*, c^*, b] + \text{其他系数}
\]

### 2.3 第 7 行：提取常数项

\[
\text{ct}_{a,b} \leftarrow \text{SampleExtract}_0(\text{Acc}_{a,b})
\]

SampleExtract 提取常数项，输出一个 **LWE 密文**，加密的正是：

\[
D[r^*, c^*, b]
\]

**这就是第 \(b\) 个字段的值。** 如果 \(b\) 对应某个 Bloom 位 \(i\)，那么提取出来的就是该位（0 或 1）。

### 2.4 三次 BFF 路径的合并

第 10-12 行：

```text
10: for b = 1 to B_pay do
11:     ct_{pay,b} ← CtctAdd(CtctAdd(ct_{0,b}, ct_{1,b}), ct_{2,b})
12: end for
```

每个关键字映射到 3 个 BFF 位置（3 列），所以 \(a = 0, 1, 2\) 对应三次检索。算术 BFF 的重构性质保证：

\[
\sum_{a=0}^{2} D[r_a^*, c_a^*, b] = \mathbf{y}_{K}[b]
\]

即三次提取的 LWE 密文相加后，得到完整 payload 第 \(b\) 个字段的 LWE 加密。

**此时，Bloom 过滤器的每一位仍然是一个独立的 LWE 密文。**

---

## 3. Bloom 位如何进入 RLWE 多项式（Pack 阶段）

第 13 行：

```text
13: resp ← Pack({ct_{pay,b}}_{b=1}^{B_pay})
```

`Pack` 把 \(B_{\text{pay}}\) 个 LWE 密文打包成 RLWE 密文。对于 Bloom 位：

- LWE 密文 \(\text{ct}_{pay, B_3+i}\) 加密的是 \(b_{v_j}[i]\)（第 \(j\) 个值的 Bloom 过滤器第 \(i\) 位）。
- `Pack` 把它放到 RLWE 多项式的某个槽位（或系数）上。

**关键**：`Pack` 的输出是一个（或多个）RLWE 密文，其多项式中有 \(B_{\text{pay}}\) 个位置，每个位置存一个字段。Bloom 位 \(b_{v_j}[i]\) 占据其中一个位置。

### 3.1 Pack 后的 RLWE 多项式结构

假设 \(B_{\text{pay}} = 6\)，pack 后一个 RLWE 密文的明文多项式系数布局可能是：

| 系数索引 | 存储内容       |
| -------- | -------------- |
| 0        | 指纹           |
| 1        | 数量 \(m_K\)   |
| 2        | 值 \(v_1\)     |
| 3        | \(b_{v_1}[0]\) |
| 4        | \(b_{v_1}[1]\) |
| 5        | \(b_{v_1}[2]\) |

**Bloom 过滤器被切成单个位，每位占一个系数（或槽位）。**

### 3.2 为什么必须切开放？

因为 CAPE 的 Bloom 分数计算需要：

\[
s_j = \langle \mathbf{b}_{\text{qry}}, \mathbf{b}_{v_j} \rangle = \sum_{i} q_i \cdot b_{v_j}[i]
\]

如果整个 Bloom 过滤器塞进一个系数，`CtCtMul` 会做大整数乘法，产生进位，破坏按位逻辑。只有每位独立占一个系数，才能通过 `CtCtMul` + `CtRotate` + `CtCtAdd` 在槽位层面完成内积。

---

## 4. 完整流程图

```text
数据库编码阶段：
  每个关键字 K_i 的 payload 展平为 [fp, m, v_1, b_1[0], b_1[1], ..., v_2, ...]
  → BFF 数组 (一维)
  → 重排为 R×C 矩阵
  → 对每个字段 b 和每列 c，构造多项式 P_{c,b}(X) = Σ_r D[r,c,b] X^r
  → Bloom 位 b_j[i] 存储在 P_{c, B_3+i}(X) 的第 r 个系数上

服务器检索阶段：
  for 每个字段 b:
      列选择: Σ_c q_col[c] · P_{c,b}(X) → P_{c*, b}(X)
      盲旋转: 旋转 X^{-r*}，把 D[r*, c*, b] 移到常数项
      SampleExtract: 提取常数项 → LWE 密文 ct_{a,b} 加密 D[r*, c*, b]
  三次 BFF 路径相加: ct_{pay,b} = ct_{0,b} + ct_{1,b} + ct_{2,b}
  → B_pay 个 LWE 密文，每个加密一个字段（包括每个 Bloom 位）

Pack 阶段：
  Pack({ct_{pay,b}}) → RLWE 密文
  → Bloom 位 b_j[i] 进入 RLWE 多项式的某个系数/槽位

CAPE 过滤阶段：
  CtCtMul(q^BF, ct_j^BF) → 逐槽位乘法
  CtRotate + CtCtAdd → 槽位求和 → 内积 s_j
```

---

## 5. 总结

| 你的疑问                          | 答案                                                         |
| --------------------------------- | ------------------------------------------------------------ |
| Bloom 过滤器在 R×C 矩阵中怎么存？ | 每个 Bloom 位作为 payload 的一个独立字段，存储在多项式 \(P_{c,b}(X)\) 的系数上。整个 Bloom 过滤器占据多个多项式（每个位一个多项式）。 |
| 是把每个 Bloom 过滤器切开存吗？   | 是的。每位一个字段，每位一个多项式，每位一个系数。           |
| SampleExtract 提取的是什么？      | 提取目标行、目标列、目标字段的**单个标量**（一个 Bloom 位）的 LWE 密文。 |
| 槽位在哪个环节出现？              | 在 `Pack` 阶段。`Pack` 把 \(B_{\text{pay}}\) 个 LWE 密文（每个加密一个字段）打包成 RLWE 密文，每个字段占据一个槽位/系数。 |
| 为什么要这样设计？                | 为了保留 Bloom 过滤器的逐位代数结构，使服务器能用 `CtCtMul` + `CtRotate` 计算内积分数 \(s_j\)。 |

**一句话总结**：
在初始 R×C 矩阵中，Bloom 过滤器以「多项式系数」形式存储，每位一个系数；SampleExtract 每次只提取一个字段（一个 Bloom 位）的 LWE 密文；`Pack` 再把这些 LWE 密文合并成 RLWE 密文，每位进入一个槽位。整个过程中，Bloom 过滤器始终是**切开存储**的，从未作为整体塞进一个格子。