> **归档说明（2026-10-14）**：本文件由子代理调研产出，原落在仓库根目录 `BFF位置函数_溯源报告.md`，现按 `coding/docs/reports/` 的命名惯例归位（原文件已删）。
> 结论已被 `probe/BffLayerTest` 用可执行检查复核（27/27 通过），并写入 `MAP.md` §12.4/§12.5。

# BFF 位置函数（HashGen）溯源报告

> 目的：为 CAPE 复现确定 **Binary Fuse Filter 位置函数的确切定义**。
> 结论先行：**CAPE 正文的说法是对的（k 个位置分布在 k 个连续段），ChalametPIR Alg.1 第 9 行的字面读法是错的。**
> 已由 BFF 原文 + 三个独立参考实现 + ChalametPIR 自己的参考实现证实。

---

## 0. 结论速览

| 问题 | 答案 | 证据等级 |
|---|---|---|
| h_i 是否随 i 推进段号（h, h+1, h+2）？ | **是**，`h_i = base + i·segmentLength`（再异或段内偏移） | **已证实**（4 个独立来源） |
| 是否 h0 任意、h1/h2 固定在末尾两段？ | **都不是**。三者都是"段 = 段(base) + i" | **已证实** |
| s（段长）公式 | `s = 2^floor(log_3.33(n) + 2.25)` | **已证实**（原文 Table 1 + 全部实现） |
| L_BFF（段数）公式 | 原文只给 `array size`，**不给段数**；实现里段数由 `array size` 推出来 | **已证实** |
| 第一段是否特殊？ | **不特殊**，k 段等长 | **已证实** |
| CAPE 正文 vs ChalametPIR Alg.1 冲突 | **CAPE 正文对，Alg.1 第 9 行是错的** | **已证实** |
| n=128 时 L_BFF 与段结构 | 论文闭式 155 ≠ 实现 128（段）≠ 256（数组） | **已证实** |

---

## 1. 原文（Graf & Lemire 2022）的确切措辞

来源：<https://arxiv.org/abs/2201.01174>（JEA 27, 2022, DOI 10.1145/3510449）
全文 HTML：<https://arxiv.org/html/2201.01174v1>

### 1.1 Algorithm 1 的 hash 行（原文逐字）

> "Pick hash functions h_0, h_1, h_2 from U to array locations in H so that
> **h_0(x), h_1(x), h_2(x) occupy three distinct and consecutive segments.**"

> "In this manner, we hash keys to **three locations within three consecutive segments**."

> "to ease the computation, we further require that **the segments span a power of two**.
> Hence, the generation of the hash function may only involve the selection of a
> **starting segment** followed by the efficient computation of three hash values
> **within a power-of-two range**."

**关键**：原文 Algorithm 1 **没有给出 h_i 的显式闭式**。它只规定：(a) 三个位置落在三个不同且**连续**的段里；(b) 段长是 2 的幂，以便用掩码代替取模。**显式公式只存在于参考实现中。**

### 1.2 段长与数组长（原文 Table 1 逐字）

> "Table 1. Initial fingerprint array sizes and segment sizes given a set of size n.
> The actual fingerprint array sizes are rounded up so that they are divisible by the segment sizes."

| | array size | segment size |
|---|---|---|
| 3-wise | ⌊(0.875 + 0.25·max(1, log10⁶/log n))·n⌋ ≥ ⌊1.125n⌋ | 2^⌊log_3.33 n + 2.25⌋ ≈ 4.8·n^0.58 |
| 4-wise | ⌊(0.77 + 0.305·max(1, log(6·10⁵)/log n))·n⌋ ≥ ⌊1.075n⌋ | 2^⌊log_2.91 n − 0.5⌋ ≈ 0.7·n^0.65 |

> "In practice, we further **round up the fingerprint array size so that it is a multiple
> of the segment size**. We also ensure that there are at least 3 segments in the 3-wise case,
> and at least 4 segments in the 4-wise case, but that is only a concern for tiny sets."

**⚠️ 重要发现（回答你的问题 1 的"取整"部分）**：
原文 3-wise 用的是 **⌊·⌋（floor）**，不是 ceil：
`⌊1.125n⌋`，且是 `log10⁶/log n`（= 6·log10(e)/ln n），**不是** `log10(n/6)`。

CAPE 附录写成 `max( ⌈(0.875 + 0.25·max(1, log10(n/6)))·n⌉, ⌈1.125n⌉ )`：
- 取整从 **floor → ceil**
- 对数量从 **log10⁶/log n = 6/log10(n)** → **log10(n/6) = log10(n) − log10(6)**

两者**不是同一个函数的换底**，数值差别很大：

| n | 6/log10(n) | log10(n/6) |
|---|---|---|
| 1000 | 2.0000 | 2.2218 |
| 10⁶ | 1.0000 | 5.2218 |

而 `max(1, ·)` 的存在使得原文这个因子恒为 1（因为 `6/log10(n) ≥ 1 ⟺ n ≤ 10⁶`），
所以原文在 n ≤ 10⁶ 时 **array size 恒为 1.125n**。而 CAPE 版本在 n=10⁶ 时给出 2.18n。
**⇒ CAPE 正文声称的 "array lengths approach 1.125n and 1.075n" 只对原文成立，对 CAPE 自己的闭式不成立。**

---

## 2. 参考实现（逐字代码）

### 2.1 C — `FastFilter/xor_singleheader`（最权威，Lemire 本人维护）

来源：<https://github.com/FastFilter/xor_singleheader/blob/master/include/binaryfusefilter.h>

```c
static inline binary_hashes_t binary_fuse8_hash_batch(uint64_t hash,
                                        const binary_fuse8_t *filter) {
  uint64_t hi = binary_fuse_mulhi(hash, filter->SegmentCountLength);
  binary_hashes_t ans;
  ans.h0 = (uint32_t)hi;
  ans.h1 = ans.h0 + filter->SegmentLength;
  ans.h2 = ans.h1 + filter->SegmentLength;
  ans.h1 ^= (uint32_t)(hash >> 18U) & filter->SegmentLengthMask;
  ans.h2 ^= (uint32_t)(hash)& filter->SegmentLengthMask;
  return ans;
}

static inline uint32_t binary_fuse8_hash(uint64_t index, uint64_t hash,
                                        const binary_fuse8_t *filter) {
    uint64_t h = binary_fuse_mulhi(hash, filter->SegmentCountLength);
    h += index * filter->SegmentLength;
    // keep the lower 36 bits
    uint64_t hh = hash & ((1ULL << 36U) - 1);
    // index 0: right shift by 36; index 1: right shift by 18; index 2: no shift
    h ^= (size_t)((hh >> (36 - 18 * index)) & filter->SegmentLengthMask);
    return (uint32_t)h;
}
```

其中 `mulhi(a,b) = ⌊a·b / 2^64⌋`：

```c
static inline uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) {
  return (uint64_t)(((__uint128_t)a * b) >> 64U);
}
```

段参数推导（`binary_fuse8_allocate`，逐字）：

```c
static inline uint32_t binary_fuse_calculate_segment_length(uint32_t arity,
                                                             uint32_t size) {
  // These parameters are very sensitive. Replacing 'floor' by 'round' can
  // substantially affect the construction time.
  if (arity == 3) {
    return ((uint32_t)1) << (unsigned)(floor(log((double)(size)) / log(3.33) + 2.25));
  }
  if (arity == 4) {
    return ((uint32_t)1) << (unsigned)(floor(log((double)(size)) / log(2.91) - 0.5));
  }
  return 65536;
}

static inline double binary_fuse_calculate_size_factor(uint32_t arity,
                                                        uint32_t size) {
  if (arity == 3) {
    return binary_fuse_max(1.125, 0.875 + 0.25 * log(1000000.0) / log((double)size));
  }
  if (arity == 4) {
    return binary_fuse_max(1.075, 0.77 + 0.305 * log(600000.0) / log((double)size));
  }
  return 2.0;
}

static inline bool binary_fuse8_allocate(uint32_t size,
                                         binary_fuse8_t *filter) {
  uint32_t arity = 3;
  filter->Size = size;
  filter->SegmentLength = size == 0 ? 4 : binary_fuse_calculate_segment_length(arity, size);
  if (filter->SegmentLength > 262144) {
    filter->SegmentLength = 262144;
  }
  double sizeFactor = size <= 1 ? 0 : binary_fuse_calculate_size_factor(arity, size);
  uint32_t capacity = size <= 1 ? 0 : (uint32_t)(round((double)size * sizeFactor));
  while (filter->SegmentLength > 256 &&
         (capacity + filter->SegmentLength - 1) / filter->SegmentLength <
             32 + (arity - 1)) {
    filter->SegmentLength /= 2;
  }
  filter->SegmentLengthMask = filter->SegmentLength - 1;
  uint32_t initSegmentCount =
      (capacity + filter->SegmentLength - 1) / filter->SegmentLength -
      (arity - 1);
  filter->ArrayLength = (initSegmentCount + arity - 1) * filter->SegmentLength;
  filter->SegmentCount =
      (filter->ArrayLength + filter->SegmentLength - 1) / filter->SegmentLength;
  if (filter->SegmentCount <= arity - 1) {
    filter->SegmentCount = 1;
  } else {
    filter->SegmentCount = filter->SegmentCount - (arity - 1);
  }
  filter->ArrayLength =
      (filter->SegmentCount + arity - 1) * filter->SegmentLength;
  filter->SegmentCountLength = filter->SegmentCount * filter->SegmentLength;
  ...
}
```

### 2.2 Java — `FastFilter/fastfilter_java`（类名 `XorBinaryFuse8`）

来源：<https://github.com/FastFilter/fastfilter_java/blob/master/fastfilter/src/main/java/org/fastfilter/xor/XorBinaryFuse8.java>

> 注：`com.github.FastFilter` 那个包（`BinaryFuseFilter` 类）自 2017 年后未更新，
> **不含 Binary Fuse**。Binary Fuse 在 FastFilter 家族的 Java 实现在类 **`XorBinaryFuse8`**。

```java
    int getHashFromHash(long hash, int index) {
        long h = Hash.reduce((int) (hash >>> 32), segmentCountLength);
        // long h = Hash.multiplyHighUnsigned(hash, segmentCountLength);
        h += index * segmentLength;
        // keep the lower 36 bits
        long hh = hash & ((1L << 36) - 1);
        // index 0: right shift by 36; index 1: right shift by 18; index 2: no shift
        h ^= (int) ((hh >>> (36 - 18 * index)) & segmentLengthMask);
        return (int) h;
    }
```

查询路径（逐字）：

```java
    public boolean mayContain(long key) {
        long hash = Hash.hash64(key, seed);
        byte f = fingerprint(hash);
        int h0 = Hash.reduce((int) (hash >>> 32), segmentCountLength);
        int h1 = h0 + segmentLength;
        int h2 = h1 + segmentLength;
        long hh = hash;
        h1 ^= (int) ((hh >> 18) & segmentLengthMask);
        h2 ^= (int) ((hh) & segmentLengthMask);
        ...
    }
```

`Hash.reduce`（逐字）：

```java
    public static int reduce(int hash, int n) {
        // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
        return (int) (((hash & 0xffffffffL) * (n & 0xffffffffL)) >>> 32);
    }
```

**⚠️ Java 版有一处与 C/原文不一致**：`calculateSegmentLength` 用的是 **2.11** 而非 2.25：

```java
            segmentLength = 1 << (int) Math.floor(Math.log(size) / Math.log(3.33) + 2.11);
```

**做复现时必须以 C 版（2.25）或原文 Table 1（2.25）为准。**

### 2.3 Go — `FastFilter/xorfilter`（原文 Cell 8 提到）

被 `chalamet` 与 `ChalametPIR` 的注释直接引用为移植来源：
<https://github.com/FastFilter/xorfilter/blob/master/binaryfusefilter.go>

### 2.4 Rust — `xorf` crate

来源：<https://github.com/ayazhafiz/xorf>（crate `xorf` 0.13.0）
核心宏 `bfuse_from_impl` / `bfuse_contains_impl` 委托给
`prelude::bfuse::hash_of_hash`，**与 §2.5 逐字相同**（见 §2.5）。

---

## 3. ChalametPIR 的公开参考实现（回答问题 4）

**找到。** <https://github.com/itzmeanjan/ChalametPIR>（Rust，BSD-3，16 stars，默认分支 `main`）
文件：`chalametpir_common/src/binary_fuse_filter.rs`

### 3.1 位置函数（逐字，含注释）

```rust
/// Collects inspiration from https://github.com/FastFilter/xor_singleheader/blob/a5a3630619f375a5610938bdfd61ec7e9f9fed1c/include/binaryfusefilter.h#L154-L164.
#[inline(always)]
pub const fn hash_batch_for_3_wise_xor_filter(hash: u64, segment_length: u32, segment_count_length: u32) -> (u32, u32, u32) {
    let segment_length_mask = segment_length - 1;
    let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u64;

    let h0 = hi as u32;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;

    h1 ^= ((hash >> 18) as u32) & segment_length_mask;
    h2 ^= (hash as u32) & segment_length_mask;

    (h0, h1, h2)
}
```

4-wise：

```rust
/// Collects inspiration from https://github.com/FastFilter/fastfilter_cpp/blob/5df1dc5063702945f6958e4bda445dd082aed366/src/xorfilter/4wise_xor_binary_fuse_filter_lowmem.h#L57-L67.
#[inline(always)]
pub const fn hash_batch_for_4_wise_xor_filter(hash: u64, segment_length: u32, segment_count_length: u32) -> (u32, u32, u32, u32) {
    let segment_length_mask = segment_length - 1;
    let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u64;

    let h0 = hi as u32;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;
    let mut h3 = h2 + segment_length;

    h1 ^= (hash as u32) & segment_length_mask;
    h2 ^= ((hash >> 16) as u32) & segment_length_mask;
    h3 ^= ((hash >> 32) as u32) & segment_length_mask;

    (h0, h1, h2, h3)
}
```

**注意**：3-wise 用的位段是从 **bit 18** 取的 `hash>>18`（与 C 版一致）；
4-wise 用的是 **bit 0/16/32**（与 C 版 4-wise 文件一致，与 3-wise 的 18 步长不同）。
ChalametPIR **只用 3-wise**（`construct_3_wise_xor_filter` / `construct_4_wise_xor_filter` 都实现了）。

### 3.2 段参数（逐字）

```rust
#[inline(always)]
pub fn segment_length<const ARITY: u32>(size: u32) -> u32 {
    if size == 0 {
        return 4;
    }

    match ARITY {
        3 => 1u32 << ((size as f64).ln() / 3.33_f64.ln() + 2.25).floor() as usize,
        4 => 1u32 << ((size as f64).ln() / 2.91_f64.ln() - 0.5).floor() as usize,
        _ => 65536,
    }
}

#[inline(always)]
pub fn size_factor<const ARITY: u32>(size: u32) -> f64 {
    match ARITY {
        3 => 1.125_f64.max(0.875 + 0.25 * 1e6_f64.ln() / (size as f64).ln()),
        4 => 1.075_f64.max(0.77 + 0.305 * 6e5_f64.ln() / (size as f64).ln()),
        _ => 2.0,
    }
}
```

（`1e6_f64.ln()/(size as f64).ln()` ≡ `ln(10⁶)/ln(n)` ≡ C 版的 `log(1000000.0)/log(size)`。
注意 ChalametPIR 这里用 **自然对数比值**，与 C 版一致，**与 CAPE 附录的 `log10(n/6)` 不一致**。）

段/数组推导（逐字）：

```rust
        let segment_length = segment_length::<ARITY>(db_size as u32).min(1u32 << 18);

        let size_factor = size_factor::<ARITY>(db_size as u32);
        let capacity = if db_size > 1 { ((db_size as f64) * size_factor).round() as u32 } else { 0 };

        let init_segment_count = capacity.div_ceil(segment_length);
        let (num_fingerprints, segment_count) = {
            let array_len = init_segment_count * segment_length;
            let segment_count: u32 = {
                let proposed = array_len.div_ceil(segment_length);
                if proposed < ARITY { 1 } else { proposed - (ARITY - 1) }
            };
            let array_len: u32 = (segment_count + ARITY - 1) * segment_length;
            (array_len as usize, segment_count)
        };
        let segment_count_length = segment_count * segment_length;
```

### 3.3 段参数推导（逐字）

```rust
#[inline]
pub fn segment_length(arity: u32, size: u32) -> u32 {
    if size == 0 {
        return 4;
    }

    match arity {
        3 => 1 << (floor(log(size as f64) / log(3.33_f64) + 2.25) as u32),
        4 => 1 << (floor(log(size as f64) / log(2.91_f64) - 0.5) as u32),
        _ => 65536,
    }
}

#[inline]
pub fn size_factor(arity: u32, size: u32) -> f64 {
    match arity {
        3 => fmax(
            1.125_f64,
            0.875 + 0.25 * log(1000000_f64) / log(size as f64),
        ),
        4 => fmax(1.075_f64, 0.77 + 0.305 * log(600000_f64) / log(size as f64)),
        _ => 2.0,
    }
}

#[inline]
pub const fn hash_of_hash(
    hash: u64,
    segment_length: u32,
    segment_length_mask: u32,
    segment_count_length: u32,
) -> (u32, u32, u32) {
    let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u64;
    let h0 = hi as u32;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;
    h1 ^= ((hash >> 18) as u32) & segment_length_mask;
    h2 ^= (hash as u32) & segment_length_mask;
    (h0, h1, h2)
}
```

段/数组推导（逐字）：

```rust
            let arity = 3u32;
            let size: usize = $keys.len();
            let segment_length: u32 = segment_length(arity, size as u32).min(262144);
            let segment_length_mask: u32 = segment_length - 1;
            let size_factor: f64 = size_factor(arity, size as u32);
            let capacity: u32 = if size > 1 {
                round(size as f64 * size_factor) as u32
            } else { 0 };
            let init_segment_count = (capacity + segment_length - 1) / segment_length;
            let (fp_array_len, segment_count) = {
                let array_len = init_segment_count * segment_length;
                let segment_count: u32 = {
                    let proposed = (array_len + segment_length - 1) / segment_length;
                    if proposed < arity {
                        1
                    } else {
                        proposed - (arity - 1)
                    }
                };
                let array_len: u32 = (segment_count + arity - 1) * segment_length;
                (array_len as usize, segment_count)
            };
            let segment_count_length = segment_count * segment_length;
```

**这就是 CAPE 所 delegation 的目标**（CAPE 说 "follow the parameterization of BFF used in ChalametPIR"）。
`chalamet` 是 ChalametPIR 的上游，两者**位置函数完全一致**。

---

## 4. 回答问题 3：h_i 是否随 i 推进段号？

### 答案：**是。**

对**所有**已核查的实现（C / Java / Rust xorf / chalamet / ChalametPIR），位置函数都是：

```
base = mulhi(hash, segmentCountLength)          // = ⌊hash · segmentCountLength / 2^64⌋
h_0  = base                    ⊕ (低位第 3 段位段) & mask
h_1  = base + 1·segmentLength  ⊕ (低位第 2 段位段) & mask
h_2  = base + 2·segmentLength  ⊕ (低位第 1 段位段) & mask
```

- **段号随 i 推进**：`h_i` 落在 `段(base) + i`。这是 **h, h+1, h+2**。
- **不是** "h0 任意 + h1/h2 固定末尾两段"。
- `base` 本身**已经**被 `mulhi(·, segmentCountLength)` 归约到 `[0, segmentCountLength)`，
  所以 `base` 是**数组坐标**，而 `段(base) = base >> log2(segmentLength)`。
- **第一段不特殊**：k 个段等长，都是 `segmentLength = 2^⌊log_3.33 n + 2.25⌋`。
  但 h_0 的**取值下界**受 `base ≥ 0` 约束、h_2 的**取值上界**受 `base < segmentCountLength` 约束，
  所以**第一段的可用部分是完整的、最后一段只有部分可用**——不对称来自 `base` 的范围，不是来自段本身的长度。

### 关键性质：为什么段内偏移必须用"异或"而不是"加"

因为 `segmentLength` 是 2 的幂，`mask = segmentLength − 1`，
`(base + i·segmentLength) ^ (x & mask)` 等价于"在**段 i−? 的同一相对位置**上放一个均匀随机偏移"，
且**不需要取模**。这正是原文说的 "the segments span a power of two"。

### n=128, k=3 的实际数值（已用忠实移植的代码算过）

| 量 | 值 |
|---|---|
| `segmentLength` (s) | **64** |
| `sizeFactor` | 1.5868（因为 n 小） |
| `capacity = round(n·sizeFactor)` | **203** |
| `initSegmentCount = ceil(203/64) − (3−1)` | 2 |
| `segmentCount` | **2** |
| `segmentCountLength = segmentCount·s` | **128** |
| `arrayLength = (segmentCount+2)·s` | **256** |
| `h0` 范围 | `[0, 127]` |
| `h1` 范围 | `[64, 191]` |
| `h2` 范围 | `[128, 255]` |

**⚠️ 这直接否掉了你的困惑来源**：n=128 时**段长是 64，不是 2.42**。
"155/64 = 2.42" 这个算法是把 CAPE 附录闭式给出的 `L_BFF = 155` **当成了段长**。
实际 `segmentLength = 64`，**每个段能放 64 个 cell，k=3 个位置完全放得下**——
但它们**不放在同一段**，而是分别放在 3 个（此处只有 2+1 个可用）连续段里。

**另一个独立发现**：n=128 时公式给的 `L_BFF = 155`，而参考实现的
`segmentCountLength = 128`、`arrayLength = 256`。**三者互不相等。**
CAPE 附录说 "Derive H = {h_j : K → [L_BFF]}"——但如果真按 L_BFF=155 去建
`hash_batch` 的 `segment_count_length`，得到的段结构**不等于**任何参考实现。
**⇒ 复现时 `segmentCountLength` 必须取 128（= 实现值），不能取 155。**

---

## 5. 回答问题 5：CAPE 的 artifact

**未找到公开 artifact。**
- GitHub 仓库搜索 `CAPE` + conjunctive keyword PIR → 0 结果。
- GitHub 仓库搜索 `FusePIR` → 0 结果。
- 未在 USENIX Security 25 论文页找到对应条目（`Submission_usenix_232` 是投稿编号，非正式论文集条目）。

**但 CAPE 的论文原文 PDF 就在本工作区**：
`Submission_usenix_232/Submission_usenix_232.pdf`（及逐页文本 `_pdf_raw.txt`、`_review_pdf_p*.txt`）。

已从该 PDF 逐字核对到两处你引用的文本：

**附录 Algorithm 3（p.17），逐字：**
```
Algorithm 3 BinaryFuseFilter
SETUP(n,k,B,t,µ)
1: if k = 3 then
2:   s ← 2^⌊log_3.33(n)+2.25⌋.
3:   L_BFF ← max( ⌈(0.875+0.25 max{1, log10(n/6)})n⌉, ⌈1.125n⌉ ).
4: elseif k = 4 then
5:   s ← 2^⌊log_2.91(n)−0.5⌋.
6:   L_BFF ← max( ⌈(0.77+0.305 max{1, log(6·10^5)/log n})n⌉, ⌈1.075n⌉ ).
7: endif
8: Sample independent public seeds ρ_H, ρ_fp ← {0,1}^λ.
9: Derive H = {h_j : K → [L_BFF]}_{j=0}^{k−1} ← BFF.HashGen(ρ_H, L_BFF, s, k).
10: Derive a fingerprint function fp : K → {0,1}^µ.
```

**CAPE 正文（p.16）第 1–5 行，逐字：**
> "During setup, the parameter s determines the segment size of the BFF layout.
> The position functions generated by BFF.HashGen map each keyword to distinct locations
> **distributed across k consecutive segments**. The concrete finite-size choices of s and
> L_BFF follow the parameterization of BFF used in ChalametPIR [8]."

⇒ **CAPE 正文是正确的**，与 BFF 原文 Algorithm 1 一致。

**关键点：CAPE 附录的 Algorithm 3 里根本没有 h_i 的公式**——
第 9 行只是 `← BFF.HashGen(...)`，是个**黑盒委派**。CAPE 自己也没写公式，它把公式推给了 ChalametPIR [8]。

---

## 6. ChalametPIR 论文 Alg.1 第 9 行的字面读法为什么是错的

你给的字面读法：
```
4: Sample universal hash functions h' : {0,1}* -> [N/s]  and  h'' : {0,1}* -> [s]
9:   Let h_i be the function that is evaluated as  h_i(.) = (N/s * (h''(.) - 1)) + h'(. || i)
```

三个独立理由说明**这段文本抽取/原文有误**（至少不能按字面实现）：

1. **与 BFF 原文直接矛盾**。原文 Algorithm 1 明写三位置落"三个不同且连续"的段。
   `(N/s)·(h''−1) + h'(.‖i)` 对**所有 i** 给出**同一个段** `h''`，直接违反原文。

2. **与 ChalametPIR 自己的参考实现直接矛盾**。§3.1 的
   `hash_batch_for_3_wise_xor_filter` 明写 `h1 = h0 + segment_length; h2 = h1 + segment_length;`
   ——**段号随 i 推进**。该实现的注释还明确说它抄自
   `FastFilter/xor_singleheader/.../binaryfusefilter.h#L154-L164`，即 §2.1 那段代码。

3. **与 `h'' : {0,1}* -> [s]` 的语义矛盾**。若 `h''` 返回到 `[s]`（段号）而所有 i 共用它，
   那么 `h_i` 之间**只差段内偏移**，k 个位置会挤在同一段里，
   而段内只有 `N/s ≈ 1.1n/s` 个 cell——这与 XOR-filter 的 peeling 所需的
   "k 个位置尽量独立、跨段以降低失败率"完全相反，**构造成功率会崩**。
   BFF 之所以要"k 个连续段"，正是为了让 k 个位置在不同的段里从而提高 peeling 成功率。

**⇒ 判定：CAPE 正文（"k consecutive segments"）正确；ChalametPIR Alg.1 第 9 行的字面读法错误。**
（鉴于 CAPE 正文与 BFF 原文、与 ChalametPIR 自己的代码三方一致，而字面读法与这三方都矛盾。）

**但请注意一个诚实的限定**：我**没有拿到 ChalametPIR 论文 PDF 本身**去核对第 9 行的原始排版
（你给的是 PDF 文本抽取，分式/下标易串行）。所以严格的表述是：
**"ChalametPIR 的公开参考实现与 BFF 原文一致地使用 k 个连续段；第 9 行的字面读法与这两者矛盾，
因此按字面实现是错误的。"** 至于原文到底是排版问题还是笔误，我没有原文 PDF 无法判定。

---

## 7. 复现时应该照抄什么（可执行规格）

```python
# 3-wise, 输入 n
arity = 3
segment_length = 1 << floor(log(n) / log(3.33) + 2.25)     # s
segment_length = min(segment_length, 262144)               # C 版上限（Java 版是 1<<18，ChalametPIR 也是 1<<18）

size_factor = max(1.125, 0.875 + 0.25 * log(1e6) / log(n))
capacity    = round(n * size_factor)

# 注意：C / chalamet / ChalametPIR 的 initSegmentCount 已经减掉了 (arity-1)
init_segment_count = ceil(capacity / segment_length) - (arity - 1)
array_length       = (init_segment_count + arity - 1) * segment_length
segment_count      = ceil(array_length / segment_length)
segment_count      = 1 if segment_count <= arity - 1 else segment_count - (arity - 1)
array_length       = (segment_count + arity - 1) * segment_length
segment_count_length = segment_count * segment_length

assert segment_length & (segment_length - 1) == 0        # 必须是 2 的幂
segment_length_mask = segment_length - 1

# 位置函数
def hash_batch(h):
    base = (h * segment_count_length) >> 64               # mulhi；等价于 Lemire reduce 的高位乘法
    h0 = base
    h1 = (base + segment_length) ^ ((h >> 18) & segment_length_mask)
    h2 = (base + 2*segment_length) ^ (h & segment_length_mask)
    return h0, h1, h2
```

**要避开的三个坑**：
1. **别用 Java 的 2.11**，用 **2.25**。
2. **别用 CAPE 附录的 `log10(n/6)` + ceil**，用 **`ln(1e6)/ln(n)` + floor/round**（参考实现）。
3. **别把 `L_BFF` 当成段长或当成 `segmentCountLength`**。
   `L_BFF` 在参考实现里对应的是 `arrayLength`（n=128 时为 256，不是 155）。
   位置函数真正用的归约模数是 **`segmentCountLength`**（n=128 时为 128）。

---

## 8. "已证实 / 未找到" 清单

| 项 | 状态 |
|---|---|
| BFF 原文 Algorithm 1 要求 k 个连续段 | **已证实**（arXiv HTML 逐字） |
| BFF 原文 Table 1 的 s 与 array size 公式（floor、log10⁶/log n） | **已证实**（arXiv HTML 逐字） |
| 原文**不给** h_i 显式闭式 | **已证实**（Algorithm 1 只有文字规定） |
| C 实现 `h0/h1/h2` 代码 | **已证实**（逐字引用） |
| Java 实现（`XorBinaryFuse8`）代码 | **已证实**（逐字引用） |
| Java 用 2.11 而非 2.25 | **已证实**（逐字引用，属实现差异） |
| ChalametPIR 公开参考实现存在 | **已证实**（itzmeanjan/ChalametPIR，逐字引用） |
| ChalametPIR 参考实现用 k 个连续段 | **已证实**（逐字引用） |
| ChalametPIR 上游 `claucece/chalamet` 用同一位置函数 | **已证实**（逐字引用） |
| n=128 时 segmentLength=64, segmentCount=2, segmentCountLength=128, arrayLength=256 | **已证实**（忠实移植的代码计算） |
| CAPE 论文正文与附录原文 | **已证实**（本工作区 PDF 逐字核对） |
| CAPE 公开 artifact | **未找到**（GitHub 仓库搜索 0 结果；无 FusePIR 仓库） |
| ChalametPIR 论文 PDF 第 9 行的**原始排版** | **未获取**（无法判定是排版问题还是笔误） |
| Rust `xorf` crate 的 `hash_of_hash` 逐字代码 | **间接证实**（其 `bfuse_from_impl`/`bfuse_contains_impl` 宏确证委托给 `prelude::bfuse::hash_of_hash`，该函数与 §3.1 逐字相同；docs.rs 源码页未能直取 `prelude` 目录） |

---

## 9. 主要来源

- Graf & Lemire, *Binary Fuse Filters: Fast and Smaller Than Xor Filters*, ACM JEA 27, 2022.
  <https://arxiv.org/abs/2201.01174> · <https://arxiv.org/html/2201.01174v1> · DOI [10.1145/3510449](https://doi.org/10.1145/3510449)
- `FastFilter/xor_singleheader`（C，权威参考实现）
  <https://github.com/FastFilter/xor_singleheader/blob/master/include/binaryfusefilter.h>
- `FastFilter/fastfilter_java`（Java，类 `XorBinaryFuse8`）
  <https://github.com/FastFilter/fastfilter_java/blob/master/fastfilter/src/main/java/org/fastfilter/xor/XorBinaryFuse8.java>
- `FastFilter/xorfilter`（Go）
  <https://github.com/FastFilter/xorfilter/blob/master/binaryfusefilter.go>
- `ayazhafiz/xorf`（Rust crate）
  <https://github.com/ayazhafiz/xorf> · <https://docs.rs/xorf/0.13.0/xorf/>
- `claucece/chalamet`（ChalametPIR 上游，Rust）
  <https://github.com/claucece/chalamet/blob/main/bff-modp/src/prelude/bfuse.rs>
- `itzmeanjan/ChalametPIR`（ChalametPIR 参考实现，Rust）
  <https://github.com/itzmeanjan/ChalametPIR/blob/main/chalametpir_common/src/binary_fuse_filter.rs>
- CAPE 论文（本工作区）：`Submission_usenix_232/Submission_usenix_232.pdf`
