# param-probe —— 参数探测工具

> 用途：把 CAPE 论文设定下的**真实模数规模**算出来，并检查这些参数在纯 Java 同态库上**能不能跑得起来**。
> 背景：论文只写了"t = 65537、N = 16384、用 SEAL 默认配置达到 128 位安全"，没有给出系数模数 q 到底多大。

---

## 怎么运行

```powershell
# MPC4J + SEAL 现在随仓库提供，就在 coding\lib 里，不再依赖 cape_test
$jdk = 'D:\Java\jdk\bin'
$lib = (Resolve-Path '..\lib').Path
$cp  = (Join-Path $lib 'mpc4j-crypto-fhe-seal.jar') + ';' +
       ((Get-ChildItem (Join-Path $lib 'deps') -Filter *.jar | ForEach-Object { $_.FullName }) -join ';')

$src = Get-ChildItem -Path .\src -Recurse -Filter *.java | ForEach-Object { $_.FullName }
& "$jdk\javac.exe" -encoding UTF-8 -cp $cp -d out $src
& "$jdk\java.exe" -Xmx8g -cp "out;$cp" com.fusepir.probe.ParamProbe
```

必须加 `-Xmx8g`（或更大），否则大 N 的实验会因为堆不够而提前失败。

---

## 实测输出（2026-09-16，JDK 25）

```
CAPE parameters in the paper's setting (SEAL default config / 128-bit security)
plaintext modulus t = 65537

--- N = 8192 ---
  prime count        = 5
  prime bit sizes    = [43 43 44 44 44]
  total modulus bits = 218
  max bits @128-bit  = 218
  q bit length       = 218
  delta = q/t        ~ 202 bit
  noise limit q/(2t) ~ 201 bit
  context check      = OK (key switching: true)

--- N = 16384 ---
  prime count        = 9
  prime bit sizes    = [48 48 48 49 49 49 49 49 49]
  total modulus bits = 438
  q bit length       = 438
  delta = q/t        ~ 422 bit
  noise limit q/(2t) ~ 421 bit
  context check      = OUT OF MEMORY

--- N = 32768 ---
  prime count        = 16
  total modulus bits = 881
  context check      = OUT OF MEMORY
```

## 关键发现一：论文设定下的 q 是 438 位

| N | 素数个数 | q 位宽 | Δ = q/t | 解密噪声上限 q/(2t) |
|---|---|---|---|---|
| 8192 | 5 | 218 | 约 202 位 | 约 201 位 |
| **16384（论文）** | **9** | **438** | **约 422 位** | **约 421 位** |
| 32768 | 16 | 881 | 约 865 位 | 约 864 位 |

**意义**：实验层用单素数 31 位 q 时，噪声上限只有 14 位（16383），所以才会出现"外部乘积一次就吃掉 1/13 余量"的紧张局面。
**那是我为了跑得快而选的玩具参数造成的，不是系统本身的性质。** 论文设定下噪声上限有 421 位，量级完全不同。

## 关键发现二：N=16384 + 默认模数，在纯 Java 库里**建不起上下文**

```
=== Galois tool memory test (N = 16384) ===
  one tool = 1073741824 bytes (1.00 GB), so level count dominates

  primes=2  (total 96   bit) -> OK                1.4 s
  primes=4  (total 192  bit) -> OK                2.6 s
  primes=9  (total 432  bit) -> OUT OF MEMORY     7.0 s
```

**根因**（已定位到源码行）：Java 同态库在建立上下文时，**每一层模数都会建一个 Galois 工具**，
而该工具内部一次性分配了 `N × N` 个整数（`AbstractGaloisTool` 第 64 行：
`permutationTables = new int[coeffCount][coeffCount]`）。

- N=16384 时单个工具就是 16384² × 4 字节 = **1.00 GB**；
- 论文设定有 9 层模数 → 约 **9 GB**，8 GB 堆直接爆掉；
- 素数减到 4 个（192 位模数）就能建起来，耗时 2.6 秒。

**这意味着**：直接用论文参数（N=16384 + SEAL 默认 9 素数）在纯 Java 路线上跑不动，
要么加大堆内存（约 10 GB 以上），要么把这个分配改成"按需分配"。

> ⚠️ 改那一行要小心：`generateTableNtt` 里对空行是**直接 return** 的，
> 所以不能简单地把 `new int[N][N]` 改成 `new int[N][]`——那会**静默跳过**所有表的生成、结果全错。
> 正确做法是按实际用到的 Galois 元素预先分配对应的行。
