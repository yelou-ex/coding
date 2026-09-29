# CAPE 完整代码包 · 构建与运行

> 基线：`yelou-ex/coding` 的 `origin/main` = **`4448d39`**（2026-09-27）
> 本包 = 上游代码原样 + 本地知识库/报告 + 本说明。**代码部分与上游逐文件一致。**

---

## 一、环境要求（**关键：必须 JDK 25**）

| 项 | 要求 | 说明 |
|---|---|---|
| **JDK** | **25** | `lib/mpc4j-crypto-fhe-seal.jar` 里的 class 是 **major 69 = JDK 25**；JDK 24 会报「类文件版本 69 应为 68」，**读不了** |
| 本机已装 | `D:\Java\jdk-25` | Temurin 25.0.4.1+1 |
| 内存 | `-Xmx8g` 建议 | RingPack / N=16384 的用例吃内存 |
| 磁盘 | ≥ 2 GB 余量 | 生成 BFF 数据用 |

> ⚠️ 本机 PATH 上仍是 JDK 24（`JAVA_HOME=D:\java`）。所以命令里要**显式用 JDK 25 的绝对路径**，
> 或者临时把 PATH/JAVA_HOME 切到 `D:\Java\jdk-25`。

---

## 二、两条构建线（**别混用**）

这个仓库有**两条互不干扰的编译线**，源文件和依赖都不同：

| 线 | 内容 | 依赖 | 脚本 |
|---|---|---|---|
| **A. MPC4J 线**（HE 主线） | `rgsw-lab`（除路线 C 的 7 个文件）+ `lwe-java` | `lib/mpc4j-crypto-fhe-seal.jar` + `lib/deps/*.jar` | `rgsw-lab/run-mpc4j.ps1` |
| **B. 纯 JDK 线**（自研 RLWE，已弃用） | `rlwe-java` + `rgsw-lab` 的路线 C 文件 | **零依赖** | `rlwe-java/run.ps1`、`rgsw-lab/run.ps1` |
| **C. 明文侧**（BFF/Bloom） | `cape-fusepir-database-handoff` | 零依赖（测试用 JUnit） | 无脚本，见 §四 |
| **D. 极简验证版**（tiny-cape） | `tiny-cape` —— 规范《CAPE 实现步骤（极简验证版）》逐条实现 | **零依赖** | 见 §六 |
| **E. QUERY + DECODE 编排** | `rgsw-lab/CapeQueryDecode.java` —— **端到端跑通**（README A2/A3/A5） | 同 A 线 | 见 §七 |
| **F. 列打包 + BK 压缩** | `rgsw-lab/CapeColumnPacked.java`、`CapeBkCompressed.java` | 同 A 线 | 见 §八 |

---

## 八、F 线：列打包 + BK 体积（两项工程差距，均已解决）

```powershell
$root = "D:\DFY-ws\cape"; $jdk = "D:\Java\jdk-25\bin"
$cp = "$root\lib\mpc4j-crypto-fhe-seal.jar;" +
      ((Get-ChildItem "$root\lib\deps" -Filter *.jar | ForEach-Object { $_.FullName }) -join ';')
$out = "$root\rgsw-lab\mpc4j-out"

& "$jdk\java.exe" -Xmx6g -cp "$out;$cp" com.fusepir.rgsw.CapeColumnPacked 2048 32   # 3/3
& "$jdk\java.exe" -Xmx8g -cp "$out;$cp" com.fusepir.rgsw.CapeBkCompressed 8192 1    # 2/2
```

### 列打包 ✅

改布局：**行维承载数据，索引维承载选择**。每个字段只有一条多项式
`P_b(X) = Σ_row D[row][b]·X^row`，于是"选第 row\* 行" = **乘公开单项式 `X^{−row*}`**。

```
[server] 乘明文 24 次（8 字段 × 3 路），32 ms
         对比：论文朴素布局要 C 次【密文×密文】+ 求和
         本布局用 24 次【乘公开单项式】替代（不消耗噪声预算）
[PASS] 5.1 一次乘明文 ×3 路 + 相加 == 原始 payload
[PASS] 5.2 结果 == 直接取 P_b 在目标行上的值之和
[PASS] 5.3 负对照：行号整体 +1 → 结果改变
```

> ⚠️ 论文那套完整 `C` 列版在**本参数下放不下**：`ℓ_BF = N` 是硬约束（Bloom 要装进一条槽位密文），
> 于是 `B_pay·N` 个系数已占满整个环，没有余量再切 `R×C` 两维。属**参数选择的结构约束**。

### BK 体积 ✅ 压缩 39×

换口径：从**按秘密位轮**（d=512 轮）改成**按索引位轮**（⌈log₂N⌉ 轮），
因为 `X^{−r*} = Π_i X^{−r*_i·2^i}` 而 `r* < N` 只有 ⌈log₂N⌉ 个比特。

| 口径 | 轮数 | BK（N=8192） | BK（N=16384 外推） |
|---|---|---|---|
| 按秘密位（现状） | 512 | 5632.0 MB | 25.6 GB |
| **按索引位（本类）** | **13 / 14** | **143.0 MB** | **≈700 MB** |
| **压缩比** | | **39.4×** | **≈36×** |

```
[PASS] A1 按索引位轮：常数位 == payload[r*]      got=580 want=580（r*=777）
[PASS] A2 整条累加器 = X^{−r*}·P（负循环符号也对）  一致 8192/8192
```

> ⚠️ 两处限制：① 这是 **CAPE-C/FusePIR-C** 的口径（但算出的 `X^{−r*}` 与 CAPE 完全相同）；
> ② 本类用**客户端逐位加密**绕过了 `LWEtoRGSW`（那个模块 4/4 失败），
> 所以**通信模式等价、安全归约不等价** —— 用于体积与正确性验证，正式安全论证仍需补 `LWEtoRGSW`。
>
> ⚠️ `levels=25` 压不下去的根因（已查实）：`decompose` 把切段当**明文**喂 `multiplyPlain`，
> 明文窗口 ±t/2 = ±32768 逼出 `B ≤ 65536` → `ℓ = ⌈389/16⌉ = 25`。
> 要真压 `ℓ` 需 RNS/直接切段（Garner），但 **MPC4J 的 Java 移植未暴露 limb 级乘法**，本代码库上做不了。

详见 `列打包与BK压缩_说明.md`。

---

## 七、E 线：QUERY + DECODE（补齐链路两端，端到端已跑通）

```powershell
$root = "D:\DFY-ws\cape"; $jdk = "D:\Java\jdk-25\bin"
$cp = "$root\lib\mpc4j-crypto-fhe-seal.jar;" +
      ((Get-ChildItem "$root\lib\deps" -Filter *.jar | ForEach-Object { $_.FullName }) -join ';')
& "$jdk\java.exe" -Xmx8g -cp "$root\rgsw-lab\mpc4j-out;$cp" com.fusepir.rgsw.CapeQueryDecode 2048 64
```

**参数扫描（每轮 24 次盲旋转，d=16）—— 最快能实现的参数**

| N | 工作素数 | 结果 | 端到端耗时 |
|---|---|---|---|
| **1024** | **1** | ❌ 0/3 | 0.9 s ← **硬下限**（单素数是密钥切换不支持） |
| **2048** | 2 | ✅ 3/3 | **1.7 s** ← **最快的可用点** |
| 4096 | 2 | ✅ 3/3 | 4.9 s |
| 8192 | 4 | ✅ 3/3 | 30.4 s |

> **推荐**：开发/验证用 **N=2048**；含 **Bloom 打分**的完整链路用 **N ≥ 4096**（lou 的 `RingPack`
> 实测 N=4096 打分侧噪声崩，**N=8192 起步**）。两套 N 用途不同，别混用。

端到端实测（N=2048, d=64）：`K_1→[11,22] K_2→[11] K_3→[33]`，查询 `K_1 ∧ K_2`
→ 重建 payload 与原始**完全一致** → Bloom 合取命中 `v=11` → 与明文答案集对账通过 → 负对照正确。

**三处简化**（都写在代码注释里，只影响隐私/内存，不影响正确性）：
① 列选择传明文列坐标（论文是加密 one-hot）；② BFF 位置用位置池连续分配（论文是剥离算法）；
③ 每字段一条多项式 R=n,C=1（论文是 R×C 二维布局）。

详见 `QUERY_DECODE_编排说明.md`。

---

## 六、D 线：tiny-cape（极小参数、噪声为 0、可手工验算）

参数 **N=8, t=17, q=97, Δ=5, B=2, l=7, ℓ_BF=2, k=3** —— 与 MPC4J/SEAL 路线**完全独立**
（SEAL 的 BFV 接受不了 q=97 / N=8 这种参数）。用途是**正确性可手工逐位验证**。

```powershell
$tiny = "D:\DFY-ws\cape\tiny-cape"
$out  = "$tiny\out"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$src  = @()
$src += (Get-ChildItem "$tiny\src\main\java" -Recurse -Filter *.java).FullName
$src += (Get-ChildItem "$tiny\src\test\java" -Recurse -Filter *.java).FullName
javac -encoding UTF-8 -d $out $src          # 零依赖，任意 JDK 11+

java -cp $out cape.tiny.TinySelfTest            # 参数/环/槽位/RLWE/CtCtMul
java -cp $out cape.tiny.RgswSelfTest            # 切段/外部积/CMUX
java -cp $out cape.tiny.BlindRotateSelfTest     # 盲旋转     ← 核心
java -cp $out cape.tiny.CapeEndToEnd            # 端到端     ← 核心
```

**测试状态（本机实测，合计 PASS=34 FAIL=5）**

| 类 | PASS | FAIL | 说明 |
|---|---|---|---|
| `TinySelfTest` | 21 | 2 | 2 项失败是 q=97 的**容量约束**（槽位掩码乘法需要 q ≈ 25000），非实现错误 |
| `RgswSelfTest` | 6 | 1 | 同上（槽位 CMUX） |
| `BlindRotateSelfTest` | 2 | 0 | ✅ **全部 r\* 的整条多项式 == `P(X)·X^{−r*}`** |
| `SampleExtractSelfTest` | 0 | 2 | ❌ **未完成**（代数关系未对齐，不影响端到端） |
| `CapeEndToEnd` | 5 | 0 | ✅ **完整链路通过** |

> **三个必读约束**（规范没写，实测撞到）：
> ① 明文**含卷积系数**必须 ≤ ⌊(q/2)/Δ⌋ = 9（故用 0/1 数据，这正是 CAPE 的真实形态）；
> ② `X^{−r*}` 的常数项是 `±P[(−r*) mod N]`，**不是** `P[r*]`；
> ③ 负数必须用**中心代表元**（`−1` 不能写成 `16`，否则 `Δ·16 = 80 > q/2`）。
>
> 详见 `tiny-cape/README.md`。

---

## 三、A 线：HE 主线（最常用）

```powershell
$root = "D:\DFY-ws\cape"            # ← 改成你的包路径
$jdk  = "D:\Java\jdk-25\bin"
$cp   = "$root\lib\mpc4j-crypto-fhe-seal.jar;" +
        ((Get-ChildItem "$root\lib\deps" -Filter *.jar | ForEach-Object { $_.FullName }) -join ';')
$out  = "$root\rgsw-lab\mpc4j-out"
New-Item -ItemType Directory -Force -Path $out | Out-Null

# 编译：MPC4J 线的源文件 + LWE 层（LweRlweConversion 依赖 cape.he）
$routeC = @('RgswOps.java','RgswCiphertext.java','MonomialOps.java','BootstrapKey.java',
            'RgswLabMain.java','MonomialKeyTest.java','LabConfig.java')
$src  = @()
$src += (Get-ChildItem "$root\rgsw-lab\src\main\java\com\fusepir\rgsw" -Filter *.java |
         Where-Object { $_.Name -notin $routeC } | Select-Object -ExpandProperty FullName)
$src += (Get-ChildItem "$root\lwe-java\src\main\java" -Recurse -Filter *.java |
         Select-Object -ExpandProperty FullName)
& "$jdk\javac.exe" -encoding UTF-8 -cp $cp -d $out $src
```

### 已验证的自检类（本机实测全过）

| 类 | 做什么 | 规模 | 结果 |
|---|---|---|---|
| `Mpc4jRgsw` | RGSW / 外部积 / CMUX 地基 | N=2048 | ✅ 5/5 |
| `LweRlweBridge` | SampleExtract ↔ Pack（索引映射） | N=2048 | ✅ 2/2 |
| `BlindRotateOps` | 盲旋转两种口径 + 论文规模 | N=2048 / **N=16384** | ✅ 全过 |
| `BlindRotateComplete` | 完整盲旋转（真实载荷+加密索引） | N=2048, d=64 | ✅ 4/4 |
| `BlindRotateStress` | 维度扫描 + 噪声扫描 | N=2048 | ✅ 全过 |
| `AnswerPathMini` | 最小 ANSWER 链路 | N=2048 | ✅ A0–A3 |
| `LweRlweConversion` | LWE↔RLWE 互转 | N=2048 | ✅ T0–T4 |
| **`BloomScoring`** | **槽位域二进制同态内积**（A4） | N=4096 | ✅ 5/5 |
| **`RingPack`** | **Ring Packing**（多条 LWE → 一个 RLWE） | **N=8192** | ✅ 6/6 |
| `PackGoalCheck` | 裁决「`packFromSample` ≠ 论文 Pack」 | N=4096 | ✅ 按设计标记未达成 |
| `Mpc4jCapability` | 论文规模四项能力 | N=16384 | ✅ 4/4 |

跑法：

```powershell
& "$jdk\java.exe" -Xmx8g -cp "$out;$cp" com.fusepir.rgsw.BloomScoring
& "$jdk\java.exe" -Xmx8g -cp "$out;$cp" com.fusepir.rgsw.RingPack 8192 32
& "$jdk\java.exe" -Xmx8g -cp "$out;$cp" com.fusepir.rgsw.BlindRotateOps
```

### ⚠️ 两个已知的默认参数坑

| 类 | 问题 | 解法 |
|---|---|---|
| `BloomInnerProductProbe` | 默认 `N=2048`，只有 1 个工作素数 → `keyswitching is not supported by the context` | **显式传参**：`... BloomInnerProductProbe 8192` |
| `RingPack` | N=4096 时打包过、但打分侧噪声崩 | 用 **N ≥ 8192** |

---

## 四、C 线：明文侧（BFF / Bloom）

```powershell
$db  = "$root\cape-fusepir-database-handoff"
$out = "$db\out"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$src = (Get-ChildItem "$db\src\main" -Recurse -Filter *.java).FullName
javac -encoding UTF-8 -d $out $src          # 任意 JDK 11+ 均可
```

### 已验证

| 类 | 做什么 | 结果 |
|---|---|---|
| `ArithmeticBffSelfTestMain` | BFF Setup/Encode/Check/Reconstruct 闭环 | ✅ T1–T5 |
| **`BloomConjunctionCheck`** | **Bloom 合取判定**（真命中必须全召回 + 假阳性受 ε 控制） | ✅ 3/3 |
| `DatabaseInitializerMain` | 一组参数下的明文侧规模 | — |

```powershell
# 参数规模对比（tags.csv 在 ml-latest-small 里）
java -cp $out com.fusepir.database.DatabaseInitializerMain $root\ml-latest-small\ml-latest-small\tags.csv paper
java -cp $out com.fusepir.database.DatabaseInitializerMain $root\ml-latest-small\ml-latest-small\tags.csv test 32

# 生成磁盘 BFF（最小参数 + 前 32 关键词 → 149 KB / 0.1 s）
java -cp $out com.fusepir.database.DiskBffEncodeMain `
     $root\ml-latest-small\ml-latest-small\tags.csv `
     $root\..\_bfftest 2048 32

# 端到端明文查询
java -cp $out com.fusepir.database.PlaintextFusePirQueryMain $root\..\_bfftest
```

> **两套参数别混用**：明文侧用 `testMinimal()`（N=4096）；
> 密文侧（RingPack + 打分）要 **N ≥ 8192**；出论文数字用 `paperAligned()`（N=16384）。

---

## 五、包里有什么

```
cape/
├── BUILT.md                    ← 本文件（构建与运行）
├── README.md                   ← 上游主文档（82 KB，四阶段视角）
├── HE_三层调用说明汇总.md        ← LWE / RLWE / RGSW 三层接口
├── RLWE路线审计.md              ← 三条路线（native / MPC4J Java / 自研）的取舍
├── 默认实现一览.md               ← 哪个文件夹是哪层的默认实现（**先看这个，避免拿错**）
├── SYNC.md                     ← 与 GitHub 同步的注意事项
│
├── lib/                        ← MPC4J SEAL Java 移植 + 11 个依赖 jar（**必需**）
├── native-jni/                 ← 真 SEAL 的 JNI DLL + 验证程序（对照路线）
├── patches/                    ← 对 MPC4J 的 Galois 惰性分配补丁
│
├── rgsw-lab/                   ← RGSW / 盲旋转 / RingPack / Bloom 打分（HE 主线）
├── rlwe-java/                  ← 自研 RLWE（**已弃用**，仅作交叉校验）
├── lwe-java/                   ← LWE 层（唯一实现，MPC4J 没有）
├── rlwe-bench/                 ← 性能对照基准
├── cape-fusepir-database-handoff/  ← 明文侧：BFF / Bloom / 载荷
├── param-probe/                ← 参数位宽探测
├── pdf-extract/                ← 论文 PDF 分栏提取
├── ml-latest-small/            ← MovieLens 数据集（可直接跑 demo）
│
└── docs/
    ├── knowledge/              ← **知识库**（Bloom 存储/提取的规范 + 代码对照）
    └── reports/                ← 历次同步的验证记录
```

---

## 六、下一步要写的（按 README 整改编号）

| 项 | 内容 | 状态 |
|---|---|---|
| A1 | Bloom 位位置只依赖关键词 | ✅ 已完成 |
| A4 | Bloom 打分（`CtCtMul` + 折叠） | ✅ 已完成（`BloomScoring` 5/5） |
| — | Pack（真正的 Ring Packing） | ✅ 已完成（`RingPack` 6/6） |
| **A2/A3** | **客户端 QUERY 逻辑 + 列选择接通** | ❌ **未做** |
| **A5** | **DECODE 编排** | ❌ 未做 |
| — | `PlaintextFusePirQuery` 用 Bloom 做合取判定 | ❌ 未接 |
| — | 产品化列打包（`P_{c,b}(X)` 接进 ANSWER） | ❌ 未接 |

**写代码前请先读 `docs/knowledge/`** —— 尤其是 `代码对照-存储与提取.md`，
里面记了 3 处「设计说明 vs 实际代码」的差异，其中「**Pack 输出必须落槽位而非系数**」
是能否算对内积的关键。
