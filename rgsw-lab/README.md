# rgsw-lab —— CAPE 的 MPC4J/SEAL 实现与实验台

> **本模块有 77 个 `.java`，其中 70 个带 `main()`** —— 也就是 70 个可执行入口。
> 这是历史积累的结果：每个被排查过的疑点都留下了一个可复跑的程序。
> 这份 README 就是给这 70 个入口做的索引，**先看「主线」一节，其余按需查**。
>
> 目录整理记录见 `coding/README.md` §变更历史；本文件 2026-10-14 建立。

---

## 一、怎么跑

### 前置一步（新克隆的仓库必须做，否则本模块编译不过）

```powershell
cd coding\native-jni
.\run.ps1 -CompileOnly        # 只编 Java 绑定，几秒
```

⚠️ **这一步不是可选的。** `run-mpc4j.ps1` 把 `native-jni/lib/classes` 放进了 classpath，
而 `classes/` 是 `.gitignore` 的构建产物、新克隆里不存在 —— 少了它本模块会直接报
`找不到符号：类 com.fusepir.nativejni`。`-CompileOnly` 就是为这个场景加的
（不带它的话 `run.ps1` 会在编译后接着跑一个耗时的 native 测试）。

### 之后

```powershell
cd coding\rgsw-lab
.\run-mpc4j.ps1 -Class com.fusepir.prim（分层后见 MAP.md）.<类名> [参数...]
```

- `run-mpc4j.ps1` 用**扁平 glob** 编译 `src\main\java\com\fusepir\rgsw\` 下的**全部** `.java`，
  只排除「路线 C」那 7 个自研文件（它们走 `.\run.ps1`）。
  ⚠️ **glob 是扁平的**：往 `com\fusepir\rgsw\` 里加子包不会被编译，需要同步改脚本。
- 新加类**不用登记**（早先这里是硬编码名单，漏登记会被静默跳过）。
- `-D` 开关通过环境变量传：`$env:DSH_JVM_OPTS='-Dcape.seeded=true'`，脚本按空白切分追加。

---

## 二、主线（前端演示与端到端走的就是这条）

| 类 | 作用 |
|---|---|
| `CapeDemoService` | **HTTP 服务本体**：启动时跑一次 SETUP，之后服务 `/api/query`。前端连的就是它 |
| `CapeDemoData` | 从 `cape-demo/db/keywords.json` 建载荷 + 明文表 `P`（BFF 编码、二维网格布局） |
| `CapeDemoSetupProbe` | 把 `P` 摊平成 native 要的一维数组 |
| `CapeEndToEndNative` | 四步端到端（走真 SEAL 4.0.0 的 C++ 路径）—— **不要改这个文件** |
| `CapeEndToEnd4` | 四步端到端的 MPC4J 版 —— **不要改这个文件** |
| `NativeCapeAnswer` | 老路径：每单元 = 列选择（C 次 `CtPtMul`）→ 盲旋转（d 轮 CMUX）→ `SampleExtract_0` |
| `CapeClientQuery` | 客户端侧构造密文查询（`/api/query-sealed` 的发送方） |
| `CapeSealedFlowTest` | 合规路径的跨进程断言（隐私 5 条 + 正确性）。默认跳过，见 `-Dcape.sealed` |

### 回归测试（改动后应当跑这两个）

| 类 | 说明 |
|---|---|
| `CapeTableDiag` | **纯 Java 几何回归测试，不碰加密、秒级、失败即非零退出**。覆盖：三路 share 求和、`dataRadius` 边界、逐关键词取回、同列行区间不重叠、**全部 16256 个关键词对的合取判定恰好性**（假阴性必须为 0） |
| `CapeBfLeakProbe` | 出站查询的隐私探针：演示「服务器用公开的 H 就能从出站 JSON 反解出查询关键词」 |

`CapeTableDiag` 值得单独说一句：它存在的理由是**一次真实事故** —— 表构造里补零判据写错了量纲
（拿多项式列号 `cc` 去比槽位下标），第 8 列起被整列清空，而症状只有加密侧一句
`result ciphertext is transparent`，完全看不出是哪一步错的。

---

## 三、按用途分类的实验/诊断入口

> 全部是「一次性但可复跑」的。名字里的 `Probe`/`Diag`/`Bench` 基本自解释。
> 跑法都是 `.\run-mpc4j.ps1 -Class com.fusepir.prim（分层后见 MAP.md）.<类名>`。

### 3.1 盲旋转（BlindRotate）—— 本项目的性能主战场

| 类 | 用途 |
|---|---|
| `BlindRotateOps` | 按 CAPE 论文定义实现的盲旋转，轮数口径按 Pirouette 修正 |
| `BlindRotateBench` | 盲旋转微基准（用 `nativePrepare`/`nativeRunWithCtx` 隔离出纯 native 部分） |
| `BlindRotateStress` | 口径 2（CAPE 口径）的压力测试 |
| `BlindRotateAlignProbe` | CMUX 里 `a[i]` 用 `+a[i]` 还是 `−a[i]` 的定号探针 |
| `BlindRotateSignProbe` | 同上，符号方向的单独探针 |
| `BlindRotateComplete` | 完整目标 `X^{−r}·P(X)`（`r = β − ⟨a,s⟩`）的验证 |
| `CapeRotationIdentity` | **纯算术**核对 `Σ a_i·s_i(bsk) ≡ β − r_a (mod 2N)`，不碰加密 |
| `CapeNoisyIndex` | 相位带噪声的索引（`β = ⟨a,s⟩ + r + e`）下盲旋转命中率怎么塌 |
| `NoiseImpact` | 同上，噪声影响的量化 |
| `CmuxProfile` | 一次 CMUX 的耗时拆解（明文 NTT / 多字算术 / `mul_plain` …） |
| `CmuxBreakdown` | 同上，用来判定「decompose 值不值得改」 |
| `ScaleProbe` / `LevelProbe` / `LevelProbe2` / `SizeProbe` / `SlotProbe` | 参数/层数/规模/槽位的探测 |

### 3.2 ANSWER 与列选择

| 类 | 用途 |
|---|---|
| `AnswerUnitProfile` | 「一个单元」到底包含什么，前端基线的口径来源 |
| `CapeAnswerProfile` | 把 ANSWER 拆成列选择 / 盲旋转 / 密文相加三部分成本 |
| `CapeAnswerSplit` | 同上，两段式拆分 |
| `CapeAnswerColumnOriginal` / `CapeAnswerFull` / `CapeAnswerHomomorphic` | ANSWER 第 4~7 行的三种实现形态 |
| `CapeColumnPacked` | 让服务端选一列只需**一次** `CtPtMul` |
| `CapeColumnSelectionFixed` / `CapeColumnSelectionIndependent` | 列选择的两条路线（服务器资源 vs 客户端独立） |
| `CapeSlotDomainExperiment` | ⚠️ **这不是论文的列选择** —— 是「槽位域列选择」的实验变体 |
| `ColumnSelectorForms` | 三种列选择形态是否**数学等价**，并量出各自代价 |
| `CtPtMulMinimal` | 最小化验证 `CtPtMul(Enc(e_{c*}), P(X)) == P(X)` |
| `CoeffExtractProbe` | 系数域抽取探针 |

### 3.3 Bloom / 合取判定

| 类 | 用途 |
|---|---|
| `BloomScoring` | 算法 2 ANSWER 第 4~7 行的槽域实现（`encryptBloomVector` / `bloomScore` / `foldAllSlots`） |
| `BloomInnerProductProbe` | 判定实验：Bloom 的二进制同态内积到底该在哪个域做 |
| `PackGoalCheck` | 把每个 LWE 密文只加密一个比特的**多个** LWE **安全且正确**地打包成一个 RLWE |
| `RingPack` | 打包成一个 RLWE、每条落在一个槽位上，从而能走 SIMD 二进制同态内积 |
| `CapeBkCompressed` | CAPE 按 LWE 秘密的**每一位**旋转，每轮一个 RGSW |

### 3.4 LWE ↔ RLWE 桥

| 类 | 用途 |
|---|---|
| `LweRlweBridge` | LWE → RLWE 桥：`SampleExtract` 与 `Pack` |
| `LweRlweConversion` | 与 `lwe-java` 模块（`cape.he`，单 `long` 模数）真正接起来 |
| `LweColumnMath` | LWE 密文 `(a,b)` 只加密一个标量：相位 `b − ⟨a,s⟩ = m` |
| `LweToRgswOps` | 子程序 `LWEtoRGSW(ct_L) → C_μ` |
| `SampleToPackLink` | ANSWER 后半段（三路相加 + Pack + Bloom 候选密文）做成全程密文的前提 |
| `CapeLweScaling` | `b = ⟨a,s⟩ + Δ·m + e (mod q)` 的标度处理 |
| `CapeQueryDecode` | SETUP → QUERY → ANSWER → DECODE 的编排 |

### 3.5 RGSW / 两条路线

| 类 | 用途 |
|---|---|
| `Mpc4jRgsw` | 建立在 MPC4J 的 BFV 之上的 RGSW 层（**默认实现，路线 B**，走 `run-mpc4j.ps1`） |
| `Mpc4jCapability` | ⚠️ 路线 **B（纯 Java 移植版）** 的能力探测，不是目标路线 native |
| `RgswBaseSweep` | 扫 RGSW gadget 分解基 `base = 2^b`，看能不能把盲旋转做快 |
| `RgswPolyDiag` / `RgswPolyTest` | 一般多项式消息的 RGSW：`RGSW(m) ⊠ ct` 应解密为 `m ⊠ msg` |
| `RnsProductDebug` | 定位 RNS 域外部乘积为什么错（四个断言逐个排除） |
| `DecomposeEquiv` | 分解等价性 |
| `CtCtMulVsBlindRotate` | 核对《Harness 的说法哪里对、哪里不对》 |
| `RgswOps` / `RgswCiphertext` / `MonomialOps` / `BootstrapKey` | **路线 C**（自研 RLWE，零依赖）的 RGSW 基础件 —— **无 `main`**，由下面的路线 C 入口使用 |
| `RgswLabMain` / `MonomialKeyTest` / `LabConfig` / `examples/RlweDemo` | **路线 C** 的子自检，走 `.\run.ps1`（不是 `run-mpc4j.ps1`） |

### 3.6 性能对照与 Q 缩放

| 类 | 用途 |
|---|---|
| `CapeQFairBench` | 逐项锁定（N/t/base/d/R/C/k/`q_L`/明文表同种子）后做 Q 缩放对比 |
| `CapeCGridProbe` | 把 `R` 放大以缩小 `C` —— CAPE 网格几何里一个**免费**的杠杆 |
| `ExpandProbe` | 唯一的确定性是噪声（SealPIR Theorem 2 的界） |
| `SelToExtractBench` | 算法 1 ANSWER 第 12 行（对 a=0..2、b=1..`B_pay`）的基准 |
| `PlaintextFillProbe` | 明文多项式填充 |
| `MonomialProbe` | 单项式探针 |
| `CapeSealedFlowTest` / `CapeTableDiag` / `CapeBfLeakProbe` | 见上面「回归测试」 |

### 3.7 仅库类（无 `main`，被上面这些调用）

`Json`、`ExpandOps`、`RgswOps`、`RgswCiphertext`、`BootstrapKey`、`MonomialOps`、`LabConfig`

---

## 四、相关文档

本模块自己的调研/实测记录（都在本目录下）：

- `RGSW_调用说明.md`
- `BlindRotate_实测.md`
- `LWE_RLWE桥_调用说明.md` / `LWE_RLWE桥_实测.md`
- `LWE_RLWE打包_RingPack_调研.md`

更上层的文档全在 `coding/docs/`（见 `coding/README.md` §文档地图）：
`缺陷总表.md` 是问题权威清单，`速度差距-逐篇检索记录-2026-10-13.md` 是性能排查的逐篇记录，
`逐子程序核对-我们的实现是否符合论文算法-2026-10-13.md` 是逐子程序对照论文的结论。
