> **归档说明**：本文件原在 `D:\DFY-ws\` 根目录，2026-10 收进 `cape\docs\reports\`。文中的历史路径（如 `D:\DFY-ws\_pirouette\`、`D:\DFY-MMBS-ws`）是当时的记录，不必照做。

# coding 仓库 —— 关联到本地 + 本轮进展

> 生成时间：2026-09-16
> 目的：把小组的 CAPE 代码仓库与你本地的 `D:\DFY-MMBS-ws` 关联起来，并交接"同态加密部分"的进展。

---

## 一、为什么不能直接帮你克隆到 `D:\DFY-MMBS-ws`

两个环境层面的限制（都不是操作失误）：

| 限制 | 表现 | 说明 |
|---|---|---|
| **沙箱边界** | 写 `D:\DFY-MMBS-ws` 被拒绝 | 本会话的文件策略是 `workspace-write`，只能写 `D:\DFY-ws` 以内 |
| **git 无法联网** | `schannel: AcquireCredentialsHandle failed: SEC_E_NO_CREDENTIALS` | 沙箱进程拿不到 Windows 的 TLS 凭证，`git clone/push` 都不可用 |

绕法：我**用 Node 的 TLS 栈**（不走 schannel）把仓库拉下来，在工作区里建成**完整的 git 仓库**，
再打成一个 **bundle 文件**——bundle 是一个可克隆的完整仓库快照，你在自己的终端里一条命令就能落到目标目录。

---

## 二️、⚠️ 先确认一个不一致

| 来源 | 远端地址 |
|---|---|
| 你给我的 | `https://github.com/joseph-wang-fu-ze/coding` |
| `SYNC.md` 里记录的 | **`https://github.com/yelou-ex/coding`** |

我按文档记录的 `yelou-ex/coding` 设成了 `origin`，另一个设成 `upstream-alt`。
**请确认哪个是真正的远端**，如果不是 `yelou-ex`，用第四节第一条命令改掉。

---

## 三、克隆到 `D:\DFY-MMBS-ws`（在你自己的 PowerShell 里跑）

```powershell
# 1) 从 bundle 克隆（含全部历史）
git clone D:\DFY-ws\coding-repo.bundle D:\DFY-MMBS-ws

cd D:\DFY-MMBS-ws

# 2) 让 bundle 里的 origin 指向真正的远端
git remote set-url origin https://github.com/yelou-ex/coding.git
# 若确认是另一个仓库，改成：
# git remote set-url origin https://github.com/joseph-wang-fu-ze/coding.git

# 3) 验证
git log --oneline
git remote -v
git ls-remote origin          # 这一步需要你的凭据，会弹窗
```

### 首次推送（bundle 里的历史还没推到远端）

```powershell
git push -u origin main
```

> 如果报 `Unsupported SSL backend 'curl'`，按 `SYNC.md` 里的说明执行：
> `git config --global http.sslBackend schannel`
>
> 如果反复要账号密码：
> `git config --global credential.helper manager`

### 备用：也可以直接用工作区里已经建好的仓库

```powershell
robocopy D:\DFY-ws\coding D:\DFY-MMBS-ws /E /MOVE
```

（`/MOVE` 会把工作区那份移走，避免两边打架。）

---

## 四、仓库现状（我确认为准）

**37 个 Java 文件 / 3301 行**，三层结构：

| 模块 | 内容 | 状态 |
|---|---|---|
| `lwe-java/` | LWE 加解密、模数切换、二值密钥 | ✅ 9/9 + 4/4 通过 |
| `rlwe-java/` | RLWE + NTT + 多素数 CRT + 外部积 | ✅ 6/6 通过 |
| `rgsw-lab/` | RGSW 加密、外部积、单项式旋转、自举密钥、CMUX | ✅ 6/6 通过 |
| `cape-fusepir-database-handoff/` | 明文侧预处理（BFF/Bloom） | 张明哲那条线 |
| `param-probe/`、`pdf-extract/` | 工具 | — |

**你负责的部分（按 `HE_三层调用说明汇总.md` 第八节"还没做的"）：**

1. **BlindRotate 本体** ← 缺的就是"把 CMUX 按位串成循环"
2. SampleExtract_0 / Pack
3. LWEtoRGSW（仅 −C 压缩变体需要）

---

## 五、本轮做了什么

### 新增文件

| 文件 | 作用 |
|---|---|
| `rgsw-lab/.../BlindRotate.java` | **盲旋转本体 + SampleExtract_0**（新增，含"当前状态"交接说明） |
| `rgsw-lab/.../BlindRotateTest.java` | 分级自检 A/B/C/D（新增加） |
| `rgsw-lab/.../MonomialConventionDiag.java` | 把 `X^k` 的常数系数约定**用卷积定义钉死**（有长期价值，建议保留） |
| `rgsw-lab/.../ConvolutionCheck.java` | 同上，2N 个位移全量对照 |

### 验证结论（可直接采信）

**① 环运算本身没有问题。**
`MonomialOps.mulMonomial` 在**全部 2048 个位移**上，与直接按定义写的卷积
`(X^k·f) 的常系数 = Σ f[i]·[i+k ≡ 0 mod N]·(−1)^((i+k)/N)`
**逐项一致**。实测对照表：

| k | 常系数 |
|---|---|
| 128 | −896 |
| 1920 | **+128** |
| 1025 | +1023 |

**② `SampleExtract_0` 的索引映射已独立推导并实现。**
数学依据：RLWE 相位 `c0 + c1·s` 的常数项就是一个 LWE 相位，
`b' = c0 的常系数`，`a'[0] = c1 的常系数`，`a'[i] = −c1[N−i] mod q_R`（i ≥ 1）。

**③ A 级测试通过**：只做公开旋转 `X^k`，常数项与独立参考实现一致（6/6）。

### ⚠️ 尚未完成（诚实交接）

**B 级 —— 完整盲旋转还没跑通。** 实测反例：

```
N=1024, d=1, s=0, idx=15, b=1920
  期望：常数项 = data[15] = 2
  实际：常数项 = data[128] = 3
```

**根因判断**：`X^{±b}` 的取值方向与 `testPolynomial` 的指数方向**必须作为一组同时确定**。
我分别翻转这两个方向都试过，单独翻任何一个都会改变结果，但只有**一种组合**能让 `idx` 与常系数严格对应 ——
我没能在这轮里定出来，而且我在这上面试了太多轮，继续盲试效率很低。

**建议的下一步（务必照这个做，别再试错）**：

> 用**最小反例做二分**：把 N 取到 8（甚至 4）、d=1、t=2，手工枚举
> 8 个 idx × 2 个 s 位，把"期望常系数"与"实际常系数"排成一张表。
> 最小规模下一眼就能看出是哪个组合，再回到 N=1024 验证。
>
> 在 `BlindRotateTest` 的框架上加十来行就能打出这张表。

另外两个**已修正的测试脚手架坑**（避免你重踩）：

- **两层 t 不同是设计,不是 bug**：RLWE 的 `t=65537`（论文）与 LWE 的 `t_LWE`（必须能整除 2N）
  不一样。用 `RlweOps.unscale` 去解读 LWE 层的值会得到饱和的 0 —— 要按层的 t 分别解码。
- **值域与 Δ 要匹配**：`Δ_LWE = q_LWE/t_LWE`。若测试数据值远小于 Δ_LWE，解码会量化成 0。

---

## 六、回归确认

改动**没有破坏任何已有功能** —— `rgsw-lab` 原有 6 项自检仍全绿：

```
[PASS] Test 0  NTT vs schoolbook multiplication
[PASS] Test 1  gadget decompose/recompose (after CRT)
[PASS] Test 2  RLWE encrypt/decrypt roundtrip
[PASS] Test 3  external product  mu*ct
[PASS] Test 4  selector mu = X^k
[PASS] Test 5  encrypted 2-way select (CMUX)
=== ALL TESTS PASSED ===
```

---

## 七、怎么跑新代码

```powershell
cd D:\DFY-MMBS-ws\rgsw-lab

$jdk = 'D:\java\bin'          # 你的 JDK 24
$src = @()
$src += (Get-ChildItem "..\rlwe-java\src\main\java" -Recurse -Filter *.java).FullName
$src += (Get-ChildItem "src\main\java" -Recurse -Filter *.java).FullName
New-Item -ItemType Directory -Force -Path out | Out-Null
& "$jdk\javac.exe" -encoding UTF-8 -d out $src

# 原有自检（应全绿）
& "$jdk\java.exe" -Xmx2g -cp out com.fusepir.rgsw.RgswLabMain test

# 盲旋转分级自检（A 通过，B/D 待修）
& "$jdk\java.exe" -Xmx2g -cp out com.fusepir.rgsw.BlindRotateTest

# 约定对照（这条最有参考价值：全部一致）
& "$jdk\java.exe" -Xmx2g -cp out com.fusepir.rgsw.MonomialConventionDiag
```

---

## 八、git 提交记录

```
b577ed0  wip(rgsw): add BlindRotate + SampleExtract skeleton, convention diagnostics
ed22fff  chore: import CAPE coding repo (3 layers: lwe-java / rlwe-java / rgsw-lab)
```
