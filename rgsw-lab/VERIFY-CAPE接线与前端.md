# 查验清单：CAPE 接线（A2 / MPC4J）与前端接入（native 演示）

> **给另一个 agent 的独立查验单**（2026-10-15 立）。
> **不许只读本文就下结论。** 本文只写三件事：
> ① 我声称了什么；② **怎么独立判定**（命令 + 期望的原始输出形态）；③ **什么算没通过**。
> 每条都要跑出原始输出再给 VERDICT。**复现不出来就报"不一致"，不要替它解释掉。**
>
> 被查验的工作分两块、两条**完全不同的技术路线**，别混：
> - **A 块（A2 / MPC4J 纯 Java）**：把 FusePIR 四步接进 CAPE 的 Algorithm 2。落在 `rgsw-lab` 的探针里。
> - **B 块（native 演示前端）**：`cape-demo` 的页面从"明文关键词"改走论文的**默认密文路径**。落在一个 HTTP 服务 + 单文件页面上。

---

## 0. 环境与纪律（照抄，踩了会浪费一整轮）

```powershell
cd E:\学习\密码赛\coding\rgsw-lab      # A 块
.\run-mpc4j.ps1 -Class <全限定类名> [args...]
```

| 纪律 | 原因（都踩过） |
|---|---|
| **先 `Get-Process java \| Stop-Process -Force`** | 本机可能还留着我起的演示服务（占 8756）；而且 `run-mpc4j.ps1` 每次清空 `mpc4j-out` |
| **同一时刻只跑一个 `run-mpc4j.ps1`** | 它启动时 `Remove-Item -Recurse -Force mpc4j-out` ⇒ 并发会把别人的类删掉 |
| **javac 报错在本机是 GBK，经 PowerShell 是乱码** | **先看行号再 `read` 那一行**，别去解码错误文本 |
| **禁止对 UTF-8 源码用 `Get-Content -Raw` / `Set-Content`** | 历史 mojibake 事故；读文件用 `read` 工具 |
| **`Start-Process` 在受限沙箱里被拒** | 起演示服务请用"后台 job"，别用 `run-demo.ps1` 里的 `Start-Process`（见 §3.1 的手工命令） |
| **时间预算** | A 块一个探针 1~6 分钟；B 块一次 ANSWER **≈75 s**（N=8192）；带 `-Dcape.selftest=true` 启动要 **≈7 分钟**（它跑 4 遍完整 ANSWER） |
| **`git` 不是安全网** | 本项目的探针大量未入库；本轮改动里 `CapeA2Wire.java`、`FusePirFourStep.java`、三个探针都是 `??` 未跟踪（见 §5.1） |

**验证方自己也该被验证**：如果你跑出来的数字与本文**完全一样**却没有任何中间输出，请检查你是不是在读旧输出文件
（`rgsw-lab` 下有一堆 `p5-diag*.txt`、`run-*.txt` 是历史日志，**不是本次运行的结果**）。

---

## 1. A 块：A2 / MPC4J 接线的 4 条判据

| # | 命令 | 期望 |
|---|---|---|
| **A1** | `.\run-mpc4j.ps1 -Class com.fusepir.probe.CapeA2WireTest 16 4096 16 18` | **exit 0**，且 P1–P6 六组全 `[达成]` |
| **A2** | `.\run-mpc4j.ps1 -Class com.fusepir.probe.ScoreMulDomainTest 4096` | **exit 0**，且**前两组是"缺陷断言"**（见 §1.3） |
| **A3** | `.\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirFourStepTest 16 4096 16 18` | **exit 0**（A1 四步回归，与上一轮同） |
| **A4** | `.\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirAnswerBisectTest 16 4096 16 18` | **exit 0**（上轮修过它的一条非确定性断言，见 §4.4） |

### 1.1 A1 的关键读数（**数值会漂，只有"关系"才是判据**）

我这一次跑到的（供对照，**不要求你复现同样的绝对值**）：

```
[A2 SETUP 11] FusePIR(pp_F: n=16, N=4096, d=16, B_pay=61, lBf=18, ...)   ← q=120 bit
[A2 SETUP 12] pp_cape(... ℓ_BF=18, G=..., m=3, B_pay=61)
K = 128；tRing = 8404993；τ = 10；τ_ring = 1280
候选 j=0：v=1001 明文内积=10  K×内积=1280  同态得分=1285
候选 j=1：v=1002 明文内积=5   K×内积=640   同态得分=637
候选 j=2：v=1003 明文内积=7   K×内积=896   同态得分=895
[达成] P3 A2 ANSWER 2-6 成立（得分取整 == 明文内积）
A2.decoded(V_{K_1}=[1001, 1002, 1003]、槽值得分=[1285, 640, 895]、字段域得分=[10, 5, 7] ... 收下 [1001])
```

**必须成立的关系**（这三条才是判据）：

1. **槽值得分是"K×内积 + 残差"**：`round(槽值得分 / K) == 明文内积`，且
   `|槽值得分 − K×明文内积| ≤ τ×ones/2`（`ones` = `s_L` 汉明重量，探针会打印）。
   ⚠️ **槽值得分每次运行都不同**（残差随加密随机化）——所以探针**不能**拿"== 1285"这种常数当判据；
   你若看到它用常数比，那才是缺陷。
2. **只有命中候选被收下**：字段域得分 `[10,5,7]` vs `τ=10` ⇒ 收 `[1001]`；另两个 `5/7 < 10` 被拒。
3. **`CtCtMul(q^BF, packedCoeff)` 逐槽 0/4096 不符**（P6 的 `[diag]` 行）——
   这是"打分能算对"的机械证据。**若这一行是 4096/4096，说明那堵墙还在**（见 §1.3）。

### 1.2 A1 里的 6 组判据（每组都自带正/负对照，查验方应逐组确认"负对照真的会红"）

| 组 | 正 | 负 |
|---|---|---|
| P1 SETUP 11-13 | `B_pay` 三处一致、`pp_C` 由 `pp_F` 加宽、`st_S` 直传、`tRing` 素数 ≡1 (mod 2N)、`K > ones` | `pp_C` 再加宽一次**必须抛** |
| P2 QUERY 1-3 | `q_anc` 形状、`q^BF` **段外逐位为 0**、`τ = ‖b_qry‖₁` | ① 锚不在查询集 ⇒ 抛；② 查询集加到 3 个关键词（`τ·ones ≥ K`）⇒ **必须抛**（守卫） |
| P3 ANSWER 2-6 | 得分取整 == 明文内积（3/3） | 漏位候选得分 < `τ`；`bloomCt` **不掩码**⇒段外实测带相邻候选的载荷 |
| P4 DECODE | `V_{K_1}` 与明文一致、合取语义收下 `[1001]` | ① 换 `st^anc_C` ⇒ `⊥`；② 阈值**不乘 K** ⇒ 收下 0 个；③ 换 `q^BF` ⇒ 原命中候选被拒 |
| P5 折叠轮数 | 6 轮 == 5 轮（本接线下等价） | **破约**：`q^BF` 段外置 1 ⇒ 6 轮得分 `= τ+v₃`、5 轮 `= τ`（两条路给出**不同的错值**） |
| P6 三方对账 | `payloadTruth` vs DB 的 `b_v` 0 处不符 | `CtCtMul` 逐槽 0/4096 不符（无 Pack 噪声时的对照） |

### 1.3 A2 是**缺陷断言**判据 —— 这里最容易被"读成绿灯"骗

`ScoreMulDomainTest` 跑四组配置：

| 组 | 配置 | 期望 |
|---|---|---|
| 1、2 | `bfvDefault(4096)`（工作 q=72 bit），`t=tRing` / `t=65537` | **`[PASS] [缺陷断言] … Pack 产物只有 N bit 预算（< 一次 CtCtMul 的 ~26 bit）⇒ 相乘后得分 ≠ Σq·槽`** ← 它的 PASS 条件是"**算错**" |
| 3、4 | `q = 3×60`（工作 120 bit），`t=tRing` / `t=65537` | **`[PASS] B1/B2 Pack 槽精确、Pack 产物 ≥30 bit、得分 == Σq·槽`** |

**查验方要盯的点**：
- 第 1/2 组**必须**报 `[PASS]`，且**必须**同时打印出"得分 ≠ 期望"。
  如果它们报 FAIL，说明那堵墙被别的东西挪了 —— 那本文 §1.4 的机制账就要重算。
- 第 3/4 组里 `稠密槽掩码 × Pack 产物` 必须 **4096/4096 槽对**（bfvDefault 组是 **0/4096**）。
  ⚠️ 这一对是我用来**推翻**旧结论的（见 §4.3），请重点验。

### 1.4 我给的机制账（**这些是"解释"，不是"判据"；请按可证伪的方式验**）

| 声称 | 我实测的数 | 你可以怎么独立证伪 |
|---|---|---|
| 一次 `CtCtMul` 的代价 ≈ **26 bit** | 新加密 51 bit → 乘后 25 bit | 看 A2 里 `[info]` 的噪声预算行；或用 `m.decryptor.invariantNoiseBudget` 自己写探针 |
| `RingPack` 产物的代价 ≈ **49 bit，且几乎与 limb 数无关**（k=1→17 bit、k=61→14 bit） | A2 的 `Pack k=… limb ⇒ N bit` 阶梯 | 改 `packK` 的 `k` 重跑 |
| 掩码那堵墙是**噪声预算**，不是"系数域乘积越界" | bfvDefault 下掩码后 **0 bit / 0-4096**；q=3×60 下 **25 bit / 4096-4096** | 同上（组 1 vs 组 3） |
| 延迟重线性化救不了 | `multiply` 后即 0 bit；且 size-3 密文不能旋转（抛 `encrypted size must be 2`） | A2 的 E 段 `[info]` |
| 自定义系数模数默认被安全标准拒 | `isParametersSet=false`（not compliant with HomomorphicEncryption.org…） | A2 最后一行 `[info]` |
| `tRing ≠ K·T` | `tRing=8404993`、`K = ⌊tRing/T⌋ = 128`；纯 A1 那条是 `1179649 = 18T−17`（`K=17`） | `read` `FusePirFourStep.ringModulusFor` + A1 的 P1.4 行 |

---

## 2. 需要你**额外**判断的两处设计选择（我给理由，但不替我担保）

1. **`K = 128` 的必要性**：我声称"判定要在 `τ=10` 个字段上累加桥残差（上界 `τ·ones/2=55`），
   所以必须 `K > τ·ones = 110`"。
   **挑战方式**：把 `CapeA2Wire.A2_MIN_SCALE_K` 改回 0（回到原来的启发式 ⇒ K=17）重跑 A1。
   若 P3/P4 **仍然全绿**，说明我把 K 的账算大了；若变红，说明这条必要。
2. **`/api/client/*` 两个出口算不算"自己发明一套"**：我认为不算 ——
   服务器侧**没有第二套 ANSWER**，页面发的就是论文默认路径的请求体（`d` + 锚位置 + `q_BF` 字节），
   客户端那两步只是被搬到同 JVM 的两个出口里（浏览器做不了 BFV）。
   **挑战方式**：`/api/query` 的 sealed 分支调用点只有 `runQueryCapeSealed` 一处吗？新出口有没有偷偷绕过它？

---

## 3. B 块：前端接入的 5 条判据

### 3.1 起服务（正确类名 + 手工命令，避开 `Start-Process`）

```powershell
Get-Process java -ErrorAction SilentlyContinue | Stop-Process -Force
cd E:\学习\密码赛\coding\rgsw-lab
$env:DSH_JVM_OPTS = '-Dcape.web=E:\学习\密码赛\coding\cape-demo\web'
.\run-mpc4j.ps1 -Class com.fusepir.cape.CapeDemoService 8756 8192 16 `
  'E:\学习\密码赛\coding\cape-demo\db\keywords.json'
# 另开一个 pwsh：等 /api/state 应答（SETUP ≈1 s，所以 30 s 内必就绪）
```

| # | 判据 | 期望 |
|---|---|---|
| **B1** | `Invoke-RestMethod http://127.0.0.1:8756/api/state` | `ready=true`、`params.N=8192`、`db.keywords=128`、`expected.answerMs ≈ 7×10⁴` |
| **B2** | `GET /` | **HTTP 200**，且页面内容**含** `wireBox`、`/api/client/seal`、`/api/client/decide`（页头**不含**回环声明 —— 2026-10-15 按用户要求删掉；回环口径改由 README 与 `/api/state` 承担，见 §6） |
| **B3** | 三步正控制（下面脚本） | `出站字段=[d,anchorColIdx,anchorRowIdx,qBFBytes]`、**体里含关键词=无**、`接受=[5706]`、`命中=True`、命中 *Spanglish (2004)*（movieId=27808） |
| **B4** | 三步负控制 `anime + golf` | `接受=[]`、`命中=False`（三个候选的 `Dec(ct_score)` 都 < τ） |
| **B5** | 类名反例 | `com.fusepir.demo.CapeDemoService` 在**任何** classpath 都不存在（源码 / `rgsw-lab/rgsw.jar` / `native-jni/lib/classes`）—— 用 `Get-ChildItem -Recurse -Filter CapeDemoService.class` 或 `javap -cp …` 验 |

**B3 的可粘贴脚本**（正/负控制都在里面）：

```powershell
function Flow([string[]]$kws) {
  $seal = Invoke-RestMethod http://127.0.0.1:8756/api/client/seal -Method Post `
            -ContentType 'application/json' -Body (@{keywords=$kws}|ConvertTo-Json -Compress) -DisableKeepAlive -TimeoutSec 60
  $body = ($seal.body | ConvertTo-Json -Depth 6 -Compress)
  $leak = @(); foreach ($k in $kws) { if ($body.Contains($k)) { $leak += $k } }
  $ans  = Invoke-RestMethod http://127.0.0.1:8756/api/query -Method Post `
            -ContentType 'application/json' -Body $body -DisableKeepAlive -TimeoutSec 600
  $dec  = Invoke-RestMethod http://127.0.0.1:8756/api/client/decide -Method Post `
            -ContentType 'application/json' -Body ("{""tau"":$($seal.tau)}") -DisableKeepAlive -TimeoutSec 60
  "τ={0} 出站=[{1}] 含关键词={2} / ANSWER {3:N1}s / f==fp(K):{4} 得分={5} 接受=[{6}] 命中={7}" -f `
    $seal.tau, ($seal.outboundFields -join ','), $(if($leak){$leak -join ','}else{'无'}), `
    ($ans.timing.totalMs/1000), $dec.fingerprintOk, (($dec.candidates|%{$_.score}) -join '/'), `
    ($dec.accepted -join ','), $dec.hit
}
Flow @('Adam Sandler','family')   # 池内命中 1 条 ⇒ 期望接受 [5706]
Flow @('anime','golf')            # 负控制 ⇒ 期望接受 []
```

### 3.2 修前的形态（为什么说"前端此前不能用"）

| 现象 | 我实测到的 |
|---|---|
| 页面那条路（`POST /api/query {"keywords":[…]}`）查池内命中组合 | `ok=true, hit=false, results=[], valueCount=171` |
| `-Dcape.selftest=true` 的 **sealed 合规路径自检** | **3 PASS / 1 FAIL**（第 4 条"答案与池内真值一致"FAIL，`接受=[]` 而池内真值 `[5706]`） |

**根因**：载荷读取下标是"40-bit 指纹占 1 槽"时代的写法，而当前 `fpSlots=2`（`B_pay` 59→60）。
`valueCount=171` 就是**指纹的高位 limb**（`171·2³² + 1381168093 = 735820575709` = 自检里的 `f`）。
⇒ **查验方可以据此独立确认**：`171·2^32 + 1381168093` 是否等于响应里的 `fingerprint`。

### 3.3 修后的对照（同一命令）

| 命令 | 修前 | 修后（我实测） |
|---|---|---|
| `POST /api/query {"keywords":["Adam Sandler","family"]}` | `hit=false` | `valueCount=3`、`hit=true`、结果 *Spanglish (2004)* |
| `-Dcape.selftest=true` 的 sealed 自检 | 3 PASS / 1 FAIL | **4 PASS / 0 FAIL**（`valueCount=3`、`接受=[5706]`） |
| `-Dcape.selftest=true` 的 CAPE 端到端自检 | 一直 9 PASS / 0 FAIL（它不走那两处下标） | 仍 9 PASS / 0 FAIL |

---

## 4. 三条已修缺陷 —— 请用**变异测试**验（把缺陷放回去，看断言是否真的变红）

> 这是本查验单里**最能识破"假绿灯"**的一段：只跑一次看到全绿，证明不了"守卫会响"。
> 每条变异做完**必须恢复**（改回原样后重跑一次确认回到全绿）。

### 4.1 变异测试表（M1–M5）

| # | 变异 | 期望（必须发生） | 恢复 |
|---|---|---|---|
| **M1** | `CapeA2Wire.A2_COEFF_BITS` 改成 `null` | A1 的 **P3.1/P3.2 变红**（Pack 产物 2 bit ⇒ 得分是均匀随机值），P6 的 `CtCtMul(q^BF, packedCoeff)` 逐槽变成 **4096/4096 不符**。若它不是"红"而是直接崩，也算红 —— 但请贴出异常原文 | 改回 `{60, 60, 60}` |
| **M2** | `CapeA2Wire.A2_MIN_SCALE_K` 改成 `0L`（回到启发式 ⇒ K=17） | A1 的 **P3.2 与 P4.2 变红**（命中候选的字段域得分 ≠ τ=10） | 改回 `128L` |
| **M3** | 注释掉 `CapeA2Wire.query()` 里那条守卫（`if ((long) tau * ones >= s.scaleK()) throw …`） | A1 里逐字为 **`[负对照] 查询集加到 3 个关键词（τ = 15 ⇒ τ·ones = 165 ≥ K）⇒ query() 必须抛`** 的那一行变红 | 恢复 |
| **M4** | `CapeDemoService`：把两处 `FusePirSetup.countOffset(fpSlots)` / `valueOffset(fpSlots, j, 1+tb.lBf)` 改回 `1` 与 `2 + j*(1+tb.lBf)` | legacy 查询 `hit=false`；sealed 自检回到 **3 PASS / 1 FAIL**（`valueCount=171`、`接受=[]`） | 恢复 |
| **M5** | 把 `CapeA2WireTest` 的 P3.1 判据从"取整 == 明文内积"改成"槽值得分 == 常数 1280" | **必须变红**（残差每次不同）—— 这条是**验我是不是拿常数糊弄** | 恢复 |

⚠️ **注意 M1/M2 的副作用**：`coeffBits`/`minScaleK` 都只影响**参数**，不影响布局
（`B_pay=61`、值槽 `[4,23,42]`、段起点 `[5,24,43]`、`tRing` 仍 `8404993`、`K` 仍 `128` 都不该变；
M1 只改**系数模数 q**，`tRing = K·T` 那条账与它无关）。如果这些也变了，说明改错了地方。

### 4.2 我推翻的旧结论（请特别验，因为这与文档冲突）

`MAP.md` **§30.2** 原先写着：掩码 × 打包件失败是"**稠密明文的系数域乘积越界**，
**与噪声无关**"。本轮 A2 的组 1 vs 组 3 实测：

| 配置 | Pack 产物预算 | 掩码 × Pack |
|---|---|---|
| `bfvDefault(4096)`（q=72 bit） | 2 bit | **0/4096 槽对**，掩码后 **0 bit** |
| `q=3×60`（q=120 bit） | 50 bit | **4096/4096 槽对**，掩码后 **25 bit** |

⇒ 唯一的变量是**预算**。原来那条"与噪声无关"的证据是"×常数明文 1 却完好"——
但**常数明文的代价 ≈0 bit**（实测 14→14/50→50），所以那条对照根本没有分辨力。
**请判断这个推理是否成立**；若你认为"越界"与"预算"其实是同一件事的两种说法，
那也请明说，别让它含糊过去。

### 4.3 上一轮修掉的一条**非确定性**断言（`FusePirAnswerBisectTest` 的 Q1.3b）

它原来同时要求"与错 100 格的差 > #ones"（认残差）和"逐位精确等于 `p[5]`"（不认残差），
**自相矛盾**；而残差每次运行都不同（三次运行 r=5 分别读回 **6 / 5 / 8**）。
**验法**：连跑 A4 三次，若三次都 exit 0 ⇒ 修法有效；若任一次红 ⇒ 修得不彻底（该断言仍在掷骰子）。

---

## 5. 没动过的东西（查验方应主动证明"没动"）

### 5.1 改动清单（`cd E:\学习\密码赛\coding ; git status --short`）

**在库（可 `git diff` 真实比对）**：
`cape-demo/README.md`、`cape-demo/run-demo.ps1`、`cape-demo/web/index.html`、
`docs/缺陷总表.md`、`rgsw-lab/.../MAP.md`、`rgsw-lab/.../cape/CapeDemoService.java`、`rgsw-lab/.../prim/Mpc4jRgsw.java`

**未入库（`??`，**git 给不了基线**，只能靠重跑 + 读代码）**：
`cape/CapeA2Wire.java`、`fusepir/FusePirFourStep.java`、
`probe/CapeA2WireTest.java`、`probe/ScoreMulDomainTest.java`、
`probe/FusePirFourStepTest.java`、`probe/FusePirAnswerBisectTest.java`

### 5.2 native 路径**一行未改**（我声称）—— 请比对

| 对象 | 我这里的值（2026-10-15） |
|---|---|
| `coding/native-jni/lib/blindrotate.dll` | size 3,584,343；LastWrite **2026-10-02 20:24**；SHA-256 前 32 位 `8D533C76C814A17A8F7EF61340313291` |
| `coding/native-jni/src/main/cpp/rgsw_blindrotate.cpp` | size 92,268；LastWrite **2026-10-02 20:24** |
| `git status --short` 里 `native-jni/` | **不出现** |

### 5.3 我**改动了** `CapeDemoService`（必须说清楚，别让它看起来"没动过"）

改动有三类，**请逐类判断是否越界**：

1. 修 2 处载荷 off-by-one（§3.2/§3.3）。
2. **新增两个出口** `/api/client/seal`、`/api/client/decide`（客户端模拟器）+ 两个内部留档类。
3. `runQueryCapeSealed` 在返回前多了一行 `lastCapeResp.set(...)` ——
   **服务器侧为此多留了一份类型化副本**（理由：`out` 里本来就有 `payloadPlain` 与 `ctScoreBytes`，
   留档只是为了不再解析嵌套 JSON，本项目的 JsonParser 不支持嵌套数组）。
   **如果你认为这构成"服务器给自己开后门"，请直接判它为问题** —— 我把它写在这里就是为了能被判。

---

## 6. 我明确**没有**声称的（别替我说，也别要求我做到）

| 没有声称 | 依据 |
|---|---|
| "实现了论文的 CAPE" | `docs/缺陷总表.md` 的 P0-1（行索引无噪声）、P0-4（单 JVM 密钥未隔离）**仍未修** |
| A2/MPC4J 那条有任何**安全性** | 系数模数 `3×60` 是**玩具参数**（不满足 128-bit），`d=16` 是玩具 |
| 前端是**两方部署** | 单进程回环：客户端模拟器与服务端**同 JVM、共享打分密钥**（口径在 `cape-demo/README.md` 的「已知边界」、`/api/state.protocol.clientSimulator`、`/api/client/decide` 响应的 `note` 里；**页面上不再展示** —— 用户 2026-10-15 要求删掉页头那段） |
| `payloadPlain` 是密文 | 它是**明文**（候选 id 就在里面）；真修要发 `B_pay` 条密文（推算 ≈30.9 MB/响应） |
| "5 轮折叠是错的" | 本接线下 5 轮与 6 轮**等价**（因为 `q^BF` 段外为 0），我用破约对照证明了这一点 |
| A 块与 B 块是**同一条**实现 | A 块是 MPC4J 纯 Java（N=4096、K=128、玩具参数）；B 块是 native 真 SEAL（N=8192、t=2³²）。前端跑的是 **B 块** |
| 前端演示了 A2 接线 | **没有**。`CapeA2Wire` 仍是探针级，没接前端 |

---

## 7. 报告格式（请照这个交，别只给"我验证过了"）

```
逐条：
  [ID] A1 / B3 / M1 …
  [命令] 原样粘贴你实际运行的命令
  [原始输出] 关键行（贴够能自证的行；不要只贴 exit code）
  [VERDICT] CONFIRMED | REFUTED | UNVERIFIABLE（说清为什么没法验）
  [偏差] 与查验单不一致的地方（数值漂移不算偏差，**关系**不一致才算）
最后：
  [可疑点] 你认为本文夸大/含糊的地方（最想要这一节）
  [未验项] 你没能验的项 + 原因
```

**判定"数值漂移"与"偏差"的界线**：噪声残差、`Dec(ct_score)` 的槽值、ANSWER 的秒数都会漂；
但**关系**（取整后 == 明文内积、命中候选被收下、逐槽 0/4096、退出码）不该漂。

---

## 8. 可复制的提示词（直接发给另一个 agent）

```
请你独立查验 E:\学习\密码赛 里的一批改动，**不许只读文档就下结论**。

【第一件事】打开并通读查验单：
  E:\学习\密码赛\coding\rgsw-lab\VERIFY-CAPE接线与前端.md

【纪律】照单子 §0 执行：先 Get-Process java | Stop-Process -Force；
同一时刻只跑一个 run-mpc4j.ps1（它清空 mpc4j-out）；javac 乱码看行号再看那一行，
不要去解码错误文本；不要用 Get-Content -Raw 读 UTF-8 源码；Start-Process 在此沙箱被拒，
起服务用后台 job + §3.1 的手工命令。git 不是安全网（很多文件 ?? 未入库）。

【要做的事】按 §1（A 块 4 个探针）→ §3（B 块前端 5 条）→ §4（5 条变异测试）→ §5（没动过的证明）
逐条跑，并**逐条给 VERDICT**（CONFIRMED / REFUTED / UNVERIFIABLE）+ 原始输出关键行。
变异测试做完必须恢复原样，并重跑确认回到全绿。

【时间预算】A 块每个探针 1~6 分钟；B 块一次 ANSWER ≈75 s（N=8192）；
带 -Dcape.selftest=true 的服务启动 ≈7 分钟。允许跑后台 job 并行等，但**不要并发跑两个 run-mpc4j.ps1**。

【重点】§6 是我明确**没有**声称的东西（例如"没实现论文 CAPE""不是两方部署"），
不要把它们算成缺陷；反过来，§2 与 §5.3 是我请你**挑战**的两处设计选择，
如果你认为越界/多余，请直接判为问题并给理由。

【报告】按 §7 的格式交，最后必须给"可疑点"与"未验项"两节。
```

---

## 附：本查验单涉及的文件

| 文件 | 作用 |
|---|---|
| `rgsw-lab/src/main/java/com/fusepir/cape/CapeA2Wire.java` | A 块：A2 侧唯一调用方（四个入口 + 打分 + 判定 + 守卫） |
| `rgsw-lab/src/main/java/com/fusepir/fusepir/FusePirFourStep.java` | A 块：两个**加法式**重载（`coeffBits`、`minScaleK`）；四个入口签名未改 |
| `rgsw-lab/src/main/java/com/fusepir/prim/Mpc4jRgsw.java` | A 块：新增 6 参构造（非标准系数模数） |
| `rgsw-lab/src/main/java/com/fusepir/probe/{CapeA2WireTest,ScoreMulDomainTest,FusePirFourStepTest,FusePirAnswerBisectTest}.java` | A 块判据 |
| `rgsw-lab/src/main/java/com/fusepir/cape/CapeDemoService.java` | B 块：HTTP 服务（修 off-by-one + 两个客户端模拟器出口） |
| `cape-demo/web/index.html` | B 块：前端（三步流程 + 线路面板 + 每候选得分） |
| `cape-demo/run-demo.ps1` | B 块：启动脚本（类名修正） |
| `rgsw-lab/src/main/java/com/fusepir/MAP.md` | 技术账：§32（A2 接线）、§33（前端接入） |
| `docs/缺陷总表.md` | 缺陷账：§四「2026-10-15 本轮」 |
| `cape-demo/README.md` | 前端说明：三步表 + 实测表 + 已知边界 |
