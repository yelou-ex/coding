# CAPE native 演示前端

浏览器演示 **CAPE（USENIX Security）+ FusePIR** 的合取关键词 PIR：
常驻 Java 服务持有 native（真 SEAL 4.0.0 C++）上下文，启动时跑一次 SETUP，
之后每次查询只跑 **QUERY / ANSWER / DECODE** 三步并分步计时。

**2026-10-15 起页面走论文的默认（密文）路径** —— 服务器收不到关键词（见"页面走的是哪条路"）；
同时修掉了两个缺陷（载荷读取 off-by-one、启动脚本类名），见文末。

---

## 一键启动

```powershell
cd coding\cape-demo
.\run-demo.ps1
```

浏览器会自动打开 `http://127.0.0.1:8756/`。

| 选项 | 说明 |
|---|---|
| `-Port 9000` | 换端口 |
| `-N 4096` | 换环维度（默认 8192） |
| `-NoBrowser` | 只起服务，不开浏览器 |
| `-Jvm "-Dcape.selftest=true"` | 启动时跑进程内自检（CAPE 端到端 + sealed 合规路径 + P1-1/P1-3），要几分钟 |

停止服务：`Get-Process java | Stop-Process`
（本脚本用 `Start-Process`；若在受限沙箱里跑，它会失败，改用
`cd coding\rgsw-lab ; .\run-mpc4j.ps1 -Class com.fusepir.cape.CapeDemoService 8756 8192 16 "..\cape-demo\db\keywords.json"`）

---

## 演示怎么用

1. **页面上方 ①** 显示本次进程启动时的 SETUP 用时 —— 它**并排单独显示、不计入查询总耗时**
2. 在搜索框输入关键词回车添加（或直接点下面候选标签）；**第一个是锚**，其余进 `b_qry` 做合取判定
3. 点 **搜索**：页面按论文默认路径跑**三步**（见下节），ANSWER 约需 **75 秒**（实测 75.1~75.8 s），
   页面有进度条（到 95% 停住，不做假完成）
4. 结果区显示：**线路面板**（客户端发了什么 / 服务器收到了什么 / 谁判定）+ 三段计时 + 总耗时
   + 每候选的 `Dec(ct_score)` + 命中的电影

> **想看"必然查到东西"的效果**，请按 **「随机添加一组可命中的组合」**。
> 它从数据集的 136 个**已验证可用组合**里抽，**池内命中率 100%**。
>
> ⚠️ 如果手动盲选两个关键词，**大概率查到空结果**——这是数据的真实稀疏性，不是 bug。
> 全 8128 个关键词组合里只有 1.67% 能命中（`maxSetSize=3` 时 3.04%、`=4` 时 4.15%），见 `docs/reports/CAPE-Native演示前端-实现计划书.md` §2.3.1。

---

## 页面走的是哪条路（2026-10-15 接入）

页面走 **论文 Algorithm 2 的默认（密文）路径**：服务器**收不到关键词**。

| 步 | 出口 | 谁在做 | 说明 |
|---|---|---|---|
| ① | `POST /api/client/seal` | **客户端模拟器** | `b_qry ← BF.Gen(0, 其余关键词)`、`τ ← ‖b_qry‖₁`、`q_BF ← Enc(b_qry)`（422 KB）、锚位置由**公开哈希 H** 算出。返回"该发给服务器的请求体"，**τ 留在客户端** |
| ② | `POST /api/query` | **服务器** | 只收 `{d, anchorColIdx, anchorRowIdx, qBFBytes}` 四个字段 —— 实测请求体里**连关键词子串都不出现**；做锚检索 + 同态打分，返回每候选的 `ct_score` 字节。**不发明文分数、不发 τ、不发候选值 id** |
| ③ | `POST /api/client/decide` | **客户端模拟器** | `V_{K_1}` 由客户端按载荷布局自己解出；判定 `f == fp(K)` 且 `Dec(ct_score,j) == τ` 才收 |

**实测（2026-10-15，N=8192）**

| 查询 | τ | 候选 | `Dec(ct_score)` | 判定 |
|---|---|---|---|---|
| `Adam Sandler + family`（池内命中 1 条） | 5 | v=5706 / 93 / 185 | **5** / 3 / 2 | 收下 **5706** ⇒ 命中 *Spanglish (2004)* |
| `anime + golf`（负对照） | 3 | v=5792 / 4299 / 5622 | 2 / 1 / 1 | **一条都不收** ⇒ 0 条 |

⚠️ **单进程回环**：①②③ 都在**同一个 JVM** 里（浏览器做不了 BFV 加解密），
所以"客户端模拟器"与服务端**共享同一把打分密钥**。它演示的是**协议形态与计时**，
**不是**真实的密钥分离或两方部署 —— 真部署要求客户端自己持有 `sk`。

---

## 实测数据（N=8192）

| 阶段 | 耗时 | 说明 |
|---|---|---|
| **SETUP** | **≈0.9 s** | 启动时一次；Java 侧 ≈0.16~0.24 s（载荷+P 表）+ native ≈0.5~0.66 s（SEALContext + 6 个 RGSW 密钥）+ 一个真实单元标定 |
| QUERY（① seal） | **< 1 ms** | 客户端：锚定位 + BF.Gen 算 `b_qry` + `Enc(b_qry)` + 构造选择子索引 |
| **ANSWER（②）** | **≈75 s** | 服务端 native：180 个单元（`k×B_pay`），全程不解密；**锚检索占 99%**（≈75.0 s），同态打分 0.6 s |
| DECODE（③ decide） | **< 1 ms** | 客户端：从载荷解 `V_{K_1}` + 逐条 `Dec(ct_score)` + Bloom 合取判定 |
| **三步合计** | **≈75.6 s** | **不含 SETUP**（2026-10-15 实测；同日另一轮 75.1 s） |

参数：`N=8192, t=2^32, base=2^32(levels=6), d=16, C=26, R=16, k=3, maxValues=3, maxSetSize=2, ℓ_BF=18, B_pay=60`

库：**128 个关键词 / 8267 个值（值空间）/ 378 条关联 / 136 个可用组合**

> 时间以本机实测为准；ANSWER 与库的**总规模无关**，只由 `maxValues`/`maxSetSize` 决定 ——
> 这正是要演示的那件事。
>
> ⚠️ **基线沿革（都实测过，留档以免再被引用成"当前值"）**
>
> | 阶段 | 配置 | ANSWER 实测 |
> |---|---|---|
> | 最初文档里的数 | — | ≈154 000 ms（**作废**，偏小约 1.55 倍） |
> | 真实基线 | `maxSetSize=4`，330 单元 | **241 400.6 / 237 651.5 ms** |
> | 降载荷（`maxSetSize` 4→3） | `ℓ_BF` 35→26，`B_pay` 110→83，330→249 单元 | **176 076.6 ms（−26%）** |
> | 降盲旋转层数 | `t` 65537→2³²，gadget 基 2¹⁶→2³²，`levels` 11→6 | **102 314.7 ~ 116 347 ms** |
> | + C6（合并 `decompose` 的两次正向 NTT） | 同批 A/B | 12.44 → 12.00 ms/CMUX（**−3.5%**） |
> | **+ C9（`maxSetSize` 3→2，当前）** | `ℓ_BF` 26→18，`B_pay` 83→59，249→177 单元 | **36 489 ms（−29%，与单元数成正比）** |
>
> 详据：`docs/reports/论文优化路径-列选择与盲旋转前后步骤-2026-10-13.md`（载荷）、
> `docs/reports/盲旋转提速41.9%-gadget基2^16到2^32-2026-10-13.md`（层数）、
> `docs/reports/ANSWER两段速度实测-列选择与盲旋转-2026-10-13.md`（列选择 vs 盲旋转剖面）。
>
> ⚠️ **绝对读数会随时间漂**：同一配置连续测到 102.3 / 104.3 / 114.0 / 116.3 s（机器越跑越热）。
> **只有同一 session 内的 A/B 比才可靠**，跨次引用请带上测量时间。

---

## 目录

```
cape-demo/
├─ run-demo.ps1              一键启动（纯 ASCII：PowerShell 5.1 按 GBK 读 .ps1）
├─ README.md
├─ db/
│  ├─ build_dataset.py       从 MovieLens 构造 keywords.json
│  └─ keywords.json          128 关键词 / 8266 值 / 247 可用组合（461 KB）
└─ web/
   └─ index.html             单文件前端（内联 CSS/JS，零依赖，固定浅色主题）

rgsw-lab/src/main/java/com/fusepir/rgsw/
├─ CapeDemoData.java         读 keywords.json + 构造 payload / P 表（自带极简 JSON 解析）
├─ CapeDemoSetupProbe.java   SETUP 计时探针 + 网格布局 + resolveDb
├─ CapeDemoService.java      HTTP 服务（com.sun.net.httpserver）+ 四步编排
└─ Json.java                 极简 JSON 输出
```

**既有文件零改动**：`CapeEndToEnd4.java`、`CapeEndToEndNative.java`、`NativeCapeAnswer.java` 都没动。

---

## 重新构造数据集

```powershell
cd coding\cape-demo\db
python build_dataset.py --max-values 3 --max-set-size 3
python build_dataset.py --help          # 全部选项
```

改完库记得重启服务（SETUP 在启动时跑）。

---

## 已知边界（演示时不要夸大）

| 项 | 论文 CAPE | 本演示 |
|---|---|---|
| N | 16384 | 8192 |
| ε_BF | 2^-20 | **2^-6（玩具值）** |
| B_pay | ≈665 092 | **60** |
| ANSWER | Table 3 ≈3.00 s（**模型输出，非实测；见逐子程序核对报告**） | **≈75 s**（2026-10-15 实测） |
| 库稠密度 | 真实多对多 | 稀疏二部图（378 条边 / 128 关键词） |
| 两方部署 | 客户端与服务端各持一把 | **单进程回环**：客户端模拟器与服务端**同 JVM**、共享打分密钥 |
| `payloadPlain` | 客户端做 `Dec_{s_R}` | **明文**（回环里服务端解的密）；真修要发 `B_pay` 条密文（≈30.9 MB/响应） |

- **行选择子不是论文的真 LWE**：`β = Σaᵢsᵢ + r (mod 2N)`，没有 Δ、没有噪声项 e ⇒ **无安全性主张**
- **列选择用基础 CAPE 选择子**，未接 FusePIR 的 EXPAND
- **单进程回环**：同一个 JVM 既持有密钥又跑查询，**不是真实两方部署**
  （口径在本文「已知边界」与 `/api/state.protocol.clientSimulator` 里；⚠️ **页面上不再展示这一段** ——
  2026-10-15 按用户要求把页头那段说明删掉了，所以别把页面的沉默读成"它声称两方部署"）

⇒ 本演示展示的是**架构与计时行为**，不是论文级性能。

---

## 本轮修掉的两个缺陷（2026-10-15，都实测过）

| # | 缺陷 | 症状 | 证据 |
|---|---|---|---|
| 1 | **载荷读取下标 off-by-one** | 40-bit 指纹上线后 `fpSlots` 由 1 变 **2**（`B_pay` 59→60），而读取侧仍按"fp 占 1 槽"写：`payload[1]` 当候选数、`2 + j·(1+ℓ_BF)` 当值槽 ⇒ **候选数读成指纹高位 limb**，合取判定永远不命中 | 修前：页面查 `Adam Sandler + family` 返回 `hit=false`；`sealed` 自检 `valueCount=171`、`接受=[]`、**3 PASS/1 FAIL**。修后：`valueCount=3`、`接受=[5706]`、**4 PASS/0 FAIL**，页面命中 *Spanglish (2004)* |
| 2 | `run-demo.ps1` 的**类名写错**（`com.fusepir.demo.CapeDemoService` 不存在，真名是 `com.fusepir.cape.CapeDemoService`） | "一键启动"永远失败，只报 `service exited early`，看起来像服务起不来 | 全 classpath（源码/jar/classes）里都不存在 `com.fusepir.demo.CapeDemoService` |

> 第 1 条之所以能藏住：`rec[b] != want[b]` 那条**整体逐位比照**（不按下标读）一直全绿 ——
> 它证明的是"解出来的载荷 == 建库时的载荷"，与"解析侧的下标对不对"无关。
> 判据已按项目纪律改成走 `FusePirSetup.countOffset/valueOffset`（全项目唯一一份布局算式），
> 不再手写下标。

---

## SETUP 为什么不做持久化

实测 SETUP 只要 **0.9 s**，是 ANSWER 的 **2.5%**。所以：

- 不需要把密钥/表写盘（N=8192 的 RGSW 有 16.8 MB，且 `Ciphertext::load` 在本机 MinGW 构建上已知不可靠）
- 更不需要动 JNI 去加"常驻引导密钥句柄"——`nativeCapeAnswer` 每次重建引导密钥只花 1.15 s

服务启动时直接跑 SETUP 即可，语义与"只加载不重跑"等价。
