# CAPE native 演示前端

浏览器演示 **CAPE（USENIX Security）+ FusePIR** 的合取关键词 PIR：
常驻 Java 服务持有 native（真 SEAL 4.0.0 C++）上下文，启动时跑一次 SETUP，
之后每次查询只跑 **QUERY / ANSWER / DECODE** 三步并分步计时。

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

停止服务：`Get-Process java | Stop-Process`

---

## 演示怎么用

1. **页面上方 ①** 显示本次进程启动时的 SETUP 用时 —— 它**并排单独显示、不计入查询总耗时**
2. 在搜索框输入关键词回车添加（或直接点下面候选标签）；**第一个是锚**，其余进 `b_qry` 做合取判定
3. 点 **搜索**：ANSWER 约需 **3 分钟**（`maxSetSize=3` 库实测 176 s），页面有进度条（到 95% 停住，不做假完成）
4. 结果区显示三段计时 + 总耗时，以及命中的电影

> **想看"必然查到东西"的效果**，请按 **「随机添加一组可命中的组合」**。
> 它从数据集的 247 个**已验证可用组合**里抽，**池内命中率 100%**。
>
> ⚠️ 如果手动盲选两个关键词，**大概率查到空结果**——这是数据的真实稀疏性，不是 bug。
> 全 8128 个关键词组合里只有 3.04% 能命中（`maxSetSize=4` 时是 4.15%），见 `docs/reports/CAPE-Native演示前端-实现计划书.md` §2.3.1。

---

## 实测数据（N=8192）

| 阶段 | 耗时 | 说明 |
|---|---|---|
| **SETUP** | **≈1.35 s** | 启动时一次；Java 侧 ≈0.3 s（载荷+P 表）+ native ≈1.05 s（SEALContext + 16 个 RGSW 密钥） |
| QUERY | **0.32 ms** | 客户端：锚定位 + BF.Gen 算 `b_qry` + 构造选择子索引 |
| **ANSWER** | **≈176 000 ms** | 服务端 native：249 个单元（`k×B_pay`），全程不解密 |
| DECODE | **0.10 ms** | 客户端：取回载荷 + 逐位比对 + Bloom 合取判定 |
| **三步合计** | **≈176 s** | **不含 SETUP** |

参数：`N=8192, t=65537, d=16, C=26, R=16, k=3, maxValues=3, maxSetSize=3, ℓ_BF=26, B_pay=83`

库：**128 个关键词 / 8266 个值（值空间）/ 349 条关联 / 247 个可用组合**

> 时间以本机实测为准；ANSWER 与库的**总规模无关**，只由 `maxValues`/`maxSetSize` 决定 ——
> 这正是要演示的那件事。
>
> ⚠️ **2026-10-13 基线校准**：本文此前记的「ANSWER ≈154 000 ms」「583 ms/CMUX」是过时数
> （实测偏小约 1.55 倍，已作废）。真实服务两次实测
> `answerMs = 241 400.6 / 237 651.5`（`maxSetSize=4`，330 单元）。
> 随后按 `docs/reports/论文优化路径-列选择与盲旋转前后步骤-2026-10-13.md` 的结论把库
> 重建为 `maxSetSize=3`（`ℓ_BF` 35→26，`B_pay` 110→83，单元数 330→249），
> 实测 `answerMs = 176 076.6` ⇒ **−26%**；代价只有一个：可用组合 337→247（随机添加仍够用），
> 而 Bloom 假阳率反而从 5.5% 降到 1.1%。

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
| B_pay | ≈665 092 | **83** |
| ANSWER | Table 3 ≈3.00 s（OCR，已标可疑） | **≈176 s** |
| 库稠密度 | 真实多对多 | 稀疏二部图（349 条边 / 128 关键词） |

- **行选择子不是论文的真 LWE**：`β = Σaᵢsᵢ + r (mod 2N)`，没有 Δ、没有噪声项 e ⇒ **无安全性主张**
- **列选择用基础 CAPE 选择子**，未接 FusePIR 的 EXPAND
- **单进程回环**：同一个 JVM 既持有密钥又跑查询，**不是真实两方部署**

⇒ 本演示展示的是**架构与计时行为**，不是论文级性能。

---

## SETUP 为什么不做持久化

实测 SETUP 只要 **1.35 s**，是 ANSWER 的 **0.77%**。所以：

- 不需要把密钥/表写盘（N=8192 的 RGSW 有 16.8 MB，且 `Ciphertext::load` 在本机 MinGW 构建上已知不可靠）
- 更不需要动 JNI 去加"常驻引导密钥句柄"——`nativeCapeAnswer` 每次重建引导密钥只花 1.15 s

服务启动时直接跑 SETUP 即可，语义与"只加载不重跑"等价。
