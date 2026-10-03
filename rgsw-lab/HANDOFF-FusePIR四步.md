# 交接：FusePIR 四步 / ANSWER 实现（2026-10-15 收尾）

> ## 📌 本项目的一条长期规矩（用户 2026-10-15 立）
> **只要会话的上下文开始压缩（compaction），就立刻写好"交接单 + 开新对话提示词"**，
> 让用户能开新对话继续，不要等被压缩切断再补。
> 具体要求：
> 1. 交接单**写进工作区文件**（不要只写在聊天里 —— 聊天会被压缩掉）；
> 2. 在聊天里同时给一段**可直接复制的提示词**；
> 3. 要点同步进 `MAP.md`。
>
> 位置约定：交接单放 `coding/rgsw-lab/HANDOFF-<主题>.md`。
> （2026-10-15 试过写进 Hindsight，服务未启动 ⇒ `ECONNREFUSED 127.0.0.1:9077`，
> 所以本条以**本文件**为准。）
>
> ## 📖 开工读序（新会话照此顺序，别跳）
> 1. `src/main/java/com/fusepir/MAP.md` 的 **§18–§27**；
> 2. **本文件**；
> 3. 才去看源码。

> **这份文件是给"新对话"用的**。开新对话时把本文件附上（或用 §7 的提示词）。
> 详细技术账在 `src/main/java/com/fusepir/MAP.md`（§18–§27）；本文只放**新会话立刻需要的**：
> 现状、卡点、命令、以及"别再从头发散"的下一步。

---

## 0. 一句话现状（2026-10-15 **第三轮**：四步已跑通，exit 0）

**`FusePirFourStepTest` 现在 exit 0、全部判据达成**（P1/P2/P3/P4.00/P4.0d/P4.0a/P4.0b/P4.0c/P4/P5/P6/P7）。
`FusePirAnswerBisectTest` 同样 exit 0。技术账：**MAP §29（种子同源根因）+ §30（两个卡点的解法）**。

| 判据 | 结果 |
|---|---|
| P4.0a 算术层相位（Z_{q_R} 上算完只舍入一次，无容差） | **61/61** |
| P4.0b 交付层相位（过桥 + 除 K） | **61/61，最大偏差 0** |
| P4.0c 落点搜索 | **恰好 1 个** = 每路 `+P[r_a]` |
| **P4 四步端到端** | **恢复出 `[1007,1008,1009]`** |
| **P5 A2 ANSWER 3 的 parse** | 全绿（含 0c/0d/0f/0g 正负对照） |
| **P6 / P7** | 全绿 |

**两条卡点各用一句话记住**：
1. **桥的缩放残差** `|E| ≤ ones/2`、与明文模数无关 ⇒ 唯一解法是**字段乘 K 倍精度存放**
   （应答通道明文模数 `tRing = K·T`，`K > ones`；客户端解码时除以 K 一次舍入）。
   **布局仍按字段域 T 算 ⇒ `B_pay` 仍是 61、值域与 limb 宽度都没变。**
2. **`bloomCt` 的掩码不是噪声问题**（上一轮我归因错了），是**稠密明文的系数域乘积越界**：
   槽掩码在系数域稠密，乘上槽值可达 `t−1` 的打包件 ⇒ 乘积系数超 `t/2` ⇒ 取模后被 NTT
   摊到每一个槽。**现在 `bloomCt` 只旋转、不掩码**（段外置零交给 CAPE 的 `q^BF`）。

**⚠️ 已知的三处"两个模数混淆"陷阱**（`T` = 字段域 65537、`tRing` = 应答通道 `K·T`）：
建表 `/` 判据的参考系 / `divideScale` 不能整体中心化（`K·field` 可超 `tRing/2`）。详见 MAP §30.1 的表。

## 0.1 第二轮那段"卡在 ANSWER 6"的记录（留作教训，已被推翻）


**ANSWER 5 / 6 从头到尾都是对的。** 那个 "0/61" 的根因是
**建表位置函数与 `pp` 发布的 ρ_H 不同源**（两处种子差 1），已修 + 加了守卫。
修完：**算术层 61/61 精确**、交付层 61/61 在残差上界内、落点搜索给出**唯一**组合
`每路 +P[r_a]`。详见 `MAP.md` **§29**。

**现在真正卡住"四步端到端"的是另外两件，都与 ANSWER 5-6 无关**：

| # | 卡点 | 精确症状 | 出处 |
|---|---|---|---|
| ① | **`q_R→Z_t` 桥的缩放残差（±1..2）** | 小字段被污染：`m_i` 解出 `4`（真值 3）⇒ `parsePayload` 抛；`decode` 判 ⊥；bloom 的 0/1 位变成 −1/0/1/2 | MAP §24.4 / §26.3（已登记）→ 本轮给了**精确复现** |
| ② | **`Resp.bloomCt(j)` 的"掩码"那一步** | 掩码乘打包件 **0/4096**（解出均匀随机值 = 解密失败）；同一条掩码乘**新加密**密文 4096/4096 | MAP **§29.8**（本轮新发现） |

**§4.2（旋转改 2 的幂组合）已做完并逐位验过**（`P5.0a/P5.0c/P5.0d/P5.0e` 全绿）；
卡住的是它**后面**那一步"掩码"。三个选项写在 §29.8，**尚未选**。

---

## 1. 环境与命令（照抄即可）

```powershell
cd E:\学习\密码赛\coding\rgsw-lab
# 编译 + 运行（脚本会先清空 mpc4j-out ⇒ 不要并发跑两个）
.\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirFourStepTest 16 4096 16 18
#                                     nkw=16  N=4096  d=16  ℓ_BF=18
```

* JDK：`D:\Java\jdk`（脚本会用 `javac/java`）。
* **⚠️ `run-mpc4j.ps1` 每次启动都 `Remove-Item mpc4j-out`** ⇒ 同一时刻只能跑一个。
* **⚠️ javac 的错误信息在本机是 GBK**，经 PowerShell 回来是乱码。
  实测有效的读法：**先看它报的行号**，再用 `read` 工具读那一行 —— 比去解码错误文本快得多。
  想直接读文本：`[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936)` 后再调 `javac`。
  **`javac -J-Duser.language=en` 会失败**（PowerShell 把内联 `-D` 拆坏，报"无效的标记"）。
* `Start-Process` 被沙箱拒绝；`Remove-Item` 可以用。
* **禁止**对 UTF-8 源码用 `Get-Content -Raw` / `Set-Content`（历史 mojibake 事故）。
* 子代理跑自己的 out 目录时要用 `mpc4j-out-ks` 这类**独立目录**，别碰 `mpc4j-out`。

---

## 2. 本轮新建/改动的文件

| 文件 | 内容 | 状态 |
|---|---|---|
| `fusepir/FusePirFourStep.java` | **CAPE 能调的四个入口**：`setup` / `query` / `answer` / `decode`（+`answerSamples` 拆出 ANSWER 5-11；`Resp` 带 `valueCt`/`bloomCt`） | 结构通、ANSWER 6 未通过 |
| `fusepir/AnswerOps.java` | **ANSWER 1-13 逐步的接口**：`polynomialNtt` / `constantSelectorNtt` / `columnSelect` / `blindRotateStep` / `sampleExtract0Rns` / `toTruncatedZLwe` / `addPaths` / `phaseOf`(诊断) | 新，全部已用 |
| `probe/FusePirFourStepTest.java` | 按 **CAPE 的调用顺序**驱动四入口 + 隔离实验 P4.00/P4.0d/P4.0/P4.0b/P4.0c | 见 §4 |
| `fusepir/FusePirPackSlot.java` | A1 ANSWER 13 的槽位域适配器 + `rnsToT`/`sumRns`/`packFromRns`（MAP §23） | ✅ 4/4 exit 0 |
| `prim/LweRlweConversion.java` | `liftLweSecretToRlwe`（规范 §0.5 的 `s_R = Σ_{j<d} s_L[j]X^j`，MAP §26） | ✅ exit 0 |
| `prim/BlindRotateOps.java` | `requireIndexConvention` / `requireIndexModulus`（P0-1 修法②，MAP §23.3） | ✅ exit 0 |
| `prim/LweKeySwitch.java` + `probe/LweKeySwitchTest.java` | LWE 密钥切换 N→d（子代理做，**我独立重跑确认 30/30**） | ✅ exit 0 |
| 其它探针 | `FusePirSecretLiftTest` / `FusePirPackSlotTest` / `FusePirPayloadLayoutTest` / `BlindRotateIndexGuardTest` / `FusePirPackSlotRnsTest` | ✅ 全部 exit 0 |
| `MAP.md` | **§18–§27** 是全部技术账 | — |

---

## 3. 已经**实测通过**的部分（判据都在探针里，可重跑）

| 内容 | 判据 | 结果 |
|---|---|---|
| CAPE 调用面 | 算法 2 原文只有 **4 处**：`A2 SETUP 11` / `QUERY 1` / `ANSWER 2` / `DECODE 2`；另有 `extendBloom`(A2 SETUP 12) 与 `st^F_S→st_S`(13) 已存在 | 签名已对齐 |
| **`DB^CAPE` 口径** | A2 SETUP 11 传的是**加宽后的** DB（值带 `b_v`）⇒ `perValue=1+ℓ_BF`、**`B_pay=61`** | P1 ✅ |
| SETUP | `R·C=48 ≥ L_BFF=48`；**铺开后秘密非零 5 个、最高下标 13 < d=16** | P1 ✅ |
| BFF 编码 | `Σ_a D[h_a(K)] = y_K`，**16/16** 个关键词 | P2 ✅ |
| QUERY | `(r_a,c_a)` 与 `h_a(K)` 一致、`recombine(R)` 回到 `u_a`、`q^row` 长 d、`q^col` 有 C 条 | P3 ✅ |
| **ANSWER 5（列选择）** | 解密 `acc` 与 `P_{c_a,b}` **逐系数相同：0/4096 不符** | **P4.00 ✅** |
| **`acc` 的形态** | `isNttForm()=false`，且 NTT∘iNTT 往返后 **0/4096 不符** ⇒ 真·系数形态 | **P4.0d ✅** |
| ANSWER 13（Pack） | 产出 `packed(t=65537, B_pay=61, 段起点=[5,24,43], 最高参与槽=60)` —— 与 §19 预测逐项相符 | P4 ✅ |
| **Pack 是忠实的** | 打包件解出的错值与相位检查的错值**完全相同** ⇒ 错在 ANSWER，不在 Pack | ✅ 对照 |

---

## 4. ✅ ANSWER 6 已清（根因不是盲旋转）—— 见 MAP §29；本节的旧结论**保留作教训**

> ⚠️ **2026-10-15 第二轮：本节 4.1 的三步已全部做完，三条嫌疑全部不成立。**
> 真根因是**位置函数种子不同源**（`BffEncode` 用 `seed0`、`pp` 用 `rhoH`，差 1），已修 + 加守卫。
> 修后：算术层 **61/61 精确**；交付层 61/61 在残差上界内；P4.0c 给出**唯一**组合 `每路 +P[r_a]`。
> **下面的旧文字保留**，因为它示范了"一条判据同时用到真值与被测物、却没先证明两者输入同源"
> 会怎样把人带偏（P4.0c 的 0/729 是**结构性**的，不是"落点不是 P 的系数"）。

### 4.0 旧记录（已被 §29 推翻，留作教训）

**症状**：`P4.0`（判据 `β − Σ_{k<d} a_k·s_L[k] mod t`，**完全不经过 Pack**）
⇒ **0/61 个字段**等于真值（例：字段 4 相位 24244，真值 1007）。

**已经被实测否掉的三条**（不要再从这三条查）：

| # | 假设 | 实验 | 结果 |
|---|---|---|---|
| 1 | 列选择错 | P4.00：解密 `acc` vs `P_{c_a,b}` 逐系数 | **0/4096 不符** ⇒ **否掉** |
| 2 | 落点错（转到了 `P` 的别的系数 / 差个符号） | P4.0c：暴力搜"每路贡献 `±P[k]` 或 `0`"的全部 `(2R+1)^3=729` 组合，要求**同时**解释 61 个字段 | **0 个组合成立** ⇒ **否掉**（`P` 支撑只有 `[0,4)`，"转错系数"最多给 `±P[k]` 或 0） |
| 3 | `acc` 形态不对（NTT 域乘 `X^k` ≠ 乘单项式） | P4.0d：NTT∘iNTT 恒等判据 | **0/4096 不符** ⇒ `acc` 是系数形态 ⇒ **否掉** |
| 附 | 零选择子用 `encrypt(全零)` 而不是 `encryptZero()` | 换成 `encryptZero()` 后重跑 | 相位几乎不变（±1 = 噪声）⇒ **否掉** |
| 附 | 奇偶符号 `(−1)^{r_a+1}` | P4.0b | **0/61** ⇒ 否掉 |

**⇒ 只剩一条主嫌疑：`bk` 与 `qRow` 的"同源"**

* `bk[i] = m.encryptRgswConstant(sL[i])` —— 在 **`s_R`** 下加密 `s_L[i]`；
* `qRow[a] = BlindRotateOps.lweEncryptIndex(sL, r_a, 2N, rnd)` —— β 在 **`s_L`** 下。
* 盲旋转累的是 `X^{Σ a_i·(bk 里那个比特)}`，所以两者必须**逐位同源**。
  本仓库**反复**在这一点上出过事（`CapeQuery` 里那段最长的不变量注释、P1-1 的四轮教训），
  而本探针这条路径**没有做** `CapeQuery` 那种同源对账。

### 4.1 下一个最小实验（按顺序，别跳）

1. **把 `HashGenRhoTest` P-9 那条**已知通过的**配方原样搬进本管线**：
   同一个来源同时产生 `bk` 与 `qRow` 的比特、`r_a` 取**奇数**（P-9 用的 `rA=5`，
   而我们的三路 `r_a = 2,1,0` 奇偶混杂）、累加器用直接加密的多项式。
   若这样能对上 ⇒ 问题在"我们的 `bk`/`qRow` 配对"或"偶数 r"；
   若还对不上 ⇒ 问题在 `columnSelect` 的输出与"直接加密"的差别（比如 parmsId / 层数）。
2. **查 `cmux` 的分支方向**：`Mpc4jRgsw.cmux(rgsw, a, b)` 在 bit=1 时返回 `a` 还是 `b`？
   与 `BlindRotateOps.blindRotateByBits` 的注释（"z_i=1 时把 ACC 乘 `X^{−2^i}`"）对齐。
   若方向反了，累的会是 `X^{Σ a_i(1−s_i)}` ⇒ 现象正好是"相位像随机数"。
3. 再查 `qRow` 的 `β` 是否真的 `≡ ⟨a,s_L⟩ + r_a (mod 2N)`（打印 `⟨a,sL⟩` 与 β 核对）。

#### 4.2 ✅ 已做（2026-10-15 第二轮）：旋转改成"2 的幂组合"

`FusePirFourStep.rotateRowsByComposedBits` —— 把步长按二进制拆开、逐位旋转复合。
`galoisKeysFor` 只给 `{0}∪{1,2,4,…}`，所以 `4 / 23 / 42`（值槽）与 `5 / 24 / 43`（Bloom 段起点）
里那些非 2 的幂**必须**这么走，否则 `Galois key not present`。
**判据全绿**：`P5.0a` 值槽对齐 3/3；`P5.0c` 负对照（多转一格必须错）；`P5.0d` 往返 4096/4096；
`P5.0e` 只旋转与打包件逐位相同。

🔴 **但它后面那一步"掩码"卡住了**（`P5.0b` 0/3）—— `bloomCt` 在旋转**之后**还要
`maskFirstSlots`（只留槽 `[0,ℓ_BF)`），这一步把密文解坏。**诊断已完成**（MAP §29.8）：
唯一剩下的解释是**噪声预算**（槽掩码在系数域稠密、`l1 ≈ N·t/2`；新加密无噪声所以连乘两次都精确，
`RingPack` 产物带噪声所以一次就过界）。三个选项见 §29.8，**尚未选**。

## 4.3 旧的"还没验到的"清单（保留）

* **P5（A2 ANSWER 3 的 parse）**：`Resp.valueCt(j)`/`bloomCt(j)` 需要把第 j 个候选的槽
  转到槽 0 —— 而 `galoisKeysFor(m)` 只提供步长 `{0}∪{1,2,4,…,N/4}`，
  **`24`、`43` 这类非 2 的幂的步长会抛 `Galois key not present`**。
  ⇒ 必须**用 2 的幂组合旋转**（`slot` 的二进制各位依次转）。这一点还没实现。
* `decode` 目前也被 4 挡住（解出的 `m_i` 是垃圾值）。

---

## 5. 必须记住的既有结论（别重新推）

1. **A1 通道的明文模数就是 65537**（`FusePirParams.NATIVE_PLAINTEXT_MODULUS`）；
   CAPE 演示服务那条 `t=2^32`（`keywords.json` 的 `plainModulus`）**上 Pack 不可能**
   —— `2^32` 上连槽位选择子都不存在（MAP §18.2 的 mod-4 证明）。
2. **`sampleExtract` 是维数盲的**：机械返回 `N+1` 项，**不管秘密支撑在哪**。
   铺开后的 `s_R` 只在 `[0,d)` 非零 ⇒ **必须显式截到 `d`**，否则 Pack 索要 `nLwe=N` 行密钥
   （N=8192 ⇒ **12.0 GB**）。已收进 `AnswerOps.toTruncatedZLwe`。
3. **`Plaintext.isNttForm()` 在本移植里默认就是 true**，**不能**当"我准备的是系数形态"的判据
   （判据恒真）。要 NTT 明文就显式 `transformToNttInplace`。
   ⚠️ 但**密文**的 `isNttForm()` 实测是可靠的（P4.0d）。
4. **`CtOps.ctPtMul` 只是转发 `multiplyPlain`**，不做形态处理；两侧必须同为 NTT。
5. **`NttTables` 的第一个参数是 `log2(N)`**，不是 `N`（传 N 会建长度 1 的表）。
6. **手工造的 `SecretKey` 必须**：data 覆盖**全部声明素数**（含 special prime）；parmsId 用
   **`m.sk.parmsId()`**（`context.firstParmsId()` 明明 `==` 却过不了 `ValCheck`）。
7. `m.sk` 是 `Mpc4jRgsw` 的公开字段；`Mpc4jRgsw` 有 `encryptZero()`，也有私有的 `toNtt()`。
8. **分层图**：`prim ← bloom ← bff ← fusepir ← cape`。
   **`prim` 不能依赖 `fusepir`**（`AnswerOps` 因此放在 `fusepir/`）。
9. **`FusePIR_Pack源码.zip` 已解到 `refs/fusepir-pack/`**：它是另一条 **递归 automorphism Pack**
   （`fusepir_he.cpp:692-743`），密钥是 **Galois keys（14 个元素，264 MB @ N=16384）**，
   **与 `nLwe` 无关** —— 是解掉 12 GB 的结构性方向。但它要 **SEAL 4.4**（我们 4.0.0）、
   非独立工程、原项目 `E:\pir` 已不在。**只能当算法参考。**
10. **不要再犯的三个格式坑**：① 复用同一个 `Plaintext`（`ctPtMul` 会就地改形态）；
    ② 用 `isNttForm()` 判明文形态；③ `q^col` 密文忘了转 NTT ⇒ `NTT form mismatch`。

---

## 6. 未提交

仓库仍是**未提交**状态（`git push` 由用户执行）。
本轮的改动没有 commit，全部在工作树里。

---

## 7. 可复制的开新对话提示词

```
继续 E:\学习\密码赛 里的 FusePIR 四步实现工作。先说结论再动手，不要重新发散。

【背景】工作目录 coding\rgsw-lab；技术账在 src\main\java\com\fusepir\MAP.md 的 §18–§27，
交接单在 coding\rgsw-lab\HANDOFF-FusePIR四步.md（先读这两处，别从源码重新推导）。

【现状】FusePIR 四步（Algorithm 1）的接口已全部实现：
fusepir/FusePirFourStep.java（CAPE 能调的四个入口 setup/query/answer/decode）
与 fusepir/AnswerOps.java（ANSWER 1-13 逐步的接口）。
Setup / Query / Answer 5（列选择，逐系数精确）/ Pack / Decode 都已实测正确；
唯一卡点是 ANSWER 6（盲旋转）：它产生的相位不是所选 P_{c_a,b} 的任何系数。

【已被实测否掉的（不要再查这三条）】
1. 列选择错 —— P4.00 显示 acc 与 P_{c_a,b} 逐系数 0/4096 不符；
2. 落点错（转到别的系数/差符号）—— P4.0c 暴力搜遍 ±P[k]/0 的全部组合，0 个能解释 61 个字段；
3. acc 形态不对 —— P4.0d 用 NTT∘iNTT 恒等判据确认真是系数形态。

【只剩一条主嫌疑】bk 与 qRow 的同源性：
bk[i] = m.encryptRgswConstant(sL[i])（在 s_R 下），而 qRow 用 lweEncryptIndex(s_L,…)。
本仓库反复在这一类"同源"上出过事。请按交接单 §4.1 的三步依次做：
先把 HashGenRhoTest P-9 那条【已知通过】的配方（同源比特 + 奇数 r + 直接加密的累加器）
原样搬进本管线，看能否对上；再查 Mpc4jRgsw.cmux(rgsw,a,b) 的分支方向；
最后核对 β ≡ ⟨a,s_L⟩ + r_a (mod 2N)。

【判据】.\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirFourStepTest 16 4096 16 18
【已做完、别再重查】ANSWER 6 的"0/61"根因是**位置函数种子不同源**（BffEncode 用 seed0、
pp 用 rhoH，差 1），已修 + 加了跨层守卫 requirePositionsMatch。修后算术层 61/61 精确
（AnswerOps.phaseOfRns）、交付层 61/61 在残差上界内、P4.0c 给出唯一组合"每路 +P[r_a]"。
§4.2（旋转改 2 的幂组合）也做完并逐位验过。**全部细节见 MAP.md §29。**
【现在真正卡住四步端到端的两件，都与 ANSWER 5-6 无关】
 ① q_R→Z_t 桥的缩放残差 ±1..2 污染小字段（m_i 解出 4 而非 3 ⇒ decode 判 ⊥）；
 ② Resp.bloomCt 的"掩码"那一步在打包件上不成立（0/4096；同一条掩码在新加密上 4096/4096）。
 ② 的三个候选解法在 MAP §29.8，**需要先决定走哪条**（①/②是两件独立的事）。
【纪律】先跑再下结论；每条断言配正/负对照；报错给行号+原始输出；不要动 CapeDemoService/native。

【纪律】每个断言配正/负对照；先跑再下结论；不许把"跑通"说成"端点正确"；
报错时给行号+原始输出；不要动 CapeDemoService/native 路径；
run-mpc4j.ps1 每次会清空 mpc4j-out，不要并发跑。
```
