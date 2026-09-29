# 在 IDEA 里跑通（四步端到端）

> **好消息：不用改任何配置，点绿三角就能跑。**
> 已把「需要密钥切换」的类的默认参数改成了 4096，直接运行即通过。
>
> 已实测：用 IDEA 的等价 classpath 编译 **66 个源文件**、
> 不带任何参数运行 `CapeEndToEnd4` → 四步端到端 **4/4 通过**。

---

## 一、⚠️ 唯一的硬要求：JDK 25

```
lib/mpc4j-crypto-fhe-seal.jar 里的 class 是 major 69 = JDK 25
JDK 24 及以下 → 报「类文件版本 69 应为 68」，读不了
```

本机 JDK 25 在 **`D:\Java\jdk-25`**。

**IDEA 设置**（中文包）：
`文件 → 项目结构…`（`Ctrl+Alt+Shift+S`）→ `项目设置 → 项目` →
**SDK 选 `jdk-25`**，**语言级别选 `25`**。

> ⚠️ 系统默认 `JAVA_HOME` 是 `D:\java`（**JDK 24**），
> 所以必须**显式**把 Project SDK 指到 `D:\Java\jdk-25`，不能靠默认。

---

## 二、直接运行（不需要改配置）

打开：

```
rgsw-lab/src/main/java/com/fusepir/rgsw/CapeEndToEnd4.java
```

在 `main` 左侧点绿色三角 → **运行**。

**就这样，不需要填「程序实参」。**

预期输出结尾：

```
[params] N=4096, t=65537, 声明素数=3(109 bit) 工作层=2(72 bit), base=65536, levels=5
...
--- 3. ANSWER（服务器）---
    列选择×24 + 盲旋转×24 + Pack + 打分，约 5000 ms
    同态 Bloom 得分 = 2

--- 4. DECODE（客户端）---
    恢复 payload   = [70, 2, 11, 1, 1, 22, 0, 1]
    原始 payload   = [70, 2, 11, 1, 1, 22, 0, 1]
    [PASS] 4.1 BFF 三路重建 == 原始 payload
    [PASS] 4.2 指纹校验通过
    值的数量 = 2，第一个值 = 11，Bloom = [1, 1]
    同态得分 = 2，τ = 2 → 命中
    [PASS] 4.3 判定命中
    [PASS] 4.4 恢复的值 ∈ 明文答案集

=== CAPE 四步端到端跑通（SETUP → QUERY → ANSWER → DECODE）===
```

**建议加内存**：默认 JVM 堆可能不够（Pack + 打分较重）。
`运行 → 编辑配置…` → 选中配置 → **`修改选项`** → 勾 **`添加 VM 选项`** → 填 `-Xmx12g`。

---

## 三、为什么之前必须手填参数（已修复）

`CapeEndToEnd4` 原来的默认参数是 `2048 16`，而 **N=2048 跑不到最后两步**：

```
BloomScoring 要构造 Galois 密钥 → 需要密钥切换 → 需要 ≥2 个工作素数
而 CoeffModulus.bfvDefault(2048) 只给 1 个
→ IllegalArgumentException: keyswitching is not supported by the context
```

**已把默认值改成 4096**，并顺手修了另外三个同样"裸跑必崩"的类：

| 类 | 原默认 | 现默认 | 原因 |
|---|---|---|---|
| `CapeEndToEnd4` | 2048 | **4096** | Pack + Bloom 打分要密钥切换 |
| `Mpc4jRgsw` | 2048 | **4096** | CMUX 要重线性化 |
| `CtCtMulVsBlindRotate` | 2048 | **4096** | 要重线性化 |
| `BloomInnerProductProbe` | 2048 | **8192** | 要重线性化（原来得手传 8192） |

**仍然想跑快一点**：在配置里填「程序实参」`2048 16`，能跑到盲旋转为止（约 2 秒）。

---

## 四、参数下限（会直接影响"能不能跑完"）

| 操作 | N=2048 | N≥4096 |
|---|---|---|
| 列选择（密文×明文） | ✅ | ✅ |
| 盲旋转 | ✅ | ✅ |
| 抽常数项 / 三路相加 | ✅ | ✅ |
| **Pack** | ✅ | ✅ |
| **Bloom 打分** | ❌ | ✅ |

**根因**：密钥切换需要 ≥2 个工作素数。

---

## 五、怎么打开工程

**用 IDEA 打开 `cape/` 目录**（含 `lib/`、`rgsw-lab/`、`lwe-java/` 的那一层）。

工程里已经放好 IDEA 原生模块文件，也配了 Maven 聚合：

```
.idea/modules.xml                    模块清单
.idea/misc.xml                       源码级别(JDK_25) / SDK名(jdk-25)
lwe-java/lwe-java.iml
rlwe-java/rlwe-java.iml
rgsw-lab/rgsw-lab.iml                ← 依赖 lib/ 下 12 个 jar（相对路径）+ lwe-java + rlwe-java
cape-fusepir-database-handoff/*.iml

pom.xml                              根聚合（4 个模块）
```

IDEA 会问是否导入为 Maven 项目 → 选 **导入** 即可。

---

## 六、其它可以跑的入口

| 类 | 作用 | 默认参数（已改好） |
|---|---|---|
| `CapeEndToEnd4` | **四步端到端** | `4096 16` |
| `CapeAnswerHomomorphic` | Pack + Bloom 打分同态化 | `4096 16` |
| `CapeAnswerFull` | ANSWER 骨架（到三路相加） | `2048 32` |
| `CapeColumnSelectionIndependent` | 列选择单独验证 | `2048` |
| `BlindRotateOps` | 盲旋转口径对比 | 2048 |
| `RingPack` | Pack 自检 | `8192 8` |
| `BloomScoring` | 打分自检 | `4096` |
| `Mpc4jRgsw` | RGSW 地基自检 | `4096` |

**明文侧**（`cape-fusepir-database-handoff`，不依赖 MPC4J，任意 JDK 17+）：

| 类 | 作用 |
|---|---|
| `ArithmeticBffSelfTestMain` | BFF 自检五项 |
| `BloomConjunctionCheck` | Bloom 合取判定 |
| `DatabaseInitializerMain` | 参数规模对比 |

**极小验证层**（`tiny-cape`，零依赖，独立编译）：见 `tiny-cape/README.md`。

---

## 七、排错

| 症状 | 原因 | 处理 |
|---|---|---|
| 类文件版本 69 应为 68 | SDK 是 JDK 24 | 项目 SDK 换成 `jdk-25` |
| 找不到符号 `unsignedMultiplyHigh` | 语言级别 < 18 | 语言级别设为 `25`（已修 `misc.xml`） |
| 找不到 `edu.alibaba.mpc4j.*` | 模块没导入 | 确认打开的是 `cape/` 根目录 |
| 找不到 `com.fusepir.rlwe.*` | 缺 `rlwe-java` 模块 | 检查 `rgsw-lab.iml` 里有 `module-name="rlwe-java"` |
| `keyswitching is not supported` | N 用了 2048 | 默认已是 4096；若手填了参数请去掉 |
| 中文注释乱码 | 编码 | 设置 → 编辑器 → 文件编码，全设 UTF-8 |

### 语言级别若仍报错，逐项检查

1. `文件 → 项目结构 → 项目` → **SDK = `jdk-25`**，**语言级别 = `25`**
2. `文件 → 项目结构 → 模块` → 每个模块的 **`源`** 页 → **语言级别 = `25`**
3. SDK 列表里没有 `jdk-25` → `平台设置 → SDK → +` → `添加 JDK` → 选 `D:\Java\jdk-25`
4. `文件 → 清除缓存…` → 重启

> **验证依据**：`javac --release 25` 编译 `rlwe-java` 退出码 0；
> `--release 17` 会在 `NttContext.java:278` 报 `unsignedMultiplyHigh` 找不到符号。
> 所以只要编译级别 ≥ 18 就没问题。

---

## 八、中文界面速查

| 你要找的 | 中文包里的名字 | 英文原名 |
|---|---|---|
| 运行配置入口 | **编辑配置…** | Edit Configurations |
| 命令行参数 | **程序实参** | Program arguments |
| 内存参数 | **VM 选项** | VM options |
| 主类 | **主类** | Main class |
| 模块类路径 | **使用模块的类路径** | Use classpath of module |
| 显示隐藏栏位 | **修改选项** | Modify options |
| 项目结构 | **项目结构…** | Project Structure |
| 语言级别 | **语言级别** | Language level |
| 清除缓存 | **清除缓存…** | Invalidate Caches |
| 临时配置 | **临时配置** | Temporary Configurations |

---

## 九、和命令行跑法的关系

`BUILT.md` 里记的是**手工 javac + java** 的方式，
需要自己拼 classpath、还要**排除 7 个"路线 C"的源文件**。

**IDEA 里不需要排除任何文件** —— 把 `rlwe-java` 作为模块依赖加进来后，
66 个源文件可以**一起编译**。

两种方式**编译产物等价**，都已实测跑通四步端到端。
