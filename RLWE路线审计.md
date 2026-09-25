# `coding/` 的 RLWE 路线审计

> 目标（用户要求）：**确保 `coding/` 里所有 RLWE 都走 `mpc4j-native-fhe` 路线**。
> 审计时间：2026-09-16。判定标准：**以文件里真正 `import` 的 HE 类为准**（不看注释、不看正则巧合）。

---

## 〇、结论更新（2026-09-19）：主线改用路线 B，且**已实测达到论文规模**

原计划是把 RLWE 全面迁到 native。但查清一件事后结论反转：

**路线 B 唯一卡着"论文规模"的地方，是 MPC4J Java 移植版里一处数据结构写法**——
`AbstractGaloisTool` 把 Galois 置换表预分配成 `new int[N][N]`，而实际用到的行只有
`2·(log₂N−1)+1 = 27` 个（N=16384），且那个 `row == null` 的惰性判断因为每行都被零填充
而**永不成立**，导致每次旋转都重算整张表。打 2 行补丁（惰性行分配 + 颠倒判断）后：

| 实测（N=16384、t=65537、声明 9 素数/438 位、**工作层 8 素数/389 位**） | 结果 |
|---|---|
| 内存 | 每层 1.07 GB → 约 1.8 MB（8 层 8.6 GB → 约 14 MB） |
| 槽打包 + 加解密往返 | ✅ 0/16384 错位 |
| 密文×密文 + 重线性化 | ✅ 0/16384 错位（346 ms + 143 ms，规模 3→2） |
| 槽旋转 rotateRows | ✅ 85 ms |
| 模数切换 | ✅ 9 → 8 素数后仍正确 |
| **RGSW.Enc + 外部乘积 + CMUX** | ✅ **5/5 全过**（`RGSW(1)⊗c = c`、`RGSW(0)⊗c = 0`、CMUX 两条分支） |
| 噪声余量 | ct×ct 后 **339 bit**（N=4096 时仅 24 bit）——论文规模下反而极其宽裕 |

补丁固化在 `patches/mpc4j-galois-lazy-permutation-tables.patch`。
**因此：路线 B 从"需要迁移"变成"主路线"**，native 保留为性能对照与交叉校验。

### 补丁顺带暴露的第二个坑：工作模数比声明少一个素数

在 N=16384 上第一次跑 RGSW 就崩了：

```
ArrayIndexOutOfBoundsException: Index 262144 out of bounds for length 262144
  at Mpc4jRgsw.addConstantNtt(Mpc4jRgsw.java:202)
```

`262144 = 2 分量 × 8 素数 × 16384`：**BFV 把最后一个素数留作缩放用的特殊素数 `q_last`**，
所以密文里只有 8 个模数分量，而代码按 `parms.coeffModulus().length`（9）去索引。
N=2048 时只有 1 个素数、没有特殊素数，所以一直是**巧合正确**，到论文规模才暴露。
修法：从真实密文的数组长度反推工作层素数个数（`length / (size * n)`），
并且 **q、层数、CRT 逆元都按工作模数算**（层数从 28 降到 25，省掉白做的几层）。

这同时说明一件事：**MPC4J 里那些 ✅（打包/ct×ct/旋转/模切换）必须逐项实测过才算数**，
"能编译、能跑小参数"不代表对。

---

## 一、三条路线

| 路线 | 依赖 | 是否目标路线 |
|---|---|---|
| **A. native** | `edu.alibaba.mpc4j.*NativeUtils` → `coding/native-jni/lib/mpc4j-native-fhe.dll` → **真 SEAL 4.0.0 C++** | ✅ **是** |
| **B. 纯 Java 移植版** | `edu.alibaba.mpc4j.crypto.fhe.seal.*` → `coding/lib/mpc4j-crypto-fhe-seal.jar`（SEAL 的 Java 重写） | ❌ 否 |
| **C. 自研** | `com.fusepir.rlwe.*` → `coding/rlwe-java/`（自己写的 RLWE） | ❌ 否（已弃用） |

LWE 不在本次范围：`com.fusepir` 的 `cape.he.*`（`coding/lwe-java/`）是自研 LWE，
且 LWE 不是 RLWE，保留。

> ⚠️ **2026-09-19 修正**：原先写"**MPC4J 全仓库没有 LWE 实现**"**不准确**。
> 实际是：MPC4J 没有**可复用的 `LWE.Enc/Dec` 原语**，但它的 `cppir` 家族
> （ChalametPIR / SimplePIR / FrodoPIR / Piano / Plinko）**本身就是 LWE / 矩阵型 PIR**
> ——例如 `ChalametCpKsPirClient` 里就有 `private IntVector[] bs; // b = s·A`、`cs; // c = s·M`、
> `seedMatrixA`、`matrixM`，并有 `GaussianLweParam`（n=1024/1408、σ=6.4）参数枚举。
> 另外 `cppir/ks/chalamet` 里的 `Arity3ByteFusePosition` 就是我们说的 **BFF（k=3）**。
> **结论不变**（CAPE 的 LWE 层仍用 `lwe-java/`），但理由要写对。

---

## 二、逐文件判定（依据 import）

### ✅ 路线 A（native）——已达标

| 文件 | 说明 |
|---|---|
| `native-jni/.../SealStdIdxPirNativeUtils.java` | JNI 声明副本（绑定到原版 C++） |
| `native-jni/.../Lpzl24BatchPirNativeUtils.java` | 同上（批量 PIR 族） |
| `native-jni/.../SealPirNativeTest.java` | N=16384 全流程验证，已通过 |
| `native-jni/.../NativeApiProbe.java` | 自定义系数模数探针，已通过 |

### ❌ 路线 B（纯 Java 移植版）——待迁移

| 文件 | 内容 | 迁移难度 |
|---|---|---|
| `rgsw-lab/.../Mpc4jRgsw.java` | **RGSW 加密 / 外部乘积 / CMUX**（测试全绿） | 需要 native 侧新增原语接口 |
| `rgsw-lab/.../Mpc4jCapability.java` | 四项能力探针（打包/ct×ct/旋转/模切换） | 同上 |
| `param-probe/.../ParamProbe.java` | 参数位宽探测（N=16384 跑不动，正是它的结论来源） | 可由 `native-jni/src/seal_params_probe.cpp` 替代 ✅ 已有替代品 |
| `rlwe-bench/src/RlweBench.java` | 自研 vs 纯 Java 移植版的性能对照 | 对照基准，可保留但需标注 |

### ❌ 路线 C（自研，已弃用）——待收敛

`rlwe-java/**`（12 个文件，模块本体，已有 `@deprecated` 与 README 警告）
及其消费者：`rgsw-lab/` 的 `RgswOps`、`RgswCiphertext`、`MonomialOps`、`BootstrapKey`、
`RgswLabMain`、`MonomialKeyTest`、`LabConfig`、`examples/RlweDemo`，以及 `rlwe-bench`。

### ⚪ 不含 HE

`cape-fusepir-database-handoff/**`（11 个文件：Bloom 参数、数据库规范化、MovieLens 载入）
—— 纯明文逻辑，与路线无关。

---

## 三、为什么不能"改个 import"就搬过去

`mpc4j-native-fhe` 暴露的是 **byte[] 序列化的协议级接口**（`keyGen` / `generateQuery` /
`generateReply` / `decryptReply` / `computeEncryptedPowers` / `optComputeMatches` …），
**没有原语级接口**，更没有 RGSW：

| 路线 B/C 用到的能力 | native 侧现状 |
|---|---|
| 上下文/密钥、打包、加解密 | 有（藏在协议接口内部） |
| 密文×密文 + 重线性化 | 有（`computeEncryptedPowers` / `optComputeMatches`，需 relinKeys） |
| 槽旋转、模数切换 | 有（`generateReply` 内部用） |
| **单步原语调用**（想按需组合） | ❌ 没有暴露 |
| **RGSW.Enc / 外部乘积 / CMUX / BlindRotate** | ❌ **MPC4J 全仓库没有任何 RGSW 实现** |

所以要让 RGSW 也走 native，**必须给同一个 DLL 增加一层原语级 JNI**
（新写一个 C++ 源文件加进 `mpc4j-native-fhe` 目标，仍然链接同一个 SEAL 静态库）。
这是唯一不改论文算法的办法——换成"用 native 现成的 PIR 接口代替 RGSW"会**改变协议步骤**，
违反"不能改变原论文的算法"。

---

## 四、迁移计划

1. **给 `mpc4j-native-fhe` 增加原语级 JNI**（新文件 `native-jni/src/cape_rlwe_jni.cpp`，
   加进 `tools/build_native_fhe.py` 的编译目标）：
   - 上下文：`ctxCreate(N, t, coeffModBits[])`、`ctxDescribe`（素数个数/位宽/链长）
   - 密钥：`skGen` / `relinKeysGen` / `galoisKeysGen(steps)`
   - 打包：`encode` / `decode`（BatchEncoder）
   - 加解密：`encryptSymmetric` / `encryptZero` / `decrypt` / `noiseBudget`
   - 运算：`ctAdd` / `ctSub` / **`ctMultiply`（含重线性化）** / **`rotateRows`** / **`modSwitchToNext`**
   - **RGSW**：`rgswEncryptConstant` / `externalProduct` / `cmux`
   - 序列化：`ctSave` / `ctLoad`、`ctSize`
2. 把 `Mpc4jRgsw` / `Mpc4jCapability` 的测试**原样搬到 native 版本**上跑（N=16384）。
3. 路线 C 的模块只保留为"交叉校验工具"，并在脚本里加红线（不再作为任何流水线的默认路径）。

### 一个需要定下的实现细节（RGSW 切段）

外部乘积需要把 `src` 的系数按底 B 切成平衡位。q 的工作模数约 389 位，切段需要
**跨 RNS 素数的 CRT 还原**，也就是大整数运算。三个选项：

| 选项 | 做法 | 取舍 |
|---|---|---|
| **a. C++ 侧实现定点大整数** | Garner 算法 + 多字乘加（约 80 行） | 全程 native，但要自己保证正确性 |
| **b. 用 SEAL 内部 RNS gadget** | `util::decompose` + key-switch 同款分解，无需大整数 | 最"native"，但必须吃准它的数学约定 |
| **c. 切段留 Java** | JNI 导出/导入系数（`long[]`），复用已完成并自测的 Java `decompose` | 最快落地；RLWE 运算体仍是 native，但分解在 Java |

倾向 **a 或 b**（满足"全 native"的字面要求），**c** 作为保底快速验证手段。
