# 盲旋转加速尝试：`-march=native` 路线（**负结果，已回滚**）

日期：2026-10-01
结论：**这条路在当前 MinGW 工具链 + 本机 CPU 上走不通 —— AVX2 构建会段错误。**
状态：已全部回滚，工作区 DLL 与基线逐字节一致（SHA256 前缀 `E8E62B5508A7EEF3`）。

---

## 1. 动机

审计发现我们的构建**一个向量化开关都没开**：

| | 我们 | OnionPIRv2 |
|---|---|---|
| SEAL 的 `CMAKE_CXX_FLAGS` | **空** | — |
| JNI DLL 编译 | `-O3 -std=c++17` | — |
| 整个项目 | — | **`-O3 -march=native -mtune=native`** |
| HEXL | `SEAL_USE_INTEL_HEXL: OFF` | `USE_HEXL` 默认 ON |

本机 CPU（gcc `-march=native -Q --help=target` 实测）：
AVX2 ✅ / FMA ✅ / BMI2 ✅ / AES ✅ / SHA ✅ / **AVX-512 ❌**

⇒ 直觉上"开个编译选项白拿加速"，而且完全可回退，所以做了。

## 2. 关键发现（决定了预期收益）

**SEAL 4.0.0 几乎没有手写的 AVX2。** 全树 `_mm256` / `__AVX2__` 命中只有 **6 行**，
而且全在 `msvc.h` / `gcc.h` / `clang.h` 三个头文件里。

SEAL 的真正加速路径是 **Intel HEXL**（`SEAL_USE_INTEL_HEXL`），它没有手写 AVX2 NTT。

⇒ 所以 `-march=native` 只能指望**编译器自动向量化** SEAL 的标量循环。
这也意味着**收益本来就不确定**——必须先测再下结论，不能想当然。

## 3. 实验做完了

### 3.1 干净基线（新写的 `BlindRotateBench`）

用 `nativePrepare` / `nativeRunWithCtx` 把**纯 native 盲旋转**隔离出来，
不经过 Java 表构建与 JNI 大数组搬运，输出每次 CMUX 的毫秒数：

```
  d    reps   total ms   ms/rotate   ms/CMUX
  1      20      423.4      21.168     20.675
  4      20     1631.8      81.589     20.483
 16      20     6331.1     316.554     19.872

三者离散度 = 4.0%   (d=1/4/16 一致 ⇒ 成本确实由 CMUX 主导)
```

**⇒ 基线 = 19.9 ~ 20.7 ms per CMUX。**

这条测量本身有价值：它证明了 CMUX 成本与 `d` 无关（离散度 4%），
所以"减少 CMUX 次数"是唯一能线性收效的方向，别的微优化都只是常数。

顺带用它交叉验证了先前的成本分离：330 单元 × 16 轮 = 5 280 次 CMUX，
× 20 ms ≈ **106 s**，占 ANSWER 147 s 的 **72%** —— 与先前"盲旋转占 70~85%"一致。

### 3.2 两种编译选项，**都崩**

| 变体 | 编译选项 | SEAL 编译 | 结果 |
|---|---|---|---|
| 基线 | `-O3 -std=c++17` | 空 | ✅ 正常 |
| 窄 AVX2 | `-mavx2 -mfma -mbmi2 -mpopcnt` | 同 | ❌ **JVM 段错误** |
| `-march=native` | `-march=native -mtune=native` | 同 | ❌ **JVM 段错误** |

两种变体都是：

```
EXCEPTION_ACCESS_VIOLATION (0xc0000005)
Problematic frame: C  [blindrotate.dll+0x560a0]
```

### 3.3 隔离：不是 JVM 的问题，是 SEAL 本身

写了一个**独立 C++ 冒烟测试**（不经 JVM，只测 SEAL 的 context/keygen/NTT 往返/
`multiply_plain`/`multiply`+relinearize），分别链接两种 SEAL：

| SEAL 构建 | 独立测试结果 |
|---|---|
| 基线（无 march） | ✅ 能跑起来（我测试代码自己有个逻辑错误，抛的是干净的 `std::invalid_argument: NTT form mismatch`） |
| `-mavx2` | ❌ **`STATUS_ACCESS_VIOLATION`（0xC0000005），连第一行输出都没打印出来** |

⇒ **`-mavx2` 版本在本机就是段错误，与 JVM 无关。** 放宽到基础 `-mavx2`
（不带 `-march=native`）一样崩，所以不是 `-march=native` 选错指令的问题，
而是**这套 MinGW-w64 + UCRT 工具链在 AVX2 上产出的代码在本机跑不起来**。

## 4. 结论与后续

**放弃编译选项路线。** 理由：不是"收益小"，是"直接崩"。

想再往前走，只剩这几条，都比我原以为的贵：

| 路线 | 说明 | 风险 |
|---|---|---|
| **换 MSVC 工具链** | Intel HEXL 官方支持 MSVC；SEAL 的 AVX2/HEXL 路径在 MSVC 下是验证过的组合 | 要重建整个 SEAL + JNI 工具链，工作量大 |
| 换 MinGW 版本/发行版 | 当前是 Brecht Sanders r1 / GCC 16.2.0 UCRT；某些 MinGW 发行版 AVX2 有问题 | 试错成本中等 |
| 用 CLANG 编译 | 换后端可能绕开 GCC 的向量化代码生成问题 | 中等 |
| **改算法**（减少 CMUX 次数） | 唯一被 3.1 证明能线性收效的方向 | 需要动 `decompose` / 旋转结构，伤筋动骨 |
| 单模数路线（OnionPIRv2 启示） | 跳过 RNS↔多精度转换 | 会改变参数结构，需重新论证 |

## 5. 复现方式

```powershell
# 1. 新临时目录 + 从只读旧目录读工具链（旧目录跨会话后变只读）
# 2. 复制 SEAL 源码到可写根
robocopy <old>\SEAL-4.0.0 <new>\SEAL-4.0.0 /E
# 3. 用 -march=native 重建 SEAL
.\tools\build_seal_native.ps1 -Old <old> -New <new>
# 4. 用同一组选项重建 DLL（脚本已支持可选旗标与输出目录）
python tools\build_blindrotate_jni.py <new> "-march=native -mtune=native" <new>\out
# 5. 换 DLL 后跑基准 —— 会在 d=1 处段错误
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateBench 8192 20
```

**注意：换 DLL 后必崩，务必先备份 `coding/native-jni/lib/blindrotate.dll`。**

## 6. 环境陷阱（本轮新踩到，已记入工具脚本注释）

1. **临时目录跨会话会换名且旧目录变只读**：`$env:TEMP` 从 `dsh-vPphwj` 变成
   `dsh-I2wJuP`，旧目录连 `mkdir` 都"拒绝访问"。所以本轮是"从只读旧目录读工具链、
   往可写新目录写产物"。
2. **`E:\学习\密码赛\` 有中文**，MinGW 不能在其下建构建根 —— 这正是
   `build_blindrotate_jni.py` 里那套 ASCII 搬运存在的原因。
3. `robocopy` 到**不存在的同级目录**会返回 16（fatal）；要先 `New-Item` 建目录。
4. PowerShell 会把未加引号的 `-Wl,-Bstatic` 当参数拆开 → 必须加引号。
5. 新增的两个脚本都保持纯 ASCII（`.ps1` 被 GBK 读会毁中文注释）。

## 7. 本轮新增文件

| 文件 | 作用 |
|---|---|
| `coding/rgsw-lab/.../BlindRotateBench.java` | 隔离式盲旋转微基准（本次基线 19.9–20.7 ms/CMUX） |
| `coding/rgsw-lab/.../CapeAnswerProfile.java` | 改 C 分离列选择/盲旋转（结果显示噪声大于信号，见其注释） |
| `tools/build_seal_native.ps1` | 用 `-march=native` 重建 SEAL 到可写目录 |
| `tools/march_probe.ps1` | 批量构建多个编译选项变体做 A/B |
| `tools/build_blindrotate_jni.py` | **已改**：新增可选"额外编译旗标"与"输出目录"参数，默认行为不变 |

既有实现（`CapeEndToEnd4` / `CapeEndToEndNative` / `native-jni/` 的 C++ 与 Java 源码）
**零改动**；唯一被改的文件是构建工具脚本，且默认行为保持逐字节不变。
