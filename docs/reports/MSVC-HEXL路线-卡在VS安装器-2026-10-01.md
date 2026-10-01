# MSVC + Intel HEXL 路线（#1）尝试记录 —— **未完成，卡在 VS 安装器**

日期：2026-10-01
结论：**走到最后一步卡住** —— VS Build Tools 装了一半，编译器二进制没落地，
VS 安装器把该实例标记成"已装 VCTools"却又拒绝继续安装（`AnotherInstallationRunning`）。
**该状态需要交互式管理员会话或重启才能修复，本会话内无法完成。**

---

## 1. 为什么走 #1

`blindrotat` 白盒剖面（见 `盲旋转白盒剖面与工具链封锁-2026-10-01.md`）给出：

| 项 | 占 CMUX |
|---|---|
| `decompose`（我们自己的代码） | 24% |
| **库操作：22 次 NTT + 22 次 `multiply_plain`** | **76%** |

那 76% 正是 **Intel HEXL** 加速的目标（HEXL 提供 AVX-512 优化的 NTT 和模乘）。
而 SEAL 4.0.0 自身几乎没有手写 AVX2（全树只有 6 行，还在头文件里），
所以 HEXL 是唯一实质路径。HEXL 是 Intel 的 MSVC 目标库 ⇒ 先要 MSVC。

## 2. 实际进展（这部分是成功的，值得记录）

| 步骤 | 结果 |
|---|---|
| 网络可达性 | ✅ `download.visualstudio.microsoft.com` 与 `codeload.github.com` 都能下 |
| 下载 bootstrapper | ✅ 4.27 MB，**Authenticode 签名 `Valid`，`CN=Microsoft Corporation`**（验签确认不是中间页） |
| 非管理员能否安装 | ✅ **能** —— VS 安装器会自己提权。`setup.exe elevate` 实际跑起来了，`dd_installer_elevated_*.log` 存在 |
| 注册表写入 | ✅ `HKLM:\SOFTWARE\Microsoft\VisualStudio\Setup` 建起来了 |
| 实例注册 | ✅ 实例 `9de8af30`，`installationPath = E:\学习\密码赛\_vs`（装到 E 盘成功） |
| Windows SDK / CRT 包 | ✅ `Microsoft.VisualStudio.UniversalCRT`、`VC.14.44.17.14.CRT.Headers` 等日志显示安装 |
| 计划无需重启即可装 | ✅ 大部分 `not applicable` 只是 .NET/UniversalCRT 的 OS 版本过滤（本机 10.0.22631） |

⇒ **"非管理员装不了 MSVC" 这个我先前的判断是错的**，VS 安装器能自行提权。
这条路本身是通的。

## 3. 卡在哪

### 3.1 直接现象

磁盘上：

```
E:\学习\密码赛\_vs\VC\Tools\MSVC\14.44.35207\
    include\      <- 有
    Auxiliary\    <- 有
    bin\          <- **没有**
    lib\          <- **没有**
Windows Kits      <- **不存在**
总占用 139.5 MB   （完整 VCTools 应 2~4 GB）
```

⇒ **没有 `cl.exe`，没有链接库，没有 Windows SDK。**

### 3.2 安装器的状态自相矛盾

`state.packages.json`（VS 自己记录的"已安装包"）里有：

```
Microsoft.VisualStudio.Workload.VCTools              <- 说装好了
Microsoft.VisualStudio.Component.VC.Tools.x86.x64    <- 说装好了
Microsoft.VisualStudio.Component.Windows11SDK.26100  <- 说装好了
```

但磁盘上这些东西不存在。**注册表/元数据说装了，实际二进制没落地。**

### 3.3 为什么后续 install/modify 全部秒退

后续每一次 `modify` 都在 **15 秒内退出**，`dd_setup_..._errors.log` 里写着：

```
Pre-check verification failed with warning(s) : AnotherInstallationRunning.
Error 0x652: Pre-check verification failed with warning(s) : AnotherInstallationRunning.
```

**根因链**：

1. 我第一次用 `Start-Process` 起的安装，在**我的工具调用结束时被连带杀掉**
   （日志停在 18:46:32，无任何"安装完成/取消"记录）。
   —— 这一点我自己有责任：应该一开始就用后台 job 保住进程。
2. 被杀留下的半成品实例被登记成"VCTools 已装"。
3. 于是之后所有 `modify --add ...` 都被 `AnotherInstallationRunning` 预检挡掉，
   **秒退且不做事**，缓存只涨了十几 MB（都是小支撑包）。

### 3.4 排除了一个疑似原因

曾怀疑是挂起的文件重命名操作（`PendingFileRenameOperations` = 3078 条）挡住安装。
核实后**不是**：那 3078 条里绝大多数是 **McAfee WebAdvisor** 和 `UU7428.tmp` 留下的，
只有 **14 条**与 VS 相关。所以重启虽然可能有帮助，但**不是这个错误的直接原因**。

## 4. 当前系统状态（交给用户处理）

| 项 | 状态 |
|---|---|
| 实例注册 | `9de8af30` 存在且 `VisualStudio.Workload.VCTools` 被标为已装 |
| 实际可用性 | ❌ 无 `cl.exe` ⇒ **不可用** |
| 占用 | `E:\学习\密码赛\_vs` 139.5 MB；`C:\ProgramData\Microsoft\VisualStudio\Packages` 121.6 MB |
| bootstrapper | `%TEMP%\vsbt\vs_buildtools.exe`（4.27 MB，已验签） |
| 挂起重命名 | 3078 条（主要与 McAfee 有关，非 VS） |

**未做破坏性清理**：没有卸除实例、没有删 `_vs`、没有删 ProgramData 缓存 ——
因为这几条都能帮用户接着修，删了反而要从零再来。

## 5. 建议用户怎么做（需要交互式提权，本会话做不到）

两条路，任选：

### A. 修（保留已下载的 260 MB 缓存，最省时间）

在**普通终端**（会弹 UAC）里跑：

```powershell
& "$env:TEMP\vsbt\vs_buildtools.exe" modify `
  --installPath "E:\学习\密码赛\_vs" `
  --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended
```

**注意：不要加 `--quiet`** —— 交互界面能看到它到底卡在哪一步。

### B. 重来（更干净，但要重下）

先从"应用和功能"里卸载 **Visual Studio Build Tools 2022**，再重跑：

```powershell
& "$env:TEMP\vsbt\vs_buildtools.exe" --installPath "E:\学习\密码赛\_vs" `
  --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended
```

装完验证：

```powershell
Get-ChildItem "E:\学习\密码赛\_vs" -Recurse -Filter cl.exe
```

### 之后我接手做 HEXL

`cl.exe` 一到位，接下来就是纯机械步骤（我可以继续）：

1. 下载 Intel HEXL 1.2.6（`https://github.com/IntelLabs/hexl`，已确认可下）
2. 用 MSVC + CMake 构建 HEXL（CMake 也能从旧工具链里借，或下独立版）
3. 用 `-DSEAL_USE_INTEL_HEXL=ON` 重建 SEAL
4. 用 MSVC 重建 JNI DLL（`build_blindrotate_jni.py` 已支持传编译选项与输出目录）
5. A/B 对比 `BlindRotateBench` 的 ms/CMUX（基线 **19.9~20.7 ms**）

**预期**：76% 的时间花在 NTT 与 `multiply_plain` 上，这两项正是 HEXL 的目标。
但**具体倍数不敢承诺** —— 本机 CPU 不支持 AVX-512（只有 AVX2/FMA/BMI2），
而 HEXL 的收益主要来自 AVX-512，所以实际提升可能明显小于 HEXL 论文的数字。

## 6. 本轮产出的脚本（在仓库外的 `tools/`，按惯例未纳管）

| 文件 | 用途 |
|---|---|
| `%TEMP%\vsbt\get_bootstrapper.py` | 下载并**验签** bootstrapper |

## 7. 教训

1. **长任务必须放后台 job**：我第一次用 `Start-Process`，installer 在工具调用结束时被连带杀掉，
   直接造成这次失败。后面 `pwsh-20/21/22` 都用了后台 job，但那时实例已经被标记成"已装"，
   预检一直拒绝。
2. **`--quiet` 会让失败无声**：所有失败细节都在 `dd_setup_*_errors.log` 里，
   而命令行什么都没有、退出码还是 0。查这类问题必须先找日志。
3. 不要凭"需要管理员"就断言不可行 —— 实测 VS 安装器能自行提权。
   我先前那条判断是错的，代价是绕了一段路。
