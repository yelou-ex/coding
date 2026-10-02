# coding/ 仓库同步说明

> 本文档说明 `coding/` 这个 git 仓库怎么同步到远端。
> 状态（2026-10-14）：**本地已就绪，只差推送**（领先 `origin/main` 33 个提交）。

---

## 一、仓库现状

| 项 | 值 |
|---|---|
| 远端 | `https://github.com/yelou-ex/coding.git` |
| 分支 | `main`（上游已设为 `origin/main`，但本地领先 33 个提交，从未推送） |
| 已跟踪文件 | **280 个**（纯源码 + 文档 + 参数 + 数据集） |
| `.gitignore` | 已就位（见第三节） |

内容构成：

```
coding/
├── README.md            入口（演示 + 文档地图 + 变更历史）
├── SYNC.md              本文件
├── docs/                全部文档（2026-10-14 起根目录只留 README/SYNC）
├── tools/               一次性探针：param-probe/、rlwe-bench/
├── ml-latest-small/     MovieLens 数据集（tracked，仓库要能直接跑演示）
├── common/              com.fusepir.common.BfGen（客户端与服务器**共用**的 BF.Gen）
├── lwe-java/            LWE 层（cape.he）
├── rlwe-java/           自研 RLWE（路线 C 的库）
├── rgsw-lab/            MPC4J/SEAL 实现与实验台（见其 README.md）
├── native-jni/          真 SEAL 的 JNI DLL + 绑定
├── cape-demo/           前端 + 数据集构建脚本
├── cape-fusepir-database-handoff/  明文侧模块
├── tiny-cape/           零依赖极小验证层（**故意不共用代码**）
├── pdf-extract/         论文 PDF 抽取脚本
├── patches/             MPC4J 补丁
└── lib/                 MPC4J/SEAL 预编译 jar 与依赖
```

---

## 二、推送步骤（在你自己的 PowerShell 里跑）

> ⚠️ **不要在我（AI）的沙箱进程里推送**：沙箱拿不到 Windows 的 TLS 凭据，
> 会报 `schannel: AcquireCredentialsHandle failed: SEC_E_NO_CREDENTIALS`。
> 在你自己的终端里跑就没这个问题。

```powershell
cd E:\学习\密码赛\coding

# 1) 先确认远端可访问、凭据可用
git ls-remote origin

# 2) 首次推送并建立 upstream
git push -u origin main
```

### 如果第 1 步报 SSL 后端错误

本机 git 的**全局**配置里 `http.sslBackend` 被设成了 `curl`，但这个 Windows Git 只支持 `schannel`：

```
fatal: Unsupported SSL backend 'curl'. Supported SSL backends: schannel
```

我已经**在本仓库范围内**修好了（写进 `coding/.git/config`，没动全局）。但你其他仓库也会遇到，
建议顺手把全局也改掉：

```powershell
git config --global http.sslBackend schannel
git config --global --get http.sslBackend     # 确认输出 schannel
```

### 如果推送时反复要账号密码

凭据管理器里没有 GitHub 凭据时会弹窗。两种做法：

```powershell
# 方式一：让 Git 凭据管理器记住（推荐）
git config --global credential.helper manager

# 方式二：用带 token 的 URL 推一次（token 只存本地 remote，注意别外泄）
git remote set-url origin https://<用户名>:<token>@github.com/yelou-ex/coding.git
```

---

## 三、`.gitignore` 覆盖了什么

**不提交**（可重新生成或与源码重复）：

| 类别 | 规则 |
|---|---|
| 构建产物 | `out/`、`classes/`、`target/`、`_build/`、`*.class` |
| 打包产物 | `*.jar`、`*.zip` |
| IDE | `.idea/`、`*.iml`、`.classpath`、`.project` |
| 派生数据 | `pdf-extract/out_*.txt`（从 PDF 重新抽取即可） |
| Python | `__pycache__/`、`*.pyc` |

**本次清理移出的已跟踪文件**（共 48 项，文件仍在磁盘上）：
34 个 `.class`、`lwe-java.zip`、`cape-fusepir-database-handoff.zip`、
`rgsw-lab/rgsw.jar`、`rlwe-java/rlwe.jar`、6 个 IDE 文件、3 个 `pdf-extract/out_*.txt`。

**2026-10-14 追加**：`ml-latest-small.zip`（978 KB）取消跟踪 —— 它与 `ml-latest-small/` 里的
CSV 内容重复，留着就是一份冗余。zip 仍在磁盘上（需要时可用它重新解出数据集），
`.gitignore` 已加显式规则，不会被重新加回。

**仍然提交**（有意保留）：
- 源码与文档；
- `params.env`（参数文件，属于"配置"而非"产物"）；
- `ml-latest-small/` 数据集（约 4.1 MB，公开数据集 MovieLens；保留是为了仓库能直接跑演示。
  若不想要，把 `ml-latest-small*` 加进 `.gitignore` 并从索引移除即可）。

> 体积现状（2026-10-14 实测，被跟踪文件合计 **35.9 MB**）：
> `lib/` **23.00 MB**（MPC4J 预编译 jar + 依赖）、`native-jni/` **7.95 MB**（两个 DLL）、
> `ml-latest-small/` **3.15 MB**、`rgsw-lab/` 0.76 MB、`cape-demo/` 0.50 MB，其余均 < 0.2 MB。
> 也就是说 **86% 的体积是「不可再生的二进制依赖」**（jar 与 DLL），
> 源码 + 文档合计不到 2 MB。
> （早先记的 4.8 MB 是加数据集与 lib 之前的快照。）

---

## 四、后续同步约定（建议）

```powershell
# 每次改完代码
git add -A
git commit -m "feat(rlwe): 补 CtCtMul + 重线性化"    # 或 fix / docs / chore
git push                      # 第二次之后不用再带 -u
```

建议约定：
1. **一个能力一个提交**（例如"补重线性化"、"补槽位打包"），别把多个改动揉一起，方便回退；
2. 提交前跑一遍自检并把结果贴进提交信息或附带文档：
   - `coding/rlwe-java`：`.\run.ps1`
   - `coding/rgsw-lab`：`.\run.ps1 test`
   - `coding/lwe-java`：`javac ... && java -cp out cape.he.LWESelfTest`
3. **不要把论文 PDF、数据集压缩包、比赛题目**放进这个仓库（版权与体积问题）。

---

## 五、如果想让 AI 直接推

我这个沙箱进程缺 Windows TLS 凭据，推不了。可选方案：

1. **你手动推一次**（上面第二节，最省事）；推完后我可以继续做后续的 commit 准备工作，
   你只需要在最后 `git push` 一下；
2. 或者把凭据配置到一个我能用的位置——但**不建议**为了自动化把 token 交给沙箱进程。
