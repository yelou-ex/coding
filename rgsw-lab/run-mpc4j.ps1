# ============================================================================
#  Compile and run the MPC4J-based sources in this lab, using ONLY coding/lib.
#  (ASCII only: Windows PowerShell 5.1 reads .ps1 as ANSI/GBK without a BOM)
#
#  Usage:  .\run-mpc4j.ps1                                  -> Mpc4jRgsw self-test
#          .\run-mpc4j.ps1 -Class com.fusepir.probe.Mpc4jCapability
#          .\run-mpc4j.ps1 -Class com.fusepir.probe.Mpc4jCapability 16384
#
#  Anything after -Class is forwarded to the Java program as its argv.
#  NOTE: without the $args forwarding below, ".\run-mpc4j.ps1 -Class X 16384"
#  silently ran at X's DEFAULT size (the 16384 was dropped), which made the
#  documented commands do the wrong thing.
# ============================================================================
param([string]$Class = 'com.fusepir.prim.Mpc4jRgsw')
$progArgs = $args
# 路线 A（native）的产物：把它的 classes 目录加进 classpath，并把 java.library.path 指过去，
# 这样 rgsw-lab 里的 NativeCapeAnswer 才能 import 到 com.fusepir.nativejni.NativeBlindRotate。
$nativeDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'native-jni/lib'

$ErrorActionPreference = 'Stop'
# Java writes UTF-8; make PowerShell decode child output as UTF-8, otherwise the
# Chinese messages come back as GBK mojibake (and get truncated mid-stream).
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$lib  = Join-Path (Split-Path -Parent $here) 'lib'
$javacPath = (Get-Command javac -ErrorAction SilentlyContinue).Source
if (-not $javacPath) { $javacPath = 'D:\Java\jdk\bin\javac.exe' }
$javaPath = Join-Path (Split-Path -Parent $javacPath) 'java.exe'

$cp = (Join-Path $lib 'mpc4j-crypto-fhe-seal.jar') + ';' +
      ((Get-ChildItem (Join-Path $lib 'deps') -Filter *.jar | ForEach-Object { $_.FullName }) -join ';')
# 路线 A（native）的 Java 绑定也在 classpath 上，rgsw-lab 的 NativeCapeAnswer 依赖它
$nativeDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'native-jni/lib'
$cp = $cp + ';' + (Join-Path $nativeDir 'classes')

$out = Join-Path $here 'mpc4j-out'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out | Out-Null

# Compile【全部】源文件，只排除「路线 C」那 7 个（自研 RLWE，零依赖，走 run.ps1）。
#
# 原来这里是一份【硬编码的文件名列表】，新加的类必须手动登记，否则会被静默跳过 ——
# 2026-09-29 合并远端的四步端到端时就踩到了：`CapeEndToEnd4` 编译都没编译，
# 只报一句 "找不到或无法加载主类"。改成 BUILT.md 里的 glob + 排除法，新类自动纳入。
# ⚠️ 2026-10-14 深夜：源码**不再是一个平铺的包**，改成按论文分层：
#     prim / bloom / bff / fusepir / cape / demo / probe / legacy
#     所以这里必须 **-Recurse**（原先是 `Get-ChildItem $srcDir -Filter *.java`，
#     只扫顶层 —— 换成分层目录后那些类会被静默漏掉，只报"找不到或无法加载主类"）。
$srcDir = Join-Path $here 'src\main\java\com\fusepir'
$routeC = @('RgswOps.java', 'RgswCiphertext.java', 'MonomialOps.java', 'BootstrapKey.java',
            'RgswLabMain.java', 'MonomialKeyTest.java', 'LabConfig.java')
$srcFiles = Get-ChildItem $srcDir -Recurse -Filter *.java |
    Where-Object { $_.Name -notin $routeC } |
    Select-Object -ExpandProperty FullName

# 共享层（com.fusepir.common.BfGen = 论文的 BF.Gen）。
# 客户端算 b_qry、服务端算 b_v，两边【必须】用同一份实现 —— 所以它不能放在任何一侧。
$commonSrc = Join-Path (Split-Path -Parent $lib) 'common\src\main\java'
if (Test-Path $commonSrc) {
    $srcFiles += Get-ChildItem $commonSrc -Recurse -Filter *.java | Select-Object -ExpandProperty FullName
}

# LweRlweConversion 要用 cape.he（lwe-java 的 LWE 层），把它的源码目录挂到 sourcepath 上。
$lweSrc = Join-Path (Split-Path -Parent $lib) 'lwe-java\src\main\java'

Write-Host "[compile] MPC4J-based sources (classpath = coding\lib)"
& $javacPath -encoding UTF-8 -cp $cp -sourcepath $lweSrc -d $out $srcFiles
if ($LASTEXITCODE -ne 0) { Write-Error 'compile failed'; exit $LASTEXITCODE }

Write-Host "[run] $Class $progArgs"
# ⚠️ 中文乱码的根因就在这一行：**`-Dfile.encoding` 管不到 `System.out`**。
#
#   JEP 400（Java 18+）之后，标准输出的编码由 `stdout.encoding` 决定，
#   而它**不再**跟随 `file.encoding`。stdout 被重定向/走管道时，
#   `stdout.encoding` 取 `native.encoding` —— 中文 Windows 上就是 **GBK**。
#   于是 Java 吐的是 GBK 字节，而本脚本上面又把 `[Console]::OutputEncoding`
#   设成了 UTF-8 ⇒ PowerShell 拿 UTF-8 去解 GBK ⇒ 满屏 "�"。
#
#   实测（`_encprobe` 探针，JDK 25）：
#     只给 -Dfile.encoding=UTF-8                  → 输出字节 d6 d0 ce c4 …（GBK 的"中文"）
#     再加上 -Dstdout.encoding=UTF-8              → 输出字节 e4 b8 ad e6 96 87 …（UTF-8）
#     探针同时打印：file.encoding=UTF-8 但 native.encoding=GBK、stdout.encoding=GBK
#
#   对照：`git log` 的中文一直是正常的 —— 因为 git 自己按 UTF-8 输出，与本行无关。
$javaOpts = @('-Xmx4g', '-Dfile.encoding=UTF-8', '-Dstdout.encoding=UTF-8', '-Dstderr.encoding=UTF-8')
# Extra -D... switches for probes, via an env var (a plain ASCII string, e.g.
#   $env:DSH_JVM_OPTS='-Dcape.grid.rs=16,64'  ).
if ($env:DSH_JVM_OPTS) { $javaOpts += ($env:DSH_JVM_OPTS -split '\s+') }
& $javaPath @javaOpts "-Djava.library.path=$nativeDir" "--enable-native-access=ALL-UNNAMED" -cp "$out;$cp;$nativeDir/classes" $Class @progArgs
exit $LASTEXITCODE
