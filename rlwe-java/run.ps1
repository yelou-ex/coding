# ============================================================================
#  RLWE layer runner (ASCII only: Windows PowerShell 5.1 reads .ps1 as ANSI/GBK
#  unless it has a UTF-8 BOM, so non-ASCII comments can corrupt the script)
#
#  Usage:
#     .\run.ps1            self-test with the default params
#     .\run.ps1 scale      self-test at N=16384, 15 primes (paper modulus scale)
#     .\run.ps1 jar        build rlwe.jar for use by other modules (rgsw-lab)
# ============================================================================
param([string]$mode = 'test')

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition

$javacPath = $null
$found = Get-Command javac -ErrorAction SilentlyContinue
if ($found) { $javacPath = $found.Source }
if (-not $javacPath -and (Test-Path 'D:\Java\jdk\bin\javac.exe')) {
    $javacPath = 'D:\Java\jdk\bin\javac.exe'
}
if (-not $javacPath) { Write-Error 'javac not found'; exit 1 }
$javaPath = Join-Path (Split-Path -Parent $javacPath) 'java.exe'
$jarPath = Join-Path (Split-Path -Parent $javacPath) 'jar.exe'

$out = Join-Path $here 'out'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out | Out-Null

$src = Get-ChildItem -Path (Join-Path $here 'src') -Recurse -Filter *.java |
    ForEach-Object { $_.FullName }

Write-Host "[compile] $javacPath"
# ⚠️ 为什么必须临时放宽 $ErrorActionPreference（第 12 行设的是 'Stop'）。
#
# Windows PowerShell 会把**原生程序 stderr 的每一行都当成一条错误记录**，而
# `'Stop'` 让第一条错误就终止脚本。javac 即使编译成功，也常往 stderr 写提示，
# 实测两种都会触发：
#     [dep-ann] 未使用 @Deprecated 注解的已过时项目      （加 -nowarn **压不住**）
#     注: 某些输入文件使用或覆盖了已过时的 API            （-nowarn 也压不住）
# 后果很误导：`out\` 里 0 个 class，日志却像"javac 编译失败"，而其实编译是好的。
# 判据只能是 $LASTEXITCODE，所以这里对这次调用放宽策略、之后立刻恢复。
#
# 同一个坑对每一处 javac / java 调用都成立 —— native-jni/run.ps1 的注释里记的是同一件事，
# 它的绕法是给 java 加 `2>&1 |` 把 stderr 导进管道；这里用作用域放宽，更直接。
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $javacPath -encoding UTF-8 -d $out $src
$compileExit = $LASTEXITCODE
$ErrorActionPreference = $prevEap
if ($compileExit -ne 0) { Write-Error "compile failed"; exit $compileExit }

if ($mode -eq 'jar') {
    $jar = Join-Path $here 'rlwe.jar'
    & $jarPath cf $jar -C $out .
    Write-Host "[jar] $jar"
    exit $LASTEXITCODE
}

$arg = if ($mode -eq 'scale') { 'scale' } else { '' }
Write-Host "[run] com.fusepir.rlwe.RlweSelfTest $arg"
& $javaPath '-Xmx4g' '-Dfile.encoding=UTF-8' '-Dstdout.encoding=UTF-8' '-Dstderr.encoding=UTF-8' -cp $out com.fusepir.rlwe.RlweSelfTest $arg
exit $LASTEXITCODE
