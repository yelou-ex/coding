# ============================================================================
#  RLWE efficiency benchmark: this implementation vs MPC4J
#  (ASCII only: Windows PowerShell 5.1 reads .ps1 as ANSI/GBK without a BOM)
#
#  Usage:  .\run.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
# 2026-10-14: moved from coding\rlwe-bench\ to coding\tools\rlwe-bench\, so the
# distance to coding\ went from 1 level to 2. One level short silently points
# every "Join-Path $coding ..." below at the wrong directory.
$coding = Split-Path -Parent (Split-Path -Parent $here)

$javacPath = (Get-Command javac -ErrorAction SilentlyContinue).Source
if (-not $javacPath) { $javacPath = 'D:\Java\jdk\bin\javac.exe' }
$javaPath = Join-Path (Split-Path -Parent $javacPath) 'java.exe'

# dependencies: rlwe-java (pure JDK) + MPC4J. Both come from inside coding\:
# rlwe-java builds its own jar, and MPC4J ships prebuilt in coding\lib.
$rlweOut = Join-Path $coding 'rlwe-java\out'
if (-not (Test-Path $rlweOut)) {
    Write-Host "[prep] building rlwe-java first"
    Push-Location (Join-Path $coding 'rlwe-java'); & .\run.ps1 jar | Out-Null; Pop-Location
}
$lib = Join-Path $coding 'lib'
$mpc4jJar = Join-Path $lib 'mpc4j-crypto-fhe-seal.jar'
if (-not (Test-Path $mpc4jJar)) {
    Write-Error "MPC4J jar not found at $mpc4jJar (coding\lib is missing)"
    exit 1
}
$jars = @($mpc4jJar) + @(Get-ChildItem (Join-Path $lib 'deps') -Filter *.jar | ForEach-Object { $_.FullName })
$cp = "$rlweOut;$($jars -join ';')"

$out = Join-Path $here 'out'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out | Out-Null

Write-Host "[compile] RlweBench.java"
# Same Windows PowerShell trap as rlwe-java/run.ps1: with $ErrorActionPreference
# = 'Stop' (line 7) every line a native program writes to stderr becomes a
# terminating error. javac emits "注: 使用了已过时的 API" even on success, so the
# script used to die here -- and because the child rlwe-java build had already
# written only part of its classes, the symptom looked like "找不到符号 RlweOps"
# rather than "脚本提前退出". Widen the policy for this call, then restore it.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $javacPath -encoding UTF-8 -cp $cp -d $out (Join-Path $here 'src\RlweBench.java')
$compileExit = $LASTEXITCODE
$ErrorActionPreference = $prevEap
if ($compileExit -ne 0) { Write-Error 'compile failed'; exit $compileExit }

Write-Host "[run] RlweBench"
$ErrorActionPreference = 'Continue'
& $javaPath '-Xmx4g' '-Dfile.encoding=UTF-8' '-Dstdout.encoding=UTF-8' '-Dstderr.encoding=UTF-8' -cp "$out;$cp" RlweBench
exit $LASTEXITCODE
