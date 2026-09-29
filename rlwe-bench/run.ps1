# ============================================================================
#  RLWE efficiency benchmark: this implementation vs MPC4J
#  (ASCII only: Windows PowerShell 5.1 reads .ps1 as ANSI/GBK without a BOM)
#
#  Usage:  .\run.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$coding = Split-Path -Parent $here

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
& $javacPath -encoding UTF-8 -cp $cp -d $out (Join-Path $here 'src\RlweBench.java')
if ($LASTEXITCODE -ne 0) { Write-Error 'compile failed'; exit $LASTEXITCODE }

Write-Host "[run] RlweBench"
& $javaPath '-Xmx4g' '-Dfile.encoding=UTF-8' '-Dstdout.encoding=UTF-8' '-Dstderr.encoding=UTF-8' -cp "$out;$cp" RlweBench
exit $LASTEXITCODE
