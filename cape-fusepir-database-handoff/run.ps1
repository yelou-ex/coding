# ============================================================================
#  Compile and run the plaintext-side (database) module.
#  (ASCII only: Windows PowerShell 5.1 reads .ps1 as ANSI/GBK without a BOM)
#
#  Usage:  .\run.ps1                                     -> BloomConjunctionCheck
#          .\run.ps1 -Class com.fusepir.database.ArithmeticBffSelfTestMain
#
#  Zero third-party dependencies: pure JDK, any JDK 17+ works.
#  NOTE: this module depends on the SHARED module ../common (com.fusepir.common.BfGen).
#        The Bloom bit function MUST be one implementation shared with rgsw-lab,
#        otherwise the client's b_qry and the server's b_v use different
#        B(keyword) and the inner product never matches tau.
# ============================================================================
param([string]$Class = 'com.fusepir.database.BloomConjunctionCheck')
$progArgs = $args

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$root = Split-Path -Parent $here
$javacPath = (Get-Command javac -ErrorAction SilentlyContinue).Source
if (-not $javacPath) { $javacPath = 'D:\Java\jdk\bin\javac.exe' }
$javaPath = Join-Path (Split-Path -Parent $javacPath) 'java.exe'

$out = Join-Path $here '_cli-out'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out | Out-Null

$srcDirs = @((Join-Path $here 'src\main\java'), (Join-Path $root 'common\src\main\java'))
$srcFiles = @()
foreach ($d in $srcDirs) {
    if (Test-Path $d) { $srcFiles += Get-ChildItem $d -Recurse -Filter *.java | Select-Object -ExpandProperty FullName }
}

Write-Host "[compile] plaintext module + shared common ($($srcFiles.Count) files)"
& $javacPath -encoding UTF-8 -nowarn -d $out $srcFiles
if ($LASTEXITCODE -ne 0) { Write-Error 'compile failed'; exit $LASTEXITCODE }

Write-Host "[run] $Class $progArgs"
# See rgsw-lab\run-mpc4j.ps1 for why stdout.encoding is needed (JEP 400:
# -Dfile.encoding no longer controls System.out, so Chinese would come out as GBK mojibake).
& $javaPath '-Dfile.encoding=UTF-8' '-Dstdout.encoding=UTF-8' '-Dstderr.encoding=UTF-8' -cp $out $Class @progArgs
exit $LASTEXITCODE
