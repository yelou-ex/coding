# ============================================================================
#  Compile and run the MPC4J-based sources in this lab, using ONLY coding/lib.
#  (ASCII only: Windows PowerShell 5.1 reads .ps1 as ANSI/GBK without a BOM)
#
#  Usage:  .\run-mpc4j.ps1                                  -> Mpc4jRgsw self-test
#          .\run-mpc4j.ps1 -Class com.fusepir.rgsw.Mpc4jCapability
#          .\run-mpc4j.ps1 -Class com.fusepir.rgsw.Mpc4jCapability 16384
#
#  Anything after -Class is forwarded to the Java program as its argv.
#  NOTE: without the $args forwarding below, ".\run-mpc4j.ps1 -Class X 16384"
#  silently ran at X's DEFAULT size (the 16384 was dropped), which made the
#  documented commands do the wrong thing.
# ============================================================================
param([string]$Class = 'com.fusepir.rgsw.Mpc4jRgsw')
$progArgs = $args

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

$out = Join-Path $here 'mpc4j-out'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out | Out-Null

# Only the sources that depend on MPC4J. The other files in this package belong
# to the self-built RGSW/rlwe-java path and must NOT be pulled in here.
$srcDir = Join-Path $here 'src\main\java\com\fusepir\rgsw'
$srcFiles = @('Mpc4jRgsw.java', 'Mpc4jCapability.java', 'BlindRotateOps.java', 'LweRlweBridge.java', 'RgswPolyTest.java', 'RgswPolyDiag.java', 'BlindRotateComplete.java', 'LweToRgswOps.java', 'SizeProbe.java', 'BlindRotateStress.java', 'AnswerPathMini.java', 'LweRlweConversion.java') |
    ForEach-Object { Join-Path $srcDir $_ } |
    Where-Object { Test-Path $_ }

# LweRlweConversion 要用 cape.he（lwe-java 的 LWE 层），把它的源码目录挂到 sourcepath 上。
$lweSrc = Join-Path (Split-Path -Parent $lib) 'lwe-java\src\main\java'

Write-Host "[compile] MPC4J-based sources (classpath = coding\lib)"
& $javacPath -encoding UTF-8 -cp $cp -sourcepath $lweSrc -d $out $srcFiles
if ($LASTEXITCODE -ne 0) { Write-Error 'compile failed'; exit $LASTEXITCODE }

Write-Host "[run] $Class $progArgs"
& $javaPath '-Xmx4g' '-Dfile.encoding=UTF-8' -cp "$out;$cp" $Class @progArgs
exit $LASTEXITCODE
