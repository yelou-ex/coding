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
& $javacPath -encoding UTF-8 -d $out $src
if ($LASTEXITCODE -ne 0) { Write-Error "compile failed"; exit $LASTEXITCODE }

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
