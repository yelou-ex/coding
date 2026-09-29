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

# Compile【全部】源文件，只排除「路线 C」那 7 个（自研 RLWE，零依赖，走 run.ps1）。
#
# 原来这里是一份【硬编码的文件名列表】，新加的类必须手动登记，否则会被静默跳过 ——
# 2026-09-29 合并远端的四步端到端时就踩到了：`CapeEndToEnd4` 编译都没编译，
# 只报一句 "找不到或无法加载主类"。改成 BUILT.md 里的 glob + 排除法，新类自动纳入。
$srcDir = Join-Path $here 'src\main\java\com\fusepir\rgsw'
$routeC = @('RgswOps.java', 'RgswCiphertext.java', 'MonomialOps.java', 'BootstrapKey.java',
            'RgswLabMain.java', 'MonomialKeyTest.java', 'LabConfig.java')
$srcFiles = Get-ChildItem $srcDir -Filter *.java |
    Where-Object { $_.Name -notin $routeC } |
    Select-Object -ExpandProperty FullName

# LweRlweConversion 要用 cape.he（lwe-java 的 LWE 层），把它的源码目录挂到 sourcepath 上。
$lweSrc = Join-Path (Split-Path -Parent $lib) 'lwe-java\src\main\java'

Write-Host "[compile] MPC4J-based sources (classpath = coding\lib)"
& $javacPath -encoding UTF-8 -cp $cp -sourcepath $lweSrc -d $out $srcFiles
if ($LASTEXITCODE -ne 0) { Write-Error 'compile failed'; exit $LASTEXITCODE }

Write-Host "[run] $Class $progArgs"
& $javaPath '-Xmx4g' '-Dfile.encoding=UTF-8' -cp "$out;$cp" $Class @progArgs
exit $LASTEXITCODE
