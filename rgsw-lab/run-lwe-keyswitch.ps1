# LWE key switching (N -> d) self-check: compile + run, using its own output directory.
#
# Why not reuse .\run-mpc4j.ps1: that script deletes and recreates mpc4j-out on every
# start, which would wipe a concurrently running agent's artifacts. This script only
# ever touches mpc4j-out-ks.
#
# Three PowerShell 5.1 hazards, all measured in this repo -- do not "clean them up":
#   1) Inline -Dfile.encoding=UTF-8 arguments get mangled (java then reports
#      "could not find main class .encoding=UTF-8"). Use an @javaOpts array splat,
#      exactly like run-mpc4j.ps1 does.
#   2) Paths are derived from $PSScriptRoot. This repo lives under a non-ASCII root
#      and PS 5.1 decodes a BOM-less UTF-8 script as GBK, so a hardcoded Chinese path
#      literal turns into mojibake ("E:\<garbage>\coding\lib\deps"). Keeping every
#      string literal ASCII makes this file immune.
#   3) Keep this file CRLF-terminated: with LF-only endings the GBK mis-decode lets a
#      trailing non-ASCII comment byte swallow the line feed, so the comment eats the
#      next code line and the parser reports a bogus "Unexpected token ')'".
#
# Usage: .\run-lwe-keyswitch.ps1 -N 8192 -D 16
param(
    [int]$N = 8192,
    [int]$D = 16
)
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$coding = Split-Path -Parent $here
$lib = Join-Path $coding 'lib'
$nativeDir = Join-Path $coding 'native-jni\lib'
$lweSrc = Join-Path $coding 'lwe-java\src\main\java'
$commonSrc = Join-Path $coding 'common\src\main\java'
$jdk = 'D:\Java\jdk'

$cp = (Join-Path $lib 'mpc4j-crypto-fhe-seal.jar')
$cp = $cp + ';' + ((Get-ChildItem (Join-Path $lib 'deps') -Filter *.jar | ForEach-Object { $_.FullName }) -join ';')
$cp = $cp + ';' + (Join-Path $nativeDir 'classes')

$out = Join-Path $here 'mpc4j-out-ks'
$srcDir = Join-Path $here 'src\main\java\com\fusepir'

$routeC = @('RgswOps.java', 'RgswCiphertext.java', 'MonomialOps.java', 'BootstrapKey.java', 'RgswLabMain.java', 'MonomialKeyTest.java', 'LabConfig.java')
$srcFiles = Get-ChildItem $srcDir -Recurse -Filter *.java | Where-Object { $_.Name -notin $routeC } | Select-Object -ExpandProperty FullName
$srcFiles += Get-ChildItem $commonSrc -Recurse -Filter *.java | Select-Object -ExpandProperty FullName

New-Item -ItemType Directory -Force -Path $out | Out-Null

$javacPath = Join-Path $jdk 'bin\javac.exe'
$javacArgs = @('-encoding', 'UTF-8', '-cp', $cp, '-sourcepath', $lweSrc, '-d', $out) + $srcFiles
& $javacPath @javacArgs
Write-Output "[javac exit code: $LASTEXITCODE]  ($($srcFiles.Count) source files -> $out)"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$javaPath = Join-Path $jdk 'bin\java.exe'
$javaOpts = @('-Xmx4g', '-Dfile.encoding=UTF-8', '-Dstdout.encoding=UTF-8', '-Dstderr.encoding=UTF-8')
& $javaPath @javaOpts "-Djava.library.path=$nativeDir" "--enable-native-access=ALL-UNNAMED" -cp "$out;$cp" com.fusepir.probe.LweKeySwitchTest "$N" "$D"
Write-Output "[java exit code: $LASTEXITCODE]"
exit $LASTEXITCODE
