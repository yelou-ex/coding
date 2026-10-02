#  ============================================================================
#  Run the native SealPIR test against the prebuilt mpc4j-native-fhe.dll.
#
#  ASCII only (Windows PowerShell 5.1 reads .ps1 as ANSI/GBK). Paths are
#  forward-slash so no backslash escape sequence can be mangled in transit.
#
#  Usage:
#    .\run.ps1                                  # use .\lib\mpc4j-native-fhe.dll
#    .\run.ps1 -Root 'C:/.../seal'              # use the freshly built one
#    .\run.ps1 -N 8192 -T 65537 -Db 128 -Index 7
#    .\run.ps1 -CompileOnly                     # 只编 Java 绑定，不跑测试
#  ============================================================================
param(
    [string]$Root = '',
    [int]$N = 16384,
    [long]$T = 65537,
    [int]$Db = 256,
    [int]$Index = 170,
    [switch]$CompileOnly
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition

$jdk = (Get-Command javac -ErrorAction SilentlyContinue).Source
if (-not $jdk) { $jdk = 'D:\Java\jdk\bin\javac.exe' }
$javac = $jdk
$java = Join-Path (Split-Path -Parent $jdk) 'java.exe'

# where is the dll?
if ($Root -ne '') {
    $libdir = "$Root/native-lib"
    if (-not (Test-Path "$libdir/mpc4j-native-fhe.dll")) {
        # fall back to the cmake output, renamed on the fly
        $built = Get-ChildItem "$Root/mpc4j-native-fhe-build" -Filter 'libmpc4j-native-fhe.dll' -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $built) { Write-Error "no dll under $Root" ; exit 1 }
        New-Item -ItemType Directory -Force -Path $libdir | Out-Null
        Copy-Item $built.FullName "$libdir/mpc4j-native-fhe.dll" -Force
    }
} else {
    $libdir = Join-Path $here 'lib'
}
if (-not (Test-Path "$libdir/mpc4j-native-fhe.dll")) {
    Write-Error "mpc4j-native-fhe.dll not found in $libdir"
    exit 1
}

# build dir must be ASCII-safe: javac/java handle unicode paths fine, but keep
# the outputs next to the dll so nothing depends on the Chinese workspace path.
$out = Join-Path $libdir 'classes'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out | Out-Null

$src = Join-Path $here 'src\main\java'
$files = Get-ChildItem $src -Recurse -Filter *.java | ForEach-Object { $_.FullName }

Write-Host "[compile] $($files.Count) java file(s)"
& $javac -encoding UTF-8 -d $out $files
if ($LASTEXITCODE -ne 0) { Write-Error 'javac failed'; exit $LASTEXITCODE }

if ($CompileOnly) {
    # 为什么需要这个开关：`rgsw-lab\run-mpc4j.ps1` 把 `native-jni/lib/classes`
    # 放进了 classpath，没有它 rgsw-lab **根本编译不过**（`找不到符号 com.fusepir.nativejni`）。
    # 而 classes/ 是 .gitignore 的构建产物，新克隆的仓库里不存在 —— 于是
    # "跑演示"的第一步就被卡在一个只能顺带跑耗时测试的脚本上。
    # 有了它，准备环境就是一句 `.\run.ps1 -CompileOnly`。
    Write-Host "[done] bindings compiled to $out (skipped the native test)"
    exit 0
}

Write-Host "[run] N=$N t=$T db=$Db index=$Index  (dll: $libdir)"
# JDK 25 warns about restricted native access unless it is enabled explicitly,
# and PowerShell 5.1 turns any native stderr line into a terminating error while
# $ErrorActionPreference is 'Stop' - which masked a successful run as exit 1.
# So: enable native access AND funnel stderr through the pipeline.
& $java '-Xmx4g' '--enable-native-access=ALL-UNNAMED' "-Djava.library.path=$libdir" `
    -cp $out com.fusepir.nativejni.SealPirNativeTest $N $T $Db $Index 2>&1 |
    ForEach-Object { Write-Host $_ }
exit $LASTEXITCODE
