# ============================================================================
#  !! LEGACY - ROUTE C ONLY !!
#  Compiles rgsw-lab together with the sibling rlwe-java module (com.fusepir.rlwe,
#  self-built, deprecated) and runs RgswLabMain. This is NOT the default path.
#
#  DEFAULT PATH:  .\run-mpc4j.ps1        (RGSW / CMUX / blind rotation)
#                 .\run-mpc4j.ps1 -Class com.fusepir.rgsw.Mpc4jCapability
#                 .\run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateOps
#  It runs on coding/lib/mpc4j-crypto-fhe-seal.jar (MPC4J's SEAL Java port).
#  Kept only as a cross-check tool. See coding/RLWE路线审计.md
# ============================================================================
# ============================================================================
#  RGSW lab runner
#
#  Usage:
#     .\run.ps1            run the mode set by RGSW_MODE in params.env (default: test)
#     .\run.ps1 test       5 correctness self-tests
#     .\run.ps1 scale      extra external-product check at N = 16384
#     .\run.ps1 sweep      parameter sweep table (for tuning)
#
#  Temporary override without editing the file:
#     $env:RGSW_BASE=256; $env:RGSW_PRIMES=2; .\run.ps1
#
#  Priority: process environment > params.env > code defaults
#
#  NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads .ps1 files as
#  ANSI/GBK unless they carry a UTF-8 BOM, so non-ASCII comments can corrupt
#  the script itself (a comment line may swallow the code line after it).
#  Chinese docs live in RGSW_调用说明.md instead.
# ============================================================================
param([string]$mode = '', [switch]$Reload)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition

# -Reload: drop RGSW_* vars inherited from a previous run in this same shell,
# so that edits to params.env take effect without opening a new window.
if ($Reload) {
    Get-ChildItem env: | Where-Object { $_.Name -like 'RGSW_*' } | ForEach-Object {
        [System.Environment]::SetEnvironmentVariable($_.Name, $null, 'Process')
    }
    Write-Host "[config] -Reload: cleared previous RGSW_* variables"
}

# ---- 1. locate JDK ----
$javacPath = $null
$found = Get-Command javac -ErrorAction SilentlyContinue
if ($found) { $javacPath = $found.Source }
if (-not $javacPath -and (Test-Path 'D:\Java\jdk\bin\javac.exe')) {
    $javacPath = 'D:\Java\jdk\bin\javac.exe'
}
if (-not $javacPath) {
    Write-Error 'javac not found: add JDK to PATH or set the fallback path in run.ps1'
    exit 1
}
$javaPath = Join-Path (Split-Path -Parent $javacPath) 'java.exe'

# ---- 2. load params.env into the process environment ----
# Read as UTF-8 explicitly: the file has Chinese comments and PowerShell 5.1
# would otherwise decode it as GBK and merge lines.
$envFile = Join-Path $here 'params.env'
$env:RGSW_ENV_FILE = $envFile
if (Test-Path $envFile) {
    $lines = [System.IO.File]::ReadAllLines($envFile, (New-Object System.Text.UTF8Encoding($false)))
    $loaded = 0
    foreach ($raw in $lines) {
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith('#') -or -not $line.Contains('=')) { continue }
        $idx = $line.IndexOf('=')
        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim()
        if ($key -eq '') { continue }
        # existing environment variables win, so command-line overrides work
        if ([string]::IsNullOrEmpty([System.Environment]::GetEnvironmentVariable($key, 'Process'))) {
            [System.Environment]::SetEnvironmentVariable($key, $val, 'Process')
            $loaded++
        }
    }
    if ($loaded -eq 0) {
        Write-Host "[config] note: 0 keys loaded - RGSW_* vars from a previous run in this shell win over the file."
        Write-Host "[config]       use  .\run.ps1 -Reload  to re-read params.env, or open a new shell."
    }
    Write-Host "[config] loaded $envFile ($loaded keys; existing env vars win)"
} else {
    Write-Host "[config] $envFile not found, using code defaults"
}

if ($mode -ne '') { $env:RGSW_MODE = $mode }
$xmx = if ($env:RGSW_XMX) { $env:RGSW_XMX } else { '2g' }
Write-Host "[config] mode=$($env:RGSW_MODE) N=$($env:RGSW_N) primes=$($env:RGSW_PRIMES)x$($env:RGSW_PRIME_BITS)bit base=$($env:RGSW_BASE) xmx=$xmx"

# ---- 3. compile ----
$out = Join-Path $here 'out'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out | Out-Null

# Compile this module together with the sibling rlwe-java module (same package tree).
$src = @()
$src += (Get-ChildItem -Path (Join-Path $here 'src') -Recurse -Filter *.java |
    ForEach-Object { $_.FullName })
$rlweSrc = Join-Path (Split-Path -Parent $here) 'rlwe-java\src'
if (Test-Path $rlweSrc) {
    $src += (Get-ChildItem -Path $rlweSrc -Recurse -Filter *.java |
        ForEach-Object { $_.FullName })
    Write-Host "[compile] + rlwe-java (sibling module)"
}

Write-Host "[compile] $javacPath"
& $javacPath -encoding UTF-8 -d $out $src
if ($LASTEXITCODE -ne 0) {
    Write-Error "compile failed (exit $LASTEXITCODE)"
    exit $LASTEXITCODE
}

# ---- 4. run (cwd = script dir so that params.env is found) ----
Write-Host "[run] com.fusepir.rgsw.RgswLabMain $mode"
Push-Location $here
try {
    & $javaPath "-Xmx$xmx" '-Dfile.encoding=UTF-8' '-Dstdout.encoding=UTF-8' '-Dstderr.encoding=UTF-8' -cp $out com.fusepir.rgsw.RgswLabMain $mode
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $code
