# ============================================================================
#  CAPE native demo - one-click launcher.
#
#  Starts the Java service (which runs SETUP once, ~1 s) and opens the browser.
#
#  NOTE: this file is deliberately ASCII-only. PowerShell 5.1 reads .ps1 as
#  ANSI/GBK, so a non-ASCII byte in here gets mangled -- that already broke a
#  Chinese path in an earlier script. Pass paths in as arguments instead.
#
#  Usage:  .\run-demo.ps1                  -> port 8756, N=8192
#          .\run-demo.ps1 -Port 9000
#          .\run-demo.ps1 -NoBrowser
# ============================================================================
param(
    [int]$Port = 8756,
    [int]$N = 8192,
    [int]$D = 16,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$lab  = Join-Path (Split-Path -Parent $here) 'rgsw-lab'
$runner = Join-Path $lab 'run-mpc4j.ps1'

if (-not (Test-Path $runner)) {
    Write-Host "[FAIL] cannot find $runner"
    exit 1
}

$db = Join-Path $here 'db\keywords.json'
if (-not (Test-Path $db)) {
    Write-Host "[FAIL] dataset missing: $db"
    Write-Host "       build it first:  cd cape-demo\db ; python build_dataset.py"
    exit 1
}

$url = "http://127.0.0.1:$Port/"

# Reuse an already-running instance if the port answers.
$alive = $false
try {
    $null = Invoke-RestMethod -Uri "${url}api/state" -TimeoutSec 3
    $alive = $true
} catch { $alive = $false }

if ($alive) {
    Write-Host "[ok] service already running at $url"
} else {
    Write-Host "[..] starting CAPE demo service on port $Port (SETUP takes ~1 s)"
    # run-mpc4j.ps1 compiles everything and sets java.library.path for the native DLL.
    $argList = @('-Class', 'com.fusepir.rgsw.CapeDemoService',
                 "$Port", "$N", "$D", $db)
    $p = Start-Process -FilePath 'powershell.exe' -PassThru -WindowStyle Minimized `
        -ArgumentList (@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $runner) + $argList)

    # Wait for the port to answer.
    $ready = $false
    for ($i = 1; $i -le 90; $i++) {
        Start-Sleep -Milliseconds 1000
        if ($p.HasExited) {
            Write-Host "[FAIL] service exited early (code $($p.ExitCode))."
            Write-Host "       run manually to see the error:"
            Write-Host "       cd `"$lab`" ; .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeDemoService $Port $N $D `"$db`""
            exit 1
        }
        try {
            $null = Invoke-RestMethod -Uri "${url}api/state" -TimeoutSec 3
            $ready = $true
            break
        } catch { }
    }
    if (-not $ready) {
        Write-Host "[FAIL] service did not become ready in 90 s (pid $($p.Id))"
        exit 1
    }
    Write-Host "[ok] service ready (pid $($p.Id))"
}

if (-not $NoBrowser) {
    Write-Host "[..] opening $url"
    Start-Process $url
}
Write-Host ""
Write-Host "   demo page : $url"
Write-Host "   stop      : Get-Process java | Stop-Process   (or close the minimized window)"
Write-Host "   note      : ANSWER takes ~2-3 min at N=$N; the page shows a progress bar."
Write-Host ""
