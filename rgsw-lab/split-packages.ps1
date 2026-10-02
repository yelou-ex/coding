# ============================================================================
#  Split the flat `com.fusepir.rgsw` package into paper-mapped layers.
#
#  WHY: the whole lab used to be ONE package with ~90 classes, so "where is
#  Algorithm 2's ANSWER?" had no answer you could see in the file tree.
#
#  TARGET
#    com.fusepir.prim/     RLWE / LWE / RGSW / CMUX / blind rotation / expand
#    com.fusepir.bloom/    encrypted Bloom scoring  (BF.Gen itself stays in the
#                          shared `common` module -- two other modules use it)
#    com.fusepir.bff/      BFF parameterisation + Encode (table D, P_{c,b})
#    com.fusepir.fusepir/  FusePIR's own steps (the anchor retrieval)
#    com.fusepir.cape/     CAPE's own steps
#    com.fusepir.demo/     dataset / service glue / JSON helper
#    com.fusepir.probe/    every probe, diag, bench and acceptance test
#    com.fusepir.legacy/   the 7 deprecated Route-C (self-built RLWE) files
#
#  RULES
#    * This is a MOVE. No logic is changed.
#    * `import P.*;` is added only for packages the file actually names.
#    * Classes with no dedicated file for a paper step are NOT invented
#      (e.g. `Pack` does not exist -- see MAP.md).
#
#  ASCII-only is NOT required here (PowerShell reads .ps1 as ANSI/GBK but this
#  file has no non-ASCII bytes in code positions).
# ============================================================================
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$root = Join-Path $here 'src\main\java\com\fusepir'
$old  = Join-Path $root 'rgsw'
if (-not (Test-Path $old)) { Write-Host "nothing to do: $old not found"; exit 0 }

# ---------------------------------------------------------------- the mapping
$prim = @('Mpc4jRgsw','BlindRotateOps','BlindRotateComplete','ExpandOps',
          'LweColumnMath','LweRlweBridge','LweRlweConversion','LweToRgswOps',
          'RingPack','NativeCapeAnswer')
$bloom = @('BloomScoring')
$bff = @('CapeDemoData')
$fusepir = @('AnswerPathMini','CapeAnswerFull','CapeAnswerColumnOriginal')
$cape = @('CapeQuery','CapeDemoService','CapeBloomScore','CapeScorerWire',
          'CapeQueryDecode')
$demo = @('CapeDemo','Json')
$legacy = @('RgswOps','RgswCiphertext','MonomialOps','BootstrapKey','RgswLabMain',
            'MonomialKeyTest','LabConfig')

$layer = @{}
foreach ($n in $prim)    { $layer[$n] = 'prim' }
foreach ($n in $bloom)   { $layer[$n] = 'bloom' }
foreach ($n in $bff)     { $layer[$n] = 'bff' }
foreach ($n in $fusepir) { $layer[$n] = 'fusepir' }
foreach ($n in $cape)    { $layer[$n] = 'cape' }
foreach ($n in $demo)    { $layer[$n] = 'demo' }
foreach ($n in $legacy)  { $layer[$n] = 'legacy' }

$pkgs = @('prim','bloom','bff','fusepir','cape','demo','probe','legacy')
# `legacy` is EXCLUDED from the build (run-mpc4j.ps1 filters those 7 by name), so it
# must not receive imports either -- a wildcard import of a package with no compiled
# classes is a hard error ("package com.fusepir.legacy does not exist").
$importPkgs = @('prim','bloom','bff','fusepir','cape','demo','probe')

# everything not named above becomes a probe
$files = Get-ChildItem $old -Filter *.java
foreach ($f in $files) {
    if (-not $layer.ContainsKey($f.BaseName)) { $layer[$f.BaseName] = 'probe' }
}

Write-Host "=== 1. move files ==="
$counts = @{}
foreach ($p in $pkgs) { $counts[$p] = 0 }
foreach ($f in $files) {
    $dest = $layer[$f.BaseName]
    $dstDir = Join-Path $root $dest
    New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
    $text = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
    $text = $text -replace 'package\s+com\.fusepir\.rgsw\s*;', "package com.fusepir.$dest;"
    [System.IO.File]::WriteAllText((Join-Path $dstDir $f.Name), $text,
        (New-Object System.Text.UTF8Encoding($false)))
    Remove-Item $f.FullName
    $counts[$dest]++
}
foreach ($p in $pkgs) { Write-Host ("  {0,-9} {1,3}" -f $p, $counts[$p]) }

Write-Host ""
Write-Host "=== 2. add cross-layer imports (only where a name is actually used) ==="
$members = @{}
foreach ($p in $importPkgs) { $members[$p] = @() }
foreach ($kv in $layer.GetEnumerator()) {
    if ($members.ContainsKey($kv.Value)) { $members[$kv.Value] += $kv.Key }
}

$added = 0
foreach ($p in $pkgs) {
    foreach ($f in Get-ChildItem (Join-Path $root $p) -Filter *.java) {
        $text = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
        $need = @()
        foreach ($q in $importPkgs) {
            if ($q -eq $p) { continue }
            foreach ($cls in $members[$q]) {
                if ($text -match ("(?<![A-Za-z0-9_])" + [regex]::Escape($cls) + "(?![A-Za-z0-9_])")) {
                    $need += "import com.fusepir.$q.*;"
                    break
                }
            }
        }
        if ($need.Count -eq 0) { continue }
        $block = ($need -join "`r`n")
        $new = $text -replace "(package\s+com\.fusepir\.$p\s*;\s*\r?\n)", "`$1`r`n$block`r`n"
        if ($new -ne $text) {
            [System.IO.File]::WriteAllText($f.FullName, $new,
                (New-Object System.Text.UTF8Encoding($false)))
            $added++
        }
    }
}
Write-Host "  files given imports: $added"

Write-Host ""
Write-Host "=== 3. widen access (a package-private member is invisible across packages) ==="
# Splitting one package into eight turns every package-private member that is used
# from another layer into a compile error. The fix is mechanical: publish them.
# `-replace` with a real regex is used throughout -- note `.Split('||')` in PowerShell
# splits on EACH '|' (the argument is a char array), which silently deleted a batch of
# declarations the first time this ran. Do not reintroduce that idiom.
$widened = 0
foreach ($p in $importPkgs) {
    foreach ($f in Get-ChildItem (Join-Path $root $p) -Filter *.java) {
        $t0 = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
        $t = $t0
        # top-level type declarations
        $t = $t -replace '(?m)^(final class |abstract class |class |interface |enum )', 'public $1'
        # 4-space-indented members that lost package-private visibility
        # NOTE: `$1` already contains the `static ` keyword -- writing
        # '    public static $1' produces `public static static long ...`
        # ("repeated modifier"). The first run of this script had exactly that bug.
        $t = $t -replace '(?m)^    (static (?!final class))', '    public $1'
        $t = $t -replace '(?m)^    (final class )', '    public final class '
        $t = $t -replace '(?m)^    (static final class )', '    public static final class '
        # Nested members at 8-space indent that are used from another layer:
        #   CapeDemoData.JsonParser / JsonValue  -- parsed by cape + probe
        #   CapeQuery.Http.get/post        -- used by the cross-process probes
        $t = $t -replace '(?m)^(        )JsonValue\(Object v\) \{', '$1public JsonValue(Object v) {'
        $t = $t -replace '(?m)^(        )JsonValue parse\(\) \{', '$1public JsonValue parse() {'
        $t = $t -replace '(?m)^(        )JsonParser\(String s\) \{', '$1public JsonParser(String s) {'
        $t = $t -replace '(?m)^(        )final Object v;', '$1public final Object v;'
        $t = $t -replace '(?m)^(        )static (Map<String, Object> (?:get|post)\()', '$1public static $2'
        # prim/Mpc4jRgsw 的两条 gadget 分解子程序：probe/DecomposeEquiv 拿它们互为对照物
        $t = $t -replace '(?m)^(    )long\[\]\[\] (decompose(?:Fast|Big)\()', '$1public long[][] $2'
        if ($t -ne $t0) {
            [System.IO.File]::WriteAllText($f.FullName, $t,
                (New-Object System.Text.UTF8Encoding($false)))
            $widened++
        }
    }
}
Write-Host "  files touched by widening: $widened"

# also: the shared `common` module import is already explicit in the sources
Remove-Item $old -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "=== done.  Now: rgsw-lab\run-mpc4j.ps1 must use -Recurse ==="
