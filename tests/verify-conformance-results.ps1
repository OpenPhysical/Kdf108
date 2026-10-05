# Verifies a CAVP gate: the pinned corpus is byte-for-byte unchanged, every test passed, nothing
# was skipped, and the per-file tests together executed exactly the manifest's vector count.
# Each per-file test writes "cavp-vectors-executed: N" to its output; this script sums them.
param(
    [Parameter(Mandatory = $true)] [string] $ResultsDirectory,
    [Parameter(Mandatory = $true)] [string] $GateName,
    [string] $ManifestPath = (Join-Path $PSScriptRoot 'conformance-manifest.json')
)

$ErrorActionPreference = 'Stop'
$manifest = Get-Content -Raw $ManifestPath | ConvertFrom-Json
$gate = $manifest.gates.$GateName
if ($null -eq $gate) { throw "Unknown gate '$GateName'." }

function Get-Sha256([string] $path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }

if ($gate.corpus -eq 'SP800-108') {
    foreach ($corpus in $manifest.corpora) {
        $path = Join-Path $PSScriptRoot $corpus.path
        if ((Get-Sha256 $path) -ne $corpus.sha256) { throw "Corpus hash mismatch: $($corpus.path)" }
    }
}
else {
    $tree = $manifest.trees | Where-Object { $_.corpus -eq $gate.corpus }
    $root = (Resolve-Path (Join-Path $PSScriptRoot $tree.path)).Path
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $root -File -Recurse) {
        $relative = [System.IO.Path]::GetRelativePath($root, $file.FullName).Replace('\', '/')
        $lines.Add("$relative`0$(Get-Sha256 $file.FullName)`n")
    }
    $sorted = [string[]] $lines.ToArray()
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]::Concat($sorted))
    $hash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    if ($sorted.Count -ne $tree.files -or $hash -ne $tree.sha256) {
        throw "Corpus tree mismatch for $($tree.path): $($sorted.Count) files, hash $hash."
    }
}

$trxFiles = @(Get-ChildItem -LiteralPath $ResultsDirectory -Filter '*.trx' -File -Recurse)
if ($trxFiles.Count -eq 0) { throw 'No TRX result was produced; the gate needs execution evidence.' }

$vectors = 0; $tests = 0; $failed = 0; $skipped = 0
foreach ($trxFile in $trxFiles) {
    [xml] $trx = Get-Content -Raw $trxFile.FullName
    $counters = $trx.TestRun.ResultSummary.Counters
    $tests += [int] $counters.executed
    $failed += [int] $counters.failed
    $skipped += [int] $counters.notExecuted
    foreach ($result in $trx.TestRun.Results.UnitTestResult) {
        foreach ($match in [regex]::Matches([string] $result.Output.StdOut, 'cavp-vectors-executed:\s*(\d+)')) {
            $vectors += [int] $match.Groups[1].Value
        }
    }
}

if ($failed -ne 0) { throw "$GateName has $failed failed tests." }
if ($skipped -ne 0) { throw "$GateName has $skipped skipped tests; gates allow none." }
if ($tests -eq 0) { throw "$GateName executed no tests." }
if ($vectors -ne $gate.expectedVectors) {
    throw "$GateName executed $vectors vectors; the manifest requires $($gate.expectedVectors)."
}
Write-Host "$GateName verified: $vectors vectors in $tests tests, corpus unchanged, no failures or skips."
