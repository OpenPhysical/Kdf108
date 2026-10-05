param(
    [Parameter(Mandatory = $true)]
    [string] $ResultsDirectory,

    [string] $ManifestPath = (Join-Path $PSScriptRoot "conformance-manifest.json"),

    [string] $GateName = 'CAVP-SP800-108'
)

$ErrorActionPreference = "Stop"
$manifest = Get-Content -Raw $ManifestPath | ConvertFrom-Json
$gate = $manifest.gates.$GateName

if ($GateName -eq 'CAVP-SP800-108') {
foreach ($corpus in $manifest.corpora) {
    $path = Join-Path $PSScriptRoot $corpus.path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required conformance corpus is missing: $($corpus.path)"
    }

    $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $corpus.sha256) {
        throw "Conformance corpus hash mismatch for $($corpus.path): expected $($corpus.sha256), got $actualHash"
    }

    $actualVectors = (Select-String -LiteralPath $path -Pattern '^COUNT\s*=').Count
    if ($actualVectors -ne $corpus.expectedVectors) {
        throw "Conformance corpus count mismatch for $($corpus.path): expected $($corpus.expectedVectors), got $actualVectors"
    }

    $legacyVectors = 0
    $inLegacySection = $false
    foreach ($line in Get-Content -LiteralPath $path) {
        if ($line -match '^\[PRF=(.+)\]$') {
            $inLegacySection = $Matches[1] -in @('CMAC_TDES2', 'CMAC_TDES3')
        }
        elseif ($inLegacySection -and $line -match '^COUNT\s*=') {
            $legacyVectors++
        }
    }
    if ($legacyVectors -ne $corpus.expectedLegacyDiagnosticVectors) {
        throw "Legacy diagnostic classification mismatch for $($corpus.path): expected $($corpus.expectedLegacyDiagnosticVectors), got $legacyVectors"
    }
    if (($actualVectors - $legacyVectors) -ne $corpus.expectedConformingVectors) {
        throw "Conforming vector classification mismatch for $($corpus.path): expected $($corpus.expectedConformingVectors), got $($actualVectors - $legacyVectors)"
    }
}
}

$trxFiles = @(Get-ChildItem -LiteralPath $ResultsDirectory -Filter '*.trx' -File -Recurse)
if ($trxFiles.Count -eq 0) {
    throw "No TRX result was produced. The CAVP gate cannot pass without execution evidence."
}

$executed = 0
$skipped = 0
$failed = 0
foreach ($trxFile in $trxFiles) {
    [xml] $trx = Get-Content -Raw $trxFile.FullName
    $counters = $trx.TestRun.ResultSummary.Counters
    $executed += [int] $counters.executed
    $skipped += [int] $counters.notExecuted
    $failed += [int] $counters.failed
}

if ($failed -ne 0) {
    throw "CAVP execution contains $failed failed tests."
}
if (-not $gate.allowSkipped -and $skipped -ne 0) {
    throw "CAVP execution contains $skipped skipped/not-executed tests; this gate requires zero skips."
}
if ($executed -ne $gate.expectedExecutedTests) {
    throw "CAVP execution count mismatch: expected $($gate.expectedExecutedTests), got $executed. This usually means vectors were filtered, skipped, or duplicated."
}

Write-Host "$GateName evidence verified: $executed tests executed, $failed failed, zero skipped; required execution count matches."
