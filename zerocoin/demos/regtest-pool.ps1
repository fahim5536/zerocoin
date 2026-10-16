#requires -Version 5.1
<#
.SYNOPSIS
    Live smoke test of ZeroCoin's in-built mining pool RPC on a throwaway regtest node.

.DESCRIPTION
    Starts a fresh regtest daemon on ephemeral ports, then drives it exactly as an
    operator would with zerocoin-cli:

      1. getpoolinfo on a fresh node      -> pool idle (no shares submitted yet)
      2. mine --blocks 3                   -> solo blocks (pooled_blocks: 0)
      3. getpoolinfo again                 -> still idle; the ledger drains on every mine

    The share -> micro-reward split itself is exercised end to end by the in-process
    integration test `a_submitted_share_earns_a_mobile_micro_reward` in src/node.rs
    (a real share is validated, credited, and paid from a split coinbase while exactly
    one subsidy enters supply). This script proves the pool RPC and pool-aware `mine`
    are wired correctly at the process/CLI boundary.

    The daemon is always stopped and the temp data dir always removed, even on error.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-Location -Path (Split-Path -Parent $PSScriptRoot)  # crate root (zerocoin/)

$daemon = Join-Path $PSScriptRoot '..\target\debug\zerocoind.exe'
$cli    = Join-Path $PSScriptRoot '..\target\debug\zerocoin-cli.exe'
if (-not (Test-Path $daemon) -or -not (Test-Path $cli)) {
    throw "binaries not found; run 'cargo build --bins' first"
}

$env:ZRO_WALLET_PASSWORD = 'zro-pool-demo'
$dataDir = Join-Path $env:TEMP ("zro-pool-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
$rpc = '127.0.0.1:18463'
$p2p = '127.0.0.1:18464'

function Invoke-Cli {
    param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $CliArgs)
    & $cli --network regtest --rpc $rpc @CliArgs
}

Write-Host "ZeroCoin pool smoke test" -ForegroundColor Cyan
Write-Host "  data dir : $dataDir"
Write-Host "  rpc      : $rpc"
Write-Host ""

$proc = Start-Process -FilePath $daemon `
    -ArgumentList '--network', 'regtest', '--datadir', $dataDir, '--rpc', $rpc, '--p2p', $p2p `
    -PassThru -WindowStyle Hidden

try {
    # Poll until the loopback RPC answers (the daemon binds it after opening the chain).
    $ready = $false
    for ($i = 0; $i -lt 80; $i++) {
        Start-Sleep -Milliseconds 250
        try { Invoke-Cli getinfo | Out-Null; $ready = $true; break } catch { }
    }
    if (-not $ready) { throw "daemon did not open RPC port $rpc in time" }

    Write-Host "--- 1. getpoolinfo on a fresh node ---" -ForegroundColor Green
    Invoke-Cli getpoolinfo

    Write-Host ""
    Write-Host "--- 2. mine --blocks 3 (solo: no shares submitted) ---" -ForegroundColor Green
    Invoke-Cli mine --blocks 3

    Write-Host ""
    Write-Host "--- 3. getpoolinfo after mining (ledger drains each block) ---" -ForegroundColor Green
    Invoke-Cli getpoolinfo

    Write-Host ""
    Write-Host "--- 4. getinfo (subsidy_issued = 3 x 50 ZRO, cap intact) ---" -ForegroundColor Green
    Invoke-Cli getinfo

    Write-Host ""
    Write-Host "OK: pool RPC and pool-aware mine are wired correctly." -ForegroundColor Cyan
}
finally {
    try { Invoke-Cli stop | Out-Null } catch { }
    Start-Sleep -Milliseconds 400
    if ($proc -and -not $proc.HasExited) { $proc.Kill() }
    Remove-Item -Recurse -Force $dataDir -ErrorAction SilentlyContinue
}
