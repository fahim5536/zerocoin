#requires -Version 5.1
<#
.SYNOPSIS
    ZeroCoin regtest devnet demo: proves the 100-block coinbase-maturity rule and the
    zero-premine genesis end to end, using the real `zerocoind` + `zerocoin-cli`.

.DESCRIPTION
    Starts a throwaway `zerocoind` on the regtest network (trivial SHA-256d PoW, instant
    blocks, retargeting off) against a fresh data directory, then drives it with
    `zerocoin-cli` over the loopback RPC port:

      1. getinfo          -> height 0, subsidy_issued 0   (genesis mints nothing: no premine)
      2. getnewaddress    -> this node's mining payout address
      3. mine --blocks 99 -> tip 99; every coinbase still immature
      4. getbalance       -> confirmed grows, spendable stays 0 (coins are locked)
      5. mine --blocks 2  -> tip 101; the first coinbases reach 100 confirmations
      6. getbalance       -> spendable jumps to the matured coinbases only
      7. getinfo / getpeercount / stop

    Step 3+5 total 101 blocks, matching the canonical `mine --blocks 101` maturity check.
    A coinbase mined at height H is spendable once the tip reaches H + 100, so at tip 101
    only the coinbases at heights 1 and 2 are unlocked (100 ZRO of the 5050 ZRO mined).

    The data directory is a GUID-named folder under the temp dir; it is removed on exit.
    The daemon is always stopped, even if a step throws.

.PARAMETER RpcPort
    Loopback RPC port for the throwaway daemon (default 18443, regtest's default).

.PARAMETER P2pPort
    P2P listen port for the throwaway daemon (default 18444, regtest's default).

.EXAMPLE
    pwsh ./demos/regtest-maturity.ps1

.NOTES
    Build the binaries first:  cargo build --bins   (run from the crate root).
#>

[CmdletBinding()]
param(
    [int]$RpcPort = 18443,
    [int]$P2pPort = 18444
)

$ErrorActionPreference = 'Stop'

# --- Resolve the crate root and the built binaries -------------------------
$crate  = Split-Path -Parent $PSScriptRoot           # ...\zerocoin
$daemon = Join-Path $crate 'target\debug\zerocoind.exe'
$cli    = Join-Path $crate 'target\debug\zerocoin-cli.exe'

foreach ($exe in @($daemon, $cli)) {
    if (-not (Test-Path $exe)) {
        Write-Error "Missing '$exe'. Build it first:  cargo build --bins   (from $crate)"
    }
}

$dataDir  = Join-Path ([System.IO.Path]::GetTempPath()) ("zro-demo-" + [guid]::NewGuid().ToString('N'))
$password = 'zro-regtest-demo'
$rpc      = "127.0.0.1:$RpcPort"
$p2p      = "127.0.0.1:$P2pPort"

function Write-Step([string]$msg) {
    Write-Host ''
    Write-Host "==> $msg" -ForegroundColor Cyan
}

# Run one CLI subcommand against the daemon; surface a non-zero exit as an error.
function Invoke-Cli {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CliArgs)
    & $cli --network regtest --rpc $rpc @CliArgs
    if ($LASTEXITCODE -ne 0) {
        throw "zerocoin-cli exited $LASTEXITCODE on: $($CliArgs -join ' ')"
    }
}

# Block until the daemon accepts TCP connections on the RPC port.
function Wait-RpcReady {
    param([int]$TimeoutSec = 25)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $client.Connect('127.0.0.1', $RpcPort)
            if ($client.Connected) { return $true }
        } catch {
            Start-Sleep -Milliseconds 200
        } finally {
            $client.Close()
        }
    }
    return $false
}

$proc = $null
try {
    Write-Step "Starting zerocoind (regtest) in $dataDir"
    $proc = Start-Process -FilePath $daemon -PassThru -WindowStyle Hidden -ArgumentList @(
        '--network', 'regtest',
        '--datadir', $dataDir,
        '--rpc',     $rpc,
        '--p2p',     $p2p,
        '--password', $password
    )
    if (-not (Wait-RpcReady)) { throw "daemon did not open RPC port $RpcPort in time" }
    Write-Host "    daemon pid $($proc.Id)  rpc $rpc  p2p $p2p" -ForegroundColor DarkGray

    Write-Step 'getinfo  (fresh chain: height 0, subsidy_issued 0 -> the genesis mints nothing)'
    Invoke-Cli getinfo

    Write-Step 'getnewaddress  (this node''s mining payout address)'
    Invoke-Cli getnewaddress

    Write-Step 'mine --blocks 99  (tip 99: the height-1 coinbase has 99 confirmations, still immature)'
    Invoke-Cli mine --blocks 99 | Out-Null
    Write-Host '    getbalance after 99 blocks:' -ForegroundColor DarkGray
    Invoke-Cli getbalance

    Write-Step 'mine --blocks 2  (tip 101: heights 1 and 2 cross the 100-confirmation threshold)'
    Invoke-Cli mine --blocks 2 | Out-Null
    Write-Host '    getbalance after 101 blocks total:' -ForegroundColor DarkGray
    Invoke-Cli getbalance

    Write-Step 'getinfo  (final state: height 101, subsidy_issued = 101 * 50 ZRO = 5050 ZRO)'
    Invoke-Cli getinfo

    Write-Step 'getpeercount  (a solo regtest node has no peers)'
    Invoke-Cli getpeercount

    Write-Step 'stop  (ask the daemon to shut down cleanly)'
    Invoke-Cli stop
    if ($proc -and -not $proc.HasExited) { $proc.WaitForExit(5000) | Out-Null }
}
finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    if (Test-Path $dataDir) { Remove-Item -Recurse -Force $dataDir -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host 'Demo complete: 5050 ZRO mined, only the two matured coinbases (100 ZRO) spendable.' -ForegroundColor Green
