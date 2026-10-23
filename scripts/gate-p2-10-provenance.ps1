#Requires -Version 5.1
<#
.SYNOPSIS
    Gate P2.10 provenance: re-derive the vendored libsecp256k1 tree's upstream
    identity from materials preserved in the repository.

.DESCRIPTION
    Closes blocker CB-3 (docs/architecture/CRYPTO_BLOCKER_REGISTER.md): the
    P2.6 acquisition transcript was the only evidence for the GPG
    verification, and SHA256SUMS proves non-drift of the vendored tree, not
    its upstream identity. This gate re-derives upstream identity with five
    checks, each a command with an exit code or an explicit comparison:

      1. materialisation: the vendored archive and detached signature exist
         with exactly the pinned sizes and SHA-256 values (ORIGIN.md section
         1, SHA256SUMS archive line);
      2. record agreement: the SHA256SUMS archive line records the same hash
         as the pinned archive;
      3. key identity: the vendored public key carries exactly the pinned
         fingerprint (ORIGIN.md section 2), checked with gpg --show-keys
         before anything is imported anywhere;
      4. signature: the detached signature verifies against the vendored key
         in an isolated, throwaway GnuPG home - GOODSIG and VALIDSIG for the
         pinned fingerprint, exit code 0. TRUST_UNDEFINED is expected on a
         host without a web of trust and is not a failure: the trust anchor is
         the fingerprint pinned in ORIGIN.md section 2, established
         independently of any downloaded artefact;
      5. tree identity: the archive is extracted and every file listed in
         SHA256SUMS is compared byte-for-byte with the same relative path in
         the archive's inner tree, and the vendored copies still hash to
         their recorded values. The comparison is deliberately
         one-directional; ORIGIN.md section 6 lists the upstream files
         intentionally not vendored.

    The GnuPG home is created empty under the work directory for each run and
    never reused. Nothing here upgrades or replaces the backend; the release
    stays pinned at v0.8.0.

.PARAMETER WorkDir
    Scratch directory for the throwaway GnuPG home and the archive extraction.
    The gate wipes it first, but only if it lives under .build/. Defaults to
    .build/p210-provenance-verify.

.PARAMETER GpgPath
    Explicit path to gpg.exe. By default the gate looks on PATH and in the
    usual Git for Windows and GnuPG install locations. Git for Windows ships
    an MSYS gpg: for that build the gate passes its path arguments in POSIX
    form (/d/...) and points --keyboxd-program at the keyboxd shipped next to
    it (GnuPG 2.4 runs keyboxd by default, and the MSYS build cannot locate
    it without the explicit option; ORIGIN.md records the same host note).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\gate-p2-10-provenance.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\gate-p2-10-provenance.ps1 -GpgPath D:\Git\usr\bin\gpg.exe
#>
[CmdletBinding()]
param(
    [string]$WorkDir = '',
    [string]$GpgPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot   = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ThirdParty = Join-Path $RepoRoot 'kernel\third_party\secp256k1'
$ProvDir    = Join-Path $ThirdParty 'provenance'
$Archive    = Join-Path $ProvDir 'libsecp256k1-0.8.0.tar.gz'
$Signature  = Join-Path $ProvDir 'libsecp256k1-0.8.0.tar.gz.sig'
$KeyFile    = Join-Path $ProvDir 'secp256k1-release-signing-key.asc'
$SumsFile   = Join-Path $ThirdParty 'SHA256SUMS'
$BuildRoot  = Join-Path $RepoRoot '.build'

# The pins. ORIGIN.md sections 1-2 and the SHA256SUMS archive line are the
# recorded sources; the gate fails if the materials, the repository records
# and these constants ever disagree.
$ArchiveSize       = 2436784
$ArchiveSha        = 'dd685546f9e717b9adde329acd5a4cd8083d40f710fdb0a603ee5a83f908132b'
$SigSize           = 566
$SigSha            = 'c7eb14bbd67fe94b9ac4b556df6ae18aebb450092c836d05a6e13ea005fc7ac8'
$Fingerprint       = '6A8F9C266528E25AEB1D7731C2371D91CB716EA7'
$InnerRoot         = 'libsecp256k1-0.8.0'
$VendoredFileCount = 60

if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $WorkDir = Join-Path $BuildRoot 'p210-provenance-verify'
}
$WorkDir = [System.IO.Path]::GetFullPath($WorkDir)

$results = New-Object System.Collections.Generic.List[object]

function Write-Step([string]$Text) {
    Write-Host ''
    Write-Host ('== ' + $Text) -ForegroundColor Cyan
}

function Write-Detail([string]$Text) {
    Write-Host ('   ' + $Text)
}

function Add-Result([string]$Name, [string]$Detail) {
    $script:results.Add([pscustomobject]@{ Name = $Name; Detail = $Detail })
}

function Fail([string]$Name, [string]$Detail) {
    Write-Host ''
    Write-Host ('P2.10 provenance: FAIL - ' + $Name + ': ' + $Detail) -ForegroundColor Red
    exit 1
}

# PowerShell 5.1 turns a native command's stderr into error records, which
# $ErrorActionPreference = 'Stop' escalates into a terminating error (gpg
# writes notes to stderr). Capture both streams as plain text and keep the
# real exit code.
function Invoke-Capture {
    param(
        [string]$Exe,
        [string[]]$Arguments
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & $Exe @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($item in @($raw)) { $lines.Add([string]$item) }
    [pscustomobject]@{ ExitCode = $code; Lines = $lines.ToArray() }
}

# A gate may only wipe scratch output it owns. Anything else is refused, so a
# mistyped -WorkDir cannot delete user data.
function Reset-OwnedWorkDir([string]$Path) {
    $prefix = $BuildRoot + [System.IO.Path]::DirectorySeparatorChar
    if (-not $Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        Fail 'fresh work directory' ('refusing to wipe a directory outside .build: ' + $Path)
    }
    if (Test-Path $Path) {
        Remove-Item -Recurse -Force $Path
    }
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# --- gpg discovery -----------------------------------------------------------

if ([string]::IsNullOrWhiteSpace($GpgPath)) {
    $candidates = @()
    $onPath = Get-Command gpg.exe -ErrorAction SilentlyContinue
    if ($onPath) { $candidates += $onPath.Source }
    $pf86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if ($pf86) {
        $candidates += @(
            (Join-Path $pf86 'Git\usr\bin\gpg.exe'),
            (Join-Path $pf86 'GnuPG\bin\gpg.exe')
        )
    }
    $candidates += @(
        (Join-Path $env:ProgramFiles 'Git\usr\bin\gpg.exe'),
        (Join-Path $env:ProgramFiles 'GnuPG\bin\gpg.exe')
    )
    if ($env:LOCALAPPDATA) {
        $candidates += Join-Path $env:LOCALAPPDATA 'Programs\Git\usr\bin\gpg.exe'
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { $GpgPath = $candidate; break }
    }
    if ([string]::IsNullOrWhiteSpace($GpgPath)) {
        Fail 'gpg discovery' 'gpg.exe not found on PATH or in the usual Git for Windows / GnuPG locations; pass -GpgPath'
    }
}
$GpgPath = (Resolve-Path $GpgPath).Path

# Git for Windows ships an MSYS gpg. Its POSIX path layer treats `d:\...` as
# a relative name (backslash is not a separator there), so path arguments
# must be converted to /d/... form. Native builds (GnuPG for Windows) take
# the Windows form unchanged.
$IsMsysGpg = $GpgPath -match '\\usr\\bin\\gpg\.exe$'

function ConvertTo-GpgPath([string]$Path) {
    if (-not $script:IsMsysGpg) { return $Path }
    $full = [System.IO.Path]::GetFullPath($Path)
    '/' + $full.Substring(0, 1).ToLowerInvariant() + $full.Substring(2).Replace('\', '/')
}

# GnuPG 2.4 runs keyboxd by default; the MSYS build cannot locate it relative
# to its own binary without an explicit --keyboxd-program (ORIGIN.md records
# the same host note). Native builds manage their own agent machinery.
$KeyboxdProgram = ''
if ($IsMsysGpg) {
    $keyboxd = Join-Path (Split-Path (Split-Path $GpgPath -Parent) -Parent) 'lib\gnupg\keyboxd.exe'
    if (Test-Path $keyboxd) {
        $KeyboxdProgram = $keyboxd
    } else {
        Fail 'gpg discovery' ('MSYS gpg without its keyboxd: expected ' + $keyboxd)
    }
}

Write-Step 'gpg'
Write-Detail ('gpg: ' + $GpgPath)
if ($KeyboxdProgram) { Write-Detail ('keyboxd: ' + $KeyboxdProgram) }

# --- 1. materialisation ------------------------------------------------------

Write-Step 'materials (pinned sizes and SHA-256)'

if (-not (Test-Path $Archive)) { Fail 'materials' ('missing archive: ' + $Archive) }
$size = (Get-Item $Archive).Length
if ($size -ne $ArchiveSize) { Fail 'materials' ('archive is ' + $size + ' bytes, expected ' + $ArchiveSize) }
$hash = Get-Sha256 $Archive
if ($hash -ne $ArchiveSha) { Fail 'materials' ('archive SHA-256 ' + $hash + ', expected ' + $ArchiveSha) }
Add-Result 'archive' ($ArchiveSize.ToString() + ' bytes, SHA-256 ' + $hash)

if (-not (Test-Path $Signature)) { Fail 'materials' ('missing signature: ' + $Signature) }
$size = (Get-Item $Signature).Length
if ($size -ne $SigSize) { Fail 'materials' ('signature is ' + $size + ' bytes, expected ' + $SigSize) }
$hash = Get-Sha256 $Signature
if ($hash -ne $SigSha) { Fail 'materials' ('signature SHA-256 ' + $hash + ', expected ' + $SigSha) }
Add-Result 'signature file' ($SigSize.ToString() + ' bytes, SHA-256 ' + $hash)

if (-not (Test-Path $KeyFile)) { Fail 'materials' ('missing public key: ' + $KeyFile) }

# --- 2. record agreement -----------------------------------------------------

$sumsArchiveLine = ''
foreach ($line in (Get-Content $SumsFile)) {
    if ($line -match 'libsecp256k1-0\.8\.0\.tar\.gz') { $sumsArchiveLine = $line; break }
}
if ([string]::IsNullOrWhiteSpace($sumsArchiveLine)) {
    Fail 'record agreement' 'SHA256SUMS has no archive line'
}
if (-not $sumsArchiveLine.StartsWith($ArchiveSha)) {
    Fail 'record agreement' ('SHA256SUMS archive line disagrees with the pinned hash: ' + $sumsArchiveLine)
}
Add-Result 'record agreement' 'SHA256SUMS archive line records the pinned hash'

# --- 3. key identity ---------------------------------------------------------

Write-Step 'vendored key identity (gpg --show-keys)'

$show = Invoke-Capture $GpgPath @('--show-keys', (ConvertTo-GpgPath $KeyFile))
$showText = $show.Lines -join [Environment]::NewLine
if ($show.ExitCode -ne 0) {
    Write-Host $showText
    Fail 'key identity' ('exit code ' + $show.ExitCode)
}
if ($showText -notmatch $Fingerprint) {
    Write-Host $showText
    Fail 'key identity' ('the vendored key does not carry the pinned fingerprint ' + $Fingerprint)
}
Add-Result 'key identity' ('pinned fingerprint ' + $Fingerprint)

# --- 4. signature ------------------------------------------------------------

Write-Step 'signature (gpg --verify, isolated throwaway GnuPG home)'

Reset-OwnedWorkDir $WorkDir
$GpgHome = Join-Path $WorkDir 'gnupghome'
New-Item -ItemType Directory -Force -Path $GpgHome | Out-Null

$gpgBaseArgs = @()
if ($KeyboxdProgram) { $gpgBaseArgs += @('--keyboxd-program', (ConvertTo-GpgPath $KeyboxdProgram)) }
$gpgBaseArgs += @('--homedir', (ConvertTo-GpgPath $GpgHome))

$import = Invoke-Capture $GpgPath ($gpgBaseArgs + @('--import', (ConvertTo-GpgPath $KeyFile)))
$importText = $import.Lines -join [Environment]::NewLine
if ($import.ExitCode -ne 0) {
    Write-Host $importText
    Fail 'signature' ('key import exit code ' + $import.ExitCode)
}
if (-not (@($import.Lines | Where-Object { $_ -match 'imported: 1' }).Count -ge 1)) {
    Write-Host $importText
    Fail 'signature' 'the import reported no key'
}

$verify = Invoke-Capture $GpgPath ($gpgBaseArgs + @('--status-fd', '1', '--verify', (ConvertTo-GpgPath $Signature), (ConvertTo-GpgPath $Archive)))
$verifyText = $verify.Lines -join [Environment]::NewLine
if ($verify.ExitCode -ne 0) {
    Write-Host $verifyText
    Fail 'signature' ('gpg --verify exit code ' + $verify.ExitCode)
}
if ($verifyText -notmatch ('GOODSIG ' + $Fingerprint.Substring(24))) {
    Write-Host $verifyText
    Fail 'signature' 'GOODSIG for the pinned key not found'
}
if ($verifyText -notmatch ('VALIDSIG ' + $Fingerprint)) {
    Write-Host $verifyText
    Fail 'signature' 'VALIDSIG for the pinned fingerprint not found'
}
Write-Detail 'TRUST_UNDEFINED is expected: the trust anchor is the pinned fingerprint, not a web-of-trust path'
Add-Result 'gpg verify' ('GOODSIG/VALIDSIG ' + $Fingerprint + ', exit code 0')

# --- 5. tree identity --------------------------------------------------------

Write-Step 'tree identity (archive inner tree vs vendored tree)'

$ExtractDir = Join-Path $WorkDir 'extract'
New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null
$tar = Invoke-Capture 'tar' @('-xzf', $Archive, '-C', $ExtractDir)
if ($tar.ExitCode -ne 0) {
    Write-Host ($tar.Lines -join [Environment]::NewLine)
    Fail 'tree identity' ('tar exit code ' + $tar.ExitCode)
}
$InnerDir = Join-Path $ExtractDir $InnerRoot
if (-not (Test-Path $InnerDir)) {
    Fail 'tree identity' ('extracted archive has no inner root ' + $InnerRoot)
}

$compared = 0
foreach ($line in (Get-Content $SumsFile)) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line -match 'libsecp256k1-0\.8\.0\.tar\.gz') { continue }
    $parts = $line -split '\s+', 3
    if ($parts.Count -lt 2) { Fail 'tree identity' ('unparsable SHA256SUMS line: ' + $line) }
    $recordedHash = $parts[0].ToLowerInvariant()
    $relative = $parts[1]
    $vendored = Join-Path $ThirdParty $relative
    $fromArchive = Join-Path $InnerDir $relative
    if (-not (Test-Path $vendored)) { Fail 'tree identity' ('SHA256SUMS lists a file missing from the vendored tree: ' + $relative) }
    if (-not (Test-Path $fromArchive)) { Fail 'tree identity' ('vendored file absent from the archive tree: ' + $relative) }
    $vendoredHash = Get-Sha256 $vendored
    if ($vendoredHash -ne $recordedHash) { Fail 'tree identity' ('vendored file drifted from SHA256SUMS: ' + $relative) }
    $archiveHash = Get-Sha256 $fromArchive
    if ($archiveHash -ne $vendoredHash) { Fail 'tree identity' ('vendored file differs from its archive original: ' + $relative) }
    $compared++
}
if ($compared -ne $VendoredFileCount) {
    Fail 'tree identity' ('compared ' + $compared + ' files, expected ' + $VendoredFileCount)
}
Add-Result 'tree identity' ($compared.ToString() + '/' + $VendoredFileCount.ToString() + ' vendored files byte-identical to the archive; SHA256SUMS non-drift re-verified')

# --- summary -----------------------------------------------------------------

Write-Step 'P2.10 provenance summary'
foreach ($result in $results) {
    Write-Host ('  {0,-20} {1}' -f $result.Name, $result.Detail)
}
Write-Host ''
Write-Host 'P2.10 provenance gate: PASS - upstream identity re-derived from repository materials (CB-3)' -ForegroundColor Green
exit 0
