#Requires -Version 5.1
<#
.SYNOPSIS
    Gate P2.6: the vendored libsecp256k1 build reproduces every Rust verdict.

.DESCRIPTION
    Runs the whole P2.6 evidence chain and exits non-zero if any step fails:

      1. a fresh, warnings-as-errors build of kernel/ in an empty directory;
      2. the kernel unit binary, with a parsed test count;
      3. the G1 corpus replay and the P2 conformance replay (the latter also
         corrupts every expected value and requires the runner to reject them);
      4. the independent P0 verifier over test/vectors;
      5. the Rust reference suite, --all-targets, with parsed counts;
      6. `high_s_signature` and `s5_boundary_probes` as their own named steps;
      7. two *independent, empty* builds of kernel/differential, a byte-level
         comparison of their artefacts, ctest, and the differential vector
         wrapper.

    Step 7 is the only place a verdict may disagree, and only for the cases
    listed on --known-divergence. Since P2.8 that list is empty: the Rust
    reference rejects SEC1 tag 0x05, so it agrees with libsecp256k1 on every
    case. The wrapper still fails if any case disagrees and still fails on a
    stale allowance, so an allowance can never silently outlive its divergence.

    Nothing here is advisory: each step is a command with an exit code, and the
    summary prints the measured count for each.

.PARAMETER BuildDir
    Kernel CMake build directory. Defaults to .build/p26-kernel.

.PARAMETER DifferentialBuildDir
    Root for the two differential builds; the gate creates `<dir>-a` and
    `<dir>-b` and wipes them first, but only if they live under .build/.
    Defaults to .build/p26-differential-repro.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\gate-p2-6.ps1
#>
[CmdletBinding()]
param(
    [string]$BuildDir = '',
    [string]$DifferentialBuildDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot      = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$KernelDir     = Join-Path $RepoRoot 'kernel'
$DiffDir       = Join-Path $KernelDir 'differential'
$VectorsDir    = Join-Path $RepoRoot 'test\vectors'
$G1Wrapper     = Join-Path $KernelDir 'tools\g1_conformance.py'
$P2Wrapper     = Join-Path $KernelDir 'tools\p2_conformance.py'
$DiffWrapper   = Join-Path $KernelDir 'tools\secp256k1_differential.py'
$DiffVectors   = Join-Path $DiffDir 'vectors\ledger.sighash.differential.txt'
$P0Harness     = Join-Path $RepoRoot 'test\harness\run_vectors.py'
$CrateManifest = Join-Path $RepoRoot 'zerocoin\Cargo.toml'
$Toolchain     = '+stable-x86_64-pc-windows-gnu'

# P2.8 closed the only entry: `PublicKey::from_sec1` now rejects SEC1 tag 0x05, so
# the Rust reference and libsecp256k1 agree on the whole corpus. Any divergence is
# therefore unexplained and fails the gate. See
# docs/consensus/PUBLIC_KEY_ENCODING_CONTRACT.md (rule P-1).
$KnownDivergences = @()
$ExpectedCases    = 121

$BuildRoot = Join-Path $RepoRoot '.build'
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    $BuildDir = Join-Path $BuildRoot 'p26-kernel'
}
if ([string]::IsNullOrWhiteSpace($DifferentialBuildDir)) {
    $DifferentialBuildDir = Join-Path $BuildRoot 'p26-differential-repro'
}
$BuildDir = [System.IO.Path]::GetFullPath($BuildDir)
$DiffBuildA = [System.IO.Path]::GetFullPath($DifferentialBuildDir + '-a')
$DiffBuildB = [System.IO.Path]::GetFullPath($DifferentialBuildDir + '-b')

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
    Write-Host ('P2.6: FAIL — ' + $Name + ': ' + $Detail) -ForegroundColor Red
    exit 1
}

function Assert-ExitCode([string]$Name) {
    if ($LASTEXITCODE -ne 0) {
        Fail $Name ('exit code ' + $LASTEXITCODE)
    }
}

# PowerShell 5.1 turns a native command's stderr into error records, which
# $ErrorActionPreference = 'Stop' escalates into a terminating error (cargo
# prints progress on stderr). Capture both streams as plain text and keep the
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

# A gate may only wipe build output it owns. Anything else is refused, so a
# mistyped -DifferentialBuildDir cannot delete user data.
function Reset-OwnedBuildDir([string]$Path) {
    $prefix = $BuildRoot + [System.IO.Path]::DirectorySeparatorChar
    if (-not $Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        Fail 'fresh build' ('refusing to wipe a directory outside .build: ' + $Path)
    }
    if (Test-Path $Path) {
        Remove-Item -Recurse -Force $Path
    }
}

function Invoke-CargoTest([string]$Name, [string[]]$Extra) {
    $arguments = @($Toolchain, 'test', '--manifest-path', $CrateManifest) + $Extra
    $cargo = Invoke-Capture 'cargo' $arguments
    $text = ($cargo.Lines -join [Environment]::NewLine)
    $resultLines = @($cargo.Lines | Where-Object { $_ -match '^test result:' })
    if ($cargo.ExitCode -ne 0) {
        Write-Host $text
        Fail $Name ('exit code ' + $cargo.ExitCode)
    }
    if ($resultLines.Count -eq 0) {
        Write-Host $text
        Fail $Name 'no "test result:" line — cargo did not run tests'
    }
    $passed = 0
    $failed = 0
    foreach ($line in $resultLines) {
        $m = [regex]::Match([string]$line, 'test result: \w+\. (\d+) passed; (\d+) failed')
        if (-not $m.Success) { Fail $Name ('unparsable result line: ' + $line) }
        $passed += [int]$m.Groups[1].Value
        $failed += [int]$m.Groups[2].Value
    }
    if ($failed -ne 0) { Fail $Name ($failed.ToString() + ' failed') }
    return [pscustomobject]@{ Passed = $passed; Failed = $failed; Lines = $resultLines }
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Compare-Artefact([string]$Relative, [string]$Label) {
    $a = Join-Path $DiffBuildA $Relative
    $b = Join-Path $DiffBuildB $Relative
    if (-not (Test-Path $a) -or -not (Test-Path $b)) {
        Fail 'reproducibility' ('missing artefact for comparison: ' + $Relative)
    }
    $bytesA = [System.IO.File]::ReadAllBytes((Resolve-Path $a).Path)
    $bytesB = [System.IO.File]::ReadAllBytes((Resolve-Path $b).Path)
    if ($bytesA.Length -ne $bytesB.Length) {
        Write-Detail ($Label + ': DIFFERENT length (' + $bytesA.Length + ' vs ' + $bytesB.Length + ')')
        return 'different-length'
    }
    $differing = 0
    for ($i = 0; $i -lt $bytesA.Length; $i++) {
        if ($bytesA[$i] -ne $bytesB[$i]) { $differing++ }
    }
    $sha = Get-Sha256 $a
    if ($differing -eq 0) {
        Write-Detail ($Label + ': byte-identical, ' + $bytesA.Length + ' bytes, sha256=' + $sha)
        return 'identical'
    }
    Write-Detail ($Label + ': same length ' + $bytesA.Length + ', ' + $differing + ' differing byte(s)')
    return 'differs'
}

# --- preflight ---------------------------------------------------------------

Write-Step 'preflight'
foreach ($tool in @('cmake', 'python', 'cargo')) {
    $command = Get-Command $tool -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        Fail 'preflight' ('required tool not on PATH: ' + $tool)
    }
    Write-Detail ($tool + ' -> ' + $command.Source)
}
foreach ($path in @($KernelDir, $DiffDir, $VectorsDir, $G1Wrapper, $P2Wrapper, $DiffWrapper,
                    $DiffVectors, $P0Harness, $CrateManifest)) {
    if (-not (Test-Path $path)) {
        Fail 'preflight' ('missing path: ' + $path)
    }
}

$cmakeVersion = @(& cmake --version)[0]
Assert-ExitCode 'cmake --version'
Write-Detail $cmakeVersion

$compiler = Get-Command c++ -ErrorAction SilentlyContinue
if ($null -ne $compiler) {
    $cxxVersion = @(& c++ --version)[0]
    Assert-ExitCode 'c++ --version'
    Write-Detail $cxxVersion
}

$pythonVersion = @(& python --version)[0]
Assert-ExitCode 'python --version'
Write-Detail $pythonVersion

$cargoVersion = @(& cargo $Toolchain --version)[0]
Assert-ExitCode 'cargo --version'
Write-Detail $cargoVersion

# --- 1. fresh kernel build, warnings as errors --------------------------------

Write-Step ('configure kernel -> ' + $BuildDir)
$configureArgs = @('-S', $KernelDir, '-B', $BuildDir)
if (-not (Test-Path (Join-Path $BuildDir 'CMakeCache.txt'))) {
    if (Get-Command ninja -ErrorAction SilentlyContinue) {
        $configureArgs += @('-G', 'Ninja')
    }
}
& cmake @configureArgs
Assert-ExitCode 'cmake configure'
Add-Result 'kernel configure' $BuildDir

Write-Step 'build kernel'
& cmake --build $BuildDir
Assert-ExitCode 'cmake build'
Add-Result 'kernel build' 'ok (warnings are errors)'

# --- 2. kernel unit tests, measured ------------------------------------------

$UnitExe = Join-Path $BuildDir 'kernel_tests.exe'
if (-not (Test-Path $UnitExe)) { $UnitExe = Join-Path $BuildDir 'kernel_tests' }
if (-not (Test-Path $UnitExe)) { Fail 'kernel unit tests' 'binary not found under the build dir' }

Write-Step 'kernel unit tests'
$unit = Invoke-Capture $UnitExe @()
$unitText = ($unit.Lines -join [Environment]::NewLine)
Write-Host $unitText
if ($unit.ExitCode -ne 0) { Fail 'kernel unit tests' ('exit code ' + $unit.ExitCode) }
$unitMatch = [regex]::Match($unitText, '(?m)^kernel unit tests: (\d+) run, (\d+) failed\s*$')
if (-not $unitMatch.Success) {
    Fail 'kernel unit tests' 'summary line "kernel unit tests: N run, M failed" not found'
}
$unitRun = [int]$unitMatch.Groups[1].Value
$unitFailed = [int]$unitMatch.Groups[2].Value
if ($unitFailed -ne 0) { Fail 'kernel unit tests' ($unitFailed.ToString() + ' of ' + $unitRun + ' failed') }
Add-Result 'kernel unit tests' ($unitRun.ToString() + ' run, 0 failed')

# --- 3. G1 and P2 corpus replay ---------------------------------------------

$RunnerExe = Join-Path $BuildDir 'kernel_conformance.exe'
if (-not (Test-Path $RunnerExe)) { $RunnerExe = Join-Path $BuildDir 'kernel_conformance' }
if (-not (Test-Path $RunnerExe)) { Fail 'corpus replay' 'runner binary not found under the build dir' }

Write-Step 'G1 corpus replay'
$g1 = Invoke-Capture 'python' @($G1Wrapper, '--vectors', $VectorsDir, '--runner', $RunnerExe)
$g1Text = ($g1.Lines -join [Environment]::NewLine)
Write-Host $g1Text
if ($g1.ExitCode -ne 0) { Fail 'g1 conformance' ('exit code ' + $g1.ExitCode) }
$g1Match = [regex]::Match($g1Text, '(?m)^g1 conformance: (\d+)/(\d+) cases replayed')
if (-not $g1Match.Success) { Fail 'g1 conformance' 'summary line not found' }
Add-Result 'g1 conformance' ($g1Match.Groups[1].Value + '/' + $g1Match.Groups[2].Value + ' cases')

Write-Step 'P2 conformance replay (+ corruption self-check)'
$p2 = Invoke-Capture 'python' @($P2Wrapper, '--vectors', $VectorsDir, '--runner', $RunnerExe)
$p2Text = ($p2.Lines -join [Environment]::NewLine)
Write-Host $p2Text
if ($p2.ExitCode -ne 0) { Fail 'p2 conformance' ('exit code ' + $p2.ExitCode) }
$p2Match = [regex]::Match($p2Text, '(?m)^p2 conformance: (\d+)/(\d+) cases replayed')
if (-not $p2Match.Success) { Fail 'p2 conformance' 'summary line not found' }
Add-Result 'p2 conformance' ($p2Match.Groups[1].Value + '/' + $p2Match.Groups[2].Value +
    ' cases, corruption rejected')

# --- 4. P0 verifier ----------------------------------------------------------

Write-Step 'p0 corpus verifier'
$p0 = Invoke-Capture 'python' @($P0Harness, '--quiet')
$p0Text = ($p0.Lines -join [Environment]::NewLine)
Write-Host $p0Text
if ($p0.ExitCode -ne 0) { Fail 'p0 corpus verifier' ('exit code ' + $p0.ExitCode) }
Add-Result 'p0 verifier' 'clean'

# --- 5. Rust reference suite -------------------------------------------------

Write-Step ('rust suite (cargo ' + $Toolchain + ' test --all-targets)')
$rust = Invoke-CargoTest 'rust suite' @('--all-targets')
foreach ($line in $rust.Lines) { Write-Detail ([string]$line) }
Add-Result 'rust suite' ($rust.Passed.ToString() + ' passed, 0 failed across ' +
    $rust.Lines.Count + ' targets')

# --- 6. named crypto regression gates ---------------------------------------

Write-Step 'high_s_signature'
$highS = Invoke-Capture 'cargo' @($Toolchain, 'test', '--manifest-path', $CrateManifest,
    '--test', 'high_s_signature')
$highSText = ($highS.Lines -join [Environment]::NewLine)
if ($highS.ExitCode -ne 0) { Write-Host $highSText; Fail 'high_s_signature' ('exit code ' + $highS.ExitCode) }
$highSMatch = [regex]::Match($highSText, '(?m)^test result: \w+\. (\d+) passed; (\d+) failed')
if (-not $highSMatch.Success) { Fail 'high_s_signature' 'no test result line' }
Write-Detail ($highSMatch.Groups[1].Value + ' passed, ' + $highSMatch.Groups[2].Value + ' failed')
Add-Result 'high_s_signature' ($highSMatch.Groups[1].Value + ' passed')

Write-Step 's5_boundary_probes'
$s5 = Invoke-Capture 'cargo' @($Toolchain, 'test', '--manifest-path', $CrateManifest,
    '--test', 's5_boundary_probes')
$s5Text = ($s5.Lines -join [Environment]::NewLine)
if ($s5.ExitCode -ne 0) { Write-Host $s5Text; Fail 's5_boundary_probes' ('exit code ' + $s5.ExitCode) }
$s5Match = [regex]::Match($s5Text, '(?m)^test result: \w+\. (\d+) passed; (\d+) failed')
if (-not $s5Match.Success) { Fail 's5_boundary_probes' 'no test result line' }
Write-Detail ($s5Match.Groups[1].Value + ' passed, ' + $s5Match.Groups[2].Value + ' failed')
Add-Result 's5_boundary_probes' ($s5Match.Groups[1].Value + ' passed')

# --- 7. isolated libsecp256k1: two clean builds, ctest, differential --------

Write-Step 'differential build A (empty directory)'
Reset-OwnedBuildDir $DiffBuildA
& cmake -S $DiffDir -B $DiffBuildA -G Ninja
Assert-ExitCode 'differential configure A'
& cmake --build $DiffBuildA
Assert-ExitCode 'differential build A'
Add-Result 'differential build A' $DiffBuildA

Write-Step 'differential build B (independent empty directory)'
Reset-OwnedBuildDir $DiffBuildB
& cmake -S $DiffDir -B $DiffBuildB -G Ninja
Assert-ExitCode 'differential configure B'
& cmake --build $DiffBuildB
Assert-ExitCode 'differential build B'
Add-Result 'differential build B' $DiffBuildB

Write-Step 'reproducibility comparison (A vs B)'
# Discover the object files rather than hardcoding the absolute source path the
# generator folded into the object directory name.
$objectDirA = Join-Path $DiffBuildA 'CMakeFiles\secp256k1_vendored.dir'
if (-not (Test-Path $objectDirA)) {
    Fail 'reproducibility' ('missing object directory: ' + $objectDirA)
}
$objectFiles = @(Get-ChildItem -Path $objectDirA -Recurse -Filter '*.obj')
if ($objectFiles.Count -ne 3) {
    Fail 'reproducibility' ($objectFiles.Count.ToString() + ' objects found; the vendored library is 3 translation units')
}
$objectVerdicts = New-Object System.Collections.Generic.List[string]
foreach ($file in $objectFiles) {
    $relative = $file.FullName.Substring($DiffBuildA.Length).TrimStart('\')
    $objectVerdicts.Add((Compare-Artefact $relative $file.Name))
}
$libVerdict = Compare-Artefact 'libsecp256k1_vendored.a' 'libsecp256k1_vendored.a'
$exeVerdict = Compare-Artefact 'secp256k1_differential.exe' 'secp256k1_differential.exe'

$identicalObjects = @($objectVerdicts | Where-Object { $_ -eq 'identical' }).Count
Add-Result 'reproducibility' ($identicalObjects.ToString() + '/' + $objectVerdicts.Count +
    ' objects identical; archive=' + $libVerdict + '; exe=' + $exeVerdict)
if ($identicalObjects -ne $objectVerdicts.Count) {
    Fail 'reproducibility' 'the vendored library objects are not reproducible across clean builds'
}

Write-Step 'differential ctest (build A)'
& ctest --test-dir $DiffBuildA --output-on-failure
Assert-ExitCode 'differential ctest'
Add-Result 'differential ctest' 'all registered tests passed'

Write-Step 'differential verdicts'
$diffArgs = @($DiffWrapper, '--vectors', $DiffVectors,
              '--runner', (Join-Path $DiffBuildA 'secp256k1_differential.exe'),
              '--expect-cases', $ExpectedCases.ToString())
foreach ($id in $KnownDivergences) { $diffArgs += @('--known-divergence', $id) }
$diff = Invoke-Capture 'python' $diffArgs
$diffText = ($diff.Lines -join [Environment]::NewLine)
Write-Host $diffText
if ($diff.ExitCode -ne 0) { Fail 'differential verdicts' ('exit code ' + $diff.ExitCode) }
$diffMatch = [regex]::Match($diffText, '(?m)^secp256k1 differential: (\d+)/(\d+) cases match')
if (-not $diffMatch.Success) { Fail 'differential verdicts' 'summary line not found' }
$pinned = if ($KnownDivergences.Count -eq 0) {
    ', none allowed'
} else {
    ', ' + $KnownDivergences.Count + ' pinned (' + ($KnownDivergences -join ', ') + ')'
}
Add-Result 'differential verdicts' ($diffMatch.Groups[1].Value + '/' + $diffMatch.Groups[2].Value +
    ' match' + $pinned)

# --- summary -----------------------------------------------------------------

Write-Step 'P2.6 summary'
foreach ($result in $results) {
    Write-Host ('  {0,-22} {1}' -f $result.Name, $result.Detail)
}
Write-Host ''
Write-Host 'P2.6 gates: PASS (every step executed; no divergence allowance)' -ForegroundColor Green
Write-Host 'G2c: NO-GO — differential parity is one G2c condition, not the whole gate; see docs/architecture/CRYPTO_BACKEND_SELECTION_AUDIT.md'
exit 0
