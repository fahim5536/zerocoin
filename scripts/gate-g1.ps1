#Requires -Version 5.1
<#
.SYNOPSIS
    Gate G1: the C++ kernel reproduces the P0 corpus byte for byte.

.DESCRIPTION
    Runs every check that gate G1 (docs/migration/03-target-architecture.md §4,
    docs/migration/05-test-strategy.md §7) consists of, and exits non-zero if
    any of them fails:

      1. configure and build kernel/ out of tree, warnings as errors;
      2. ctest, so the CMake test registration itself is exercised;
      3. the unit binary, which must report zero failures;
      4. the corpus replay, which must account for every G1 case;
      5. the Rust suite, which must stay green (the reference implementation
         is not modified by the port);
      6. the independent P0 verifier over test/vectors.

    Nothing here is advisory: each step is a command with an exit code.

.PARAMETER BuildDir
    CMake build directory. Defaults to .build/kernel-g1 inside the repository
    (git-ignored). Pass an absolute path to keep the tree untouched.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\gate-g1.ps1
#>
[CmdletBinding()]
param(
    [string]$BuildDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot     = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$KernelDir    = Join-Path $RepoRoot 'kernel'
$VectorsDir   = Join-Path $RepoRoot 'test\vectors'
$Wrapper      = Join-Path $KernelDir 'tools\g1_conformance.py'
$P0Harness    = Join-Path $RepoRoot 'test\harness\run_vectors.py'
$CrateManifest = Join-Path $RepoRoot 'zerocoin\Cargo.toml'
$Toolchain    = '+stable-x86_64-pc-windows-gnu'

if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    $BuildDir = Join-Path $RepoRoot '.build\kernel-g1'
}
$BuildDir = [System.IO.Path]::GetFullPath($BuildDir)

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
    Write-Host ('G1: FAIL — ' + $Name + ': ' + $Detail) -ForegroundColor Red
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

# --- preflight ---------------------------------------------------------------

Write-Step 'preflight'
foreach ($tool in @('cmake', 'python', 'cargo')) {
    $command = Get-Command $tool -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        Fail 'preflight' ("required tool not on PATH: " + $tool)
    }
    Write-Detail ($tool + ' -> ' + $command.Source)
}
foreach ($path in @($KernelDir, $VectorsDir, $Wrapper, $P0Harness, $CrateManifest)) {
    if (-not (Test-Path $path)) {
        Fail 'preflight' ('missing path: ' + $path)
    }
}

$cmakeVersion = @(& cmake --version)[0]
Assert-ExitCode 'cmake --version'
Write-Detail $cmakeVersion

$pythonVersion = @(& python --version)[0]
Assert-ExitCode 'python --version'
Write-Detail $pythonVersion

$cargoVersion = @(& cargo $Toolchain --version)[0]
Assert-ExitCode 'cargo --version'
Write-Detail $cargoVersion

# --- 1. configure and build --------------------------------------------------

Write-Step ('configure ' + $KernelDir + ' -> ' + $BuildDir)
$configureArgs = @('-S', $KernelDir, '-B', $BuildDir)
if (-not (Test-Path (Join-Path $BuildDir 'CMakeCache.txt'))) {
    if (Get-Command ninja -ErrorAction SilentlyContinue) {
        $configureArgs += @('-G', 'Ninja')
    }
}
& cmake @configureArgs
Assert-ExitCode 'cmake configure'
Add-Result 'configure' $BuildDir

Write-Step 'build'
& cmake --build $BuildDir
Assert-ExitCode 'cmake build'
Add-Result 'build' 'ok (warnings are errors)'

# --- 2. ctest wiring ---------------------------------------------------------

Write-Step 'ctest'
& ctest --test-dir $BuildDir --output-on-failure
Assert-ExitCode 'ctest'
Add-Result 'ctest' 'all registered tests passed'

# --- 3. unit tests, measured -------------------------------------------------

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
if ($unitFailed -ne 0) {
    Fail 'kernel unit tests' ($unitFailed.ToString() + ' of ' + $unitRun + ' failed')
}
Add-Result 'kernel unit tests' ($unitRun.ToString() + ' run, 0 failed')

# --- 4. corpus replay --------------------------------------------------------

$RunnerExe = Join-Path $BuildDir 'kernel_conformance.exe'
if (-not (Test-Path $RunnerExe)) { $RunnerExe = Join-Path $BuildDir 'kernel_conformance' }
if (-not (Test-Path $RunnerExe)) { Fail 'corpus replay' 'runner binary not found under the build dir' }

Write-Step 'corpus replay (G1 slice)'
$conf = Invoke-Capture 'python' @($Wrapper, '--vectors', $VectorsDir, '--runner', $RunnerExe)
$confText = ($conf.Lines -join [Environment]::NewLine)
Write-Host $confText
if ($conf.ExitCode -ne 0) { Fail 'corpus replay' ('exit code ' + $conf.ExitCode) }

$confMatch = [regex]::Match($confText, '(?m)^g1 conformance: (\d+)/(\d+) cases replayed')
if (-not $confMatch.Success) {
    Fail 'corpus replay' 'summary line "g1 conformance: N/N cases replayed" not found'
}
Add-Result 'corpus replay' ($confMatch.Groups[1].Value + '/' + $confMatch.Groups[2].Value + ' cases')

# --- 5. Rust reference suite -------------------------------------------------

Write-Step ('rust suite (cargo ' + $Toolchain + ' test --all-targets)')
$cargo = Invoke-Capture 'cargo' @($Toolchain, 'test', '--all-targets', '--manifest-path', $CrateManifest)
$cargoText = ($cargo.Lines -join [Environment]::NewLine)
if ($cargo.ExitCode -ne 0) {
    Write-Host $cargoText
    Fail 'rust suite' ('exit code ' + $cargo.ExitCode)
}

$cargoResults = @($cargo.Lines | Where-Object { $_ -match '^test result:' })
if ($cargoResults.Count -eq 0) {
    Write-Host $cargoText
    Fail 'rust suite' 'no "test result:" lines — cargo did not run tests'
}
$rustPassed = 0
$rustFailed = 0
foreach ($line in $cargoResults) {
    Write-Detail ([string]$line)
    $m = [regex]::Match([string]$line, 'test result: \w+\. (\d+) passed; (\d+) failed')
    if (-not $m.Success) { Fail 'rust suite' ('unparsable result line: ' + $line) }
    $rustPassed += [int]$m.Groups[1].Value
    $rustFailed += [int]$m.Groups[2].Value
}
if ($rustFailed -ne 0) {
    Fail 'rust suite' ($rustFailed.ToString() + ' failed')
}
Add-Result 'rust suite' ($rustPassed.ToString() + ' passed, 0 failed across ' +
    $cargoResults.Count + ' targets')

# --- 6. P0 verifier ----------------------------------------------------------

Write-Step 'p0 corpus verifier'
$p0 = Invoke-Capture 'python' @($P0Harness, '--quiet')
$p0Text = ($p0.Lines -join [Environment]::NewLine)
Write-Host $p0Text
if ($p0.ExitCode -ne 0) { Fail 'p0 corpus verifier' ('exit code ' + $p0.ExitCode) }
Add-Result 'p0 corpus verifier' 'clean'

# --- summary -----------------------------------------------------------------

Write-Step 'G1 summary'
foreach ($result in $results) {
    Write-Host ('  {0,-22} {1}' -f $result.Name, $result.Detail)
}
Write-Host ''
Write-Host 'G1: PASS' -ForegroundColor Green
exit 0
