[CmdletBinding()]
param(
    [ValidateSet('Release','Debug')]
    [string]$Configuration = 'Release',
    [string]$Generator = 'Visual Studio 17 2022',
    [string]$Arch = 'x64',
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'

function Find-VsDevCmd {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) {
        throw "vswhere not found: $vswhere"
    }

    $installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $installPath) {
        throw "No Visual Studio installation with C++ toolchain found."
    }

    $devCmd = Join-Path $installPath 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path $devCmd)) {
        throw "VsDevCmd.bat not found: $devCmd"
    }

    return $devCmd
}

function Invoke-InVsDevShell {
    param(
        [Parameter(Mandatory=$true)][string]$DevCmd,
        [Parameter(Mandatory=$true)][string]$Command
    )

    $wrapped = "`"$DevCmd`" -arch=$Arch && $Command"
    cmd.exe /c $wrapped
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE: $Command"
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $repoRoot 'build-win'
$passfiltDll = Join-Path $buildDir "$Configuration\PassFiltEx.dll"

Write-Host "[1/5] Detect Visual Studio C++ build environment..."
$devCmd = Find-VsDevCmd
Write-Host "      VsDevCmd: $devCmd"

Write-Host "[2/5] Configure CMake project..."
$cmakeConfig = "cmake -S `"$repoRoot`" -B `"$buildDir`" -G `"$Generator`" -A $Arch -DPASSFILTEX_BUILD_TESTS=ON"
Invoke-InVsDevShell -DevCmd $devCmd -Command $cmakeConfig

Write-Host "[3/5] Build project ($Configuration)..."
$cmakeBuild = "cmake --build `"$buildDir`" --config $Configuration"
Invoke-InVsDevShell -DevCmd $devCmd -Command $cmakeBuild

if (-not $SkipTests) {
    Write-Host "[4/5] Run unit tests..."
    $testExe = Join-Path $buildDir "$Configuration\password_policy_test.exe"
    if (-not (Test-Path $testExe)) {
        throw "Test executable not found: $testExe"
    }
    & $testExe
    if ($LASTEXITCODE -ne 0) {
        throw "Tests failed with exit code $LASTEXITCODE"
    }
} else {
    Write-Host "[4/5] Skip unit tests (--SkipTests specified)."
}

Write-Host "[5/5] Validate DLL output and print SHA256..."
if (-not (Test-Path $passfiltDll)) {
    throw "DLL not found: $passfiltDll"
}

$hash = Get-FileHash -Path $passfiltDll -Algorithm SHA256
Write-Host "Build success"
Write-Host "DLL Path : $passfiltDll"
Write-Host "SHA256   : $($hash.Hash)"
