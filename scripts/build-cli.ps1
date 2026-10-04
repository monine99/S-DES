<#
.SYNOPSIS
    Build the core library, the CLI and the self-test with plain g++ - no Qt required.

.DESCRIPTION
    Use this on machines without Qt to verify the algorithm implementation quickly.
    By default it prefers the g++ shipped with w64devkit; pass -Compiler to override.

    NOTE: this script is intentionally ASCII-only. Windows PowerShell 5.1 decodes
    UTF-8 .ps1 files without a BOM as ANSI, which corrupts non-ASCII characters.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build-cli.ps1
    powershell -ExecutionPolicy Bypass -File scripts\build-cli.ps1 -Configuration Debug
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$Compiler = ''
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    # ---- Pick a compiler ----
    if ([string]::IsNullOrWhiteSpace($Compiler)) {
        $candidates = @(
            'D:\w64devkit\bin\g++.exe',
            'C:\msys64\mingw64\bin\g++.exe'
        )
        foreach ($candidate in $candidates) {
            if (Test-Path $candidate) { $Compiler = $candidate; break }
        }
    }
    if ([string]::IsNullOrWhiteSpace($Compiler)) {
        $found = Get-Command 'g++' -ErrorAction SilentlyContinue
        if ($found) { $Compiler = $found.Source }
    }
    if ([string]::IsNullOrWhiteSpace($Compiler) -or -not (Test-Path $Compiler)) {
        throw 'g++ not found. Pass -Compiler <path>, e.g. -Compiler "D:\w64devkit\bin\g++.exe"'
    }

    Write-Host "Compiler : $Compiler"

    $outDir = Join-Path $root 'build'
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    # ---- Compile flags ----
    $flags = @('-std=c++17', '-Wall', '-Wextra', '-Iinclude', '-pthread')
    if ($Configuration -eq 'Debug') {
        $flags += @('-g3', '-O0', '-D_GLIBCXX_ASSERTIONS')
    } else {
        $flags += @('-O2', '-DNDEBUG')
    }

    $librarySources = @(
        'src/key_schedule.cpp',
        'src/cipher.cpp',
        'src/brute_force.cpp',
        'src/analysis.cpp'
    )

    # ---- CLI ----
    Write-Host 'Building sdes-cli.exe ...'
    & $Compiler @flags @librarySources 'apps/cli/main.cpp' '-o' (Join-Path $outDir 'sdes-cli.exe')
    if ($LASTEXITCODE -ne 0) { throw 'Failed to build the CLI.' }

    # ---- Self-test ----
    Write-Host 'Building test-sdes.exe ...'
    & $Compiler @flags @librarySources 'tests/test_sdes.cpp' '-o' (Join-Path $outDir 'test-sdes.exe')
    if ($LASTEXITCODE -ne 0) { throw 'Failed to build the self-test.' }

    Write-Host ''
    Write-Host 'Build finished:'
    Write-Host "  $outDir\sdes-cli.exe"
    Write-Host "  $outDir\test-sdes.exe"
    Write-Host ''
    Write-Host 'Try:'
    Write-Host '  .\build\test-sdes.exe'
    Write-Host '  .\build\sdes-cli.exe demo'
}
finally {
    Pop-Location
}
