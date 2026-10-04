<#
.SYNOPSIS
    Build the Qt 6 GUI (sdes-gui.exe) with CMake, then deploy the runtime DLLs.

.DESCRIPTION
    Locates the Qt installation, its bundled MinGW toolchain and CMake automatically.

    IMPORTANT: a Qt program must be compiled with the MinGW that ships with Qt.
    Do not mix it with w64devkit's g++ - the libstdc++ versions differ and the
    C++ ABI is not compatible.

    After a successful build the script copies the MinGW runtime DLLs and runs
    windeployqt, so that everything under build-gui\ can be started by
    double-clicking and can be copied to another machine as-is.
    Pass -SkipDeploy to skip that step.

    NOTE: this script is intentionally ASCII-only. Windows PowerShell 5.1 decodes
    UTF-8 .ps1 files without a BOM as ANSI, which corrupts non-ASCII characters.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build-gui.ps1
    powershell -ExecutionPolicy Bypass -File scripts\build-gui.ps1 -SkipDeploy
#>
param(
    [string]$QtRoot = 'C:\Qt',
    [string]$QtVersion = '',
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$BuildDir = 'build-gui',
    [switch]$SkipDeploy
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not (Test-Path $QtRoot)) {
        throw "Qt root '$QtRoot' does not exist. Install Qt 6 first, or pass -QtRoot <path>."
    }

    # ---- Locate the Qt kit directory, e.g. C:\Qt\6.12.0\mingw_64 ----
    if ([string]::IsNullOrWhiteSpace($QtVersion)) {
        $versionDirs = Get-ChildItem -Path $QtRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d+\.\d+' } |
            Sort-Object { [version]$_.Name } -Descending
        if ($versionDirs) { $QtVersion = $versionDirs[0].Name }
    }
    if ([string]::IsNullOrWhiteSpace($QtVersion)) {
        throw "No Qt version directory found under $QtRoot."
    }

    $kits = Get-ChildItem -Path (Join-Path $QtRoot $QtVersion) -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'mingw*' } |
        Sort-Object Name -Descending
    if (-not $kits) {
        throw "No mingw kit found under $QtRoot\$QtVersion. Re-run the Qt installer and select a MinGW build of Qt."
    }
    $qtKitDir = $kits[0].FullName
    Write-Host "Qt kit   : $qtKitDir"

    # ---- Locate the MinGW bundled with Qt ----
    $toolsRoot = Join-Path $QtRoot 'Tools'
    $mingwDirs = Get-ChildItem -Path $toolsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'mingw*' } |
        Sort-Object Name -Descending
    if (-not $mingwDirs) {
        throw "No mingw found under $toolsRoot. Install it via the Qt Maintenance Tool (category 'Build Tools')."
    }
    $mingwBin = Join-Path $mingwDirs[0].FullName 'bin'
    Write-Host "MinGW    : $mingwBin"

    # ---- Locate CMake: prefer the one bundled with Qt ----
    $cmakeExe = ''
    $qtCmakes = Get-ChildItem -Path $toolsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'CMake*' } |
        Sort-Object Name -Descending
    foreach ($directory in $qtCmakes) {
        $candidate = Join-Path $directory.FullName 'bin\cmake.exe'
        if (Test-Path $candidate) { $cmakeExe = $candidate; break }
    }
    if ([string]::IsNullOrWhiteSpace($cmakeExe)) {
        $found = Get-Command 'cmake' -ErrorAction SilentlyContinue
        if ($found) { $cmakeExe = $found.Source }
    }
    if ([string]::IsNullOrWhiteSpace($cmakeExe)) {
        throw 'cmake not found. Select CMake in the Qt Maintenance Tool, or install CMake and add it to PATH.'
    }
    Write-Host "CMake    : $cmakeExe"

    # ---- Prefer Ninja when Qt ships it, otherwise fall back to MinGW Makefiles ----
    $qtNinjas = Get-ChildItem -Path $toolsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'Ninja*' } |
        Sort-Object Name -Descending
    if ($qtNinjas) {
        $ninjaDir = $qtNinjas[0].FullName
        $env:PATH = "$ninjaDir;$env:PATH"
        $generator = @('-G', 'Ninja')
        Write-Host "Ninja    : $ninjaDir"
    } else {
        $generator = @('-G', 'MinGW Makefiles')
    }

    # windeployqt lives in the Qt bin directory and itself needs the Qt DLLs on PATH.
    $qtBin = Join-Path $qtKitDir 'bin'
    $env:PATH = "$qtBin;$mingwBin;$env:PATH"

    $buildPath = Join-Path $root $BuildDir
    New-Item -ItemType Directory -Force -Path $buildPath | Out-Null

    Write-Host 'Configuring ...'
    & $cmakeExe -S $root -B $buildPath @generator `
        "-DCMAKE_BUILD_TYPE=$Configuration" `
        "-DCMAKE_PREFIX_PATH=$qtKitDir" `
        "-DCMAKE_CXX_COMPILER=$mingwBin\g++.exe"
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }

    Write-Host 'Building ...'
    & $cmakeExe --build $buildPath -j
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }

    # -------------------------------------------------------------------------
    #  Deploy: make build-gui\ self-contained
    # -------------------------------------------------------------------------
    if (-not $SkipDeploy) {
        Write-Host 'Deploying runtime libraries ...'

        # 1) MinGW runtime DLLs. Required by EVERY executable built with this
        #    toolchain - including test-sdes.exe and sdes-cli.exe, which use no Qt.
        $mingwRuntimeDlls = @('libstdc++-6.dll', 'libgcc_s_seh-1.dll', 'libwinpthread-1.dll')
        foreach ($dllName in $mingwRuntimeDlls) {
            $source = Join-Path $mingwBin $dllName
            if (Test-Path $source) {
                Copy-Item $source $buildPath -Force
            } else {
                Write-Warning "MinGW runtime DLL not found: $source"
            }
        }

        # 2) Qt DLLs, platform plugin and styles for the GUI executable.
        $windeployqt = Join-Path $qtBin 'windeployqt.exe'
        $guiExe = Join-Path $buildPath 'sdes-gui.exe'
        if ((Test-Path $windeployqt) -and (Test-Path $guiExe)) {
            $deployMode = if ($Configuration -eq 'Debug') { '--debug' } else { '--release' }
            & $windeployqt $deployMode '--no-translations' '--no-system-d3d-compiler' '--no-opengl-sw' $guiExe |
                Out-Null
            if ($LASTEXITCODE -ne 0) {
                Write-Warning 'windeployqt reported an error; you may still need the Qt bin directory on PATH.'
            }
        } else {
            Write-Warning 'windeployqt not found; add the Qt bin directory to PATH before running the GUI.'
        }
    }

    Write-Host ''
    Write-Host "Build finished: $buildPath\sdes-gui.exe"
    if (-not $SkipDeploy) {
        Write-Host 'Runtime DLLs were deployed, so these executables run standalone:'
        Write-Host "  $buildPath\sdes-gui.exe"
        Write-Host "  $buildPath\sdes-cli.exe"
        Write-Host "  $buildPath\test-sdes.exe"
    } else {
        Write-Host 'Deployment skipped (-SkipDeploy). Add this to PATH before running:'
        Write-Host "  $qtBin"
    }
}
finally {
    Pop-Location
}
