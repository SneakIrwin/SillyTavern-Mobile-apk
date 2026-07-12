param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Clean', 'Smudge')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'
try {
    [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
} catch {
    [Console]::Error.WriteLine("ST Mobile launcher filter priority blocker: $($_.Exception.Message)")
}

[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$source = [Console]::In.ReadToEnd()
$beginMarker = 'REM >>> ST MOBILE AUTH HUB INTEGRATION (managed)'
$endMarker = 'REM <<< ST MOBILE AUTH HUB INTEGRATION (managed)'
$launchScript = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'Launch-StMobileTray.ps1'))
$launchCommand = 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -SillyTavernRoot "%st_install_path%" -LauncherIconPath "%~dp0..\..\..\..\..\st-launcher.ico"' -f $launchScript
$legacyLaunchCommand = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -SillyTavernRoot "%st_install_path%" -LauncherIconPath "%~dp0..\..\..\..\..\st-launcher.ico"' -f $launchScript

function Get-CanonicalBlock([string]$Newline) {
    return $beginMarker + $Newline +
        $launchCommand + $Newline +
        'if errorlevel 1 (' + $Newline +
        '    echo [ERROR] SillyTavern Mobile tray/provenance setup failed.' + $Newline +
        '    exit /b 1' + $Newline +
        ')' + $Newline +
        $endMarker + $Newline
}

function Get-PriorBlock([string]$Command, [string]$Newline) {
    return $beginMarker + $Newline + $Command + $Newline + $endMarker + $Newline + $Newline
}

function Add-ExactBlockAtAnchor([string]$CleanText, [string]$Block) {
    $anchor = [regex]::new('(?m)^if %ps_errorlevel% equ 0 \(\r?\n')
    if ($anchor.Matches($CleanText).Count -ne 1) {
        throw 'ST Launcher update_start_st.bat must contain exactly one supported injection anchor.'
    }
    return $anchor.Replace(
        $CleanText,
        [System.Text.RegularExpressions.MatchEvaluator]{ param($match) $match.Value + $Block },
        1)
}

function Add-PriorBlockAtOldAnchor([string]$CleanText, [string]$Block) {
    $anchor = [regex]::new('(?m)^REM Clear the old log file if it exists\r?$')
    if ($anchor.Matches($CleanText).Count -ne 1) {
        throw 'ST Launcher update_start_st.bat must contain exactly one legacy migration anchor.'
    }
    return $anchor.Replace(
        $CleanText,
        [System.Text.RegularExpressions.MatchEvaluator]{ param($match) $Block + $match.Value },
        1)
}

$beginCount = [regex]::Matches($source, '(?m)^' + [regex]::Escape($beginMarker) + '\r?$').Count
$endCount = [regex]::Matches($source, '(?m)^' + [regex]::Escape($endMarker) + '\r?$').Count
$clean = $source
if ($beginCount -ne 0 -or $endCount -ne 0) {
    if ($beginCount -ne 1 -or $endCount -ne 1) {
        throw "ST Mobile integration markers are missing or duplicated (begin=$beginCount end=$endCount); refusing to clean."
    }
    $canonicalCrLf = Get-CanonicalBlock "`r`n"
    $canonicalLf = Get-CanonicalBlock "`n"
    $priorCurrentCrLf = Get-PriorBlock $launchCommand "`r`n"
    $priorCurrentLf = Get-PriorBlock $launchCommand "`n"
    $priorLegacyCrLf = Get-PriorBlock $legacyLaunchCommand "`r`n"
    $priorLegacyLf = Get-PriorBlock $legacyLaunchCommand "`n"
    $canonical = if ($source.Contains($canonicalCrLf)) { $canonicalCrLf } `
        elseif ($source.Contains($canonicalLf)) { $canonicalLf } `
        elseif ($source.Contains($priorCurrentCrLf)) { $priorCurrentCrLf } `
        elseif ($source.Contains($priorCurrentLf)) { $priorCurrentLf } `
        elseif ($source.Contains($priorLegacyCrLf)) { $priorLegacyCrLf } `
        elseif ($source.Contains($priorLegacyLf)) { $priorLegacyLf } `
        else { $null }
    if (-not $canonical -or $source.IndexOf($canonical, [System.StringComparison]::Ordinal) -ne $source.LastIndexOf($canonical, [System.StringComparison]::Ordinal)) {
        throw 'ST Mobile integration block was modified or duplicated; refusing to clean or overwrite it.'
    }
    $canonicalIndex = $source.IndexOf($canonical, [System.StringComparison]::Ordinal)
    $clean = $source.Remove($canonicalIndex, $canonical.Length)
    $expectedCurrentPlacement = Add-ExactBlockAtAnchor $clean $canonical
    $isPriorBlock = $canonical -in @($priorCurrentCrLf, $priorCurrentLf, $priorLegacyCrLf, $priorLegacyLf)
    $expectedPriorPlacement = if ($isPriorBlock) { Add-PriorBlockAtOldAnchor $clean $canonical } else { '' }
    if ($source -cne $expectedCurrentPlacement -and $source -cne $expectedPriorPlacement) {
        throw 'ST Mobile integration block is not in its exact canonical anchor position; refusing to clean or move it.'
    }
}

if ($Mode -eq 'Clean') {
    [Console]::Out.Write($clean)
    exit 0
}

$newline = if ($clean.Contains("`r`n")) { "`r`n" } else { "`n" }
$block = Get-CanonicalBlock $newline
$smudged = Add-ExactBlockAtAnchor $clean $block
[Console]::Out.Write($smudged)
