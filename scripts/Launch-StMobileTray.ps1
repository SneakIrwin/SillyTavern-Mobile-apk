param(
    [int]$HubPort = 38444,
    [int]$SillyTavernPort = 3000,
    [string]$SillyTavernRoot = 'C:\Users\Sneak\SillyTavern-Launcher\SillyTavern-Launcher\SillyTavern',
    [string]$LauncherIconPath = 'C:\Users\Sneak\SillyTavern-Launcher\SillyTavern-Launcher\st-launcher.ico'
)

$ErrorActionPreference = 'Stop'
$currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
$currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$CommonScript = Join-Path $PSScriptRoot 'StMobileTrayCommon.ps1'
. $CommonScript
$StateRoot = Join-Path $ProjectRoot 'state'
$LogRoot = Join-Path $ProjectRoot 'logs'
$TrayProcessRecord = Join-Path $StateRoot 'tray-process.json'
$SillyTavernProcessRecord = Join-Path $StateRoot 'sillytavern-process.json'
$LaunchLog = Join-Path $LogRoot 'tray-launch.log'
$TrayScript = Join-Path $PSScriptRoot 'Start-StMobileTray.ps1'
$PowerShellExe = Get-StMobileWindowsPowerShellExecutable

New-Item -ItemType Directory -Force -Path $StateRoot, $LogRoot | Out-Null

function Write-LaunchLog([string]$Message) {
    Add-Content -LiteralPath $LaunchLog -Value ('{0} {1}' -f ([DateTime]::UtcNow.ToString('o')), $Message) -Encoding UTF8
}

function Get-VerifiedTrayProcess {
    $verified = Get-VerifiedStMobileTrayProcess `
        -RecordPath $TrayProcessRecord `
        -PowerShellExe $PowerShellExe `
        -TrayScriptPath $TrayScript `
        -ExpectedHubPort $HubPort `
        -ExpectedSillyTavernPort $SillyTavernPort `
        -ExpectedSillyTavernRoot $SillyTavernRoot `
        -ExpectedLauncherIconPath $LauncherIconPath `
        -ThrowOnInvalid
    return $(if ($verified) { $verified.Process } else { $null })
}

function Publish-TrustedSillyTavernSession {
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    $session = $null
    do {
        $session = Get-StMobileSillyTavernCandidateSession `
            -Port $SillyTavernPort `
            -SillyTavernRoot $SillyTavernRoot
        if (-not $session) {
            Start-Sleep -Milliseconds 250
        }
    } while (-not $session -and [DateTime]::UtcNow -lt $deadline)
    if (-not $session) {
        throw "ST Launcher option 1 did not produce a verified loopback SillyTavern process within 60 seconds; tray remains running but gateway provenance was not published."
    }
    $record = Write-StMobileSillyTavernRecord `
        -Session $session `
        -RecordPath $SillyTavernProcessRecord `
        -Provenance 'st-launcher-option-1'
    Write-LaunchLog "ST_SESSION_TRUSTED pid=$($record.pid) start=$($record.processStartTimeUtc) root=$($record.sillyTavernRoot)"
}

$existing = Get-VerifiedTrayProcess
if ($existing) {
    if ($existing.PriorityClass -ne [System.Diagnostics.ProcessPriorityClass]::Idle) {
        try {
            $existing.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
        } catch {
            Write-LaunchLog "PRIORITY_BLOCKER existing_tray_pid=$($existing.Id) error=$($_.Exception.Message)"
        }
    }
    $existing.Refresh()
    if ($existing.PriorityClass -ne [System.Diagnostics.ProcessPriorityClass]::Idle) {
        throw "Existing tray PID $($existing.Id) is not Idle; it remains hidden/no-focus but was not accepted as a successful reuse."
    }
    if ($existing.MainWindowHandle -ne 0) {
        throw "Existing tray PID $($existing.Id) unexpectedly owns a visible main window."
    }
    Write-LaunchLog "TRAY_REUSED pid=$($existing.Id) hidden=true no_focus=true priority=$($existing.PriorityClass)"
    Publish-TrustedSillyTavernSession
    exit 0
}

$arguments = @(
    '-NoProfile',
    '-STA',
    '-WindowStyle', 'Hidden',
    '-ExecutionPolicy', 'Bypass',
    '-File', $TrayScript,
    '-Mode', 'Tray',
    '-HubPort', [string]$HubPort,
    '-SillyTavernPort', [string]$SillyTavernPort,
    '-SillyTavernRoot', $SillyTavernRoot,
    '-LauncherIconPath', $LauncherIconPath
)

$info = New-Object System.Diagnostics.ProcessStartInfo
$info.FileName = $PowerShellExe
$info.Arguments = Join-WindowsCommandLineArguments $arguments
$info.WorkingDirectory = $ProjectRoot
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$info.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
$tray = [System.Diagnostics.Process]::Start($info)
try {
    $tray.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
} catch {
    Write-LaunchLog "PRIORITY_BLOCKER new_tray_pid=$($tray.Id) error=$($_.Exception.Message); child remains hidden/no-focus."
}

$verified = $null
$verificationDeadline = [DateTime]::UtcNow.AddSeconds(5)
do {
    Start-Sleep -Milliseconds 100
    $verified = Get-VerifiedTrayProcess
    if ($verified -or $tray.HasExited) {
        break
    }
} while ([DateTime]::UtcNow -lt $verificationDeadline)
if (-not $verified) {
    if ($tray.HasExited) {
        throw "Tray host exited during launch with code $($tray.ExitCode). See $LaunchLog and logs\tray.log."
    }
    throw "Tray host PID $($tray.Id) did not publish a verified process record within five seconds. See $LaunchLog and logs\tray.log."
}
if ($verified.PriorityClass -ne [System.Diagnostics.ProcessPriorityClass]::Idle) {
    throw "Tray host PID $($verified.Id) is not Idle after launch; it remains hidden/no-focus but requires repair."
}
if ($verified.MainWindowHandle -ne 0) {
    throw "Tray host PID $($verified.Id) unexpectedly owns a visible main window."
}

Write-LaunchLog "TRAY_LAUNCHED pid=$($verified.Id) hidden=true no_focus=true main_window_handle=0 priority=Idle"
Publish-TrustedSillyTavernSession
