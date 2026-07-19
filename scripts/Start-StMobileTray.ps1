param(
    [ValidateSet('Tray', 'EnableStartup', 'DisableStartup', 'Status')]
    [string]$Mode = 'Tray',
    [int]$HubPort = 38444,
    [int]$SillyTavernPort = 3000,
    [string]$SillyTavernRoot = 'C:\Users\Sneak\SillyTavern-Launcher\SillyTavern-Launcher\SillyTavern',
    [string]$LauncherIconPath = 'C:\Users\Sneak\SillyTavern-Launcher\SillyTavern-Launcher\st-launcher.ico',
    [string]$StartupDirectory
)

$ErrorActionPreference = 'Stop'

# Rank Audit For This Tray Host
# - Rank 4: every automatic/background process remains hidden/no-focus and uses Idle priority;
#   Start with Windows is opt-in; disabling it must remove only this hub's verified shortcut.
# - Rank 3: the tray may watch loopback ST readiness and retry the gateway with bounded backoff.

$priorityBlocker = $null
$currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
try {
    $currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
} catch {
    $priorityBlocker = "Could not set tray host PID $($currentProcess.Id) to Idle: $($_.Exception.Message)"
}

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$CommonScript = Join-Path $PSScriptRoot 'StMobileTrayCommon.ps1'
. $CommonScript
$LogRoot = Join-Path $ProjectRoot 'logs'
$StateRoot = Join-Path $ProjectRoot 'state'
$TrayProcessRecord = Join-Path $StateRoot 'tray-process.json'
$SillyTavernProcessRecord = Join-Path $StateRoot 'sillytavern-process.json'
$TrayStopFile = Join-Path $StateRoot 'tray.stop.request'
$SuppressionFile = Join-Path $StateRoot 'tray-gateway-suppression.json'
$RetryStateFile = Join-Path $StateRoot 'tray-gateway-retry.json'
$TrayLogFile = Join-Path $LogRoot 'tray.log'
$StartScript = Join-Path $PSScriptRoot 'Start-StMobile.ps1'
$StopScript = Join-Path $PSScriptRoot 'Stop-StMobile.ps1'
$ProbeScript = Join-Path $PSScriptRoot 'Probe-StMobileTrayState.ps1'
$PowerShellExe = Get-StMobileWindowsPowerShellExecutable
$StartupShortcutName = 'SillyTavern Mobile Auth Hub.lnk'
$StartupShortcutDescription = 'Managed by SillyTavern Mobile Auth Hub tray v1'
$TrayScriptPath = $PSCommandPath

New-Item -ItemType Directory -Force -Path $LogRoot, $StateRoot | Out-Null

function Write-TrayLog([string]$Message) {
    $line = '{0} {1}' -f ([DateTime]::UtcNow.ToString('o')), $Message
    Add-Content -LiteralPath $TrayLogFile -Value $line -Encoding UTF8
}

if ($priorityBlocker) {
    Write-TrayLog "PRIORITY_BLOCKER $priorityBlocker; process remains hidden/no-focus."
}

function Get-EffectiveStartupDirectory {
    if ($StartupDirectory) {
        return [System.IO.Path]::GetFullPath($StartupDirectory)
    }
    return [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)
}

function Get-StartupShortcutPath {
    return Join-Path (Get-EffectiveStartupDirectory) $StartupShortcutName
}

function Get-TrayLaunchArguments {
    return Join-WindowsCommandLineArguments @(
        '-NoProfile', '-STA', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
        '-File', $TrayScriptPath, '-Mode', 'Tray', '-HubPort', [string]$HubPort,
        '-SillyTavernPort', [string]$SillyTavernPort, '-SillyTavernRoot', $SillyTavernRoot,
        '-LauncherIconPath', $LauncherIconPath)
}

function Get-ExpectedStartupIconLocation {
    if (Test-Path -LiteralPath $LauncherIconPath) {
        return "$LauncherIconPath,0"
    }
    return "$PowerShellExe,0"
}

function Test-StartupShortcutOwnership([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    return (Test-StMobilePathEqual $shortcut.TargetPath $PowerShellExe) `
            -and ($shortcut.Arguments -eq (Get-TrayLaunchArguments)) `
            -and (Test-StMobilePathEqual $shortcut.WorkingDirectory $ProjectRoot) `
            -and ($shortcut.Description -eq $StartupShortcutDescription) `
            -and ([int]$shortcut.WindowStyle -eq 7) `
            -and ($shortcut.IconLocation -eq (Get-ExpectedStartupIconLocation)) `
            -and ([string]::IsNullOrWhiteSpace([string]$shortcut.Hotkey))
}

function Get-StartupShortcutOwnedSnapshot([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    Assert-StMobileNonReparsePath $Path 'startup shortcut'
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $identity = [StMobile.PinnedFileOperations]::InspectExact(
        [System.IO.Path]::GetFullPath($Path),
        $bytes,
        '',
        '')
    if (-not (Test-StartupShortcutOwnership $Path)) {
        throw "Startup shortcut is modified or unrecognized: $Path"
    }
    [void][StMobile.PinnedFileOperations]::InspectExact(
        [System.IO.Path]::GetFullPath($Path),
        $bytes,
        $identity.ParentToken,
        $identity.FileToken)
    return [pscustomobject]@{
        Path = [System.IO.Path]::GetFullPath($Path)
        Bytes = $bytes
        ParentToken = $identity.ParentToken
        FileToken = $identity.FileToken
    }
}

function Get-StartupShortcutState {
    $shortcutPath = Get-StartupShortcutPath
    if (-not (Test-Path -LiteralPath $shortcutPath)) {
        return 'absent'
    }
    try {
        return $(if (Get-StartupShortcutOwnedSnapshot $shortcutPath) { 'owned' } else { 'absent' })
    } catch {
        Write-TrayLog "STARTUP_STATUS_ERROR $($_.Exception.Message)"
        return 'conflict'
    }
}

function Test-StartupShortcutEnabled {
    return (Get-StartupShortcutState) -eq 'owned'
}

function Set-StartupShortcut([bool]$Enabled) {
    $shortcutPath = Get-StartupShortcutPath
    $ownedSnapshot = $null
    $state = 'absent'
    if (Test-Path -LiteralPath $shortcutPath) {
        try {
            $ownedSnapshot = Get-StartupShortcutOwnedSnapshot $shortcutPath
            $state = 'owned'
        } catch {
            $state = 'conflict'
        }
    }
    if (-not $Enabled) {
        if ($state -eq 'conflict') {
            throw "Refusing to remove modified or unrecognized startup shortcut: $shortcutPath"
        }
        if ($state -eq 'owned') {
            [StMobile.PinnedFileOperations]::DeleteExact(
                $ownedSnapshot.Path,
                $ownedSnapshot.Bytes,
                $ownedSnapshot.ParentToken,
                $ownedSnapshot.FileToken)
            Write-TrayLog "STARTUP_DISABLED path=$shortcutPath"
        }
        return
    }

    if ($state -eq 'conflict') {
        throw "Refusing to overwrite modified or unrecognized startup shortcut: $shortcutPath"
    }
    if ($state -eq 'owned') {
        Write-TrayLog "STARTUP_ALREADY_ENABLED path=$shortcutPath"
        return
    }

    $startupRoot = Get-EffectiveStartupDirectory
    if (-not (Test-Path -LiteralPath $startupRoot -PathType Container)) {
        throw "Windows Startup directory does not exist; refusing pathname creation: $startupRoot"
    }
    $serializedIconPath = if (Test-Path -LiteralPath $LauncherIconPath) {
        [System.IO.Path]::GetFullPath($LauncherIconPath)
    } else {
        [System.IO.Path]::GetFullPath($PowerShellExe)
    }
    $shortcutBytes = [StMobile.ShellLinkSerializer]::SerializeAndValidate(
        [System.IO.Path]::GetFullPath($PowerShellExe),
        (Get-TrayLaunchArguments),
        [System.IO.Path]::GetFullPath($ProjectRoot),
        $StartupShortcutDescription,
        7,
        $serializedIconPath,
        0)
    $parentLease = [StMobile.PinnedFileOperations]::PinParent(
        [System.IO.Path]::GetFullPath($shortcutPath),
        '')
    $publishedIdentity = $null
    try {
        if (Test-Path -LiteralPath $shortcutPath) {
            throw "Startup shortcut destination became occupied; preserving it: $shortcutPath"
        }
        $publishedIdentity = [StMobile.PinnedFileOperations]::CreateNew(
            [System.IO.Path]::GetFullPath($shortcutPath),
            $shortcutBytes,
            $parentLease.ParentToken)
        if (-not (Test-StartupShortcutOwnership $shortcutPath)) {
            throw "Published startup shortcut readback failed: $shortcutPath"
        }
        [void][StMobile.PinnedFileOperations]::InspectExact(
            [System.IO.Path]::GetFullPath($shortcutPath),
            $shortcutBytes,
            $publishedIdentity.ParentToken,
            $publishedIdentity.FileToken)
    } catch {
        $failure = $_.Exception.Message
        $cleanupError = ''
        try {
            if ($publishedIdentity -and (Test-Path -LiteralPath $shortcutPath)) {
                [StMobile.PinnedFileOperations]::DeleteExact(
                    [System.IO.Path]::GetFullPath($shortcutPath),
                    $shortcutBytes,
                    $publishedIdentity.ParentToken,
                    $publishedIdentity.FileToken)
            }
        } catch {
            $cleanupError = $_.Exception.Message
        }
        if ($cleanupError) {
            throw "$failure Exact-generation cleanup was blocked: $cleanupError"
        }
        throw $failure
    } finally {
        $parentLease.Dispose()
    }
    if (-not (Test-StartupShortcutEnabled)) {
        throw "Startup shortcut readback failed: $shortcutPath"
    }
    Write-TrayLog "STARTUP_ENABLED path=$shortcutPath hidden=true priority=Idle"
}

function Test-TcpListener([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $client.ConnectAsync('127.0.0.1', $Port)
        return $connect.Wait(500) -and $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Test-HubReady {
    if (-not (Test-TcpListener $HubPort)) {
        return $false
    }
    try {
        $request = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$HubPort/api/devices")
        $request.Method = 'GET'
        $request.Proxy = $null
        $request.Timeout = 800
        $request.ReadWriteTimeout = 800
        $response = $request.GetResponse()
        try {
            if ([int]$response.StatusCode -ne 200 -or $response.Headers['X-ST-Mobile-Hub'] -ne '1') {
                return $false
            }
            $body = (Read-StMobileBoundedResponseText `
                -Response $response `
                -MaxCharacters 65536 `
                -ReadTimeoutMilliseconds 800) | ConvertFrom-Json
            $properties = @($body.PSObject.Properties.Name)
            return $body.service -ceq 'sillytavern-mobile-auth-hub' `
                -and [int]$body.schemaVersion -eq 1 `
                -and -not [string]::IsNullOrWhiteSpace([string]$body.gatewayUrl) `
                -and $properties -contains 'devices' `
                -and $properties -contains 'pendingPairings'
        } finally {
            $response.Dispose()
        }
    } catch {
        return $false
    }
}

function Get-VerifiedTrayProcess {
    $ownership = Get-StMobileTrayOwnershipState `
        -RecordPath $TrayProcessRecord `
        -PowerShellExe $PowerShellExe `
        -TrayScriptPath $TrayScriptPath `
        -ExpectedHubPort $HubPort `
        -ExpectedSillyTavernPort $SillyTavernPort `
        -ExpectedSillyTavernRoot $SillyTavernRoot `
        -ExpectedLauncherIconPath $LauncherIconPath
    if ($ownership.State -eq 'Conflict') {
        throw $ownership.Error
    }
    return $(if ($ownership.State -eq 'OwnedLive') { $ownership.Verified.Process } else { $null })
}

if ($Mode -eq 'EnableStartup') {
    Set-StartupShortcut $true
    [pscustomobject]@{ startupEnabled = Test-StartupShortcutEnabled; shortcut = Get-StartupShortcutPath } | ConvertTo-Json -Compress
    exit 0
}
if ($Mode -eq 'DisableStartup') {
    Set-StartupShortcut $false
    [pscustomobject]@{ startupEnabled = Test-StartupShortcutEnabled; shortcut = Get-StartupShortcutPath } | ConvertTo-Json -Compress
    exit 0
}
if ($Mode -eq 'Status') {
    $tray = $null
    $trayOwnershipConflict = ''
    try {
        $tray = Get-VerifiedTrayProcess
    } catch {
        $trayOwnershipConflict = $_.Exception.Message
    }
    [pscustomobject]@{
        startupEnabled = Test-StartupShortcutEnabled
        startupState = Get-StartupShortcutState
        shortcut = Get-StartupShortcutPath
        trayRunning = [bool]$tray
        trayPid = if ($tray) { $tray.Id } else { $null }
        trayPriority = if ($tray) { [string]$tray.PriorityClass } else { $null }
        trayMainWindowHandle = if ($tray) { [int64]$tray.MainWindowHandle } else { $null }
        trayOwnershipConflict = $trayOwnershipConflict
        sillyTavernListening = Test-TcpListener $SillyTavernPort
        hubReady = Test-HubReady
    } | ConvertTo-Json -Compress
    exit 0
}

$createdNew = $false
$mutex = New-Object System.Threading.Mutex($true, 'Local\SillyTavernMobileAuthHubTray', [ref]$createdNew)
if (-not $createdNew) {
    Write-TrayLog 'DUPLICATE_TRAY_SUPPRESSED existing named mutex is active.'
    $mutex.Dispose()
    exit 0
}

if (Test-Path -LiteralPath $TrayProcessRecord) {
    $staleTrayRecordSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot(
        [System.IO.Path]::GetFullPath($TrayProcessRecord), '')
    $staleTrayRecordBytes = $staleTrayRecordSnapshot.Bytes
    $trayOwnership = Get-StMobileTrayOwnershipState `
        -RecordPath $TrayProcessRecord `
        -RecordSnapshot $staleTrayRecordSnapshot `
        -PowerShellExe $PowerShellExe `
        -TrayScriptPath $TrayScriptPath `
        -ExpectedHubPort $HubPort `
        -ExpectedSillyTavernPort $SillyTavernPort `
        -ExpectedSillyTavernRoot $SillyTavernRoot `
        -ExpectedLauncherIconPath $LauncherIconPath
    if ($trayOwnership.State -eq 'Conflict') {
        throw "Tray ownership conflict; refusing record overwrite: $($trayOwnership.Error)"
    }
    if ($trayOwnership.State -eq 'OwnedLive') {
        throw "A live exact-owned tray PID $($trayOwnership.Verified.Process.Id) exists despite acquisition of the single-instance mutex; refusing record overwrite."
    }
    if ($trayOwnership.State -ne 'OwnedStale') {
        throw "Tray ownership classification changed unexpectedly: $($trayOwnership.State)"
    }
    Remove-StMobileFileIfUnchanged $TrayProcessRecord $staleTrayRecordBytes 'stale tray ownership record' `
        $staleTrayRecordSnapshot.ParentToken $staleTrayRecordSnapshot.FileToken
}
$processRecord = [ordered]@{
    schema = 'st-mobile-tray-process/v2'
    pid = $PID
    processStartTimeUtc = Get-StMobileProcessStartIdentity $currentProcess
    executablePath = $PowerShellExe
    scriptPath = $TrayScriptPath
    mode = 'Tray'
    hubPort = $HubPort
    sillyTavernPort = $SillyTavernPort
    sillyTavernRoot = [System.IO.Path]::GetFullPath($SillyTavernRoot)
    launcherIconPath = [System.IO.Path]::GetFullPath($LauncherIconPath)
    instanceId = [guid]::NewGuid().ToString('D')
    stopCapability = [guid]::NewGuid().ToString('D')
}
$processRecordText = ($processRecord | ConvertTo-Json) + [Environment]::NewLine
$processRecordBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($processRecordText)
$processRecordIdentity = Write-StMobileBytesCreateNew $TrayProcessRecord $processRecordBytes -PassThru
Write-TrayLog "TRAY_STARTED pid=$PID hidden=true no_focus=true priority=$($currentProcess.PriorityClass)"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Start-HiddenIdlePowerShell([string]$ScriptPath, [string[]]$ScriptArguments, [string]$Purpose) {
    $parts = @('-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath) + $ScriptArguments
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $PowerShellExe
    $info.Arguments = Join-WindowsCommandLineArguments $parts
    $info.WorkingDirectory = $ProjectRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $process = [System.Diagnostics.Process]::Start($info)
    # Process.Start is the commitment boundary. Everything below is deliberately
    # best-effort so a created child is always returned to the transaction owner.
    try {
        $process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
    } catch {
        try { Write-TrayLog "PRIORITY_BLOCKER purpose=$Purpose error=$($_.Exception.Message); child remains hidden/no-focus." } catch {}
    }
    try {
        $childId = $process.Id
        $childPriority = $process.PriorityClass
        Write-TrayLog "CHILD_STARTED purpose=$Purpose pid=$childId hidden=true no_focus=true priority=$childPriority"
    } catch {
        try { Write-TrayLog "CHILD_STARTED_POSTCHECK_BLOCKED purpose=$Purpose error=$($_.Exception.Message); child was created and remains committed." } catch {}
    }
    return $process
}

$script:StartAttempt = $null
$script:NextStartAttemptUtc = [DateTime]::MinValue
$script:AutoStartSuppressed = $false
$script:AutoStartAttempts = 0
$script:AutoRetryExhausted = $false
$script:CurrentStSession = $null
$script:HubWasReady = $false
$script:LastHubReady = $false
$script:LastListenerReady = $false
$script:ProbeAttempt = $null
$script:ProbeId = ''
$script:ProbeResultPath = ''
$script:StateRecordConflict = $false
$script:StateRecordConflictReason = ''
$script:StateRecordConflictSnapshots = [ordered]@{ Retry = $null; Suppression = $null }
$script:ForceResetTransactionActive = $false
$MaxAutoStartAttempts = 3
$ForceResetReservationBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes("st-mobile-force-reset-reservation/v1`n")

function Write-TrayStateRecordCas {
    param(
        [string]$Path,
        [object]$Record,
        [scriptblock]$Validator,
        [scriptblock]$TransitionValidator,
        [string]$OwnershipName
    )
    $newBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(
        ($Record | ConvertTo-Json) + [Environment]::NewLine)
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-StMobileBytesCreateNew $Path $newBytes
        return
    }
    $oldBytes = [System.IO.File]::ReadAllBytes($Path)
    $oldIdentity = [StMobile.PinnedFileOperations]::InspectExact(
        [System.IO.Path]::GetFullPath($Path),
        $oldBytes,
        '',
        '')
    try {
        $oldRecord = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($oldBytes) | ConvertFrom-Json
    } catch {
        throw "$OwnershipName is invalid; refusing replacement: $($_.Exception.Message)"
    }
    if (-not (& $Validator $oldRecord) `
            -or $oldRecord.stSessionKey -cne $Record.stSessionKey) {
        throw "$OwnershipName is foreign, modified, or belongs to another ST session; refusing replacement."
    }
    if ($TransitionValidator -and -not (& $TransitionValidator $oldRecord $Record)) {
        throw "$OwnershipName update would violate its monotonic state transition; refusing replacement."
    }
    [void][StMobile.PinnedFileOperations]::InspectExact(
        [System.IO.Path]::GetFullPath($Path),
        $oldBytes,
        $oldIdentity.ParentToken,
        $oldIdentity.FileToken)
    $priorPath = "$Path.st-mobile-prior-$([guid]::NewGuid().ToString('N'))"
    $priorIdentity = [StMobile.PinnedFileOperations]::MoveExact(
        [System.IO.Path]::GetFullPath($Path),
        [System.IO.Path]::GetFullPath($priorPath),
        $oldBytes,
        $oldIdentity.ParentToken,
        $oldIdentity.FileToken)
    $newIdentity = $null
    try {
        [void][StMobile.PinnedFileOperations]::InspectExact(
            [System.IO.Path]::GetFullPath($priorPath),
            $oldBytes,
            $priorIdentity.ParentToken,
            $priorIdentity.FileToken)
        $newIdentity = [StMobile.PinnedFileOperations]::CreateNew(
            [System.IO.Path]::GetFullPath($Path),
            $newBytes,
            $priorIdentity.ParentToken)
    } catch {
        $failure = $_.Exception.Message
        $rollbackErrors = New-Object 'System.Collections.Generic.List[string]'
        if ($newIdentity -and (Test-Path -LiteralPath $Path)) {
            try {
                [StMobile.PinnedFileOperations]::DeleteExact(
                    [System.IO.Path]::GetFullPath($Path),
                    $newBytes,
                    $newIdentity.ParentToken,
                    $newIdentity.FileToken)
            } catch {
                $rollbackErrors.Add("new generation cleanup: $($_.Exception.Message)")
            }
        }
        if (-not (Test-Path -LiteralPath $Path) -and (Test-Path -LiteralPath $priorPath)) {
            try {
                [void][StMobile.PinnedFileOperations]::MoveExact(
                    [System.IO.Path]::GetFullPath($priorPath),
                    [System.IO.Path]::GetFullPath($Path),
                    $oldBytes,
                    $priorIdentity.ParentToken,
                    $priorIdentity.FileToken)
            } catch {
                $rollbackErrors.Add("prior generation restore: $($_.Exception.Message)")
            }
        } elseif (Test-Path -LiteralPath $priorPath) {
            $rollbackErrors.Add('prior generation restore: destination is occupied; preserving both paths')
        }
        if ($rollbackErrors.Count -gt 0) {
            throw "$failure Exact-generation rollback also failed: $($rollbackErrors -join '; ')"
        }
        throw $failure
    }
    try {
        [StMobile.PinnedFileOperations]::DeleteExact(
            [System.IO.Path]::GetFullPath($priorPath),
            $oldBytes,
            $priorIdentity.ParentToken,
            $priorIdentity.FileToken)
    } catch {
        Write-TrayLog "STATE_PRIOR_CLEANUP_BLOCKED name=$OwnershipName error=$($_.Exception.Message)"
    }
}

function Set-FrozenStateRecordConflict {
    param(
        [ValidateSet('Retry', 'Suppression')][string]$Kind,
        [string]$Path,
        [byte[]]$Bytes,
        [object]$Identity,
        [string]$Reason,
        [string]$CaptureError = ''
    )
    if (-not $script:StateRecordConflictSnapshots[$Kind]) {
        $script:StateRecordConflictSnapshots[$Kind] = [pscustomobject]@{
            Kind = $Kind
            Path = [System.IO.Path]::GetFullPath($Path)
            Bytes = if ($null -ne $Bytes) { [byte[]]$Bytes.Clone() } else { [byte[]]@() }
            ParentToken = if ($Identity) { [string]$Identity.ParentToken } else { '' }
            FileToken = if ($Identity) { [string]$Identity.FileToken } else { '' }
            Captured = [bool]($Identity -and $null -ne $Bytes)
            CaptureError = $CaptureError
            Reason = $Reason
        }
    }
    $script:StateRecordConflict = $true
    $script:StateRecordConflictReason = $Reason
}

function Get-RetryStateRecord {
    if ($script:StateRecordConflictSnapshots.Retry) {
        $script:StateRecordConflict = $true
        $script:StateRecordConflictReason = $script:StateRecordConflictSnapshots.Retry.Reason
        return $null
    }
    if (-not (Test-Path -LiteralPath $RetryStateFile)) {
        return $null
    }
    $bytes = $null
    $identity = $null
    try {
        $identity = [StMobile.PinnedFileOperations]::ReadSnapshot(
            [System.IO.Path]::GetFullPath($RetryStateFile), '')
        $bytes = $identity.Bytes
    } catch {
        $captureFailure = $_.Exception.Message
        Write-TrayLog "RETRY_RECORD_INVALID $captureFailure"
        Set-FrozenStateRecordConflict 'Retry' $RetryStateFile $bytes $null `
            'invalid gateway retry state requires explicit manual rearm' $captureFailure
        return $null
    }
    try {
        $record = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes) | ConvertFrom-Json
        if (-not (Test-StMobileGatewayRetryStateRecord $record $MaxAutoStartAttempts)) {
            throw 'record schema, session key, attempt count, or exhaustion flag is invalid'
        }
        return $record
    } catch {
        Write-TrayLog "RETRY_RECORD_INVALID $($_.Exception.Message)"
        Set-FrozenStateRecordConflict 'Retry' $RetryStateFile $bytes $identity `
            'invalid gateway retry state requires explicit manual rearm'
        return $null
    }
}

function Remove-RetryStateRecord {
    if ($script:ForceResetTransactionActive) { Write-TrayLog 'STATE_MUTATION_DEFERRED name=remove_retry reason=force_reset_transaction_active'; return }
    if (-not (Test-Path -LiteralPath $RetryStateFile)) {
        return
    }
    $bytes = $null
    $identity = $null
    try {
        $identity = [StMobile.PinnedFileOperations]::ReadSnapshot(
            [System.IO.Path]::GetFullPath($RetryStateFile), '')
        $bytes = $identity.Bytes
    } catch {
        Set-FrozenStateRecordConflict 'Retry' $RetryStateFile $bytes $null `
            'invalid gateway retry state requires explicit manual rearm' $_.Exception.Message
        Write-TrayLog 'RETRY_REMOVE_REFUSED reason=generation_capture_failed'
        return
    }
    try {
        $record = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes) | ConvertFrom-Json
    } catch {
        $record = $null
    }
    if (-not (Test-StMobileGatewayRetryStateRecord $record $MaxAutoStartAttempts)) {
        Set-FrozenStateRecordConflict 'Retry' $RetryStateFile $bytes $identity `
            'invalid gateway retry state requires explicit manual rearm'
        Write-TrayLog 'RETRY_REMOVE_REFUSED reason=invalid_or_changed'
        return
    }
    # TEST-HARNESS-ANCHOR: before-retry-state-exact-cleanup
    Remove-StMobileFileIfUnchanged $RetryStateFile $bytes 'gateway retry state' `
        $identity.ParentToken $identity.FileToken
}

function Write-RetryStateRecord([object]$Session) {
    if ($script:ForceResetTransactionActive) { Write-TrayLog 'STATE_MUTATION_DEFERRED name=write_retry reason=force_reset_transaction_active'; return }
    if (-not $Session) {
        throw 'Cannot persist gateway retry state without a verified SillyTavern session.'
    }
    $record = [ordered]@{
        schema = 'st-mobile-gateway-retry/v1'
        stSessionKey = $Session.Key
        stPid = $Session.Pid
        stProcessStartTimeUtc = $Session.ProcessStartTimeUtc
        attempts = $script:AutoStartAttempts
        exhausted = $script:AutoRetryExhausted
        updatedAtUtc = [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    Write-TrayStateRecordCas `
        -Path $RetryStateFile `
        -Record $record `
        -Validator { param($value) Test-StMobileGatewayRetryStateRecord $value $MaxAutoStartAttempts } `
        -TransitionValidator {
            param($old, $new)
            [int]$new.attempts -ge [int]$old.attempts `
                -and (-not [bool]$old.exhausted -or [bool]$new.exhausted)
        } `
        -OwnershipName 'gateway retry state'
}

function Get-SuppressionRecord {
    if ($script:StateRecordConflictSnapshots.Suppression) {
        $script:StateRecordConflict = $true
        $script:StateRecordConflictReason = $script:StateRecordConflictSnapshots.Suppression.Reason
        return $null
    }
    if (-not (Test-Path -LiteralPath $SuppressionFile)) {
        return $null
    }
    $bytes = $null
    $identity = $null
    try {
        $identity = [StMobile.PinnedFileOperations]::ReadSnapshot(
            [System.IO.Path]::GetFullPath($SuppressionFile), '')
        $bytes = $identity.Bytes
    } catch {
        $captureFailure = $_.Exception.Message
        Write-TrayLog "SUPPRESSION_RECORD_INVALID $captureFailure"
        Set-FrozenStateRecordConflict 'Suppression' $SuppressionFile $bytes $null `
            'invalid gateway suppression state requires explicit manual rearm' $captureFailure
        return $null
    }
    try {
        $record = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes) | ConvertFrom-Json
        if (-not (Test-StMobileGatewaySuppressionStateRecord $record)) {
            throw 'record schema or session key is invalid'
        }
        return $record
    } catch {
        Write-TrayLog "SUPPRESSION_RECORD_INVALID $($_.Exception.Message)"
        Set-FrozenStateRecordConflict 'Suppression' $SuppressionFile $bytes $identity `
            'invalid gateway suppression state requires explicit manual rearm'
        return $null
    }
}

function Remove-SuppressionRecord {
    if ($script:ForceResetTransactionActive) { Write-TrayLog 'STATE_MUTATION_DEFERRED name=remove_suppression reason=force_reset_transaction_active'; return }
    if (-not (Test-Path -LiteralPath $SuppressionFile)) {
        return
    }
    $bytes = $null
    $identity = $null
    try {
        $identity = [StMobile.PinnedFileOperations]::ReadSnapshot(
            [System.IO.Path]::GetFullPath($SuppressionFile), '')
        $bytes = $identity.Bytes
    } catch {
        Set-FrozenStateRecordConflict 'Suppression' $SuppressionFile $bytes $null `
            'invalid gateway suppression state requires explicit manual rearm' $_.Exception.Message
        Write-TrayLog 'SUPPRESSION_REMOVE_REFUSED reason=generation_capture_failed'
        return
    }
    try {
        $record = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes) | ConvertFrom-Json
    } catch {
        $record = $null
    }
    if (-not (Test-StMobileGatewaySuppressionStateRecord $record)) {
        Set-FrozenStateRecordConflict 'Suppression' $SuppressionFile $bytes $identity `
            'invalid gateway suppression state requires explicit manual rearm'
        Write-TrayLog 'SUPPRESSION_REMOVE_REFUSED reason=invalid_or_changed'
        return
    }
    # TEST-HARNESS-ANCHOR: before-suppression-state-exact-cleanup
    Remove-StMobileFileIfUnchanged $SuppressionFile $bytes 'gateway suppression state' `
        $identity.ParentToken $identity.FileToken
}

function Write-SuppressionRecord([object]$Session) {
    if ($script:ForceResetTransactionActive) { Write-TrayLog 'STATE_MUTATION_DEFERRED name=write_suppression reason=force_reset_transaction_active'; return }
    if (-not $Session) {
        throw 'Cannot persist gateway suppression without a verified SillyTavern session.'
    }
    $record = [ordered]@{
        schema = 'st-mobile-gateway-suppression/v1'
        stSessionKey = $Session.Key
        stPid = $Session.Pid
        stProcessStartTimeUtc = $Session.ProcessStartTimeUtc
        suppressedAtUtc = [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    Write-TrayStateRecordCas `
        -Path $SuppressionFile `
        -Record $record `
        -Validator { param($value) Test-StMobileGatewaySuppressionStateRecord $value } `
        -TransitionValidator { param($old, $new) $new.suppressedAtUtc -cge $old.suppressedAtUtc } `
        -OwnershipName 'gateway suppression state'
}

function Quarantine-StateRecordConflictsForManualRearm {
    if (-not $script:StateRecordConflict) {
        return
    }
    $snapshots = @($script:StateRecordConflictSnapshots.Values | Where-Object { $null -ne $_ })
    if ($snapshots.Count -eq 0) {
        throw 'State record conflict has no frozen exact generation; refusing manual rearm.'
    }
    foreach ($snapshot in $snapshots) {
        if (-not $snapshot.Captured) {
            throw "State record conflict generation was not safely captured; refusing manual rearm: $($snapshot.Path): $($snapshot.CaptureError)"
        }
        [void][StMobile.PinnedFileOperations]::InspectExact(
            $snapshot.Path, $snapshot.Bytes,
            $snapshot.ParentToken, $snapshot.FileToken)
    }
    $suffix = '{0}.{1}.conflict' -f ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')), ([guid]::NewGuid().ToString('N'))
    # TEST-HARNESS-ANCHOR: after-state-record-conflict-preflight
    $moved = New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($snapshot in $snapshots) {
            $destination = "$($snapshot.Path).$suffix"
            $movedIdentity = [StMobile.PinnedFileOperations]::MoveExact(
                $snapshot.Path, $destination, $snapshot.Bytes,
                $snapshot.ParentToken, $snapshot.FileToken)
            $moved.Add([pscustomobject]@{ Snapshot = $snapshot; Destination = $destination; Identity = $movedIdentity })
        }
    } catch {
        $moveFailure = $_.Exception.Message
        $rollbackErrors = New-Object 'System.Collections.Generic.List[string]'
        for ($index = $moved.Count - 1; $index -ge 0; $index--) {
            $entry = $moved[$index]
            try {
                [void][StMobile.PinnedFileOperations]::MoveExact(
                    $entry.Destination, $entry.Snapshot.Path, $entry.Snapshot.Bytes,
                    $entry.Identity.ParentToken, $entry.Identity.FileToken)
            } catch {
                $rollbackErrors.Add("$($entry.Snapshot.Kind): $($_.Exception.Message)")
            }
        }
        if ($rollbackErrors.Count -gt 0) {
            throw "State record conflict quarantine failed: $moveFailure. Exact-generation rollback also failed: $($rollbackErrors -join '; ')"
        }
        throw "State record conflict quarantine failed and all staged generations were restored: $moveFailure"
    }
    foreach ($entry in $moved) {
        Write-TrayLog "STATE_RECORD_QUARANTINED source=$($entry.Snapshot.Path) destination=$($entry.Destination) reason=explicit_manual_rearm"
        $script:StateRecordConflictSnapshots[$entry.Snapshot.Kind] = $null
    }
    $script:StateRecordConflict = $false
    $script:StateRecordConflictReason = ''
}

function Set-CurrentSillyTavernSession([object]$Session) {
    if ($script:ForceResetTransactionActive) { Write-TrayLog 'STATE_MUTATION_DEFERRED name=set_session reason=force_reset_transaction_active'; return }
    $oldKey = if ($script:CurrentStSession) { [string]$script:CurrentStSession.Key } else { '' }
    $newKey = if ($Session) { [string]$Session.Key } else { '' }
    if ($oldKey -eq $newKey) {
        $script:StateRecordConflict = $false
        $script:StateRecordConflictReason = ''
        [void](Get-RetryStateRecord)
        [void](Get-SuppressionRecord)
        if ($script:StateRecordConflict) {
            $script:AutoStartSuppressed = $true
            $script:AutoRetryExhausted = $true
            Write-TrayLog "STATE_RECORD_CONFLICT fail_closed=true reason=$($script:StateRecordConflictReason)"
        }
        return
    }
    $script:CurrentStSession = $Session
    $script:AutoStartAttempts = 0
    $script:AutoRetryExhausted = $false
    $script:NextStartAttemptUtc = [DateTime]::MinValue
    $script:HubWasReady = $false
    $script:StateRecordConflict = $false
    $script:StateRecordConflictReason = ''
    $retryState = Get-RetryStateRecord
    if ($Session -and $retryState -and $retryState.stSessionKey -eq $Session.Key) {
        $script:AutoStartAttempts = [int]$retryState.attempts
        $script:AutoRetryExhausted = [bool]$retryState.exhausted
        Write-TrayLog "RETRY_STATE_RESTORED st_session=$($Session.Key) attempts=$($script:AutoStartAttempts) exhausted=$($script:AutoRetryExhausted)"
    } elseif ($retryState) {
        Remove-RetryStateRecord
        Write-TrayLog "RETRY_STATE_CLEARED reason=st_session_changed old=$($retryState.stSessionKey) new=$newKey"
    }
    $suppression = Get-SuppressionRecord
    if ($script:StateRecordConflict) {
        $script:AutoStartSuppressed = $true
        $script:AutoRetryExhausted = $true
        Write-TrayLog "STATE_RECORD_CONFLICT fail_closed=true reason=$($script:StateRecordConflictReason)"
        Write-TrayLog "ST_SESSION_CHANGED old=$oldKey new=$newKey"
        return
    }
    if ($Session -and $suppression -and $suppression.stSessionKey -eq $Session.Key) {
        $script:AutoStartSuppressed = $true
        Write-TrayLog "SUPPRESSION_RESTORED st_session=$($Session.Key)"
    } else {
        $script:AutoStartSuppressed = $false
        if ($suppression) {
            Remove-SuppressionRecord
            Write-TrayLog "SUPPRESSION_CLEARED reason=st_session_changed old=$($suppression.stSessionKey) new=$newKey"
        }
    }
    Write-TrayLog "ST_SESSION_CHANGED old=$oldKey new=$newKey"
}

function Get-CachedSillyTavernSessionState {
    if ($script:CurrentStSession -and (Test-SillyTavernSessionAlive $script:CurrentStSession)) {
        return [pscustomobject]@{
            Session = $script:CurrentStSession
            ListenerReady = [bool]$script:LastListenerReady
        }
    }
    Set-CurrentSillyTavernSession $null
    return [pscustomobject]@{ Session = $null; ListenerReady = $false }
}

function Start-TrayProbe {
    if ($script:ProbeAttempt -and -not $script:ProbeAttempt.HasExited) {
        return
    }
    $script:ProbeId = [guid]::NewGuid().ToString('D')
    $script:ProbeResultPath = Join-Path $StateRoot ("tray-probe-$PID-$($script:ProbeId).json")
    $arguments = @(
        '-HubPort', [string]$HubPort,
        '-SillyTavernPort', [string]$SillyTavernPort,
        '-SillyTavernRoot', $SillyTavernRoot,
        '-SillyTavernProcessRecord', $SillyTavernProcessRecord,
        '-ResultPath', $script:ProbeResultPath,
        '-ProbeId', $script:ProbeId)
    $script:ProbeAttempt = Start-HiddenIdlePowerShell $ProbeScript $arguments 'tray_state_probe'
}

function Read-TrayProbeResultSnapshot([string]$Path, [string]$ExpectedProbeId) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw 'probe result path is absent'
    }
    $fileSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot(
        [System.IO.Path]::GetFullPath($Path), '')
    $bytes = $fileSnapshot.Bytes
    try {
        $result = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes) | ConvertFrom-Json
    } catch {
        throw "probe result is not strict UTF-8 JSON: $($_.Exception.Message)"
    }
    $fields = @('schema', 'probeId', 'completedAtUtc', 'hubReady', 'listenerReady', 'session', 'error')
    if (-not (Test-StMobileExactPropertySet $result $fields) `
            -or $result.schema -cne 'st-mobile-tray-probe/v1' `
            -or $result.probeId -cne $ExpectedProbeId `
            -or -not (Test-StMobileCanonicalGuid $result.probeId) `
            -or -not (Test-StMobileCanonicalProcessStartIdentity $result.completedAtUtc) `
            -or $result.hubReady -isnot [bool] `
            -or $result.listenerReady -isnot [bool] `
            -or $result.error -isnot [string] `
            -or ([bool]$result.listenerReady -and -not $result.session) `
            -or (-not [bool]$result.listenerReady -and $null -ne $result.session)) {
        throw 'probe result failed exact schema or identity validation'
    }
    return [pscustomobject]@{
        Bytes = $bytes; Result = $result
        ParentToken = $fileSnapshot.ParentToken; FileToken = $fileSnapshot.FileToken
    }
}

function Complete-TrayProbe {
    if ($script:ForceResetTransactionActive) { return }
    if (-not $script:ProbeAttempt -or -not $script:ProbeAttempt.HasExited) {
        return
    }
    $probePid = $script:ProbeAttempt.Id
    $exitCode = $script:ProbeAttempt.ExitCode
    $script:ProbeAttempt.Dispose()
    $script:ProbeAttempt = $null
    $snapshot = $null
    try {
        if ($exitCode -ne 0 -or -not (Test-Path -LiteralPath $script:ProbeResultPath)) {
            throw "probe PID $probePid exited $exitCode without a result"
        }
        $snapshot = Read-TrayProbeResultSnapshot $script:ProbeResultPath $script:ProbeId
        $result = $snapshot.Result
        if ([bool]$result.listenerReady) {
            $verifiedSession = Get-SillyTavernSession `
                -Port $SillyTavernPort `
                -SillyTavernRoot $SillyTavernRoot `
                -RecordPath $SillyTavernProcessRecord `
                -ThrowOnInvalid
            if (-not $verifiedSession `
                    -or [string]$result.session.Key -cne [string]$verifiedSession.Key `
                    -or [string]$result.session.RootProofMethod -cne [string]$verifiedSession.RootProofMethod `
                    -or (ConvertTo-StMobileProcessStartIdentity $result.session.RootProofAtUtc) -cne (ConvertTo-StMobileProcessStartIdentity $verifiedSession.RootProofAtUtc)) {
                throw 'probe nested session did not match a fresh exact SillyTavern verification'
            }
            Set-CurrentSillyTavernSession $verifiedSession
        } elseif (-not ($script:CurrentStSession -and (Test-SillyTavernSessionAlive $script:CurrentStSession))) {
            Set-CurrentSillyTavernSession $null
        }
        $script:LastListenerReady = [bool]$result.listenerReady
        $script:LastHubReady = [bool]$result.hubReady
        if (-not [string]::IsNullOrWhiteSpace([string]$result.error)) {
            Write-TrayLog "TRAY_PROBE_CONSERVATIVE_ERROR pid=$probePid error=$($result.error)"
        }
    } catch {
        $script:LastListenerReady = $false
        $script:LastHubReady = $false
        Write-TrayLog "TRAY_PROBE_INVALID pid=$probePid error=$($_.Exception.Message)"
    } finally {
        if ($snapshot -and (Test-Path -LiteralPath $script:ProbeResultPath)) {
            try {
                Remove-StMobileFileIfUnchanged `
                    $script:ProbeResultPath `
                    $snapshot.Bytes `
                    'completed tray probe result' `
                    $snapshot.ParentToken `
                    $snapshot.FileToken
            } catch {
                Write-TrayLog "TRAY_PROBE_CLEANUP_REFUSED pid=$probePid error=$($_.Exception.Message)"
            }
        }
        $script:ProbeResultPath = ''
        $script:ProbeId = ''
    }
}

function New-ForceResetNamespaceReservations {
    $leases = New-Object 'System.Collections.Generic.List[object]'
    try {
        $leases.Add([StMobile.PinnedFileOperations]::ReserveNew(
            [System.IO.Path]::GetFullPath($RetryStateFile), $ForceResetReservationBytes, ''))
        # TEST-HARNESS-ANCHOR: after-force-retry-reservation
        $leases.Add([StMobile.PinnedFileOperations]::ReserveNew(
            [System.IO.Path]::GetFullPath($SuppressionFile), $ForceResetReservationBytes, ''))
        # TEST-HARNESS-ANCHOR: after-force-suppression-reservation
        return ,$leases.ToArray()
    } catch {
        $failure = $_.Exception.Message
        $rollbackErrors = New-Object 'System.Collections.Generic.List[string]'
        for ($index = $leases.Count - 1; $index -ge 0; $index--) {
            $lease = $leases[$index]
            try { $lease.Retire() } catch {
                $retireFailure = $_.Exception.Message
                $disposeFailure = ''
                try { $lease.Dispose() } catch { $disposeFailure = $_.Exception.Message }
                $rollbackErrors.Add("path=$($lease.Path) parent_token=$($lease.ParentToken) file_token=$($lease.FileToken) retire_validation=$retireFailure emergency_dispose=$disposeFailure")
            }
        }
        if ($rollbackErrors.Count -gt 0) {
            throw "Force-reset namespace reservation failed: $failure. Exact reservation rollback also failed: $($rollbackErrors -join '; ')"
        }
        throw "Force-reset namespace reservation failed and partial reservations were retired: $failure"
    }
}

function New-ForceResetStateTransaction {
    foreach ($canonicalPath in @([System.IO.Path]::GetFullPath($RetryStateFile), [System.IO.Path]::GetFullPath($SuppressionFile))) {
        $parent = Split-Path -Parent $canonicalPath
        $leaf = [System.IO.Path]::GetFileName($canonicalPath)
        if (@(Get-ChildItem -LiteralPath $parent -Force -Filter "$leaf.st-mobile-force-stage-*").Count -ne 0) {
            throw "Force-reset crash residue exists for $canonicalPath; refusing a new launch transaction."
        }
    }
    $candidates = @(
        [pscustomobject]@{ Kind='Retry'; Path=[System.IO.Path]::GetFullPath($RetryStateFile); Frozen=$script:StateRecordConflictSnapshots.Retry },
        [pscustomobject]@{ Kind='Suppression'; Path=[System.IO.Path]::GetFullPath($SuppressionFile); Frozen=$script:StateRecordConflictSnapshots.Suppression })
    $entries = New-Object 'System.Collections.Generic.List[object]'
    foreach ($candidate in $candidates) {
        if ($candidate.Frozen) {
            if (-not $candidate.Frozen.Captured) { throw "Frozen $($candidate.Kind) conflict has no exact generation: $($candidate.Frozen.CaptureError)" }
            $entries.Add([pscustomobject]@{ Kind=$candidate.Kind; Path=$candidate.Path; Bytes=$candidate.Frozen.Bytes; ParentToken=$candidate.Frozen.ParentToken; FileToken=$candidate.Frozen.FileToken; Conflict=$true })
        } elseif (Test-Path -LiteralPath $candidate.Path) {
            $snapshot = [StMobile.PinnedFileOperations]::ReadSnapshot($candidate.Path, '')
            $record = $null
            try { $record = (New-Object System.Text.UTF8Encoding($false,$true)).GetString($snapshot.Bytes) | ConvertFrom-Json } catch {}
            $valid = if ($candidate.Kind -eq 'Retry') { Test-StMobileGatewayRetryStateRecord $record $MaxAutoStartAttempts } else { Test-StMobileGatewaySuppressionStateRecord $record }
            if (-not $valid) { throw "Unclassified invalid $($candidate.Kind) record appeared during force reset; refusing transaction." }
            $entries.Add([pscustomobject]@{ Kind=$candidate.Kind; Path=$candidate.Path; Bytes=$snapshot.Bytes; ParentToken=$snapshot.ParentToken; FileToken=$snapshot.FileToken; Conflict=$false })
        }
    }
    foreach ($entry in $entries) { [void][StMobile.PinnedFileOperations]::InspectExact($entry.Path,$entry.Bytes,$entry.ParentToken,$entry.FileToken) }
    $moved = New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($entry in $entries) {
            $stage = "$($entry.Path).st-mobile-force-stage-$([guid]::NewGuid().ToString('N'))"
            $identity = [StMobile.PinnedFileOperations]::MoveExact($entry.Path,$stage,$entry.Bytes,$entry.ParentToken,$entry.FileToken)
            $moved.Add([pscustomobject]@{ Kind=$entry.Kind; Original=$entry.Path; Stage=$stage; Bytes=$entry.Bytes; ParentToken=$identity.ParentToken; FileToken=$identity.FileToken; Conflict=$entry.Conflict })
            # TEST-HARNESS-ANCHOR: after-force-state-stage-move
        }
        return $moved.ToArray()
    } catch {
        $failure=$_.Exception.Message;$errors=New-Object 'System.Collections.Generic.List[string]'
        for($index=$moved.Count-1;$index-ge 0;$index--){$entry=$moved[$index];try{[void][StMobile.PinnedFileOperations]::MoveExact($entry.Stage,$entry.Original,$entry.Bytes,$entry.ParentToken,$entry.FileToken)}catch{$errors.Add($_.Exception.Message)}}
        if($errors.Count){throw "Force-reset state staging failed: $failure. Exact rollback also failed: $($errors -join '; ')"}
        throw "Force-reset state staging failed and all generations were restored: $failure"
    }
}

function Restore-ForceResetStateTransaction([object[]]$Entries) {
    $errors=New-Object 'System.Collections.Generic.List[string]'
    for($index=$Entries.Count-1;$index-ge 0;$index--){$entry=$Entries[$index];try{[void][StMobile.PinnedFileOperations]::MoveExact($entry.Stage,$entry.Original,$entry.Bytes,$entry.ParentToken,$entry.FileToken)}catch{$errors.Add($_.Exception.Message)}}
    if($errors.Count){throw "Force-reset state restore failed: $($errors -join '; ')"}
}

function Complete-ForceResetStateTransaction([object[]]$Entries) {
    foreach($entry in @($Entries | Where-Object { $null -ne $_ })){
        if($entry.Conflict){
            $destination="$($entry.Original).$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')).$([guid]::NewGuid().ToString('N')).conflict"
            [void][StMobile.PinnedFileOperations]::MoveExact($entry.Stage,$destination,$entry.Bytes,$entry.ParentToken,$entry.FileToken)
            $script:StateRecordConflictSnapshots[$entry.Kind]=$null
        } else {
            [StMobile.PinnedFileOperations]::DeleteExact($entry.Stage,$entry.Bytes,$entry.ParentToken,$entry.FileToken)
        }
        # TEST-HARNESS-ANCHOR: after-force-state-finalization-entry
    }
}

function Remove-ForceResetNamespaceReservations([object[]]$Reservations) {
    $errors = New-Object 'System.Collections.Generic.List[string]'
    for ($index = $Reservations.Count - 1; $index -ge 0; $index--) {
        $lease = $Reservations[$index]
        try { $lease.Retire() } catch {
            $retireFailure = $_.Exception.Message
            $disposeFailure = ''
            try { $lease.Dispose() } catch { $disposeFailure = $_.Exception.Message }
            $errors.Add("path=$($lease.Path) parent_token=$($lease.ParentToken) file_token=$($lease.FileToken) retire_validation=$retireFailure emergency_dispose=$disposeFailure")
        }
    }
    if ($errors.Count -gt 0) { throw "Force-reset reservation retirement failed: $($errors -join '; ')" }
}

function Start-GatewayAttempt([bool]$Force) {
    if ($script:ForceResetTransactionActive) {
        Write-TrayLog 'GATEWAY_START_DEFERRED reason=force_reset_transaction_active'
        return
    }
    if ($script:StartAttempt -and -not $script:StartAttempt.HasExited) {
        return
    }
    $sessionState = Get-CachedSillyTavernSessionState
    if (-not $sessionState.Session -or -not $sessionState.ListenerReady) {
        Write-TrayLog 'GATEWAY_START_DEFERRED reason=sillytavern_not_listening'
        return
    }
    if ($Force) { $script:ForceResetTransactionActive = $true }
    $forceReservations = $null
    $forceStateEntries = $null
    if ($Force) {
        try {
            $forceStateEntries = @(New-ForceResetStateTransaction)
            # TEST-HARNESS-ANCHOR: after-force-suppression-removal
            # TEST-HARNESS-ANCHOR: after-force-retry-removal
            $forceReservations = @(New-ForceResetNamespaceReservations)
        } catch {
            $forceResetFailure = $_.Exception.Message
            if ($forceStateEntries) {
                try { Restore-ForceResetStateTransaction $forceStateEntries } catch {
                    $forceResetFailure += "; state restore: $($_.Exception.Message)"
                }
            }
            $script:StateRecordConflict = $true
            $script:StateRecordConflictReason = "forced gateway reset failed: $forceResetFailure"
            $script:AutoStartSuppressed = $true
            $script:AutoRetryExhausted = $true
            Write-TrayLog "GATEWAY_FORCE_RESET_BLOCKED error=$forceResetFailure"
            $script:ForceResetTransactionActive = $false
            return
        }
    } elseif ($script:AutoStartSuppressed) {
        return
    } elseif ($script:AutoStartAttempts -ge $MaxAutoStartAttempts) {
        if (-not $script:AutoRetryExhausted) {
            Write-TrayLog "GATEWAY_AUTO_RETRY_EXHAUSTED st_session=$($sessionState.Session.Key) attempts=$($script:AutoStartAttempts)"
            $script:AutoRetryExhausted = $true
            Write-RetryStateRecord $sessionState.Session
        }
        return
    }
    if ((-not $Force) -and ([DateTime]::UtcNow -lt $script:NextStartAttemptUtc)) {
        return
    }
    if (-not $Force) {
        $script:AutoStartAttempts++
        $script:AutoRetryExhausted = $script:AutoStartAttempts -ge $MaxAutoStartAttempts
        Write-RetryStateRecord $sessionState.Session
    }
    $script:NextStartAttemptUtc = [DateTime]::UtcNow.AddSeconds(30)
    $arguments = @('-NoStartSillyTavern', '-HubPort', [string]$HubPort, '-SillyTavernRoot', $SillyTavernRoot)
    if ($Force) {
        try {
            # TEST-HARNESS-ANCHOR: before-force-child-launch
            $script:StartAttempt = Start-HiddenIdlePowerShell $StartScript $arguments 'start_gateway'
        } catch {
            $forceLaunchFailure = $_.Exception.Message
            if ($forceReservations) {
                try { Remove-ForceResetNamespaceReservations $forceReservations } catch {
                    $forceLaunchFailure += "; reservation cleanup: $($_.Exception.Message)"
                }
            }
            if ($forceStateEntries) {
                try { Restore-ForceResetStateTransaction $forceStateEntries } catch {
                    $forceLaunchFailure += "; state restore: $($_.Exception.Message)"
                }
            }
            $script:StateRecordConflict = $true
            $script:StateRecordConflictReason = "forced gateway launch failed: $forceLaunchFailure"
            $script:AutoStartSuppressed = $true
            $script:AutoRetryExhausted = $true
            Write-TrayLog "GATEWAY_FORCE_RESET_BLOCKED error=$forceLaunchFailure"
            $script:ForceResetTransactionActive = $false
            return
        }
        # A successful hidden/Idle Process return stored in StartAttempt is the launch commitment.
        # Cleanup after this boundary never pretends it can roll back an already-created child.
        $committedCleanupErrors = New-Object 'System.Collections.Generic.List[string]'
        try { Remove-ForceResetNamespaceReservations $forceReservations; $forceReservations = $null } catch {
            $committedCleanupErrors.Add("reservation retirement: $($_.Exception.Message)")
        }
        try { Complete-ForceResetStateTransaction $forceStateEntries; $forceStateEntries = $null } catch {
            $committedCleanupErrors.Add("state finalization: $($_.Exception.Message)")
        }
        if ($committedCleanupErrors.Count -gt 0) {
            $cleanupFailure = $committedCleanupErrors -join '; '
            $script:StateRecordConflict = $true
            $script:StateRecordConflictReason = "forced gateway launch committed with cleanup residue: $cleanupFailure"
            $script:AutoStartSuppressed = $true
            $script:AutoRetryExhausted = $true
            Write-TrayLog "GATEWAY_FORCE_RESET_COMMITTED_CLEANUP_BLOCKED error=$cleanupFailure"
        } else {
            $script:StateRecordConflict = $false
            $script:StateRecordConflictReason = ''
            $script:AutoStartSuppressed = $false
            $script:AutoStartAttempts = 0
            $script:AutoRetryExhausted = $false
        }
        $script:ForceResetTransactionActive = $false
    } else {
        $script:StartAttempt = Start-HiddenIdlePowerShell $StartScript $arguments 'start_gateway'
    }
}

function Stop-GatewayFromTray {
    if ($script:ForceResetTransactionActive) { Write-TrayLog 'STATE_MUTATION_DEFERRED name=stop_gateway reason=force_reset_transaction_active'; return }
    $sessionState = Get-CachedSillyTavernSessionState
    if (-not $sessionState.Session) {
        throw 'Cannot bind gateway suppression because no verified SillyTavern session is active.'
    }
    Write-SuppressionRecord $sessionState.Session
    Remove-RetryStateRecord
    $script:AutoStartSuppressed = $true
    $script:NextStartAttemptUtc = [DateTime]::MaxValue
    [void](Start-HiddenIdlePowerShell $StopScript @() 'stop_gateway')
}

function Open-VerifiedSillyTavernDesktop {
    param(
        [int]$Port,
        [string]$Root,
        [string]$RecordPath
    )
    $verifiedSession = Get-SillyTavernSession `
        -Port $Port `
        -SillyTavernRoot $Root `
        -RecordPath $RecordPath `
        -ThrowOnInvalid
    if (-not $verifiedSession) {
        throw 'No live root-verified SillyTavern desktop session is available.'
    }
    [void](Start-Process -FilePath "http://127.0.0.1:$Port/")
}

$context = New-Object System.Windows.Forms.ApplicationContext
$menu = New-Object System.Windows.Forms.ContextMenuStrip
$statusItem = New-Object System.Windows.Forms.ToolStripMenuItem
$statusItem.Text = 'Status: starting'
$statusItem.Enabled = $false
$openSillyTavernItem = New-Object System.Windows.Forms.ToolStripMenuItem
$openSillyTavernItem.Text = 'Open SillyTavern on Desktop'
$openHubItem = New-Object System.Windows.Forms.ToolStripMenuItem
$openHubItem.Text = 'Open Authentication Hub'
$startGatewayItem = New-Object System.Windows.Forms.ToolStripMenuItem
$startGatewayItem.Text = 'Start Gateway Now'
$stopGatewayItem = New-Object System.Windows.Forms.ToolStripMenuItem
$stopGatewayItem.Text = 'Stop Gateway for This ST Session'
$startupItem = New-Object System.Windows.Forms.ToolStripMenuItem
$startupItem.Text = 'Start with Windows'
$startupItem.Checked = Test-StartupShortcutEnabled
$exitItem = New-Object System.Windows.Forms.ToolStripMenuItem
$exitItem.Text = 'Exit Tray (leave gateway running)'

[void]$menu.Items.Add($statusItem)
[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
[void]$menu.Items.Add($openSillyTavernItem)
[void]$menu.Items.Add($openHubItem)
[void]$menu.Items.Add($startGatewayItem)
[void]$menu.Items.Add($stopGatewayItem)
[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
[void]$menu.Items.Add($startupItem)
[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
[void]$menu.Items.Add($exitItem)

$notifyIcon = New-Object System.Windows.Forms.NotifyIcon
$customIcon = $null
if (Test-Path -LiteralPath $LauncherIconPath) {
    $customIcon = New-Object System.Drawing.Icon($LauncherIconPath)
    $notifyIcon.Icon = $customIcon
} else {
    $notifyIcon.Icon = [System.Drawing.SystemIcons]::Application
    Write-TrayLog "ICON_FALLBACK missing=$LauncherIconPath"
}
$notifyIcon.ContextMenuStrip = $menu
$notifyIcon.Text = 'ST Mobile Hub: starting'
$notifyIcon.Visible = $true

$openSillyTavernItem.add_Click({
    try {
        Open-VerifiedSillyTavernDesktop `
            -Port $SillyTavernPort `
            -Root $SillyTavernRoot `
            -RecordPath $SillyTavernProcessRecord
        Write-TrayLog "SILLYTAVERN_DESKTOP_OPENED url=http://127.0.0.1:$SillyTavernPort/ verified=true"
    } catch {
        Write-TrayLog "SILLYTAVERN_DESKTOP_OPEN_BLOCKED error=$($_.Exception.Message)"
        $notifyIcon.ShowBalloonTip(
            5000,
            'SillyTavern is not ready',
            'The verified desktop SillyTavern session is unavailable.',
            [System.Windows.Forms.ToolTipIcon]::Warning)
    }
})
$openHubAction = {
    if ($script:LastHubReady) {
        Start-Process "http://127.0.0.1:$HubPort/"
    } else {
        Start-GatewayAttempt $true
    }
}
$openHubItem.add_Click($openHubAction)
$notifyIcon.add_DoubleClick($openHubAction)
$startGatewayItem.add_Click({
    Start-GatewayAttempt $true
})
$stopGatewayItem.add_Click({ Stop-GatewayFromTray })
$startupItem.add_Click({
    try {
        Set-StartupShortcut (-not (Test-StartupShortcutEnabled))
        $startupItem.Checked = Test-StartupShortcutEnabled
    } catch {
        Write-TrayLog "STARTUP_TOGGLE_ERROR $($_.Exception.Message)"
        $startupItem.Checked = Test-StartupShortcutEnabled
    }
})
$menu.add_Opening({ $startupItem.Checked = Test-StartupShortcutEnabled })
$exitItem.add_Click({ $context.ExitThread() })

function Update-TrayState {
    if ($script:ForceResetTransactionActive) { return }
    if (Test-Path -LiteralPath $TrayStopFile) {
        try {
            $stopRequest = Get-StMobileOwnedTrayStopRequest `
                -Path $TrayStopFile `
                -TrayRecord $processRecord
            Remove-StMobileFileIfUnchanged `
                $TrayStopFile `
                $stopRequest.Bytes `
                'accepted tray stop request' `
                $stopRequest.ParentToken `
                $stopRequest.FileToken
            Write-TrayLog "TRAY_STOP_REQUEST accepted=true instance_id=$($processRecord.instanceId) request_nonce=$($stopRequest.Record.requestNonce)"
            $context.ExitThread()
            return
        } catch {
            Write-TrayLog "TRAY_STOP_REQUEST accepted=false preserved=true error=$($_.Exception.Message)"
        }
    }
    if ($script:StartAttempt -and $script:StartAttempt.HasExited) {
        $exitCode = $script:StartAttempt.ExitCode
        Write-TrayLog "GATEWAY_START_FINISHED pid=$($script:StartAttempt.Id) exit_code=$exitCode"
        $script:StartAttempt.Dispose()
        $script:StartAttempt = $null
        $script:NextStartAttemptUtc = [DateTime]::UtcNow.AddSeconds(30)
    }

    Complete-TrayProbe
    $sessionState = Get-CachedSillyTavernSessionState
    $stReady = [bool]$sessionState.ListenerReady
    $hubReady = [bool]$script:LastHubReady
    if ($hubReady -and -not $script:HubWasReady) {
        $script:AutoStartAttempts = 0
        $script:AutoRetryExhausted = $false
        Remove-RetryStateRecord
    }
    $script:HubWasReady = $hubReady

    if ($stReady -and -not $hubReady -and -not $script:AutoStartSuppressed -and -not $script:StateRecordConflict) {
        Start-GatewayAttempt $false
    }

    if ($hubReady) {
        $statusItem.Text = 'Status: gateway and auth hub online'
        $notifyIcon.Text = 'ST Mobile Hub: online'
        $openHubItem.Enabled = $true
        $openSillyTavernItem.Enabled = $stReady
        $startGatewayItem.Enabled = $false
        $stopGatewayItem.Enabled = $true
    } elseif ($script:StartAttempt -and -not $script:StartAttempt.HasExited) {
        $statusItem.Text = 'Status: starting gateway'
        $notifyIcon.Text = 'ST Mobile Hub: starting gateway'
        $openHubItem.Enabled = $false
        $openSillyTavernItem.Enabled = $stReady
        $startGatewayItem.Enabled = $false
        $stopGatewayItem.Enabled = $false
    } elseif ($script:StateRecordConflict -and $stReady) {
        $statusItem.Text = 'Status: state conflict; manual start will quarantine and rearm'
        $notifyIcon.Text = 'ST Mobile Hub: manual repair needed'
        $openHubItem.Enabled = $false
        $openSillyTavernItem.Enabled = $stReady
        $startGatewayItem.Enabled = $true
        $stopGatewayItem.Enabled = $false
    } elseif ($script:AutoStartSuppressed -and $stReady) {
        $statusItem.Text = 'Status: gateway stopped for this ST session'
        $notifyIcon.Text = 'ST Mobile Hub: paused'
        $openHubItem.Enabled = $false
        $openSillyTavernItem.Enabled = $stReady
        $startGatewayItem.Enabled = $true
        $stopGatewayItem.Enabled = $false
    } elseif ($script:AutoRetryExhausted -and $stReady) {
        $statusItem.Text = 'Status: automatic retries exhausted; manual start available'
        $notifyIcon.Text = 'ST Mobile Hub: manual retry needed'
        $openHubItem.Enabled = $false
        $openSillyTavernItem.Enabled = $stReady
        $startGatewayItem.Enabled = $true
        $stopGatewayItem.Enabled = $false
    } elseif ($stReady) {
        $statusItem.Text = 'Status: SillyTavern ready; gateway pending'
        $notifyIcon.Text = 'ST Mobile Hub: gateway pending'
        $openHubItem.Enabled = $false
        $openSillyTavernItem.Enabled = $stReady
        $startGatewayItem.Enabled = $true
        $stopGatewayItem.Enabled = $false
    } else {
        $statusItem.Text = 'Status: waiting for SillyTavern'
        $notifyIcon.Text = 'ST Mobile Hub: waiting for ST'
        $openHubItem.Enabled = $false
        $openSillyTavernItem.Enabled = $false
        $startGatewayItem.Enabled = $false
        $stopGatewayItem.Enabled = $false
    }
    Start-TrayProbe
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 3000
$timer.add_Tick({ Update-TrayState })
$timer.Start()
Update-TrayState

try {
    [System.Windows.Forms.Application]::Run($context)
} finally {
    $timer.Stop()
    $timer.Dispose()
        if ($script:ProbeAttempt) {
        if (-not $script:ProbeAttempt.HasExited) {
            $script:ProbeAttempt.Kill()
            $script:ProbeAttempt.WaitForExit(2000) | Out-Null
        }
            $script:ProbeAttempt.Dispose()
        }
        if (-not [string]::IsNullOrWhiteSpace($script:ProbeResultPath)) {
            try {
                $finalProbeSnapshot = Read-TrayProbeResultSnapshot $script:ProbeResultPath $script:ProbeId
                Remove-StMobileFileIfUnchanged `
                    $script:ProbeResultPath `
                    $finalProbeSnapshot.Bytes `
                    'exiting tray probe result' `
                    $finalProbeSnapshot.ParentToken `
                    $finalProbeSnapshot.FileToken
            } catch {
                Write-TrayLog "TRAY_PROBE_EXIT_CLEANUP_REFUSED error=$($_.Exception.Message)"
            }
        }
    $notifyIcon.Visible = $false
    $notifyIcon.Dispose()
    $menu.Dispose()
    if ($customIcon) {
        $customIcon.Dispose()
    }
    if (Test-Path -LiteralPath $TrayProcessRecord) {
        try {
            $currentRecordBytes = [System.IO.File]::ReadAllBytes($TrayProcessRecord)
            if (Test-BytesEqual $currentRecordBytes $processRecordBytes) {
                Remove-StMobileFileIfUnchanged `
                    $TrayProcessRecord `
                    $processRecordBytes `
                    'exiting tray ownership record' `
                    $processRecordIdentity.ParentToken `
                    $processRecordIdentity.FileToken
            } else {
                Write-TrayLog 'PROCESS_RECORD_CLEANUP_REFUSED reason=record_bytes_changed'
            }
        } catch {
            Write-TrayLog "PROCESS_RECORD_CLEANUP_ERROR $($_.Exception.Message)"
        }
    }
    Write-TrayLog "TRAY_EXITED pid=$PID gateway_left_running=true"
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
