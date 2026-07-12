param(
    [switch]$StopSillyTavern,
    [int]$Port = 38443,
    [int]$HubPort = 38444,
    [string]$SillyTavernRoot = 'C:\Users\Sneak\SillyTavern-Launcher\SillyTavern-Launcher\SillyTavern'
)

$ErrorActionPreference = 'Stop'
$currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
$currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle

# Rank Audit For This Stop Path
# - Rank 4: stop only a process whose PID, start time, executable, exact argv, and ownership record agree.
# - Rank 3: preserve the legacy numeric PID file beside the stronger JSON record for compatibility.

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$GatewayCli = Join-Path $ProjectRoot 'gateway\src\cli.js'
$CommonScript = Join-Path $PSScriptRoot 'StMobileTrayCommon.ps1'
. $CommonScript
$StateRoot = Join-Path $ProjectRoot 'state'
$GatewayPidFile = Join-Path $StateRoot 'gateway.pid'
$GatewayProcessRecord = Join-Path $StateRoot 'gateway-process.json'
$HubUrlFile = Join-Path $StateRoot 'auth-hub.url'
$SillyTavernPidFile = Join-Path $StateRoot 'sillytavern.pid'
$SillyTavernProcessRecord = Join-Path $StateRoot 'sillytavern-process.json'
$node = (Get-Command node.exe -ErrorAction Stop).Source

function Read-ExactPositivePid([string]$Path, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    return Read-StMobileCanonicalPositivePidBytes ([System.IO.File]::ReadAllBytes($Path)) $Name
}

function Get-OwnedHubUrlEntryForGatewayRecord([object]$GatewayRecord) {
    if (-not (Test-Path -LiteralPath $HubUrlFile)) {
        return $null
    }
    try {
        $owned = Publish-StMobileAuthHubUrlRecord `
            -Path $HubUrlFile `
            -GatewayRecord $GatewayRecord `
            -AllowLegacyUrlCas
        return [pscustomobject]@{
            Path = $HubUrlFile; Bytes = $owned.Bytes
            ParentToken = $owned.ParentToken; FileToken = $owned.FileToken
        }
    } catch {
        Write-Warning "Auth-hub URL record is not exact-owned by the verified gateway and will be preserved: $($_.Exception.Message)"
        return $null
    }
}

function Stop-VerifiedGateway {
    $pidExists = Test-Path -LiteralPath $GatewayPidFile
    $hasRecord = Test-Path -LiteralPath $GatewayProcessRecord
    if (-not $pidExists -and -not $hasRecord) {
        Write-Host 'ST Mobile Gateway ownership files not found.'
        return
    }
    if (-not $pidExists -or -not $hasRecord) {
        throw 'Gateway ownership state is incomplete; refusing to stop any process.'
    }
    $gatewayPidSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot([System.IO.Path]::GetFullPath($GatewayPidFile), '')
    $gatewayRecordSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot([System.IO.Path]::GetFullPath($GatewayProcessRecord), '')
    $stalePidBytes = $gatewayPidSnapshot.Bytes
    $staleRecordBytes = $gatewayRecordSnapshot.Bytes
    $pidValue = Read-StMobileCanonicalPositivePidBytes $stalePidBytes 'ST Mobile Gateway'
    try {
        $capturedGatewayRecord = (New-Object System.Text.UTF8Encoding($false, $true)).GetString(
            $staleRecordBytes) | ConvertFrom-Json
    } catch {
        throw "Gateway ownership record is invalid; refusing to stop or clean up: $($_.Exception.Message)"
    }
    $ownership = Get-StMobileGatewayOwnershipState `
        -RecordPath $GatewayProcessRecord `
        -RecordSnapshot $gatewayRecordSnapshot `
        -NodeExe $node `
        -GatewayCli $GatewayCli `
        -PublicHost ([string]$capturedGatewayRecord.publicHost) `
        -Port $Port `
        -HubPort $HubPort
    if ($ownership.State -eq 'Conflict') {
        throw $ownership.Error
    }
    if ($ownership.State -ne 'OwnedLive') {
        $staleRecord = $capturedGatewayRecord
        $staleEntries = @(
            [pscustomobject]@{ Path = $GatewayPidFile; Bytes = $stalePidBytes; ParentToken = $gatewayPidSnapshot.ParentToken; FileToken = $gatewayPidSnapshot.FileToken },
            [pscustomobject]@{ Path = $GatewayProcessRecord; Bytes = $staleRecordBytes; ParentToken = $gatewayRecordSnapshot.ParentToken; FileToken = $gatewayRecordSnapshot.FileToken })
        $staleHubEntry = Get-OwnedHubUrlEntryForGatewayRecord $staleRecord
        if ($staleHubEntry) {
            $staleEntries += $staleHubEntry
        }
        Remove-StMobileFileSetIfUnchanged -OwnershipName 'stale gateway ownership set' -Entries $staleEntries
        Write-Host 'Removed stale ST Mobile Gateway ownership files; no owned process was alive.'
        return
    }
    $verified = $ownership.Verified
    if ($verified.Process.Id -ne $pidValue) {
        throw "Gateway PID file names $pidValue but the exact ownership record names $($verified.Process.Id); refusing termination."
    }
    $gatewayPidBytesBeforeStop = $gatewayPidSnapshot.Bytes
    $gatewayRecordBytesBeforeStop = $gatewayRecordSnapshot.Bytes
    $ownedHubUrlEntry = Get-OwnedHubUrlEntryForGatewayRecord $verified.Record
    [void][StMobile.PinnedFileOperations]::InspectExact(
        [System.IO.Path]::GetFullPath($GatewayPidFile), $gatewayPidSnapshot.Bytes,
        $gatewayPidSnapshot.ParentToken, $gatewayPidSnapshot.FileToken)
    [void][StMobile.PinnedFileOperations]::InspectExact(
        [System.IO.Path]::GetFullPath($GatewayProcessRecord), $gatewayRecordSnapshot.Bytes,
        $gatewayRecordSnapshot.ParentToken, $gatewayRecordSnapshot.FileToken)
    Assert-StMobilePinnedProcessIdentity $verified.Process $verified.Record.processStartTimeUtc 'Gateway'
    [StMobile.PinnedFileOperations]::TerminatePinnedProcess($verified.Process, 1)
    $verified.Process.WaitForExit(10000) | Out-Null
    if (-not $verified.Process.HasExited) {
        throw "Gateway PID $($verified.Process.Id) remained alive after pinned-handle termination; preserving ownership files."
    }
    if (-not (Test-BytesEqual $gatewayPidBytesBeforeStop ([System.IO.File]::ReadAllBytes($GatewayPidFile))) `
            -or -not (Test-BytesEqual $gatewayRecordBytesBeforeStop ([System.IO.File]::ReadAllBytes($GatewayProcessRecord)))) {
        throw 'Gateway ownership files changed during stop; preserving them and refusing cleanup.'
    }
    $stoppedGatewayEntries = @(
        [pscustomobject]@{ Path = $GatewayPidFile; Bytes = $gatewayPidBytesBeforeStop; ParentToken = $gatewayPidSnapshot.ParentToken; FileToken = $gatewayPidSnapshot.FileToken },
        [pscustomobject]@{ Path = $GatewayProcessRecord; Bytes = $gatewayRecordBytesBeforeStop; ParentToken = $gatewayRecordSnapshot.ParentToken; FileToken = $gatewayRecordSnapshot.FileToken })
    if ($ownedHubUrlEntry) {
        $stoppedGatewayEntries += $ownedHubUrlEntry
    }
    Remove-StMobileFileSetIfUnchanged -OwnershipName 'stopped gateway ownership set' -Entries $stoppedGatewayEntries
    Write-Host "Stopped exact-owned ST Mobile Gateway PID $($verified.Process.Id)."
}

function Stop-VerifiedSillyTavern {
    $pidExists = Test-Path -LiteralPath $SillyTavernPidFile
    $recordExists = Test-Path -LiteralPath $SillyTavernProcessRecord
    if (-not $pidExists -and -not $recordExists) {
        Write-Host 'SillyTavern PID file not found.'
        return
    }
    if (-not $pidExists -or -not $recordExists) {
        throw 'SillyTavern ownership state is incomplete; refusing to stop any process.'
    }
    $stPidSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot([System.IO.Path]::GetFullPath($SillyTavernPidFile), '')
    $stRecordSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot([System.IO.Path]::GetFullPath($SillyTavernProcessRecord), '')
    $pidValue = Read-StMobileCanonicalPositivePidBytes $stPidSnapshot.Bytes 'SillyTavern'
    $session = Get-SillyTavernSession `
        -Port 3000 `
        -SillyTavernRoot $SillyTavernRoot `
        -RecordPath $SillyTavernProcessRecord `
        -RecordSnapshot $stRecordSnapshot `
        -IncludeProcessCapability `
        -ThrowOnInvalid
    if (-not $session -or $session.Pid -ne $pidValue) {
        throw "SillyTavern PID $pidValue does not match the exact loopback server.js session; refusing termination."
    }
    $stPidBytesBeforeStop = $stPidSnapshot.Bytes
    $stRecordBytesBeforeStop = $stRecordSnapshot.Bytes
    $stProcess = $session.ProcessCapability
    [void][StMobile.PinnedFileOperations]::InspectExact(
        [System.IO.Path]::GetFullPath($SillyTavernPidFile), $stPidSnapshot.Bytes,
        $stPidSnapshot.ParentToken, $stPidSnapshot.FileToken)
    [void][StMobile.PinnedFileOperations]::InspectExact(
        [System.IO.Path]::GetFullPath($SillyTavernProcessRecord), $stRecordSnapshot.Bytes,
        $stRecordSnapshot.ParentToken, $stRecordSnapshot.FileToken)
    Assert-StMobilePinnedProcessIdentity $stProcess $session.ProcessStartTimeUtc 'SillyTavern'
    [StMobile.PinnedFileOperations]::TerminatePinnedProcess($stProcess, 1)
    $stProcess.WaitForExit(10000) | Out-Null
    if (-not $stProcess.HasExited) {
        throw "SillyTavern PID $pidValue remained alive after pinned-handle termination; preserving ownership files."
    }
    if (-not (Test-BytesEqual $stPidBytesBeforeStop ([System.IO.File]::ReadAllBytes($SillyTavernPidFile))) `
            -or -not (Test-BytesEqual $stRecordBytesBeforeStop ([System.IO.File]::ReadAllBytes($SillyTavernProcessRecord)))) {
        throw 'SillyTavern ownership files changed during stop; preserving them and refusing cleanup.'
    }
    Remove-StMobileFileSetIfUnchanged -OwnershipName 'stopped SillyTavern ownership set' -Entries @(
        [pscustomobject]@{ Path = $SillyTavernPidFile; Bytes = $stPidBytesBeforeStop; ParentToken = $stPidSnapshot.ParentToken; FileToken = $stPidSnapshot.FileToken },
        [pscustomobject]@{ Path = $SillyTavernProcessRecord; Bytes = $stRecordBytesBeforeStop; ParentToken = $stRecordSnapshot.ParentToken; FileToken = $stRecordSnapshot.FileToken })
    Write-Host "Stopped verified SillyTavern PID $pidValue."
}

Stop-VerifiedGateway
if ($StopSillyTavern) {
    Stop-VerifiedSillyTavern
}
