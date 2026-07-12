param(
    [switch]$DisableStartup,
    [switch]$StopGateway
)

$ErrorActionPreference = 'Stop'
$currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
$currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$CommonScript = Join-Path $PSScriptRoot 'StMobileTrayCommon.ps1'
. $CommonScript
$StateRoot = Join-Path $ProjectRoot 'state'
$TrayProcessRecord = Join-Path $StateRoot 'tray-process.json'
$TrayStopFile = Join-Path $StateRoot 'tray.stop.request'
$TrayScript = Join-Path $PSScriptRoot 'Start-StMobileTray.ps1'
$GatewayStopScript = Join-Path $PSScriptRoot 'Stop-StMobile.ps1'
$PowerShellExe = Get-StMobileWindowsPowerShellExecutable

function Get-VerifiedTrayProcess {
    $recordSnapshot = if (Test-Path -LiteralPath $TrayProcessRecord) {
        [StMobile.PinnedFileOperations]::ReadSnapshot([System.IO.Path]::GetFullPath($TrayProcessRecord), '')
    } else {
        $null
    }
    $ownership = Get-StMobileTrayOwnershipState `
        -RecordPath $TrayProcessRecord `
        -RecordSnapshot $recordSnapshot `
        -PowerShellExe $PowerShellExe `
        -TrayScriptPath $TrayScript
    if ($ownership.State -eq 'Conflict') {
        throw $ownership.Error
    }
    if ($ownership.State -ne 'OwnedLive') {
        if ($recordSnapshot) {
            Remove-StMobileFileIfUnchanged `
                $TrayProcessRecord `
                $recordSnapshot.Bytes `
                'stale tray ownership record' `
                $recordSnapshot.ParentToken `
                $recordSnapshot.FileToken
        }
        return $null
    }
    return [pscustomobject]@{
        Process = $ownership.Verified.Process
        Record = $ownership.Verified.Record
        RecordSnapshot = $recordSnapshot
    }
}

$verifiedTray = Get-VerifiedTrayProcess
if ($verifiedTray) {
    $tray = $verifiedTray.Process
    $trayRecordBytesBeforeStop = $verifiedTray.RecordSnapshot.Bytes
    [void][StMobile.PinnedFileOperations]::InspectExact(
        [System.IO.Path]::GetFullPath($TrayProcessRecord),
        $verifiedTray.RecordSnapshot.Bytes,
        $verifiedTray.RecordSnapshot.ParentToken,
        $verifiedTray.RecordSnapshot.FileToken)
    $stopRequestNonce = [guid]::NewGuid().ToString('D')
    $stopRequestBytes = New-StMobileTrayStopRequestBytes `
        -TrayRecord $verifiedTray.Record `
        -Nonce $stopRequestNonce
    Assert-StMobileNonReparsePath $TrayStopFile 'tray stop request'
    $stopRequestIdentity = Write-StMobileBytesCreateNew $TrayStopFile $stopRequestBytes -PassThru
    $publishedStopRequest = Get-StMobileOwnedTrayStopRequest `
        -Path $TrayStopFile `
        -TrayRecord $verifiedTray.Record
    if (-not (Test-BytesEqual $publishedStopRequest.Bytes $stopRequestBytes)) {
        throw 'Tray stop request changed during create-new readback; preserving it and refusing termination.'
    }
    if ([string]$publishedStopRequest.ParentToken -cne [string]$stopRequestIdentity.ParentToken `
            -or [string]$publishedStopRequest.FileToken -cne [string]$stopRequestIdentity.FileToken) {
        throw 'Tray stop request generation changed during create-new readback; preserving it and refusing termination.'
    }
    $stopRequestCleaned = $false
    $tray.WaitForExit(10000) | Out-Null
    if (-not $tray.HasExited) {
        try {
            $stillOwnedRequest = Get-StMobileOwnedTrayStopRequest `
                -Path $TrayStopFile `
                -TrayRecord $verifiedTray.Record
        } catch {
            throw "Tray stop request was removed, modified, or redirected before acceptance; preserving it and refusing forced termination: $($_.Exception.Message)"
        }
        if (-not $stillOwnedRequest `
                -or -not (Test-BytesEqual $stillOwnedRequest.Bytes $stopRequestBytes)) {
            throw 'Tray stop request no longer matches the exact request published for this tray instance; refusing forced termination.'
        }
        Remove-StMobileFileIfUnchanged `
            $TrayStopFile `
            $stopRequestBytes `
            'timed-out exact tray stop request' `
            $stopRequestIdentity.ParentToken `
            $stopRequestIdentity.FileToken
        $stopRequestCleaned = $true
        [void][StMobile.PinnedFileOperations]::InspectExact(
            [System.IO.Path]::GetFullPath($TrayProcessRecord),
            $verifiedTray.RecordSnapshot.Bytes,
            $verifiedTray.RecordSnapshot.ParentToken,
            $verifiedTray.RecordSnapshot.FileToken)
        Assert-StMobilePinnedProcessIdentity $tray $verifiedTray.Record.processStartTimeUtc 'Tray'
        [StMobile.PinnedFileOperations]::TerminatePinnedProcess($tray, 1)
        $tray.WaitForExit(10000) | Out-Null
        if (-not $tray.HasExited) {
            throw "Tray PID $($tray.Id) remained alive after pinned-handle termination; preserving its ownership record."
        }
    }
    if (Test-Path -LiteralPath $TrayProcessRecord) {
        $trayRecordBytesAfterStop = [System.IO.File]::ReadAllBytes($TrayProcessRecord)
        if (-not (Test-BytesEqual $trayRecordBytesBeforeStop $trayRecordBytesAfterStop)) {
            throw 'Tray ownership record changed during stop; preserving it and refusing cleanup.'
        }
        Remove-StMobileFileIfUnchanged `
            $TrayProcessRecord `
            $trayRecordBytesBeforeStop `
            'stopped tray ownership record' `
            $verifiedTray.RecordSnapshot.ParentToken `
            $verifiedTray.RecordSnapshot.FileToken
    }
    if (-not $stopRequestCleaned -and (Test-Path -LiteralPath $TrayStopFile)) {
        $remainingStopRequest = Get-StMobileOwnedTrayStopRequest `
            -Path $TrayStopFile `
            -TrayRecord $verifiedTray.Record
        if (-not (Test-BytesEqual $remainingStopRequest.Bytes $stopRequestBytes)) {
            throw 'Tray stop request changed before cleanup; preserving it.'
        }
        Remove-StMobileFileIfUnchanged `
            $TrayStopFile `
            $stopRequestBytes `
            'completed tray stop request' `
            $stopRequestIdentity.ParentToken `
            $stopRequestIdentity.FileToken
        $stopRequestCleaned = $true
    }
}

if ($DisableStartup) {
    & $PowerShellExe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File $TrayScript -Mode DisableStartup | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Disabling tray startup failed with exit code $LASTEXITCODE"
    }
}
if ($StopGateway) {
    & $PowerShellExe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File $GatewayStopScript | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Stopping the mobile gateway failed with exit code $LASTEXITCODE"
    }
}

[pscustomobject]@{
    trayStopped = -not [bool](Get-VerifiedTrayProcess)
    startupDisabled = [bool]$DisableStartup
    gatewayStopRequested = [bool]$StopGateway
} | ConvertTo-Json -Compress
