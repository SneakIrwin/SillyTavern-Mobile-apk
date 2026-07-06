param(
    [switch]$StopSillyTavern
)

$ErrorActionPreference = 'Stop'

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$StateRoot = Join-Path $ProjectRoot 'state'
$GatewayPidFile = Join-Path $StateRoot 'gateway.pid'
$HubUrlFile = Join-Path $StateRoot 'auth-hub.url'
$SillyTavernPidFile = Join-Path $StateRoot 'sillytavern.pid'

function Stop-FromPidFile([string]$PidFile, [string]$Name) {
    if (-not (Test-Path $PidFile)) {
        Write-Host "$Name PID file not found."
        return
    }
    $pidText = (Get-Content -LiteralPath $PidFile -Raw).Trim()
    if (-not $pidText) {
        return
    }
    $process = Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
    if ($process) {
        Stop-Process -Id $process.Id
        Write-Host "Stopped $Name PID $($process.Id)."
    }
    Remove-Item -LiteralPath $PidFile -Force
}

Stop-FromPidFile $GatewayPidFile 'ST Mobile Gateway'
Remove-Item -LiteralPath $HubUrlFile -Force -ErrorAction SilentlyContinue
if ($StopSillyTavern) {
    Stop-FromPidFile $SillyTavernPidFile 'SillyTavern'
}
