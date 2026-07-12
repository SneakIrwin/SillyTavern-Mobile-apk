param(
    [int]$Port = 38443,
    [int]$HubPort = 38444,
    [string]$SillyTavernRoot = 'C:\Users\Sneak\SillyTavern-Launcher\SillyTavern-Launcher\SillyTavern',
    [string]$LauncherIconPath = 'C:\Users\Sneak\SillyTavern-Launcher\SillyTavern-Launcher\st-launcher.ico'
)

$ErrorActionPreference = 'Stop'
try {
    [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
} catch {}

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$StartScript = Join-Path $PSScriptRoot 'Start-StMobile.ps1'
$LaunchTrayScript = Join-Path $PSScriptRoot 'Launch-StMobileTray.ps1'
$LogRoot = Join-Path $ProjectRoot 'logs'
$LogPath = Join-Path $LogRoot 'one-click-hub.log'
$HubUrl = "http://127.0.0.1:$HubPort/"
New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null

function Write-OneClickLog([string]$Message) {
    Add-Content -LiteralPath $LogPath -Encoding UTF8 -Value ('{0} {1}' -f ([DateTime]::UtcNow.ToString('o'), $Message))
}

function Test-AuthHubReady {
    try {
        $request = [System.Net.HttpWebRequest]::Create("${HubUrl}api/devices")
        $request.Method = 'GET'
        $request.Proxy = $null
        $request.Timeout = 1000
        $request.ReadWriteTimeout = 1000
        $response = $request.GetResponse()
        try {
            if ([int]$response.StatusCode -ne 200 -or $response.Headers['X-ST-Mobile-Hub'] -ne '1') {
                return $false
            }
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            try {
                $body = $reader.ReadToEnd() | ConvertFrom-Json
                return $body.service -ceq 'sillytavern-mobile-auth-hub' -and [int]$body.schemaVersion -eq 1
            } finally {
                $reader.Dispose()
            }
        } finally {
            $response.Dispose()
        }
    } catch {
        return $false
    }
}

try {
    if (-not (Test-AuthHubReady)) {
        Write-OneClickLog 'STACK_START requested=true'
        & $StartScript -Port $Port -HubPort $HubPort -SillyTavernRoot $SillyTavernRoot | Out-Null
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-AuthHubReady) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-AuthHubReady)) {
        throw "Authentication hub did not become ready at $HubUrl. See $LogPath."
    }

    # The hub and tray have independent lifetimes. Always ensure the tray even
    # when a pre-existing gateway made the hub readiness check succeed.
    & $LaunchTrayScript -HubPort $HubPort -SillyTavernPort 3000 -SillyTavernRoot $SillyTavernRoot -LauncherIconPath $LauncherIconPath | Out-Null
    Write-OneClickLog 'TRAY_ENSURED hidden=true no_focus=true priority=Idle'

    Write-OneClickLog "HUB_OPEN url=$HubUrl intentional_user_facing=true"
    Start-Process $HubUrl
} catch {
    Write-OneClickLog "FAILED error=$($_.Exception.Message)"
    Add-Type -AssemblyName System.Windows.Forms
    [void][System.Windows.Forms.MessageBox]::Show(
        $_.Exception.Message,
        'SillyTavern Mobile Auth Hub',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}
