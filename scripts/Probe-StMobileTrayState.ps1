param(
    [Parameter(Mandatory = $true)][int]$HubPort,
    [Parameter(Mandatory = $true)][int]$SillyTavernPort,
    [Parameter(Mandatory = $true)][string]$SillyTavernRoot,
    [Parameter(Mandatory = $true)][string]$SillyTavernProcessRecord,
    [Parameter(Mandatory = $true)][string]$ResultPath,
    [Parameter(Mandatory = $true)][string]$ProbeId
)

$ErrorActionPreference = 'Stop'
[System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
. (Join-Path $PSScriptRoot 'StMobileTrayCommon.ps1')

function Test-ProbeTcpListener([int]$Port) {
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

function Test-ProbeHubReady {
    if (-not (Test-ProbeTcpListener $HubPort)) {
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

$session = $null
$errorText = ''
try {
    $session = Get-SillyTavernSession `
        -Port $SillyTavernPort `
        -SillyTavernRoot $SillyTavernRoot `
        -RecordPath $SillyTavernProcessRecord
} catch {
    $errorText = $_.Exception.Message
}

$result = [ordered]@{
    schema = 'st-mobile-tray-probe/v1'
    probeId = $ProbeId
    completedAtUtc = [DateTime]::UtcNow.ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
        [System.Globalization.CultureInfo]::InvariantCulture)
    hubReady = [bool](Test-ProbeHubReady)
    listenerReady = [bool]$session
    session = $session
    error = $errorText
}
$resultDirectory = Split-Path -Parent $ResultPath
New-Item -ItemType Directory -Force -Path $resultDirectory | Out-Null
$resultBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(
    ($result | ConvertTo-Json -Depth 6) + [Environment]::NewLine)
Write-StMobileBytesCreateNew $ResultPath $resultBytes
