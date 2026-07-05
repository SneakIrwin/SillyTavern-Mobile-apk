param(
    [string]$LogPath = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')) 'logs\disable-adb-firewall.log')
)

$ErrorActionPreference = 'Stop'

try {
    [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
} catch {
    Write-Warning "Could not set Idle priority for Disable-AdbFirewallRules.ps1: $($_.Exception.Message)"
}

$logDir = Split-Path -Parent $LogPath
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

"=== disable adb.exe inbound firewall rules ===" | Set-Content -LiteralPath $LogPath
(Get-Date -Format o) | Add-Content -LiteralPath $LogPath

$rules = @(Get-NetFirewallRule -DisplayName 'adb.exe' -ErrorAction SilentlyContinue)
if ($rules.Count -eq 0) {
    "No adb.exe firewall rules found." | Add-Content -LiteralPath $LogPath
} else {
    "Disabling $($rules.Count) adb.exe rule(s)." | Add-Content -LiteralPath $LogPath
    $rules | Disable-NetFirewallRule
}

"=== readback ===" | Add-Content -LiteralPath $LogPath
Get-NetFirewallRule -DisplayName 'adb.exe' -ErrorAction SilentlyContinue |
    ForEach-Object {
        $app = $_ | Get-NetFirewallApplicationFilter
        $port = $_ | Get-NetFirewallPortFilter
        $addr = $_ | Get-NetFirewallAddressFilter
        [pscustomobject]@{
            Name = $_.Name
            Enabled = $_.Enabled
            Direction = $_.Direction
            Action = $_.Action
            Profile = $_.Profile
            Program = $app.Program
            Protocol = $port.Protocol
            LocalPort = $port.LocalPort
            RemoteAddress = $addr.RemoteAddress
        }
    } |
    ConvertTo-Json -Depth 5 |
    Add-Content -LiteralPath $LogPath

"=== done ===" | Add-Content -LiteralPath $LogPath
