param(
    [int]$Port = 38443,
    [string]$RuleName = 'SillyTavern Secure Mobile Gateway',
    [ValidateSet('Public', 'Private')]
    [string]$Profile = 'Public'
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must run elevated because Windows Firewall rule changes require administrator rights.'
}

$existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
if ($existing) {
    $existing | Remove-NetFirewallRule
}

New-NetFirewallRule `
    -DisplayName $RuleName `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort $Port `
    -Profile $Profile `
    -RemoteAddress LocalSubnet `
    -Description "Allows paired Android clients on the local subnet to reach only the authenticated HTTPS SillyTavern mobile gateway. Does not expose SillyTavern port 3000." |
    Out-Null

$rule = Get-NetFirewallRule -DisplayName $RuleName
$portFilter = $rule | Get-NetFirewallPortFilter
$addressFilter = $rule | Get-NetFirewallAddressFilter

[pscustomobject]@{
    RuleName = $rule.DisplayName
    Enabled = $rule.Enabled
    Profile = $rule.Profile
    Direction = $rule.Direction
    Action = $rule.Action
    Protocol = $portFilter.Protocol
    LocalPort = $portFilter.LocalPort
    RemoteAddress = $addressFilter.RemoteAddress
}
