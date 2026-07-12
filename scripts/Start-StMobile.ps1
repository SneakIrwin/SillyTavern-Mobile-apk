param(
    [int]$Port = 38443,
    [int]$HubPort = 38444,
    [string]$SillyTavernRoot = 'C:\Users\Sneak\SillyTavern-Launcher\SillyTavern-Launcher\SillyTavern',
    [switch]$NoStartSillyTavern
)

$ErrorActionPreference = 'Stop'

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$GatewayRoot = Join-Path $ProjectRoot 'gateway'
$GatewayCli = Join-Path $GatewayRoot 'src\cli.js'
$CommonScript = Join-Path $PSScriptRoot 'StMobileTrayCommon.ps1'
. $CommonScript
$LogRoot = Join-Path $ProjectRoot 'logs'
$StateRoot = Join-Path $ProjectRoot 'state'
$CertRoot = Join-Path $StateRoot 'certs'
$GatewayPidFile = Join-Path $StateRoot 'gateway.pid'
$GatewayProcessRecord = Join-Path $StateRoot 'gateway-process.json'
$HubUrlFile = Join-Path $StateRoot 'auth-hub.url'
$SillyTavernPidFile = Join-Path $StateRoot 'sillytavern.pid'
$SillyTavernProcessRecord = Join-Path $StateRoot 'sillytavern-process.json'
$ProtectCertAcls = Join-Path $ProjectRoot 'scripts\Protect-CertAcls.ps1'
$FirewallRuleName = 'SillyTavern Secure Mobile Gateway'

New-Item -ItemType Directory -Force -Path $LogRoot, $StateRoot, $CertRoot | Out-Null

function Get-NodePath {
    $node = Get-Command node.exe -ErrorAction SilentlyContinue
    if (-not $node) {
        throw 'node.exe was not found on PATH.'
    }
    return $node.Source
}

function Set-IdlePriority([System.Diagnostics.Process]$Process, [string]$Name) {
    try {
        $Process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
    } catch {
        Write-Warning "Could not set Idle priority for $Name PID $($Process.Id): $($_.Exception.Message)"
    }
}

function Get-DefaultPrivateIPv4 {
    function Get-AdapterScore($Address) {
        $alias = (Get-NetAdapter -InterfaceIndex $Address.InterfaceIndex -ErrorAction SilentlyContinue).Name
        $score = 0
        if ($alias -match '^(Wi-?Fi|WLAN|Ethernet|Local Area Connection)$') { $score += 100 }
        if ($Address.IPAddress -match '^192\.168\.') { $score += 30 }
        elseif ($Address.IPAddress -match '^10\.') { $score += 20 }
        if ($alias -match '(Hyper-V|vEthernet|WSL|Docker|VirtualBox|VMware|Bluetooth|VPN|TAP|TUN|Tailscale|ZeroTier)') { $score -= 200 }
        return $score
    }

    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1
    $routeAddress = $null
    if ($route) {
        $routeAddress = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -match '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)' } |
            Select-Object -First 1
    }

    $candidates = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -match '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)' } |
        Sort-Object @{ Expression = {
            $score = Get-AdapterScore $_
            if ($routeAddress -and $_.IPAddress -eq $routeAddress.IPAddress) {
                $routeAlias = (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).Name
                if ($routeAlias -match '(Hyper-V|vEthernet|WSL|Docker|VirtualBox|VMware|Bluetooth|VPN|TAP|TUN|Tailscale|ZeroTier)') { $score += 40 }
                else { $score += 1000 }
            }
            -1 * $score
        } }, IPAddress)
    $candidate = $candidates | Select-Object -First 1
    if (-not $candidate) {
        throw 'No private LAN IPv4 address found for mobile pairing.'
    }
    return $candidate.IPAddress
}

function Get-NetshFirewallRules([string]$RuleName) {
    $output = & netsh advfirewall firewall show rule name="$RuleName" verbose
    if ($LASTEXITCODE -ne 0) {
        throw "netsh failed while reading firewall rule '$RuleName'"
    }
    $rules = New-Object System.Collections.Generic.List[object]
    $current = $null
    foreach ($line in $output) {
        if ($line -match '^Rule Name:\s*(.+?)\s*$') {
            $current = [ordered]@{ DisplayName = $matches[1].Trim() }
            $rules.Add($current)
            continue
        }
        if ($null -eq $current) {
            continue
        }
        if ($line -match '^([A-Za-z ]+):\s*(.*?)\s*$') {
            $key = ($matches[1].Trim() -replace '\s+', '')
            $current[$key] = $matches[2].Trim()
        }
    }
    foreach ($rule in $rules) {
        [pscustomobject]$rule
    }
}

function Test-FirewallLocalPortIncludes([object]$LocalPort, [int]$ExpectedPort) {
    $text = ([string]$LocalPort).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $false
    }
    if ($text -eq 'Any') {
        return $true
    }

    $normalized = $text -replace '\s*-\s*', '-'
    foreach ($part in ($normalized -split '[,\s]+')) {
        if ([string]::IsNullOrWhiteSpace($part)) {
            continue
        }
        if ($part -match '^\d+$') {
            if ([int]$part -eq $ExpectedPort) {
                return $true
            }
            continue
        }
        if ($part -match '^(\d+)-(\d+)$') {
            $start = [int]$matches[1]
            $end = [int]$matches[2]
            if ($start -gt $end) {
                $tmp = $start
                $start = $end
                $end = $tmp
            }
            if ($ExpectedPort -ge $start -and $ExpectedPort -le $end) {
                return $true
            }
        }
    }
    return $false
}

function Test-FirewallLocalPortExplicitlyIncludes([object]$LocalPort, [int]$ExpectedPort) {
    $text = ([string]$LocalPort).Trim()
    return $text -ne 'Any' -and (Test-FirewallLocalPortIncludes $LocalPort $ExpectedPort)
}

function Test-FirewallLocalPortExactly([object]$LocalPort, [int]$ExpectedPort) {
    return ([string]$LocalPort).Trim() -eq [string]$ExpectedPort
}

function Test-FirewallProgramAppliesToGateway([object]$Program, [string]$NodePath) {
    $text = ([string]$Program).Trim()
    return [string]::IsNullOrWhiteSpace($text) -or $text -eq 'Any' -or $text.ToLowerInvariant() -eq $NodePath.ToLowerInvariant()
}

function Test-FirewallNamedProgramAppliesToGateway([object]$Program, [string]$NodePath) {
    $text = ([string]$Program).Trim()
    return [string]::IsNullOrWhiteSpace($text) -or $text -eq 'Any' -or $text.ToLowerInvariant() -eq $NodePath.ToLowerInvariant()
}

function Test-FirewallProfilesExactly([object]$Profiles, [string]$ExpectedProfile) {
    $parts = @(([string]$Profiles).Split(',') | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    return $parts.Count -eq 1 -and $parts[0] -eq $ExpectedProfile
}

function Test-FirewallRuleHasExactGatewayScope([object]$Candidate, [int]$ExpectedPort) {
    return $Candidate.Protocol -eq 'TCP' -and
        (Test-FirewallLocalPortExactly $Candidate.LocalPort $ExpectedPort) -and
        [string]$Candidate.RemoteIP -eq 'LocalSubnet'
}

function Test-FirewallRuleShadowsGatewayScope([object]$Candidate, [int]$ExpectedPort, [string]$NodePath) {
    return $Candidate.Enabled -eq 'Yes' -and
        $Candidate.Direction -eq 'In' -and
        $Candidate.Action -eq 'Allow' -and
        $Candidate.Protocol -in @('Any', 'TCP') -and
        (Test-FirewallLocalPortIncludes $Candidate.LocalPort $ExpectedPort) -and
        (Test-FirewallProgramAppliesToGateway $Candidate.Program $NodePath) -and
        -not (Test-FirewallRuleHasExactGatewayScope $Candidate $ExpectedPort)
}

function Test-ActiveNamedGatewayRulesExactly([object[]]$Rules, [int]$ExpectedPort, [string]$ExpectedProfile, [string]$NodePath) {
    $activeNamedRules = @($Rules | Where-Object {
        $_.Enabled -eq 'Yes' -and
        (([string]$_.Profiles).Split(',') | ForEach-Object { $_.Trim() }) -contains $ExpectedProfile
    })
    $exactNamedRules = @($activeNamedRules | Where-Object {
        $_.Direction -eq 'In' -and
        $_.Action -eq 'Allow' -and
        $_.Protocol -eq 'TCP' -and
        [string]$_.LocalPort -eq [string]$ExpectedPort -and
        [string]$_.RemoteIP -eq 'LocalSubnet' -and
        (Test-FirewallProfilesExactly $_.Profiles $ExpectedProfile) -and
        (Test-FirewallNamedProgramAppliesToGateway $_.Program $NodePath)
    })
    return $activeNamedRules.Count -eq 1 -and $exactNamedRules.Count -eq 1
}

function Test-WindowsFirewallProfileEnabled([object]$Enabled) {
    if ($Enabled -is [bool]) {
        return $Enabled
    }
    $text = ([string]$Enabled).Trim().ToLowerInvariant()
    return $text -in @('true', '1', 'yes')
}

function Test-WindowsFirewallDefaultInboundBlocked([object]$DefaultInboundAction) {
    $text = ([string]$DefaultInboundAction).Trim().ToLowerInvariant()
    return $text -in @('block', '0')
}

function Assert-ActiveFirewallProfileClosed([object]$FirewallProfile, [object]$ConnectionProfile) {
    $category = $ConnectionProfile.NetworkCategory.ToString()
    $alias = $ConnectionProfile.InterfaceAlias
    if (-not $FirewallProfile) {
        throw "Windows Firewall profile '$category' was not found for active interface '$alias'."
    }
    if (-not (Test-WindowsFirewallProfileEnabled $FirewallProfile.Enabled)) {
        throw "Windows Firewall is disabled for active $category profile on interface '$alias'."
    }
    if (-not (Test-WindowsFirewallDefaultInboundBlocked $FirewallProfile.DefaultInboundAction)) {
        throw "Windows Firewall default inbound action is $($FirewallProfile.DefaultInboundAction), not Block, for active $category profile on interface '$alias'."
    }
}

function Assert-PublicHostNetworkReady {
    $ip = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $PublicHost -ErrorAction Stop | Select-Object -First 1
    $profile = Get-NetConnectionProfile -InterfaceIndex $ip.InterfaceIndex -ErrorAction Stop | Select-Object -First 1
    $firewallProfile = Get-NetFirewallProfile -Profile $profile.NetworkCategory -PolicyStore ActiveStore -ErrorAction Stop | Select-Object -First 1
    Assert-ActiveFirewallProfileClosed $firewallProfile $profile
    $nodePath = (Get-NodePath).ToLowerInvariant()

    $namedRules = @(Get-NetshFirewallRules $FirewallRuleName | Where-Object { $_.DisplayName -eq $FirewallRuleName })
    if (-not $namedRules) {
        throw "Firewall rule '$FirewallRuleName' is missing. Run scripts\Configure-Firewall.ps1 elevated before advertising the gateway."
    }
    if (-not (Test-ActiveNamedGatewayRulesExactly $namedRules $Port $profile.NetworkCategory.ToString() $nodePath)) {
        throw "Exactly one active firewall rule '$FirewallRuleName' must allow only Program Any or gateway executable '$nodePath', TCP $Port from LocalSubnet for the active $($profile.NetworkCategory) profile."
    }

    $broadRules = foreach ($candidate in (Get-NetshFirewallRules 'all')) {
        $candidateProfiles = $candidate.Profiles.ToString().Split(',') | ForEach-Object { $_.Trim() }
        $profileMatches = $candidateProfiles -contains 'Any' -or $candidateProfiles -contains $profile.NetworkCategory.ToString()
        if (-not $profileMatches) {
            continue
        }
        if (Test-FirewallRuleShadowsGatewayScope $candidate $Port $nodePath) {
            [pscustomobject]@{
                DisplayName = $candidate.DisplayName
                Profiles = $candidate.Profiles
                Program = $candidate.Program
                Protocol = $candidate.Protocol
                LocalPort = $candidate.LocalPort
                RemoteAddress = $candidate.RemoteIP
            }
        }
    }
    if ($broadRules) {
        $summary = ($broadRules | ForEach-Object { "$($_.DisplayName) Program=$($_.Program) Port=$($_.LocalPort) Remote=$($_.RemoteAddress)" }) -join '; '
        throw "Broad inbound firewall allow rule(s) shadow the gateway scope: $summary"
    }
}

function Start-HiddenIdleProcess([string]$FilePath, [string[]]$ArgumentList, [string]$WorkingDirectory, [string]$Name, [string]$OutLog, [string]$ErrLog) {
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $ArgumentList `
        -WorkingDirectory $WorkingDirectory `
        -WindowStyle Hidden `
        -RedirectStandardOutput $OutLog `
        -RedirectStandardError $ErrLog `
        -PassThru
    try {
        [void][StMobile.PinnedFileOperations]::PinProcess($process)
        $startIdentity = Get-StMobileProcessStartIdentity $process
        if ([string]::IsNullOrWhiteSpace($startIdentity)) {
            throw 'The canonical process start identity was empty.'
        }
        Set-IdlePriority $process $Name
        return [pscustomobject]@{
            Process = $process
            ExpectedStartIdentity = $startIdentity
        }
    } catch {
        $initializationFailure = $_.Exception.Message
        try { [System.IO.File]::AppendAllText($ErrLog, "$Name post-start initialization failed: $initializationFailure$([Environment]::NewLine)") } catch {}
        $cleanupFailure = $null
        try {
            $process.Refresh()
            if (-not $process.HasExited) {
                [void][StMobile.PinnedFileOperations]::PinProcess($process)
                [StMobile.PinnedFileOperations]::TerminatePinnedProcess($process, 1)
                $process.WaitForExit(10000) | Out-Null
            }
            if (-not $process.HasExited) {
                throw "$Name PID $($process.Id) remained alive after exact post-start cleanup."
            }
        } catch {
            $cleanupFailure = $_.Exception.Message
        }
        if ($cleanupFailure) {
            throw "$Name launch initialization failed after Process.Start for PID $($process.Id): $initializationFailure Exact-handle cleanup blocked: $cleanupFailure The process may still be live and no ownership record was published."
        }
        throw "$Name launch initialization failed after Process.Start for PID $($process.Id), and the exact child was terminated or had already exited: $initializationFailure"
    }
}

function Stop-JustLaunchedProcessAndConfirm {
    param(
        [System.Diagnostics.Process]$Process,
        [string]$ExpectedStartIdentity,
        [string]$Name
    )
    $Process.Refresh()
    if ($Process.HasExited) {
        return
    }
    Assert-StMobilePinnedProcessIdentity `
        -Process $Process `
        -ExpectedProcessStartTimeUtc $ExpectedStartIdentity `
        -OwnershipName $Name
    [StMobile.PinnedFileOperations]::TerminatePinnedProcess($Process, 1)
    $Process.WaitForExit(10000) | Out-Null
    if (-not $Process.HasExited) {
        throw "$Name PID $($Process.Id) remained alive after exact just-launched forced termination."
    }
}

function Test-LoopbackSillyTavern {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort 3000 -ErrorAction SilentlyContinue
    return [bool]($listeners | Where-Object { $_.LocalAddress -in @('127.0.0.1', '::1') })
}

function Assert-SillyTavernPortSafe {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort 3000 -ErrorAction SilentlyContinue
    foreach ($listener in $listeners) {
        if ($listener.LocalAddress -notin @('127.0.0.1', '::1')) {
            throw "Unsafe SillyTavern listener on $($listener.LocalAddress):3000 owned by PID $($listener.OwningProcess). Refusing to start or advertise mobile gateway."
        }
    }
}

function Assert-SillyTavernIdentity {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort 3000 -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -in @('127.0.0.1', '::1') }
    if (-not $listeners) {
        throw 'No loopback SillyTavern listener found on port 3000. Refusing to expose mobile gateway.'
    }

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:3000/' -TimeoutSec 5
    } catch {
        throw "Could not probe loopback SillyTavern identity on port 3000: $($_.Exception.Message)"
    }

    $content = [string]$response.Content
    $anchors = @(
        '<title>\s*SillyTavern\s*</title>',
        'href=["'']manifest\.json["'']',
        'href=["'']css/st-tailwind\.css["'']',
        'id=["'']top-settings-holder["'']',
        'id=["'']ai-config-button["'']'
    )
    $missingAnchor = $anchors | Where-Object { $content -notmatch $_ } | Select-Object -First 1
    if ($response.StatusCode -ne 200 -or $missingAnchor) {
        $owners = ($listeners | Select-Object -ExpandProperty OwningProcess -Unique) -join ','
        throw "Loopback port 3000 did not return the expected SillyTavern page fingerprint. Missing anchor: $missingAnchor. Owning PID(s): $owners. Refusing to expose mobile gateway."
    }

    $ownerProcesses = foreach ($ownerPid in ($listeners | Select-Object -ExpandProperty OwningProcess -Unique)) {
        Get-CimInstance Win32_Process -Filter "ProcessId=$ownerPid" -ErrorAction SilentlyContinue
    }
    if (-not ($ownerProcesses | Where-Object { $_.CommandLine -match '(^|[\\\s])server\.js(\s|$)' })) {
        $commands = ($ownerProcesses | ForEach-Object { "PID $($_.ProcessId): $($_.CommandLine)" }) -join '; '
        throw "Loopback port 3000 fingerprinted as SillyTavern HTML but no owning process looked like the expected server.js process. $commands"
    }
    $trustedSession = Get-SillyTavernSession `
        -Port 3000 `
        -SillyTavernRoot $SillyTavernRoot `
        -RecordPath $SillyTavernProcessRecord `
        -ThrowOnInvalid
    if (-not $trustedSession) {
        throw "Loopback SillyTavern has no exact trusted launcher record at $SillyTavernProcessRecord. Start it through ST Launcher option 1 before exposing the mobile gateway."
    }
}

function Get-GatewayListener {
    Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Assert-GatewayListenerExpected {
    $listener = Get-GatewayListener
    if (-not $listener) {
        return $false
    }

    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)" -ErrorAction SilentlyContinue
    if (-not $process -or [string]::IsNullOrWhiteSpace([string]$process.CommandLine)) {
        throw "Gateway port $Port listener PID $($listener.OwningProcess) vanished or has no readable command line; refusing to trust it."
    }
    $commandLine = $process.CommandLine
    $expectedCli = (Resolve-Path $GatewayCli).Path
    $normalizedExpectedCli = $expectedCli.Replace('/', '\')
    $normalizedCommandLine = $commandLine.Replace('/', '\')
    $hasExpectedCli = $commandLine.Contains($expectedCli) -or $normalizedCommandLine.Contains($normalizedExpectedCli)
    if (-not $commandLine -or -not $hasExpectedCli -or -not $commandLine.Contains('serve') -or -not $commandLine.Contains("$Port")) {
        throw "Gateway port $Port occupied by unexpected process PID $($listener.OwningProcess): $commandLine"
    }
    foreach ($forbiddenArg in @('--target', '--listen-host', '--state-dir', '--host')) {
        if ($forbiddenArg -eq '--host') {
            continue
        }
        if ($commandLine -match "(^|\s)$([regex]::Escape($forbiddenArg))(\s|=|$)") {
            throw "Gateway port $Port is running with forbidden argument $forbiddenArg in PID $($listener.OwningProcess): $commandLine"
        }
    }
    $hostMatches = [regex]::Matches($commandLine, "(^|\s)--host(?:\s+|=)(`"[^`"]+`"|'[^']+'|\S+)")
    if ($hostMatches.Count -ne 1) {
        throw "Gateway port $Port must have exactly one --host argument in PID $($listener.OwningProcess): $commandLine"
    }
    $actualHost = $hostMatches[0].Groups[2].Value.Trim('"', "'")
    if ($actualHost -ne $PublicHost) {
        throw "Gateway port $Port is pinned to $actualHost instead of expected public host $PublicHost in PID $($listener.OwningProcess): $commandLine"
    }
    if ($commandLine -notmatch "(^|\s)--hub-port(?:\s+|=)$HubPort(\s|$)") {
        throw "Gateway port $Port listener PID $($listener.OwningProcess) is not running the auth hub on expected loopback port $HubPort."
    }
    if ($commandLine -match "(^|\s)--no-hub(\s|$)") {
        throw "Gateway port $Port listener PID $($listener.OwningProcess) explicitly disabled the auth hub."
    }
    if (Test-Path $GatewayPidFile) {
        $listenerPidSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot(
            [System.IO.Path]::GetFullPath($GatewayPidFile), '')
        $expectedPid = Read-StMobileCanonicalPositivePidBytes $listenerPidSnapshot.Bytes 'Gateway'
        if ($expectedPid -ne [int]$listener.OwningProcess) {
            throw "Gateway port $Port is owned by PID $($listener.OwningProcess), but gateway pid file names $expectedPid. Refusing to reuse ambiguous listener."
        }
    } else {
        throw "Gateway port $Port is already listening but $GatewayPidFile is missing. Refusing to reuse listener without launcher provenance."
    }
    $listenerRecordSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot(
        [System.IO.Path]::GetFullPath($GatewayProcessRecord), '')
    $gatewayOwnership = Get-StMobileGatewayOwnershipState `
        -RecordPath $GatewayProcessRecord `
        -RecordSnapshot $listenerRecordSnapshot `
        -NodeExe $node `
        -GatewayCli $GatewayCli `
        -PublicHost $PublicHost `
        -Port $Port `
        -HubPort $HubPort `
        -RequireListeners
    if ($gatewayOwnership.State -ne 'OwnedLive' `
            -or $gatewayOwnership.Verified.Process.Id -ne [int]$listener.OwningProcess) {
        throw "Gateway port $Port listener lacks an exact live ownership record at $GatewayProcessRecord."
    }
    $gatewayProcess = $gatewayOwnership.Verified.Process
    $gatewayStartIdentity = [string]$gatewayOwnership.Verified.Record.processStartTimeUtc
    Assert-StMobilePinnedProcessIdentity `
        -Process $gatewayProcess `
        -ExpectedProcessStartTimeUtc $gatewayStartIdentity `
        -OwnershipName 'existing ST Mobile Gateway'
    if ($gatewayProcess.PriorityClass -ne [System.Diagnostics.ProcessPriorityClass]::Idle) {
        Assert-StMobilePinnedProcessIdentity `
            -Process $gatewayProcess `
            -ExpectedProcessStartTimeUtc $gatewayStartIdentity `
            -OwnershipName 'existing ST Mobile Gateway'
        Set-IdlePriority $gatewayProcess 'existing ST Mobile Gateway'
        Start-Sleep -Milliseconds 100
        Assert-StMobilePinnedProcessIdentity `
            -Process $gatewayProcess `
            -ExpectedProcessStartTimeUtc $gatewayStartIdentity `
            -OwnershipName 'existing ST Mobile Gateway'
        $gatewayProcess.Refresh()
        if ($gatewayProcess.PriorityClass -ne [System.Diagnostics.ProcessPriorityClass]::Idle) {
            throw "Gateway port $Port listener PID $($listener.OwningProcess) is not Idle priority."
        }
    }
    return $true
}

function Clear-StaleGatewayOwnershipForLaunch {
    $pidExists = Test-Path -LiteralPath $GatewayPidFile
    $recordExists = Test-Path -LiteralPath $GatewayProcessRecord
    if (-not $pidExists -and -not $recordExists) {
        if (Test-Path -LiteralPath $HubUrlFile) {
            throw 'An orphaned or foreign auth-hub URL record exists without gateway ownership; refusing overwrite.'
        }
        return
    }
    if ($pidExists -ne $recordExists) {
        throw 'Gateway ownership state is incomplete; refusing to overwrite either record.'
    }
    $stalePidSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot([System.IO.Path]::GetFullPath($GatewayPidFile), '')
    $staleRecordSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot([System.IO.Path]::GetFullPath($GatewayProcessRecord), '')
    $stalePidBytes = $stalePidSnapshot.Bytes
    $staleRecordBytes = $staleRecordSnapshot.Bytes
    try {
        $record = Get-Content -LiteralPath $GatewayProcessRecord -Raw | ConvertFrom-Json
    } catch {
        throw "Gateway ownership record is invalid; refusing overwrite: $($_.Exception.Message)"
    }
    $pidValue = Read-StMobileCanonicalPositivePidBytes $stalePidBytes 'Gateway'
    if ($pidValue -ne [int]$record.pid) {
        throw 'Gateway numeric PID and JSON ownership records do not agree; refusing overwrite.'
    }
    $gatewayOwnership = Get-StMobileGatewayOwnershipState `
        -RecordPath $GatewayProcessRecord `
        -RecordSnapshot $staleRecordSnapshot `
        -NodeExe $node `
        -GatewayCli $GatewayCli `
        -PublicHost $PublicHost `
        -Port $Port `
        -HubPort $HubPort
    if ($gatewayOwnership.State -eq 'Conflict') {
        throw "Gateway ownership conflict; refusing overwrite: $($gatewayOwnership.Error)"
    }
    if ($gatewayOwnership.State -eq 'OwnedLive') {
        throw "Exact-owned gateway PID $($gatewayOwnership.Verified.Process.Id) is still alive without the expected listener; refusing to overwrite its records."
    }
    if ($gatewayOwnership.State -ne 'OwnedStale') {
        throw "Gateway ownership classification changed unexpectedly: $($gatewayOwnership.State)"
    }
    $staleGatewayEntries = @(
        [pscustomobject]@{ Path = $GatewayPidFile; Bytes = $stalePidBytes; ParentToken = $stalePidSnapshot.ParentToken; FileToken = $stalePidSnapshot.FileToken },
        [pscustomobject]@{ Path = $GatewayProcessRecord; Bytes = $staleRecordBytes; ParentToken = $staleRecordSnapshot.ParentToken; FileToken = $staleRecordSnapshot.FileToken })
    if (Test-Path -LiteralPath $HubUrlFile) {
        $staleHub = Publish-StMobileAuthHubUrlRecord `
            -Path $HubUrlFile `
            -GatewayRecord $record `
            -AllowLegacyUrlCas
        $staleGatewayEntries += [pscustomobject]@{ Path = $HubUrlFile; Bytes = $staleHub.Bytes; ParentToken = $staleHub.ParentToken; FileToken = $staleHub.FileToken }
    }
    Remove-StMobileFileSetIfUnchanged `
        -OwnershipName 'stale gateway ownership set' `
        -Entries $staleGatewayEntries
}

function Clear-StaleSillyTavernOwnershipForLaunch {
    $pidExists = Test-Path -LiteralPath $SillyTavernPidFile
    $recordExists = Test-Path -LiteralPath $SillyTavernProcessRecord
    if (-not $pidExists -and -not $recordExists) {
        return
    }
    if ($pidExists -ne $recordExists) {
        throw 'SillyTavern ownership state is incomplete; refusing to overwrite either record.'
    }
    $pidSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot([System.IO.Path]::GetFullPath($SillyTavernPidFile), '')
    $recordSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot([System.IO.Path]::GetFullPath($SillyTavernProcessRecord), '')
    $pidBytes = $pidSnapshot.Bytes
    $recordBytes = $recordSnapshot.Bytes
    $pidValue = Read-StMobileCanonicalPositivePidBytes $pidBytes 'SillyTavern'
    try {
        $record = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($recordBytes) | ConvertFrom-Json
    } catch {
        throw "SillyTavern ownership record is invalid; refusing overwrite: $($_.Exception.Message)"
    }
    $serverScript = [System.IO.Path]::GetFullPath((Join-Path $SillyTavernRoot 'server.js'))
    $legacyFields = @(
        'schema', 'pid', 'processStartTimeUtc', 'executablePath', 'sillyTavernRoot',
        'serverScriptPath', 'provenance', 'instanceId')
    $legacyExact = (Test-StMobileExactPropertySet $record $legacyFields) `
        -and $record.schema -ceq 'st-mobile-sillytavern-process/v1' `
        -and (Test-StMobileJsonInteger $record.pid) `
        -and [int64]$record.pid -gt 0 `
        -and (Test-StMobileCanonicalProcessStartIdentity $record.processStartTimeUtc) `
        -and (Test-StMobileCanonicalGuid $record.instanceId) `
        -and (Test-StMobileCanonicalAbsolutePath $record.executablePath) `
        -and (Test-StMobileCanonicalAbsolutePath $record.sillyTavernRoot) `
        -and (Test-StMobileCanonicalAbsolutePath $record.serverScriptPath) `
        -and [string]$record.executablePath -ceq [System.IO.Path]::GetFullPath($node) `
        -and [string]$record.sillyTavernRoot -ceq [System.IO.Path]::GetFullPath($SillyTavernRoot) `
        -and [string]$record.serverScriptPath -ceq $serverScript `
        -and $record.provenance -cin @('st-launcher-option-1', 'start-st-mobile')
    $currentExact = Test-StMobileSillyTavernRecordStructure `
        -Record $record `
        -ExpectedRoot $SillyTavernRoot `
        -ExpectedServerScript $serverScript `
        -ExpectedExecutablePath $node
    if ((-not $legacyExact -and -not $currentExact) -or [int]$record.pid -ne $pidValue) {
        throw 'SillyTavern PID and JSON ownership records are foreign, modified, or disagree; refusing overwrite.'
    }
    $candidate = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
    if ($candidate -and (Get-StMobileProcessStartIdentity $candidate) -ceq $record.processStartTimeUtc) {
        throw "Exact-owned SillyTavern PID $pidValue is still alive; refusing to overwrite its ownership set."
    }
    Remove-StMobileFileSetIfUnchanged -OwnershipName 'stale SillyTavern ownership set' -Entries @(
        [pscustomobject]@{ Path = $SillyTavernPidFile; Bytes = $pidBytes; ParentToken = $pidSnapshot.ParentToken; FileToken = $pidSnapshot.FileToken },
        [pscustomobject]@{ Path = $SillyTavernProcessRecord; Bytes = $recordBytes; ParentToken = $recordSnapshot.ParentToken; FileToken = $recordSnapshot.FileToken })
}

function Assert-GatewayReadyThroughCli {
    $output = & $node $GatewayCli ready --host $PublicHost --port $Port
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticated gateway readiness probe failed with exit code $LASTEXITCODE"
    }
    Write-Host ($output -join "`n")
}

function Assert-AuthHubReady {
    $uri = "http://127.0.0.1:$HubPort/api/devices"
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -TimeoutSec 5
    } catch {
        throw "Auth hub readiness probe failed at $uri`: $($_.Exception.Message)"
    }
    if ($response.StatusCode -ne 200) {
        throw "Auth hub readiness probe returned HTTP $($response.StatusCode) at $uri."
    }
    $body = $response.Content | ConvertFrom-Json
    if (-not $body.gatewayUrl -or $body.gatewayUrl -ne "https://$PublicHost`:$Port") {
        throw "Auth hub readiness probe returned unexpected gatewayUrl '$($body.gatewayUrl)' instead of https://$PublicHost`:$Port."
    }
    if ($null -eq $body.devices -or $null -eq $body.pendingPairings) {
        throw "Auth hub readiness probe did not return devices and pendingPairings arrays."
    }
}

function Invoke-GatewayProbe([string]$Path, [string]$Cookie) {
    $caPath = Join-Path $ProjectRoot 'state\certs\st-mobile-ca.crt'
    $probe = @"
const https = require('node:https');
const fs = require('node:fs');
const path = process.env.ST_MOBILE_PROBE_PATH;
const cookie = process.env.ST_MOBILE_PROBE_COOKIE || '';
const ca = fs.readFileSync(process.env.ST_MOBILE_PROBE_CA);
const req = https.request({
  host: '127.0.0.1',
  port: $Port,
  path,
  method: 'GET',
  ca,
  rejectUnauthorized: true,
  headers: cookie ? { cookie } : {},
}, (res) => {
  res.resume();
  res.on('end', () => {
    console.log(res.statusCode);
  });
});
req.on('error', (error) => {
  console.error(error.message);
  process.exit(2);
});
req.end();
"@
    $oldPath = $env:ST_MOBILE_PROBE_PATH
    $oldCookie = $env:ST_MOBILE_PROBE_COOKIE
    $oldCa = $env:ST_MOBILE_PROBE_CA
    try {
        $env:ST_MOBILE_PROBE_PATH = $Path
        $env:ST_MOBILE_PROBE_COOKIE = $Cookie
        $env:ST_MOBILE_PROBE_CA = $caPath
        $output = & $node '--input-type=commonjs' '-e' $probe
    } finally {
        $env:ST_MOBILE_PROBE_PATH = $oldPath
        $env:ST_MOBILE_PROBE_COOKIE = $oldCookie
        $env:ST_MOBILE_PROBE_CA = $oldCa
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Gateway security probe failed for $Path"
    }
    return [int]($output | Select-Object -Last 1)
}

function Assert-GatewaySecurityProbes {
    $health = Invoke-GatewayProbe '/__mobile/health' ''
    $unauth = Invoke-GatewayProbe '/' ''
    $badCookie = Invoke-GatewayProbe '/' 'stmg=bad-cookie'

    if ($health -ne 200 -or $unauth -ne 403 -or $badCookie -ne 403) {
        throw "Gateway security probes failed: health=$health unauth=$unauth bad-cookie=$badCookie"
    }
}

$node = Get-NodePath
$PublicHost = Get-DefaultPrivateIPv4
Assert-PublicHostNetworkReady

& powershell -NoProfile -ExecutionPolicy Bypass -File $ProtectCertAcls -CertDir $CertRoot -PrivatePath $StateRoot | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Private ACL protection failed with exit code $LASTEXITCODE"
}

if (-not $NoStartSillyTavern -and -not (Test-LoopbackSillyTavern)) {
    Clear-StaleSillyTavernOwnershipForLaunch
    $serverScript = [System.IO.Path]::GetFullPath((Join-Path $SillyTavernRoot 'server.js'))
    if (-not (Test-Path -LiteralPath $serverScript)) {
        throw "SillyTavern server.js not found under $SillyTavernRoot"
    }
    $stLaunch = Start-HiddenIdleProcess `
        -FilePath $node `
        -ArgumentList @($serverScript) `
        -WorkingDirectory $SillyTavernRoot `
        -Name 'SillyTavern' `
        -OutLog (Join-Path $LogRoot 'sillytavern.out.log') `
        -ErrLog (Join-Path $LogRoot 'sillytavern.err.log')
    $stProcess = $stLaunch.Process
    $stProcessStartIdentity = $stLaunch.ExpectedStartIdentity
    $stPidPublished = $false
    try {
        $stPidBytesWritten = (New-Object System.Text.ASCIIEncoding).GetBytes(
            ([string]$stProcess.Id) + [Environment]::NewLine)
        $stPidIdentity = Write-StMobileBytesCreateNew $SillyTavernPidFile $stPidBytesWritten -PassThru
        $stPidPublished = $true
        $launchedSession = [pscustomobject]@{
            Pid = $stProcess.Id
            ProcessStartTimeUtc = $stProcessStartIdentity
            ExecutablePath = $node
            SillyTavernRoot = [System.IO.Path]::GetFullPath($SillyTavernRoot)
            ServerScriptPath = $serverScript
            RootProofMethod = 'absolute-server-argv-v1'
            RootProofAtUtc = [DateTime]::UtcNow.ToString(
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                [System.Globalization.CultureInfo]::InvariantCulture)
        }
        [void](Write-StMobileSillyTavernRecord `
            -Session $launchedSession `
            -RecordPath $SillyTavernProcessRecord `
            -Provenance 'start-st-mobile')
    } catch {
        $publicationFailure = $_.Exception.Message
        try {
            Stop-JustLaunchedProcessAndConfirm $stProcess $stProcessStartIdentity 'SillyTavern'
        } catch {
            throw "Could not publish exact SillyTavern launch ownership: $publicationFailure Cleanup blocked: $($_.Exception.Message) Ownership files were preserved."
        }
        if ($stPidPublished -and (Test-Path -LiteralPath $SillyTavernPidFile)) {
            Remove-StMobileFileIfUnchanged $SillyTavernPidFile $stPidBytesWritten 'failed SillyTavern launch PID record' `
                $stPidIdentity.ParentToken $stPidIdentity.FileToken
        }
        throw "Could not publish exact SillyTavern launch ownership: $publicationFailure"
    }
}

Assert-SillyTavernPortSafe
Assert-SillyTavernIdentity

if (Assert-GatewayListenerExpected) {
    Write-Host "Gateway port $Port is already listening."
} else {
    Clear-StaleGatewayOwnershipForLaunch
    $gatewayLaunch = Start-HiddenIdleProcess `
        -FilePath $node `
        -ArgumentList @($GatewayCli, 'serve', '--host', $PublicHost, '--port', "$Port", '--hub-port', "$HubPort") `
        -WorkingDirectory $ProjectRoot `
        -Name 'ST Mobile Gateway' `
        -OutLog (Join-Path $LogRoot 'gateway.out.log') `
        -ErrLog (Join-Path $LogRoot 'gateway.err.log')
    $gatewayProcess = $gatewayLaunch.Process
    $gatewayProcessStartIdentity = $gatewayLaunch.ExpectedStartIdentity
    try {
        $gatewayWrittenEntries = New-Object 'System.Collections.Generic.List[object]'
        $gatewayPidBytesWritten = (New-Object System.Text.ASCIIEncoding).GetBytes(
            ([string]$gatewayProcess.Id) + [Environment]::NewLine)
        $gatewayPidIdentity = Write-StMobileBytesCreateNew $GatewayPidFile $gatewayPidBytesWritten -PassThru
        $gatewayWrittenEntries.Add([pscustomobject]@{ Path = $GatewayPidFile; Bytes = $gatewayPidBytesWritten; ParentToken = $gatewayPidIdentity.ParentToken; FileToken = $gatewayPidIdentity.FileToken })
        $gatewayRecord = [ordered]@{
            schema = 'st-mobile-gateway-process/v1'
            pid = $gatewayProcess.Id
            processStartTimeUtc = $gatewayProcessStartIdentity
            executablePath = $node
            cliPath = [System.IO.Path]::GetFullPath($GatewayCli)
            publicHost = $PublicHost
            port = $Port
            hubPort = $HubPort
            instanceId = [guid]::NewGuid().ToString()
        }
        $recordJson = ($gatewayRecord | ConvertTo-Json) + [Environment]::NewLine
        $gatewayRecordBytesWritten = (New-Object System.Text.UTF8Encoding($false)).GetBytes($recordJson)
        $gatewayRecordIdentity = Write-StMobileBytesCreateNew $GatewayProcessRecord $gatewayRecordBytesWritten -PassThru
        $gatewayWrittenEntries.Add([pscustomobject]@{ Path = $GatewayProcessRecord; Bytes = $gatewayRecordBytesWritten; ParentToken = $gatewayRecordIdentity.ParentToken; FileToken = $gatewayRecordIdentity.FileToken })
        $verifiedGatewayForPublication = Get-VerifiedStMobileGatewayProcess `
            -RecordPath $GatewayProcessRecord `
            -NodeExe $node `
            -GatewayCli $GatewayCli `
            -PublicHost $PublicHost `
            -Port $Port `
            -HubPort $HubPort `
            -ThrowOnInvalid
        if (-not $verifiedGatewayForPublication) {
            throw 'The just-launched gateway did not match its exact ownership record.'
        }
        $publishedHubRecord = Publish-StMobileAuthHubUrlRecord `
            -Path $HubUrlFile `
            -GatewayRecord $verifiedGatewayForPublication.Record `
            -AllowLegacyUrlCas
        $gatewayWrittenEntries.Add([pscustomobject]@{ Path = $HubUrlFile; Bytes = $publishedHubRecord.Bytes; ParentToken = $publishedHubRecord.ParentToken; FileToken = $publishedHubRecord.FileToken })
    } catch {
        $publicationFailure = $_.Exception.Message
        try {
            Stop-JustLaunchedProcessAndConfirm $gatewayProcess $gatewayProcessStartIdentity 'ST Mobile Gateway'
        } catch {
            throw "Could not write the exact gateway process ownership record: $publicationFailure Cleanup blocked: $($_.Exception.Message) Ownership files were preserved."
        }
        if ($gatewayWrittenEntries -and $gatewayWrittenEntries.Count -gt 0) {
            Remove-StMobileFileSetIfUnchanged `
                -Entries @($gatewayWrittenEntries) `
                -OwnershipName 'failed gateway launch ownership set'
        }
        throw "Could not write the exact gateway process ownership record: $publicationFailure"
    }
}

$deadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadline -and -not (Get-GatewayListener)) {
    Start-Sleep -Milliseconds 250
}

if (-not (Get-GatewayListener)) {
    throw "Gateway failed to listen on port $Port. See $LogRoot"
}

Assert-GatewayListenerExpected | Out-Null
Assert-SillyTavernPortSafe
Assert-SillyTavernIdentity
Assert-GatewaySecurityProbes
Assert-GatewayReadyThroughCli
Assert-AuthHubReady

node $GatewayCli info --host $PublicHost --port $Port
$verifiedGatewayForHubRecord = Get-VerifiedStMobileGatewayProcess `
    -RecordPath $GatewayProcessRecord `
    -NodeExe $node `
    -GatewayCli $GatewayCli `
    -PublicHost $PublicHost `
    -Port $Port `
    -HubPort $HubPort `
    -RequireListeners `
    -ThrowOnInvalid
if (-not $verifiedGatewayForHubRecord) {
    throw 'Gateway readiness passed without a live exact-owned gateway instance; refusing auth-hub URL publication.'
}
[void](Publish-StMobileAuthHubUrlRecord `
    -Path $HubUrlFile `
    -GatewayRecord $verifiedGatewayForHubRecord.Record `
    -AllowLegacyUrlCas)
Write-Host "Auth hub: http://127.0.0.1:$HubPort/"
Write-Host "Generate a QR with: node `"$GatewayCli`" pair --host $PublicHost --port $Port --label `"S24 Ultra`""
Write-Host "Open the auth hub with: Start-Process http://127.0.0.1:$HubPort/"
