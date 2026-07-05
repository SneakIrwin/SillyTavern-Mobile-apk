param(
    [string]$CertDir = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')) 'state\certs'),
    [string[]]$PrivatePath = @()
)

$ErrorActionPreference = 'Stop'

try {
    [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
} catch {
    Write-Warning "Could not set ACL helper process to Idle priority: $($_.Exception.Message)"
}

$allowedSids = @(
    [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
    [System.Security.Principal.SecurityIdentifier]'S-1-5-18',
    [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'
)

function Protect-PathAcl([string]$LiteralPath, [bool]$IsDirectory) {
    $acl = if ($IsDirectory) {
        [System.IO.Directory]::GetAccessControl($LiteralPath, [System.Security.AccessControl.AccessControlSections]::Access)
    } else {
        [System.IO.File]::GetAccessControl($LiteralPath, [System.Security.AccessControl.AccessControlSections]::Access)
    }
    $acl.SetAccessRuleProtection($true, $false)

    foreach ($rule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleAll($rule)
    }

    foreach ($sid in $allowedSids) {
        $inheritance = if ($IsDirectory) {
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
        } else {
            [System.Security.AccessControl.InheritanceFlags]'None'
        }
        $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($accessRule)
    }

    if ($IsDirectory) {
        [System.IO.Directory]::SetAccessControl($LiteralPath, $acl)
    } else {
        [System.IO.File]::SetAccessControl($LiteralPath, $acl)
    }
}

function Resolve-OrFullPath([string]$LiteralPath) {
    if (Test-Path $LiteralPath) {
        return (Resolve-Path $LiteralPath).Path
    }
    return [System.IO.Path]::GetFullPath($LiteralPath)
}

function Protect-PrivateTree([string]$RootPath) {
    $resolvedRoot = Resolve-OrFullPath $RootPath
    New-Item -ItemType Directory -Force -Path $resolvedRoot | Out-Null
    Protect-PathAcl -LiteralPath $resolvedRoot -IsDirectory $true

    Get-ChildItem -LiteralPath $resolvedRoot -Force -Recurse | ForEach-Object {
        Protect-PathAcl -LiteralPath $_.FullName -IsDirectory $_.PSIsContainer
    }
    return $resolvedRoot
}

$roots = @($CertDir) + $PrivatePath
$protectedRoots = foreach ($root in $roots) {
    if ([string]::IsNullOrWhiteSpace($root)) {
        continue
    }
    Protect-PrivateTree -RootPath $root
}

Write-Host "Protected private ACLs: $($protectedRoots -join '; ')"
