param(
    [ValidateSet('Install', 'Remove', 'Status')]
    [string]$Mode = 'Install',
    [string]$LauncherRoot = 'C:\Users\Sneak\SillyTavern-Launcher\SillyTavern-Launcher',
    [string]$BackupBase = '',
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$env:GIT_OPTIONAL_LOCKS = '0'
$currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
$currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle

# Rank Audit For This Launcher Integration
# - Rank 4: mutate only exact-owned target/config/attribute state, preserve byte identity
#   outside the managed block, roll back every surface on failure, and keep Git filters hidden/Idle.
# - Rank 3: use a required local Git clean/smudge filter so upstream self-updates retain option-1 integration.

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $PSScriptRoot 'StMobileTrayCommon.ps1')
if ([string]::IsNullOrWhiteSpace($BackupBase)) {
    $BackupBase = Join-Path $ProjectRoot 'scratch\st-launcher-integration'
}
$BackupBase = [System.IO.Path]::GetFullPath($BackupBase)
$LauncherRoot = [System.IO.Path]::GetFullPath($LauncherRoot)
$FilterScript = Join-Path $PSScriptRoot 'StLauncherIntegrationFilter.ps1'
$TargetRelative = 'bin/functions/Toolbox/App_Launcher/Core_Utilities/update_start_st.bat'
$TargetPath = Join-Path $LauncherRoot ($TargetRelative -replace '/', '\')
$FilterName = 'stmobileauthhubv1'
$LegacyFilterName = 'stmobile'
$AttributeBegin = '# >>> ST MOBILE AUTH HUB FILTER (managed)'
$AttributeEnd = '# <<< ST MOBILE AUTH HUB FILTER (managed)'
$AttributeLine = "$TargetRelative filter=$FilterName"
$LegacyAttributeLine = "$TargetRelative filter=$LegacyFilterName"
$PowerShellExe = $null
try {
    $PowerShellExe = $currentProcess.MainModule.FileName
} catch {
    $PowerShellExe = $null
}
if ([string]::IsNullOrWhiteSpace($PowerShellExe) -or -not (Test-Path -LiteralPath $PowerShellExe)) {
    $hostExecutableName = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    $PowerShellExe = Join-Path $PSHOME $hostExecutableName
}
if (-not (Test-Path -LiteralPath $PowerShellExe)) {
    throw "Could not resolve the current PowerShell host executable: $PowerShellExe"
}
$StrictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)

function Invoke-Git([string[]]$Arguments, [switch]$AllowFailure) {
    $output = & git -C $LauncherRoot @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "git $($Arguments -join ' ') failed with exit code $exitCode`: $($output -join [Environment]::NewLine)"
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = @($output) }
}

function Get-TargetGitStatus {
    $worktree = Invoke-Git @('diff', '--quiet', '--', $TargetRelative) -AllowFailure
    $cached = Invoke-Git @('diff', '--cached', '--quiet', '--', $TargetRelative) -AllowFailure
    if ($worktree.ExitCode -eq 0 -and $cached.ExitCode -eq 0) {
        return ''
    }
    return ((Invoke-Git @('status', '--porcelain', '--', $TargetRelative)).Output -join "`n")
}

function Assert-EffectiveTargetFilter([string]$AttributeState) {
    $expected = switch ($AttributeState) {
        'absent' { 'unspecified' }
        'current' { $FilterName }
        'legacy' { $LegacyFilterName }
        default { throw "Cannot validate effective target filter for attribute state $AttributeState." }
    }
    $result = Invoke-Git @('check-attr', 'filter', '--', $TargetRelative)
    if ($result.Output.Count -ne 1) {
        throw 'git check-attr returned an unexpected number of filter records.'
    }
    $expectedLine = "$TargetRelative`: filter: $expected"
    if ([string]$result.Output[0] -cne $expectedLine) {
        throw "Effective Git filter for $TargetRelative is not exact-owned (expected '$expectedLine', got '$($result.Output[0])')."
    }
    return $expectedLine
}

function Get-ConfigValues([string]$Key) {
    $result = Invoke-Git @('config', '--local', '--get-all', $Key) -AllowFailure
    if ($result.ExitCode -eq 1) {
        return @()
    }
    if ($result.ExitCode -ne 0) {
        throw "Could not read local Git config key $Key."
    }
    return @($result.Output | ForEach-Object { [string]$_ })
}

function Test-ExactSingleValue([string[]]$Values, [string]$Expected) {
    return $Values.Count -eq 1 -and $Values[0] -ceq $Expected
}

function Test-StringArraysEqual([string[]]$Left, [string[]]$Right) {
    if ($Left.Count -ne $Right.Count) {
        return $false
    }
    for ($index = 0; $index -lt $Left.Count; $index++) {
        if ($Left[$index] -cne $Right[$index]) {
            return $false
        }
    }
    return $true
}

function Test-BytesEqual([byte[]]$Left, [byte[]]$Right) {
    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) {
            return $false
        }
    }
    return $true
}

function Write-NewExactFile([string]$Path, [byte[]]$Bytes) {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Pinned launcher CAS is unavailable off Windows; refusing pathname fallback.'
    }
    return [StMobile.PinnedFileOperations]::CreateNew([System.IO.Path]::GetFullPath($Path), $Bytes, '')
}

function Remove-PinnedExactFile([string]$Path, [byte[]]$Bytes, [object]$Identity) {
    if (-not $Identity) { return }
    [StMobile.PinnedFileOperations]::DeleteExact(
        [System.IO.Path]::GetFullPath($Path), $Bytes,
        $Identity.ParentToken, $Identity.FileToken)
}

function Get-PinnedParentToken([string]$Path) {
    $parent = Split-Path -Parent ([System.IO.Path]::GetFullPath($Path))
    $probe = Join-Path $parent ('.st-mobile-parent-probe-' + [guid]::NewGuid().ToString('N'))
    $identity = [StMobile.PinnedFileOperations]::CreateNew($probe, [byte[]]@(), '')
    try {
        return $identity.ParentToken
    } finally {
        [StMobile.PinnedFileOperations]::DeleteExact($probe, [byte[]]@(), $identity.ParentToken, $identity.FileToken)
    }
}

function Restore-QuarantinedGeneration(
    [string]$Path, [string]$Quarantine, [byte[]]$ExpectedBytes,
    [string]$ExpectedParentToken, [string]$ExpectedFileToken, [string]$Surface
) {
    [void][StMobile.PinnedFileOperations]::MoveExact(
        [System.IO.Path]::GetFullPath($Quarantine),
        [System.IO.Path]::GetFullPath($Path),
        $ExpectedBytes, $ExpectedParentToken, $ExpectedFileToken)
}

function Recover-FrozenPriorGeneration(
    [string]$Path, [string]$Quarantine, [byte[]]$PriorBytes,
    [string]$PriorParentToken, [string]$PriorFileToken, [string]$Surface
) {
    $quarantineFailure = $null
    try {
        Restore-QuarantinedGeneration $Path $Quarantine $PriorBytes $PriorParentToken $PriorFileToken $Surface
        return 'the exact quarantined prior generation was reinserted'
    } catch {
        $quarantineFailure = $_.Exception.Message
    }

    try {
        [void][StMobile.PinnedFileOperations]::InspectExact(
            [System.IO.Path]::GetFullPath($Path), $PriorBytes, $PriorParentToken, $PriorFileToken)
        return "the exact frozen prior generation was already live; tampered or blocked quarantine preserved at $Quarantine; quarantine blocker: $quarantineFailure"
    } catch {
        $liveFailure = $_.Exception.Message
    }

    try {
        $recreated = [StMobile.PinnedFileOperations]::CreateNew(
            [System.IO.Path]::GetFullPath($Path), $PriorBytes, $PriorParentToken)
    } catch {
        throw "$Surface could not recreate the exact frozen prior generation without overwriting a collision: $($_.Exception.Message); live blocker: $liveFailure; quarantine blocker: $quarantineFailure; preserved quarantine: $Quarantine"
    }
    return "the exact frozen prior generation was recreated from immutable bytes; tampered or unreadable quarantine preserved at $Quarantine; quarantine blocker: $quarantineFailure"
}

function Set-FileGenerationCas(
    [string]$Path,
    [bool]$ExpectedExists,
    [byte[]]$ExpectedBytes,
    [bool]$DesiredExists,
    [byte[]]$DesiredBytes,
    [string]$Surface,
    [string]$ExpectedParentToken = '',
    [string]$ExpectedFileToken = ''
) {
    $priorBytes = if ($ExpectedExists) { [byte[]]$ExpectedBytes.Clone() } else { [byte[]]@() }
    $publishedBytes = if ($DesiredExists) { [byte[]]$DesiredBytes.Clone() } else { [byte[]]@() }
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $parentToken = if ([string]::IsNullOrWhiteSpace($ExpectedParentToken)) { Get-PinnedParentToken $Path } else { $ExpectedParentToken }
    $quarantine = $null
    $staging = $null
    $stagingIdentity = $null
    $priorIdentity = $null
    if ($DesiredExists) {
        $staging = Join-Path $parent ('.' + [System.IO.Path]::GetFileName($Path) + '.st-mobile-cas-' + [guid]::NewGuid().ToString('N') + '.new')
        $stagingIdentity = [StMobile.PinnedFileOperations]::CreateNew($staging, $publishedBytes, $parentToken)
    }
    if ($ExpectedExists) {
        $quarantine = Join-Path $parent ('.' + [System.IO.Path]::GetFileName($Path) + '.st-mobile-cas-' + [guid]::NewGuid().ToString('N') + '.quarantine')
        try {
            $priorIdentity = [StMobile.PinnedFileOperations]::MoveExact(
                [System.IO.Path]::GetFullPath($Path), [System.IO.Path]::GetFullPath($quarantine),
                $priorBytes, $parentToken, $ExpectedFileToken)
            # TEST-HARNESS-ANCHOR: after-live-generation-moved
        } catch {
            $moveFailure = $_.Exception.Message
            $recoveryFailure = $null
            $stagingCleanupFailure = $null
            $recoveryResult = 'the pinned move did not publish a quarantine'
            try {
                if ($priorIdentity) {
                    $recoveryResult = Recover-FrozenPriorGeneration `
                        $Path $quarantine $priorBytes $parentToken $ExpectedFileToken $Surface
                } else {
                    [void][StMobile.PinnedFileOperations]::InspectExact(
                        $Path, $priorBytes, $parentToken, $ExpectedFileToken)
                    $recoveryResult = 'the exact prior generation remained live; no quarantine residue was created'
                }
            } catch {
                $recoveryFailure = $_.Exception.Message
            } finally {
                if ($stagingIdentity) {
                    try { Remove-PinnedExactFile $staging $publishedBytes $stagingIdentity } catch { $stagingCleanupFailure = $_.Exception.Message }
                }
            }
            if ($stagingCleanupFailure) {
                throw "$Surface quarantine move failed ($moveFailure); staging cleanup preserved changed generation at $staging`: $stagingCleanupFailure; recovery: $recoveryResult"
            }
            if ($recoveryFailure) {
                throw "$Surface quarantine move failed ($moveFailure) and recovery failed: $recoveryFailure"
            }
            throw "$Surface could not quarantine the exact live generation: $moveFailure; recovery: $recoveryResult"
        }
    }

    try {
        if ($ExpectedExists) {
            [void][StMobile.PinnedFileOperations]::InspectExact(
                $quarantine, $priorBytes, $priorIdentity.ParentToken, $priorIdentity.FileToken)
        }
        if ($DesiredExists) {
            [void][StMobile.PinnedFileOperations]::MoveExact(
                $staging, $Path, $publishedBytes,
                $stagingIdentity.ParentToken, $stagingIdentity.FileToken)
        }
    } catch {
        $publicationFailure = $_.Exception.Message
        if ($ExpectedExists) {
            try {
                $recoveryResult = Recover-FrozenPriorGeneration `
                    $Path $quarantine $priorBytes $priorIdentity.ParentToken $priorIdentity.FileToken $Surface
            } catch {
                $priorRecoveryFailure = $_.Exception.Message
                $stagingCleanupFailure = $null
                if ($stagingIdentity) {
                    try { Remove-PinnedExactFile $staging $publishedBytes $stagingIdentity } catch { $stagingCleanupFailure = $_.Exception.Message }
                }
                if ($stagingCleanupFailure) {
                    throw "$Surface publication failed ($publicationFailure); prior recovery failed: $priorRecoveryFailure; staging cleanup preserved changed generation at $staging`: $stagingCleanupFailure"
                }
                throw "$Surface create-new publication failed ($publicationFailure) and the just-moved live generation could not be reinserted safely: $priorRecoveryFailure"
            }
        }
        $stagingCleanupFailure = $null
        if ($stagingIdentity) {
            try { Remove-PinnedExactFile $staging $publishedBytes $stagingIdentity } catch { $stagingCleanupFailure = $_.Exception.Message }
        }
        if ($stagingCleanupFailure) {
            throw "$Surface publication failed ($publicationFailure); staging cleanup preserved changed generation at $staging`: $stagingCleanupFailure; recovery: $recoveryResult"
        }
        throw "$Surface create-new publication failed without overwriting an existing generation: $publicationFailure; recovery: $recoveryResult"
    }

    return [pscustomobject]@{
        Surface = $Surface
        Path = $Path
        ExpectedExists = $ExpectedExists
        ExpectedBytes = $priorBytes
        DesiredExists = $DesiredExists
        DesiredBytes = $publishedBytes
        OriginalQuarantine = $quarantine
        PriorParentToken = if ($priorIdentity) { $priorIdentity.ParentToken } else { $parentToken }
        PriorFileToken = if ($priorIdentity) { $priorIdentity.FileToken } else { '' }
        PublishedParentToken = if ($stagingIdentity) { $stagingIdentity.ParentToken } else { $parentToken }
        PublishedFileToken = if ($stagingIdentity) { $stagingIdentity.FileToken } else { '' }
    }
}

function Undo-FileGenerationCas([object]$Token) {
    $rollbackQuarantine = $null
    if ($Token.ExpectedExists) {
        [void][StMobile.PinnedFileOperations]::InspectExact(
            $Token.OriginalQuarantine, $Token.ExpectedBytes,
            $Token.PriorParentToken, $Token.PriorFileToken)
    }

    $currentMoved = $false
    $currentIdentity = $null
    try {
        if ($Token.DesiredExists) {
            $parent = Split-Path -Parent $Token.Path
            $rollbackQuarantine = Join-Path $parent ('.' + [System.IO.Path]::GetFileName($Token.Path) + '.st-mobile-rollback-' + [guid]::NewGuid().ToString('N') + '.quarantine')
            $currentIdentity = [StMobile.PinnedFileOperations]::MoveExact(
                $Token.Path, $rollbackQuarantine, $Token.DesiredBytes,
                $Token.PublishedParentToken, $Token.PublishedFileToken)
            $currentMoved = $true
        }
        if ($Token.ExpectedExists) {
            # TEST-HARNESS-ANCHOR: before-original-quarantine-restore
            Restore-QuarantinedGeneration `
                $Token.Path $Token.OriginalQuarantine $Token.ExpectedBytes `
                $Token.PriorParentToken $Token.PriorFileToken $Token.Surface
        }
        if ($currentIdentity) {
            Remove-PinnedExactFile $rollbackQuarantine $Token.DesiredBytes $currentIdentity
        }
    } catch {
        $rollbackFailure = $_.Exception.Message
        if (-not $currentMoved) {
            throw "$($Token.Surface) rollback failed before moving the current generation: $rollbackFailure"
        }
        $recoveryFailure = $null
        try {
            if ($currentIdentity) {
                Restore-QuarantinedGeneration `
                    $Token.Path $rollbackQuarantine $Token.DesiredBytes `
                    $currentIdentity.ParentToken $currentIdentity.FileToken $Token.Surface
            }
        } catch {
            $recoveryFailure = $_.Exception.Message
        }
        if ($recoveryFailure) {
            throw "$($Token.Surface) rollback failed ($rollbackFailure) and could not reinsert the just-moved current generation: $recoveryFailure"
        }
        throw "$($Token.Surface) rollback failed; the just-moved current generation was reinserted without alteration: $rollbackFailure"
    }
}

function Complete-FileGenerationCas([object]$Token) {
    if ($Token.ExpectedExists -and $Token.OriginalQuarantine) {
        [StMobile.PinnedFileOperations]::DeleteExact(
            $Token.OriginalQuarantine, $Token.ExpectedBytes,
            $Token.PriorParentToken, $Token.PriorFileToken)
    }
}

function Get-StrictUtf8File([string]$Path) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    try {
        $text = $StrictUtf8.GetString($bytes)
    } catch {
        throw "Refusing unsupported non-UTF-8 text file $Path`: $($_.Exception.Message)"
    }
    $roundTrip = $StrictUtf8.GetBytes($text)
    if (-not (Test-BytesEqual $bytes $roundTrip)) {
        throw "Refusing text file whose UTF-8 bytes do not round-trip exactly: $Path"
    }
    return [pscustomobject]@{ Bytes = $bytes; Text = $text }
}

function Get-GitBlobIdForText([string]$Text) {
    $temporaryInput = Join-Path ([System.IO.Path]::GetTempPath()) ("st-mobile-git-blob-$PID-$([guid]::NewGuid().ToString('N')).tmp")
    [System.IO.File]::WriteAllBytes($temporaryInput, $StrictUtf8.GetBytes($Text))
    $gitExe = (Get-Command git.exe -ErrorAction Stop).Source
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $gitExe
    $info.Arguments = Join-WindowsCommandLineArguments @('-C', $LauncherRoot, 'hash-object', "--path=$TargetRelative", $temporaryInput)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = $null
    try {
        $process = [System.Diagnostics.Process]::Start($info)
        $process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
    } catch {
        if ($process) {
            try { $process.Kill() } catch {}
        }
        Remove-Item -LiteralPath $temporaryInput -Force -ErrorAction SilentlyContinue
        $processId = if ($process) { $process.Id } else { 'not-started' }
        throw "Could not start or set Git blob verifier PID $processId to Idle: $($_.Exception.Message)"
    }
    try {
        $stdout = $process.StandardOutput.ReadToEnd().Trim()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "git hash-object failed with exit code $($process.ExitCode): $stderr"
        }
        if ($stdout -notmatch '^[0-9a-f]{40,64}$') {
            throw "git hash-object returned an invalid object ID: $stdout"
        }
        return $stdout
    } finally {
        $process.Dispose()
        Remove-Item -LiteralPath $temporaryInput -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Filter([string]$FilterMode, [string]$Text) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $PowerShellExe
    $info.Arguments = Join-WindowsCommandLineArguments @(
        '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
        '-File', $FilterScript, '-Mode', $FilterMode)
    $info.WorkingDirectory = $ProjectRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($info)
    try {
        $process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
    } catch {
        try { $process.Kill() } catch {}
        throw "Could not set launcher filter child PID $($process.Id) to Idle: $($_.Exception.Message)"
    }
    $process.StandardInput.Write($Text)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Launcher filter $FilterMode failed with exit code $($process.ExitCode): $stderr"
    }
    $process.Dispose()
    return $stdout
}

function Get-AttributeBlock([string]$Line, [string]$Newline) {
    return $AttributeBegin + $Newline + $Line + $Newline + $AttributeEnd + $Newline
}

function Assert-NoOutOfBlockTargetAttribute([string]$Text) {
    $targetPattern = '(?m)^[\t ]*' + [regex]::Escape($TargetRelative) + '[\t ]+.*$'
    if ([regex]::IsMatch($Text, $targetPattern)) {
        throw "Target $TargetRelative already has an out-of-block attributes mapping; refusing ambiguous ownership."
    }
}

function Get-AttributeState([string]$Text) {
    $beginCount = [regex]::Matches($Text, '(?m)^' + [regex]::Escape($AttributeBegin) + '\r?$').Count
    $endCount = [regex]::Matches($Text, '(?m)^' + [regex]::Escape($AttributeEnd) + '\r?$').Count
    if ($beginCount -eq 0 -and $endCount -eq 0) {
        Assert-NoOutOfBlockTargetAttribute $Text
        return [pscustomobject]@{ State = 'absent'; CleanText = $Text; Block = '' }
    }
    if ($beginCount -ne 1 -or $endCount -ne 1) {
        throw "Managed attributes markers are missing or duplicated (begin=$beginCount end=$endCount)."
    }
    $candidates = @(
        [pscustomobject]@{ State = 'current'; Block = (Get-AttributeBlock $AttributeLine "`r`n") },
        [pscustomobject]@{ State = 'current'; Block = (Get-AttributeBlock $AttributeLine "`n") },
        [pscustomobject]@{ State = 'legacy'; Block = (Get-AttributeBlock $LegacyAttributeLine "`r`n") },
        [pscustomobject]@{ State = 'legacy'; Block = (Get-AttributeBlock $LegacyAttributeLine "`n") }
    )
    $match = $candidates | Where-Object {
        $Text.Contains($_.Block) -and $Text.IndexOf($_.Block, [System.StringComparison]::Ordinal) -eq $Text.LastIndexOf($_.Block, [System.StringComparison]::Ordinal)
    } | Select-Object -First 1
    if (-not $match) {
        throw 'Managed attributes block was modified or duplicated.'
    }
    $index = $Text.IndexOf($match.Block, [System.StringComparison]::Ordinal)
    if ($index + $match.Block.Length -ne $Text.Length) {
        throw 'Managed attributes block is not in its exact canonical end-of-file position.'
    }
    $cleanText = $Text.Remove($index, $match.Block.Length)
    Assert-NoOutOfBlockTargetAttribute $cleanText
    return [pscustomobject]@{
        State = $match.State
        CleanText = $cleanText
        Block = $match.Block
    }
}

function Add-CurrentAttributeBlock([string]$CleanText) {
    if ($CleanText.Length -gt 0 -and -not $CleanText.EndsWith("`n")) {
        throw 'Refusing to append managed attributes to a file without a terminating newline.'
    }
    $newline = if ($CleanText.Contains("`r`n") -or $CleanText.Length -eq 0) { "`r`n" } else { "`n" }
    return $CleanText + (Get-AttributeBlock $AttributeLine $newline)
}

function Assert-ReservedManagedConfigSentinelShape([byte[]]$BaseBytes) {
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $text = $latin1.GetString($BaseBytes)
    $beginMarker = '# >>> ST MOBILE AUTH HUB FILTER CONFIG (managed)'
    $endMarker = '# <<< ST MOBILE AUTH HUB FILTER CONFIG (managed)'
    $beginCount = [regex]::Matches($text, [regex]::Escape($beginMarker)).Count
    $endCount = [regex]::Matches($text, [regex]::Escape($endMarker)).Count
    if ($beginCount -eq 0 -and $endCount -eq 0) { return }
    $exactBeginLines = [regex]::Matches($text, '(?m)^' + [regex]::Escape($beginMarker) + '\r?$').Count
    $exactEndLines = [regex]::Matches($text, '(?m)^' + [regex]::Escape($endMarker) + '\r?$').Count
    if ($beginCount -ne 1 -or $endCount -ne 1 -or $exactBeginLines -ne 1 -or $exactEndLines -ne 1) {
        throw "Reserved managed Git config sentinels are missing, duplicated, nested, inline, or malformed (begin=$beginCount end=$endCount exact_begin=$exactBeginLines exact_end=$exactEndLines)."
    }
}

if (-not (Test-Path -LiteralPath $TargetPath)) {
    throw "ST Launcher option 1 script was not found: $TargetPath"
}
if (-not (Test-Path -LiteralPath $FilterScript)) {
    throw "Integration filter was not found: $FilterScript"
}
$preflightDotGit = Join-Path $LauncherRoot '.git'
$preflightGitDir = $null
if (Test-Path -LiteralPath $preflightDotGit -PathType Container) {
    $preflightGitDir = $preflightDotGit
} elseif (Test-Path -LiteralPath $preflightDotGit -PathType Leaf) {
    $dotGitText = [System.IO.File]::ReadAllText($preflightDotGit, $StrictUtf8).Trim()
    if ($dotGitText -match '^gitdir: (.+)$') {
        $candidate = $Matches[1]
        $preflightGitDir = if ([System.IO.Path]::IsPathRooted($candidate)) { $candidate } else { Join-Path $LauncherRoot $candidate }
    }
}
if ($preflightGitDir) {
    $preflightCommonDir = $preflightGitDir
    $commonDirFile = Join-Path $preflightGitDir 'commondir'
    if (Test-Path -LiteralPath $commonDirFile -PathType Leaf) {
        $commonDirText = [System.IO.File]::ReadAllText($commonDirFile, $StrictUtf8).Trim()
        $preflightCommonDir = if ([System.IO.Path]::IsPathRooted($commonDirText)) { $commonDirText } else { Join-Path $preflightGitDir $commonDirText }
    }
    $preflightConfigPath = Join-Path $preflightCommonDir 'config'
    if (Test-Path -LiteralPath $preflightConfigPath -PathType Leaf) {
        Assert-ReservedManagedConfigSentinelShape ([System.IO.File]::ReadAllBytes($preflightConfigPath))
    }
}
$repoRoot = (Invoke-Git @('rev-parse', '--show-toplevel')).Output[0]
if (-not (Test-StMobilePathEqual $repoRoot $LauncherRoot)) {
    throw "LauncherRoot is not the Git worktree root: expected $LauncherRoot, got $repoRoot"
}
$gitDirText = (Invoke-Git @('rev-parse', '--git-dir')).Output[0]
$gitDir = if ([System.IO.Path]::IsPathRooted($gitDirText)) { $gitDirText } else { Join-Path $LauncherRoot $gitDirText }
$gitConfigText = (Invoke-Git @('rev-parse', '--git-path', 'config')).Output[0]
$GitConfigPath = if ([System.IO.Path]::IsPathRooted($gitConfigText)) { $gitConfigText } else { Join-Path $LauncherRoot $gitConfigText }
$gitIndexText = (Invoke-Git @('rev-parse', '--git-path', 'index')).Output[0]
$GitIndexPath = if ([System.IO.Path]::IsPathRooted($gitIndexText)) { $gitIndexText } else { Join-Path $LauncherRoot $gitIndexText }
$InfoAttributes = Join-Path $gitDir 'info\attributes'
$IntegrationLockPath = Join-Path $gitDir 'st-mobile-auth-hub.integration.lock'
try {
    $IntegrationLock = [System.IO.File]::Open(
        $IntegrationLockPath,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None)
} catch {
    throw "Another ST Mobile launcher integration operation owns the repository lock $IntegrationLockPath`: $($_.Exception.Message)"
}
$filterPathForGit = $FilterScript.Replace('\', '/')
$filterPathArgument = if ($filterPathForGit -match '\s') { '"' + $filterPathForGit + '"' } else { $filterPathForGit }
$cleanCommand = 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File {0} -Mode Clean' -f $filterPathArgument
$smudgeCommand = 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File {0} -Mode Smudge' -f $filterPathArgument
$legacyCleanCommand = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {0} -Mode Clean' -f $filterPathArgument
$legacySmudgeCommand = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {0} -Mode Smudge' -f $filterPathArgument
$newConfig = [ordered]@{
    "filter.$FilterName.clean" = $cleanCommand
    "filter.$FilterName.smudge" = $smudgeCommand
    "filter.$FilterName.required" = 'true'
}
$legacyConfig = [ordered]@{
    "filter.$LegacyFilterName.clean" = $legacyCleanCommand
    "filter.$LegacyFilterName.smudge" = $legacySmudgeCommand
    "filter.$LegacyFilterName.required" = 'true'
}
$allConfigKeys = @($newConfig.Keys) + @($legacyConfig.Keys)

function Get-FilterNamespaceKeys {
    $result = Invoke-Git @(
        'config', '--local', '--name-only', '--get-regexp',
        "^filter\.($([regex]::Escape($FilterName))|$([regex]::Escape($LegacyFilterName)))\.") -AllowFailure
    if ($result.ExitCode -eq 1) {
        return @()
    }
    if ($result.ExitCode -ne 0) {
        throw 'Could not enumerate the complete owned and legacy Git filter namespaces.'
    }
    return @($result.Output | ForEach-Object { ([string]$_).Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique)
}

function Get-ConfigSnapshot {
    $snapshot = [ordered]@{}
    $keys = @($allConfigKeys) + @(Get-FilterNamespaceKeys) | Sort-Object -Unique
    foreach ($key in $keys) {
        $snapshot[$key] = @(Get-ConfigValues $key)
    }
    return $snapshot
}

function Get-ConfigState([object]$Snapshot) {
    $extraKeys = @($Snapshot.Keys | Where-Object { $allConfigKeys -notcontains $_ })
    if ($extraKeys.Count -gt 0) {
        return 'conflict'
    }
    $newExact = $true
    $newAbsent = $true
    foreach ($key in $newConfig.Keys) {
        $values = @($Snapshot[$key])
        $newExact = $newExact -and (Test-ExactSingleValue $values $newConfig[$key])
        $newAbsent = $newAbsent -and $values.Count -eq 0
    }
    $legacyExact = $true
    $legacyAbsent = $true
    foreach ($key in $legacyConfig.Keys) {
        $values = @($Snapshot[$key])
        $legacyExact = $legacyExact -and (Test-ExactSingleValue $values $legacyConfig[$key])
        $legacyAbsent = $legacyAbsent -and $values.Count -eq 0
    }
    if ($newExact -and $legacyAbsent) { return 'current' }
    if ($newAbsent -and $legacyExact) { return 'legacy' }
    if ($newAbsent -and $legacyAbsent) { return 'absent' }
    return 'conflict'
}

function Test-ConfigSnapshotsEqual([object]$Left, [object]$Right) {
    $leftKeys = @($Left.Keys | Sort-Object -Unique)
    $rightKeys = @($Right.Keys | Sort-Object -Unique)
    if (-not (Test-StringArraysEqual $leftKeys $rightKeys)) {
        return $false
    }
    foreach ($key in $leftKeys) {
        if (-not (Test-StringArraysEqual @($Left[$key]) @($Right[$key]))) {
            return $false
        }
    }
    return $true
}

function Quote-GitConfigValue([string]$Value) {
    return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
}

function Get-ObservedManagedConfigNames([object]$Snapshot) {
    $desiredNames = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in @($FilterName, $LegacyFilterName)) {
        $hasValues = $false
        foreach ($suffix in @('clean', 'smudge', 'required')) {
            if (@($Snapshot["filter.$name.$suffix"]).Count -gt 0) { $hasValues = $true }
        }
        if ($hasValues) { $desiredNames.Add($name) }
    }
    return @($desiredNames.ToArray())
}

function Get-CanonicalManagedConfigSections([object]$Snapshot, [string]$Newline, [bool]$QuoteValues = $true) {
    $desiredNames = @(Get-ObservedManagedConfigNames $Snapshot)
    if ($desiredNames.Count -eq 0) { return '' }
    $blockLines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in $desiredNames) {
        $blockLines.Add("[filter `"$name`"]")
        foreach ($suffix in @('clean', 'smudge', 'required')) {
            foreach ($value in @($Snapshot["filter.$name.$suffix"])) {
                $serialized = if ($suffix -eq 'required' -and [string]$value -ceq 'true') {
                    'true'
                } elseif ($QuoteValues) {
                    Quote-GitConfigValue ([string]$value)
                } else {
                    ([string]$value).Replace('\', '\\').Replace('"', '\"')
                }
                $blockLines.Add("`t$suffix = $serialized")
            }
        }
    }
    $blockLines.Add('')
    return ($blockLines -join $Newline)
}

function Get-CanonicalManagedConfigBlock([object]$Snapshot) {
    $sections = Get-CanonicalManagedConfigSections $Snapshot "`r`n"
    if ([string]::IsNullOrEmpty($sections)) { return '' }
    return '# >>> ST MOBILE AUTH HUB FILTER CONFIG (managed)' + "`r`n" +
        $sections + '# <<< ST MOBILE AUTH HUB FILTER CONFIG (managed)' + "`r`n"
}

function Get-OwnedConfigSectionMatches([string]$Text) {
    $matches = New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in @($FilterName, $LegacyFilterName)) {
        $escaped = [regex]::Escape($name)
        $sectionPattern = '(?ims)^[\t ]*\[filter(?:[\t ]+["'']?' + $escaped + '["'']?|\.' + $escaped + ')\][^\r\n]*(?:\r?\n|$).*?(?=^[\t ]*\[|\z)'
        foreach ($match in [regex]::Matches($Text, $sectionPattern)) { $matches.Add($match) }
    }
    return @($matches | Sort-Object Index)
}

function Get-ValidatedManagedConfigBlock([byte[]]$BaseBytes, [object]$ObservedSnapshot) {
    Assert-ReservedManagedConfigSentinelShape $BaseBytes
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $text = $latin1.GetString($BaseBytes)
    $beginMarker = '# >>> ST MOBILE AUTH HUB FILTER CONFIG (managed)'
    $endMarker = '# <<< ST MOBILE AUTH HUB FILTER CONFIG (managed)'
    $beginCount = [regex]::Matches($text, [regex]::Escape($beginMarker)).Count
    $endCount = [regex]::Matches($text, [regex]::Escape($endMarker)).Count
    if ($beginCount -eq 0 -and $endCount -eq 0) {
        $ownedSections = @(Get-OwnedConfigSectionMatches $text)
        $observedNames = @(Get-ObservedManagedConfigNames $ObservedSnapshot)
        if ($observedNames.Count -eq 0) {
            if ($ownedSections.Count -ne 0) {
                throw 'Reserved Git config namespace has an empty, comment-only, or otherwise unowned section.'
            }
            return $null
        }
        if ($observedNames.Count -ne 1 -or $ownedSections.Count -ne 1) {
            throw "Pre-marker Git config namespace must have exactly one observed canonical section (names=$($observedNames.Count) sections=$($ownedSections.Count))."
        }
        $expectedCrLf = Get-CanonicalManagedConfigSections $ObservedSnapshot "`r`n"
        $expectedLf = Get-CanonicalManagedConfigSections $ObservedSnapshot "`n"
        $expectedLegacyCrLf = Get-CanonicalManagedConfigSections $ObservedSnapshot "`r`n" $false
        $expectedLegacyLf = Get-CanonicalManagedConfigSections $ObservedSnapshot "`n" $false
        $ownedSection = $ownedSections[0]
        if ($ownedSection.Value -cne $expectedCrLf -and $ownedSection.Value -cne $expectedLf -and
            $ownedSection.Value -cne $expectedLegacyCrLf -and $ownedSection.Value -cne $expectedLegacyLf) {
            throw 'Pre-marker Git config namespace is not the byte-exact canonical serialization for the observed state.'
        }
        return [pscustomobject]@{ Index = $ownedSection.Index; Length = $ownedSection.Length }
    } elseif ($beginCount -ne 1 -or $endCount -ne 1) {
        throw "Reserved managed Git config sentinels are missing, duplicated, nested, or malformed (begin=$beginCount end=$endCount)."
    } else {
        $expectedObservedBlock = Get-CanonicalManagedConfigBlock $ObservedSnapshot
        if ([string]::IsNullOrEmpty($expectedObservedBlock)) {
            throw 'Managed Git config block exists while the observed owned namespace is absent.'
        }
        $blockIndex = $text.IndexOf($expectedObservedBlock, [System.StringComparison]::Ordinal)
        if ($blockIndex -lt 0 -or $blockIndex -ne $text.LastIndexOf($expectedObservedBlock, [System.StringComparison]::Ordinal)) {
            throw 'Managed Git config block is not the byte-exact canonical block for the observed installed state.'
        }
        $remainingText = $text.Remove($blockIndex, $expectedObservedBlock.Length)
        if (@(Get-OwnedConfigSectionMatches $remainingText).Count -ne 0) {
            throw 'Reserved Git config namespace exists outside the exact canonical managed block.'
        }
        return [pscustomobject]@{ Index = $blockIndex; Length = $expectedObservedBlock.Length }
    }
}

function New-ConfigBytesFromBase([byte[]]$BaseBytes, [object]$DesiredSnapshot, [object]$ObservedSnapshot) {
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $text = $latin1.GetString($BaseBytes)
    $managedBlock = Get-ValidatedManagedConfigBlock $BaseBytes $ObservedSnapshot
    if ($null -ne $managedBlock) {
        $text = $text.Remove($managedBlock.Index, $managedBlock.Length)
    }
    [byte[]]$cleanBytes = $latin1.GetBytes($text)
    $block = Get-CanonicalManagedConfigBlock $DesiredSnapshot
    if ([string]::IsNullOrEmpty($block)) { return ,$cleanBytes }
    $newlineBytes = if ($cleanBytes.Length -gt 0 -and $cleanBytes[$cleanBytes.Length - 1] -ne 10) {
        $StrictUtf8.GetBytes("`r`n")
    } else { [byte[]]@() }
    [byte[]]$blockBytes = $StrictUtf8.GetBytes($block)
    return ,[byte[]]($cleanBytes + $newlineBytes + $blockBytes)
}

function Get-WrittenConfigSnapshot {
    $snapshot = [ordered]@{}
    foreach ($key in $allConfigKeys) {
        if ($Mode -eq 'Install' -and $newConfig.Contains($key)) {
            $snapshot[$key] = @([string]$newConfig[$key])
        } else {
            $snapshot[$key] = @()
        }
    }
    return $snapshot
}

function Get-TargetState([string]$Text) {
    $beginCount = [regex]::Matches($Text, '(?m)^REM >>> ST MOBILE AUTH HUB INTEGRATION \(managed\)\r?$').Count
    $endCount = [regex]::Matches($Text, '(?m)^REM <<< ST MOBILE AUTH HUB INTEGRATION \(managed\)\r?$').Count
    $clean = Invoke-Filter 'Clean' $Text
    if ($beginCount -eq 0 -and $endCount -eq 0) {
        return [pscustomobject]@{ State = 'absent'; CleanText = $clean }
    }
    if ($beginCount -ne 1 -or $endCount -ne 1) {
        throw "Target integration markers are missing or duplicated (begin=$beginCount end=$endCount)."
    }
    $baseState = if ($Text -match '(?m)^powershell\.exe .* -WindowStyle Hidden .*Launch-StMobileTray\.ps1') { 'current' } else { 'legacy' }
    $markerIndex = $Text.IndexOf('REM >>> ST MOBILE AUTH HUB INTEGRATION (managed)', [System.StringComparison]::Ordinal)
    $oldAnchorIndex = $Text.IndexOf('REM Clear the old log file if it exists', [System.StringComparison]::Ordinal)
    $newAnchor = [regex]::Match($Text, '(?m)^if %ps_errorlevel% equ 0 \(\r?\n')
    $isAtNewAnchor = $newAnchor.Success -and $markerIndex -eq ($newAnchor.Index + $newAnchor.Length)
    $state = if (-not $isAtNewAnchor -and $markerIndex -ge 0 -and $oldAnchorIndex -ge 0 -and $markerIndex -lt $oldAnchorIndex) {
        "migration-$baseState"
    } else {
        $baseState
    }
    return [pscustomobject]@{ State = $state; CleanText = $clean }
}

$attributeExisted = Test-Path -LiteralPath $InfoAttributes
$originalAttributes = if ($attributeExisted) { Get-StrictUtf8File $InfoAttributes } else { [pscustomobject]@{ Bytes = [byte[]]@(); Text = '' } }
$attributeState = Get-AttributeState $originalAttributes.Text
$preConfigBytes = [System.IO.File]::ReadAllBytes($GitConfigPath)
Assert-ReservedManagedConfigSentinelShape $preConfigBytes
$configSnapshot = Get-ConfigSnapshot
[void](Get-ValidatedManagedConfigBlock $preConfigBytes $configSnapshot)
$configState = Get-ConfigState $configSnapshot
if ($configState -eq 'conflict') {
    throw 'Launcher integration ownership state is mixed or modified: config=conflict'
}

$originalTarget = Get-StrictUtf8File $TargetPath
$targetState = Get-TargetState $originalTarget.Text
$cleanTargetBytes = $StrictUtf8.GetBytes($targetState.CleanText)
$effectiveFilterLine = Assert-EffectiveTargetFilter $attributeState.State
$cleanTargetBlobId = Get-GitBlobIdForText -Text $targetState.CleanText
$headBlobId = ((Invoke-Git @('rev-parse', "HEAD:$TargetRelative")).Output[0]).Trim()
if ($cleanTargetBlobId -cne $headBlobId) {
    $cleanCrLf = [regex]::Matches($targetState.CleanText, "`r`n").Count
    $cleanLf = [regex]::Matches($targetState.CleanText, "(?<!`r)`n").Count
    $firstCodePoint = if ($targetState.CleanText.Length) { [int][char]$targetState.CleanText[0] } else { -1 }
    $lastCodePoint = if ($targetState.CleanText.Length) { [int][char]$targetState.CleanText[$targetState.CleanText.Length - 1] } else { -1 }
    throw "Option 1 script has non-managed Git blob changes; refusing to install or remove the integration (clean_blob=$cleanTargetBlobId head_blob=$headBlobId chars=$($targetState.CleanText.Length) crlf=$cleanCrLf lf=$cleanLf first=$firstCodePoint last=$lastCodePoint)."
}
$originalIndexEntry = @((Invoke-Git @('ls-files', '--stage', '--', $TargetRelative)).Output)
if ($originalIndexEntry.Count -ne 1 -or [string]$originalIndexEntry[0] -notmatch "^[0-7]{6} $([regex]::Escape($headBlobId)) 0\t$([regex]::Escape($TargetRelative))$") {
    throw 'Option 1 script index entry is missing, unmerged, or does not exactly name the HEAD blob.'
}

$cachedDiff = Invoke-Git @('diff', '--cached', '--quiet', '--', $TargetRelative) -AllowFailure
if ($cachedDiff.ExitCode -ne 0) {
    throw 'Option 1 script has staged changes; refusing to install or remove the integration.'
}
$configFileExisted = Test-Path -LiteralPath $GitConfigPath
$originalConfigBytes = if ($configFileExisted) { [System.IO.File]::ReadAllBytes($GitConfigPath) } else { [byte[]]@() }
$indexFileExisted = Test-Path -LiteralPath $GitIndexPath
$originalIndexBytes = if ($indexFileExisted) { [System.IO.File]::ReadAllBytes($GitIndexPath) } else { [byte[]]@() }
$targetIdentity = [StMobile.PinnedFileOperations]::InspectExact($TargetPath, $originalTarget.Bytes, '', '')
$attributeParentToken = Get-PinnedParentToken $InfoAttributes
$attributeIdentity = if ($attributeExisted) {
    [StMobile.PinnedFileOperations]::InspectExact($InfoAttributes, $originalAttributes.Bytes, $attributeParentToken, '')
} else { $null }
$configIdentity = [StMobile.PinnedFileOperations]::InspectExact($GitConfigPath, $originalConfigBytes, '', '')
$indexIdentity = [StMobile.PinnedFileOperations]::InspectExact($GitIndexPath, $originalIndexBytes, '', '')

function Assert-PreMutationSnapshotStillExact {
    try {
        [void][StMobile.PinnedFileOperations]::InspectExact(
            $TargetPath, $originalTarget.Bytes, $targetIdentity.ParentToken, $targetIdentity.FileToken)
    } catch {
        throw 'target generation changed after snapshot; refusing mutation'
    }
    $currentAttributeExists = Test-Path -LiteralPath $InfoAttributes -PathType Leaf
    if ($currentAttributeExists -ne $attributeExisted) {
        throw 'attributes generation changed after snapshot; refusing mutation'
    }
    if ((Get-PinnedParentToken $InfoAttributes) -cne $attributeParentToken) {
        throw 'attributes parent generation changed after snapshot; refusing mutation'
    }
    if ($attributeExisted) {
        try {
            [void][StMobile.PinnedFileOperations]::InspectExact(
                $InfoAttributes, $originalAttributes.Bytes, $attributeParentToken, $attributeIdentity.FileToken)
        } catch { throw 'attributes generation changed after snapshot; refusing mutation' }
    }
    try {
        [void][StMobile.PinnedFileOperations]::InspectExact(
            $GitConfigPath, $originalConfigBytes, $configIdentity.ParentToken, $configIdentity.FileToken)
    } catch {
        throw 'Git config generation changed after snapshot; refusing mutation'
    }
    try {
        [void][StMobile.PinnedFileOperations]::InspectExact(
            $GitIndexPath, $originalIndexBytes, $indexIdentity.ParentToken, $indexIdentity.FileToken)
    } catch {
        throw 'Git index generation changed after snapshot; refusing mutation'
    }
    $currentConfigSnapshot = Get-ConfigSnapshot
    if (-not (Test-ConfigSnapshotsEqual $currentConfigSnapshot $configSnapshot)) {
        throw 'owned Git config namespace changed after snapshot; refusing mutation'
    }
    $currentIndexEntry = @((Invoke-Git @('ls-files', '--stage', '--', $TargetRelative)).Output)
    if ($currentIndexEntry.Count -ne 1 -or [string]$currentIndexEntry[0] -cne [string]$originalIndexEntry[0]) {
        throw 'target index entry changed after snapshot; refusing mutation'
    }
    [void](Assert-EffectiveTargetFilter $attributeState.State)
}

function Refresh-TargetIndexStatWithoutChangingEntries {
    $beforeEntries = @((Invoke-Git @('ls-files', '--stage')).Output | ForEach-Object { [string]$_ })
    $beforeTarget = @((Invoke-Git @('ls-files', '--stage', '--', $TargetRelative)).Output)
    if ($beforeTarget.Count -ne 1 -or [string]$beforeTarget[0] -cne [string]$originalIndexEntry[0]) {
        throw 'Target index entry changed before Git-owned stat refresh.'
    }
    [void](Invoke-Git @('add', '--', $TargetRelative))
    $afterEntries = @((Invoke-Git @('ls-files', '--stage')).Output | ForEach-Object { [string]$_ })
    if (-not (Test-StringArraysEqual $beforeEntries $afterEntries)) {
        throw 'Git-owned target stat refresh changed staged entries; refusing success.'
    }
}

$overallState = if ($targetState.State -eq 'absent' -and $attributeState.State -eq 'absent' -and $configState -eq 'absent') {
    'absent'
} elseif ($targetState.State -eq 'current' -and $attributeState.State -eq 'current' -and $configState -eq 'current') {
    'current'
} elseif ($targetState.State -eq 'legacy' -and $attributeState.State -eq 'legacy' -and $configState -eq 'legacy') {
    'legacy'
} elseif ($targetState.State -eq 'migration-current' -and $attributeState.State -eq 'current' -and $configState -eq 'current') {
    'migration'
} elseif ($targetState.State -eq 'migration-legacy' -and $attributeState.State -eq 'legacy' -and $configState -eq 'legacy') {
    'migration'
} else {
    'conflict'
}
if ($overallState -eq 'conflict') {
    throw "Launcher integration ownership state is mixed or modified: target=$($targetState.State) attributes=$($attributeState.State) config=$configState"
}
$gitStatus = Get-TargetGitStatus

function New-StatusObject([string]$State, [string]$TargetStatus, [string]$AttributeStatus, [string]$ConfigStatus, [string]$GitStatus) {
    return [pscustomobject]@{
        state = $State
        markerPresent = $TargetStatus -in @('current', 'legacy')
        markerState = $TargetStatus
        attributePresent = $AttributeStatus -in @('current', 'legacy')
        attributeState = $AttributeStatus
        configState = $ConfigStatus
        cleanFilterMatches = $ConfigStatus -eq 'current'
        smudgeFilterMatches = $ConfigStatus -eq 'current'
        filterRequired = $ConfigStatus -eq 'current'
        targetGitClean = [string]::IsNullOrWhiteSpace($GitStatus)
        targetGitStatus = $GitStatus
        target = $TargetPath
        attributes = $InfoAttributes
        filterName = $FilterName
    }
}

if ($Mode -eq 'Status') {
    $roundTripSmudgedText = Invoke-Filter 'Smudge' $targetState.CleanText
    $roundTripCleanText = Invoke-Filter 'Clean' $roundTripSmudgedText
    $roundTripBlobId = Get-GitBlobIdForText -Text $roundTripCleanText
    if ($roundTripBlobId -cne $headBlobId) {
        throw "Launcher integration filter round-trip produced the wrong blob (round_trip_blob=$roundTripBlobId head_blob=$headBlobId)."
    }
    $status = New-StatusObject $overallState $targetState.State $attributeState.State $configState $gitStatus
    $status | Add-Member -NotePropertyName managedConfig -NotePropertyValue $configSnapshot
    $status | Add-Member -NotePropertyName effectiveFilter -NotePropertyValue $effectiveFilterLine
    $status | Add-Member -NotePropertyName cleanBlobId -NotePropertyValue $cleanTargetBlobId
    $status | Add-Member -NotePropertyName headBlobId -NotePropertyValue $headBlobId
    $status | Add-Member -NotePropertyName roundTripBlobId -NotePropertyValue $roundTripBlobId
    $status | ConvertTo-Json -Depth 8 -Compress
    $IntegrationLock.Dispose()
    exit 0
}

$smudgedText = Invoke-Filter 'Smudge' $targetState.CleanText
$smudgedBytes = $StrictUtf8.GetBytes($smudgedText)
$installedAttributesText = Add-CurrentAttributeBlock $attributeState.CleanText
$installedAttributesBytes = $StrictUtf8.GetBytes($installedAttributesText)
$writtenTargetBytes = if ($Mode -eq 'Install') { $smudgedBytes } else { $cleanTargetBytes }
$writtenAttributesExist = $Mode -eq 'Install' -or $attributeState.CleanText.Length -gt 0
$writtenAttributesBytes = if ($Mode -eq 'Install') {
    $installedAttributesBytes
} elseif ($attributeState.CleanText.Length -gt 0) {
    $StrictUtf8.GetBytes($attributeState.CleanText)
} else {
    [byte[]]@()
}
if ($WhatIf) {
    [pscustomobject]@{
        mode = $Mode
        currentState = $overallState
        target = $TargetPath
        wouldConfigureLocalGitFilter = ($Mode -eq 'Install')
        wouldInsertTrayLaunch = ($Mode -eq 'Install')
        wouldRemoveOnlyExactOwnedIntegration = ($Mode -eq 'Remove')
    } | ConvertTo-Json -Compress
    $IntegrationLock.Dispose()
    exit 0
}

$writtenConfigSnapshot = Get-WrittenConfigSnapshot
$writtenConfigBytes = New-ConfigBytesFromBase $originalConfigBytes $writtenConfigSnapshot $configSnapshot

$backupRoot = Join-Path $BackupBase ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
[System.IO.File]::WriteAllBytes((Join-Path $backupRoot 'update_start_st.bat.before'), $originalTarget.Bytes)
if ($attributeExisted) {
    [System.IO.File]::WriteAllBytes((Join-Path $backupRoot 'info.attributes.before'), $originalAttributes.Bytes)
}
$configSnapshot | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $backupRoot 'git-filter-config.before.json') -Encoding UTF8
if ($configFileExisted) {
    [System.IO.File]::WriteAllBytes((Join-Path $backupRoot 'git-config.before'), $originalConfigBytes)
}
if ($indexFileExisted) {
    [System.IO.File]::WriteAllBytes((Join-Path $backupRoot 'git-index.before'), $originalIndexBytes)
}

function Restore-ConfigGeneration([object]$Token) {
    if (-not (Test-Path -LiteralPath $GitConfigPath -PathType Leaf)) {
        throw 'Git config disappeared after publication'
    }
    $currentBytes = [System.IO.File]::ReadAllBytes($GitConfigPath)
    if (Test-BytesEqual $currentBytes $Token.DesiredBytes) {
        Undo-FileGenerationCas $Token
        return
    }

    $currentSnapshot = Get-ConfigSnapshot
    if (-not (Test-ConfigSnapshotsEqual $currentSnapshot $writtenConfigSnapshot)) {
        throw 'owned Git config namespace changed after publication; refusing to overwrite foreign values'
    }
    $restoredBytes = New-ConfigBytesFromBase $currentBytes $configSnapshot $currentSnapshot
    $currentIdentity = [StMobile.PinnedFileOperations]::InspectExact(
        $GitConfigPath, $currentBytes, $Token.PriorParentToken, '')
    $restoreToken = Set-FileGenerationCas `
        $GitConfigPath $true $currentBytes $true $restoredBytes 'Git config rollback' `
        $currentIdentity.ParentToken $currentIdentity.FileToken
    Complete-FileGenerationCas $restoreToken
    Complete-FileGenerationCas $Token
    $restoredSnapshot = Get-ConfigSnapshot
    if (-not (Test-ConfigSnapshotsEqual $restoredSnapshot $configSnapshot)) {
        throw 'owned Git config namespace did not match its snapshot after CAS rollback'
    }
}

$mutationTokens = New-Object 'System.Collections.Generic.List[object]'

function Restore-OwnedSnapshot {
    $restoreErrors = New-Object 'System.Collections.Generic.List[string]'
    for ($index = $mutationTokens.Count - 1; $index -ge 0; $index--) {
        $token = $mutationTokens[$index]
        try {
            if ($token.Surface -eq 'Git config') {
                Restore-ConfigGeneration $token
            } else {
                Undo-FileGenerationCas $token
            }
        } catch {
            $restoreErrors.Add("$($token.Surface): $($_.Exception.Message)")
            try {
                Complete-FileGenerationCas $token
            } catch {
                $restoreErrors.Add("$($token.Surface) quarantine cleanup: $($_.Exception.Message)")
            }
        }
    }
    if ($restoreErrors.Count -eq 0 -and $mutationTokens.Count -gt 0) {
        try { Refresh-TargetIndexStatWithoutChangingEntries } catch { $restoreErrors.Add("Git index stat rollback: $($_.Exception.Message)") }
    }
    if ($restoreErrors.Count -gt 0) {
        throw ($restoreErrors -join '; ')
    }
}

try {
    # TEST-HARNESS-ANCHOR: after-snapshots
    Assert-PreMutationSnapshotStillExact
    $mutationTokens.Add((Set-FileGenerationCas `
        $TargetPath $true $originalTarget.Bytes $true $writtenTargetBytes 'target' `
        $targetIdentity.ParentToken $targetIdentity.FileToken))
    # TEST-HARNESS-ANCHOR: after-target-publication
    $mutationTokens.Add((Set-FileGenerationCas `
        $InfoAttributes $attributeExisted $originalAttributes.Bytes $writtenAttributesExist $writtenAttributesBytes 'attributes' `
        $attributeParentToken $(if ($attributeIdentity) { $attributeIdentity.FileToken } else { '' })))
    # TEST-HARNESS-ANCHOR: after-attributes-publication
    $mutationTokens.Add((Set-FileGenerationCas `
        $GitConfigPath $configFileExisted $originalConfigBytes $true $writtenConfigBytes 'Git config' `
        $configIdentity.ParentToken $configIdentity.FileToken))
    # TEST-HARNESS-ANCHOR: after-config-publication
    Refresh-TargetIndexStatWithoutChangingEntries
    # TEST-HARNESS-ANCHOR: after-index-publication
    [void](Assert-EffectiveTargetFilter $(if ($Mode -eq 'Install') { 'current' } else { 'absent' }))
    # TEST-HARNESS-ANCHOR: after-effective-attributes
    $writtenTargetText = $StrictUtf8.GetString([System.IO.File]::ReadAllBytes($TargetPath))
    $writtenCleanBlobId = Get-GitBlobIdForText -Text $writtenTargetText
    if ($writtenCleanBlobId -cne $headBlobId) {
        throw "Launcher integration clean filter produced the wrong blob (clean_blob=$writtenCleanBlobId head_blob=$headBlobId)."
    }
    $afterWorktree = Invoke-Git @('diff', '--quiet', '--', $TargetRelative) -AllowFailure
    if ($afterWorktree.ExitCode -ne 0) {
        throw 'Launcher integration did not produce a filter-clean worktree target.'
    }
    $afterCached = Invoke-Git @('diff', '--cached', '--quiet', '--', $TargetRelative) -AllowFailure
    if ($afterCached.ExitCode -ne 0) {
        throw 'Launcher integration unexpectedly changed the staged target blob.'
    }

    $finalTarget = Get-StrictUtf8File $TargetPath
    $finalTargetState = Get-TargetState $finalTarget.Text
    $finalAttributeText = if (Test-Path -LiteralPath $InfoAttributes) { (Get-StrictUtf8File $InfoAttributes).Text } else { '' }
    $finalAttributeState = Get-AttributeState $finalAttributeText
    $finalConfigState = Get-ConfigState (Get-ConfigSnapshot)
    $finalGitStatus = Get-TargetGitStatus
    $finalOverall = if ($finalTargetState.State -eq 'current' -and $finalAttributeState.State -eq 'current' -and $finalConfigState -eq 'current') {
        'current'
    } elseif ($finalTargetState.State -eq 'absent' -and $finalAttributeState.State -eq 'absent' -and $finalConfigState -eq 'absent') {
        'absent'
    } else {
        'conflict'
    }
    $expected = if ($Mode -eq 'Install') { 'current' } else { 'absent' }
    $final = New-StatusObject $finalOverall $finalTargetState.State $finalAttributeState.State $finalConfigState $finalGitStatus
    if ($finalOverall -ne $expected -or -not $final.targetGitClean) {
        throw "Launcher integration final readback failed: $($final | ConvertTo-Json -Compress)"
    }
    foreach ($token in $mutationTokens) {
        Complete-FileGenerationCas $token
    }
    $final | Add-Member -NotePropertyName mode -NotePropertyValue $Mode
    $final | Add-Member -NotePropertyName backup -NotePropertyValue $backupRoot
    $final | ConvertTo-Json -Compress
} catch {
    $failure = $_.Exception.Message
    try {
        Restore-OwnedSnapshot
    } catch {
        throw "Launcher integration failed: $failure. Compare-and-swap rollback also failed: $($_.Exception.Message). Backup: $backupRoot"
    }
    throw "Launcher integration failed and owned state was rolled back: $failure. Backup: $backupRoot"
} finally {
    $IntegrationLock.Dispose()
}
