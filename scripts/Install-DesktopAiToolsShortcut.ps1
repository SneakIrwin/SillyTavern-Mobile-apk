param(
    [ValidateSet('Install', 'Status')][string]$Mode = 'Install',
    [string]$AiToolsDirectory = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)) 'AI Tools')
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$OpenScript = Join-Path $PSScriptRoot 'Open-StMobileAuthHub.ps1'
$PowerShellExe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$ShortcutPath = Join-Path $AiToolsDirectory 'SillyTavern Mobile Auth Hub.lnk'
$LauncherIcon = 'C:\Users\Sneak\SillyTavern-Launcher\SillyTavern-Launcher\st-launcher.ico'
$Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$OpenScript`""

if (-not (Test-Path -LiteralPath $AiToolsDirectory -PathType Container)) {
    if ($Mode -eq 'Status') { throw "AI Tools directory is missing: $AiToolsDirectory" }
    New-Item -ItemType Directory -Path $AiToolsDirectory | Out-Null
}
if ((Get-Item -LiteralPath $AiToolsDirectory -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw "AI Tools directory is a reparse point; refusing shortcut mutation: $AiToolsDirectory"
}

$shell = New-Object -ComObject WScript.Shell
function Read-Shortcut([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $item = $shell.CreateShortcut($Path)
    [pscustomobject]@{
        target = [System.IO.Path]::GetFullPath($item.TargetPath)
        arguments = [string]$item.Arguments
        workingDirectory = [string]$item.WorkingDirectory
        iconLocation = [string]$item.IconLocation
    }
}

$current = Read-Shortcut $ShortcutPath
$isCurrent = $current `
    -and $current.target -ceq $PowerShellExe `
    -and $current.arguments -ceq $Arguments `
    -and $current.workingDirectory -ceq $ProjectRoot `
    -and $current.iconLocation -ceq "$LauncherIcon,0"
if ($Mode -eq 'Status') {
    [pscustomobject]@{ state = $(if ($isCurrent) { 'current' } elseif ($current) { 'legacy_or_foreign' } else { 'absent' }); path = $ShortcutPath; target = $current.target; arguments = $current.arguments } | ConvertTo-Json -Compress
    exit $(if ($isCurrent) { 0 } else { 1 })
}
if ($current -and -not $isCurrent) {
    $legacyAllowed = $current.target -ceq 'C:\Windows\explorer.exe' -and $current.arguments -ceq 'http://127.0.0.1:38444/'
    if (-not $legacyAllowed) {
        throw "Refusing to overwrite an unrecognized AI Tools shortcut: $ShortcutPath"
    }
}

$temporaryPath = Join-Path $AiToolsDirectory ('.SillyTavern-Mobile-Auth-Hub.{0}.tmp.lnk' -f ([guid]::NewGuid().ToString('N')))
try {
    $shortcut = $shell.CreateShortcut($temporaryPath)
    $shortcut.TargetPath = $PowerShellExe
    $shortcut.Arguments = $Arguments
    $shortcut.WorkingDirectory = $ProjectRoot
    $shortcut.Description = 'Start or reuse SillyTavern Mobile, then open the authentication hub'
    $shortcut.IconLocation = "$LauncherIcon,0"
    $shortcut.WindowStyle = 7
    $shortcut.Save()
    $staged = Read-Shortcut $temporaryPath
    if (-not $staged -or $staged.target -cne $PowerShellExe -or $staged.arguments -cne $Arguments -or $staged.workingDirectory -cne $ProjectRoot -or $staged.iconLocation -cne "$LauncherIcon,0") {
        throw 'Staged one-click shortcut failed exact readback.'
    }
    Move-Item -LiteralPath $temporaryPath -Destination $ShortcutPath -Force
} finally {
    if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
}

$final = Read-Shortcut $ShortcutPath
if (-not $final -or $final.target -cne $PowerShellExe -or $final.arguments -cne $Arguments -or $final.workingDirectory -cne $ProjectRoot -or $final.iconLocation -cne "$LauncherIcon,0") {
    throw 'Installed one-click shortcut failed final readback.'
}
[pscustomobject]@{ state = 'current'; path = $ShortcutPath; target = $final.target; arguments = $final.arguments } | ConvertTo-Json -Compress
