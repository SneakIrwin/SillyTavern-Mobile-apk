param(
    [string]$GradleVersion = '9.6.1',
    [string]$GradleSha256 = '9c0f7faeeb306cb14e4279a3e084ca6b596894089a0638e68a07c945a32c9e14',
    [string]$JdkVersion = '21.0.11+10',
    [string]$JdkSha256 = 'd3625e7cadf23787ea540229544b6e2ab494b3b54da1801879e583e1dfee0a64',
    [string]$CommandLineToolsRevision = '15641748',
    [string]$CommandLineToolsSha256 = 'f911b4f03fbee117e2d22edb5f51a5efeae4e8c8aa78bb6bd3de4862ae299da6',
    [string]$PlatformToolsVersion = '37.0.3',
    [string]$PlatformToolsSha256 = 'b5d2015f5d5b7a24a2ac646a245f20f63fb501e4174c61863c74bed1df6de4bd'
)

$ErrorActionPreference = 'Stop'
[System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$ToolsRoot = Join-Path $ProjectRoot '.tools'
$DownloadsRoot = Join-Path $ToolsRoot 'downloads'
$JdkRoot = Join-Path $ToolsRoot 'jdk-21'
$SdkRoot = Join-Path $ToolsRoot 'android-sdk'
$GradleRoot = Join-Path $ToolsRoot "gradle-$GradleVersion"
$AndroidRoot = Join-Path $ProjectRoot 'android'
$ApkPath = Join-Path $AndroidRoot 'app\build\outputs\apk\release\app-release.apk'
$UpdateRoot = Join-Path $ProjectRoot 'update'
$UpdateApkName = 'SillyTavern-Mobile-debug.apk'
$UpdateApkPath = Join-Path $UpdateRoot $UpdateApkName
$UpdateManifestPath = Join-Path $UpdateRoot 'latest.json'
$GitHubRawUpdateBase = 'https://raw.githubusercontent.com/SneakIrwin/SillyTavern-Mobile-apk/main/update'
$GatewayCaPath = Join-Path $ProjectRoot 'state\certs\st-mobile-ca.crt'
$AndroidCaPath = Join-Path $AndroidRoot 'app\src\main\res\raw\st_mobile_ca.crt'
$ProtectCertAcls = Join-Path $ProjectRoot 'scripts\Protect-CertAcls.ps1'
$SdkHashManifest = Join-Path $ProjectRoot 'quality\android-sdk-package-hashes.tsv'
$GradleVerificationMetadata = Join-Path $AndroidRoot 'gradle\verification-metadata.xml'
$SigningPolicyPath = Join-Path $ProjectRoot 'quality\release-signing.json'
$SigningStore = if ($env:ST_MOBILE_SIGNING_STORE) { $env:ST_MOBILE_SIGNING_STORE } else { Join-Path $env:USERPROFILE '.android\debug.keystore' }
if (-not (Test-Path -LiteralPath $SigningStore -PathType Leaf)) {
    throw 'The existing signing keystore is required. Restore it or set ST_MOBILE_SIGNING_STORE; never generate a replacement identity for an update.'
}

New-Item -ItemType Directory -Force -Path $ToolsRoot, $DownloadsRoot, $SdkRoot | Out-Null

function Assert-UnderTools([string]$PathToCheck) {
    $resolvedTools = (Resolve-Path $ToolsRoot).Path
    $resolvedPath = if (Test-Path $PathToCheck) {
        (Resolve-Path $PathToCheck).Path
    } else {
        [System.IO.Path]::GetFullPath($PathToCheck)
    }
    $toolsPrefix = $resolvedTools.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolvedPath.StartsWith($toolsPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify path outside tools root: $resolvedPath"
    }
}

function Remove-UnderTools([string]$PathToRemove) {
    if (Test-Path $PathToRemove) {
        Assert-UnderTools $PathToRemove
        Remove-Item -LiteralPath $PathToRemove -Recurse -Force
    }
}

function Download-File([string]$Url, [string]$Destination) {
    if (Test-Path $Destination) {
        return
    }
    Write-Host "Downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
}

function Ensure-Archive([string]$Url, [string]$Destination, [string]$ExpectedSha256, [string]$Name) {
    if (Test-Path $Destination) {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant()
        if ($hash -eq $ExpectedSha256.ToLowerInvariant()) {
            return
        }
        Write-Warning "$Name archive hash mismatch at $Destination. Re-downloading."
        Remove-UnderTools $Destination
    }

    Download-File $Url $Destination
    $downloadedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant()
    if ($downloadedHash -ne $ExpectedSha256.ToLowerInvariant()) {
        throw "$Name archive hash mismatch. Expected $ExpectedSha256, got $downloadedHash"
    }
}

function Ensure-Jdk {
    $jdkTag = "jdk-$($JdkVersion.Replace('+', '%2B'))"
    $jdkArchiveVersion = $JdkVersion.Replace('+', '_')
    $jdkUrl = "https://github.com/adoptium/temurin21-binaries/releases/download/$jdkTag/OpenJDK21U-jdk_x64_windows_hotspot_$jdkArchiveVersion.zip"
    $zip = Join-Path $DownloadsRoot 'temurin-jdk-21.zip'
    Ensure-Archive $jdkUrl $zip $JdkSha256 "Temurin JDK $JdkVersion"

    $tmp = Join-Path $ToolsRoot 'jdk-extract'
    Remove-UnderTools $tmp
    Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force
    $extracted = Get-ChildItem -LiteralPath $tmp -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'bin\java.exe') } | Select-Object -First 1
    if (-not $extracted) {
        throw 'Downloaded JDK archive did not contain bin\java.exe'
    }
    Remove-UnderTools $JdkRoot
    Move-Item -LiteralPath $extracted.FullName -Destination $JdkRoot | Out-Null
    Remove-UnderTools $tmp
    $releasePath = Join-Path $JdkRoot 'release'
    $releaseText = if (Test-Path $releasePath) { Get-Content -LiteralPath $releasePath -Raw } else { '' }
    if ($releaseText -notmatch "SEMANTIC_VERSION=`"$([regex]::Escape($JdkVersion))`"") {
        throw "Extracted JDK release metadata did not match $JdkVersion"
    }
    $java = Join-Path $JdkRoot 'bin\java.exe'
    if (-not (Test-Path $java)) {
        throw "Extracted JDK is missing java.exe at $java"
    }
    return $java
}

function Ensure-AndroidSdk {
    $env:ANDROID_HOME = $SdkRoot
    $env:ANDROID_SDK_ROOT = $SdkRoot
    $sdkManager = Join-Path $SdkRoot 'cmdline-tools\latest\bin\sdkmanager.bat'
    $packageRoots = @('platform-tools', 'platforms\android-36', 'build-tools\36.0.0')
    if (@($packageRoots | Where-Object { -not (Test-Path -LiteralPath (Join-Path $SdkRoot $_) -PathType Container) }).Count -eq 0) {
        # Never update installed packages before verifying their pinned bytes.
        # A new SDK release must be reviewed and repinned deliberately.
        Assert-AndroidSdkPackageHashes
        return $sdkManager
    }
    $zip = Join-Path $DownloadsRoot "commandlinetools-win-$CommandLineToolsRevision`_latest.zip"
    Ensure-Archive "https://dl.google.com/android/repository/commandlinetools-win-$CommandLineToolsRevision`_latest.zip" $zip $CommandLineToolsSha256 "Android command-line tools $CommandLineToolsRevision"

    $sdkManager = Join-Path $SdkRoot 'cmdline-tools\latest\bin\sdkmanager.bat'
    $tmp = Join-Path $ToolsRoot 'cmdline-tools-extract'
    $latest = Join-Path $SdkRoot 'cmdline-tools\latest'
    Remove-UnderTools $tmp
    Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force
    $source = Join-Path $tmp 'cmdline-tools'
    if (-not (Test-Path $source)) {
        throw 'Downloaded Android command-line tools archive did not contain cmdline-tools'
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $latest -Parent) | Out-Null
    Remove-UnderTools $latest
    Move-Item -LiteralPath $source -Destination $latest | Out-Null
    Remove-UnderTools $tmp

    $env:ANDROID_HOME = $SdkRoot
    $env:ANDROID_SDK_ROOT = $SdkRoot

    Write-Host 'Installing only the required Android SDK packages (no blanket license acceptance or updates)'
    & $sdkManager "--sdk_root=$SdkRoot" 'platforms;android-36' 'build-tools;36.0.0'
    if ($LASTEXITCODE -ne 0) {
        throw "sdkmanager failed with exit code $LASTEXITCODE"
    }

    $platformZip = Join-Path $DownloadsRoot "platform-tools-$PlatformToolsVersion.zip"
    Ensure-Archive "https://dl.google.com/android/repository/platform-tools_r$PlatformToolsVersion-win.zip" $platformZip $PlatformToolsSha256 "Android platform tools $PlatformToolsVersion"
    $platformTmp = Join-Path $ToolsRoot 'platform-tools-extract'
    Remove-UnderTools $platformTmp
    Expand-Archive -LiteralPath $platformZip -DestinationPath $platformTmp -Force
    $platformRoot = Join-Path $SdkRoot 'platform-tools'
    Remove-UnderTools $platformRoot
    Move-Item -LiteralPath (Join-Path $platformTmp 'platform-tools') -Destination $platformRoot
    Remove-UnderTools $platformTmp

    Assert-AndroidSdkPackageHashes
    return $sdkManager
}

function Ensure-Gradle {
    $gradle = Join-Path $GradleRoot 'bin\gradle.bat'
    $zip = Join-Path $DownloadsRoot "gradle-$GradleVersion-bin.zip"
    Ensure-Archive "https://services.gradle.org/distributions/gradle-$GradleVersion-bin.zip" $zip $GradleSha256 "Gradle $GradleVersion"
    Remove-UnderTools $GradleRoot
    Expand-Archive -LiteralPath $zip -DestinationPath $ToolsRoot -Force
    if (-not (Test-Path $gradle)) {
        throw 'Gradle archive did not extract to the expected path'
    }
    return $gradle
}

function Sync-GatewayCa {
    $stateRoot = Join-Path $ProjectRoot 'state'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $ProtectCertAcls -CertDir (Join-Path $stateRoot 'certs') -PrivatePath $stateRoot | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Private ACL protection failed with exit code $LASTEXITCODE"
    }

    if (-not (Test-Path $GatewayCaPath)) {
        Write-Host 'Generating gateway CA before Android build'
        $node = Get-Command node.exe -ErrorAction Stop
        & $node.Source (Join-Path $ProjectRoot 'gateway\src\cli.js') info | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Gateway CA generation failed with exit code $LASTEXITCODE"
        }
    }

    if (-not (Test-Path $GatewayCaPath)) {
        throw "Active gateway CA not found at $GatewayCaPath"
    }

    & powershell -NoProfile -ExecutionPolicy Bypass -File $ProtectCertAcls -CertDir (Join-Path $stateRoot 'certs') -PrivatePath $stateRoot | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Private ACL protection failed with exit code $LASTEXITCODE"
    }

    New-Item -ItemType Directory -Force -Path (Split-Path $AndroidCaPath -Parent) | Out-Null
    Copy-Item -LiteralPath $GatewayCaPath -Destination $AndroidCaPath -Force

    $gatewayHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $GatewayCaPath).Hash
    $embeddedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $AndroidCaPath).Hash
    if ($gatewayHash -ne $embeddedHash) {
        throw "Embedded Android CA does not match active gateway CA before build. gateway=$gatewayHash embedded=$embeddedHash"
    }
}

function Assert-AndroidSdkPackageHashes {
    if (-not (Test-Path $SdkHashManifest)) {
        throw "Android SDK hash manifest is missing: $SdkHashManifest"
    }

    $expected = @{}
    foreach ($line in Get-Content -LiteralPath $SdkHashManifest) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
            continue
        }
        $parts = $line -split "`t"
        if ($parts.Count -ne 3) {
            throw "Malformed SDK hash manifest line: $line"
        }
        $expected[$parts[0]] = @{ Sha256 = $parts[1].ToLowerInvariant(); Length = [int64]$parts[2] }
    }

    $packageRoots = @(
        (Join-Path $SdkRoot 'platform-tools'),
        (Join-Path $SdkRoot 'platforms\android-36'),
        (Join-Path $SdkRoot 'build-tools\36.0.0')
    )
    $actualPaths = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($packageRoot in $packageRoots) {
        if (-not (Test-Path $packageRoot)) {
            throw "Android SDK package root missing before hash verification: $packageRoot"
        }
        Get-ChildItem -Recurse -File -LiteralPath $packageRoot | ForEach-Object {
            $relative = $_.FullName.Substring($ProjectRoot.Path.Length + 1).Replace('\', '/')
            # sdkmanager generates this bookkeeping file; the signed archive's
            # executable payload and source.properties remain pinned below.
            if ($relative -eq '.tools/android-sdk/platform-tools/package.xml') { return }
            [void]$actualPaths.Add($relative)
            if (-not $expected.ContainsKey($relative)) {
                throw "Unexpected Android SDK package file not present in manifest: $relative"
            }
            $expectedEntry = $expected[$relative]
            if ($_.Length -ne $expectedEntry.Length) {
                throw "Android SDK package length mismatch for $relative. Expected $($expectedEntry.Length), got $($_.Length)"
            }
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
            if ($hash -ne $expectedEntry.Sha256) {
                throw "Android SDK package hash mismatch for $relative. Expected $($expectedEntry.Sha256), got $hash"
            }
        }
    }
    foreach ($relative in $expected.Keys) {
        if (-not $actualPaths.Contains($relative)) {
            throw "Android SDK package manifest file missing from install: $relative"
        }
    }
    Write-Host "Verified Android SDK package hash manifest: $($expected.Count) files"
}

function Assert-GradleDependencyVerification {
    if (-not (Test-Path $GradleVerificationMetadata)) {
        throw "Gradle dependency verification metadata missing: $GradleVerificationMetadata"
    }
    $verificationText = Get-Content -LiteralPath $GradleVerificationMetadata -Raw
    foreach ($needle in @('com.android.application.gradle.plugin', 'gradle-', '<sha256 value=')) {
        if ($verificationText -notmatch [regex]::Escape($needle)) {
            throw "Gradle dependency verification metadata is missing expected marker: $needle"
        }
    }
}

function Assert-ApkCaMatchesGateway {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $extractDir = Join-Path $ToolsRoot 'apk-ca-check'
    Remove-UnderTools $extractDir
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    $extractPath = Join-Path $extractDir 'st_mobile_ca.crt'
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ApkPath)
    try {
        # Release resource optimization renames physical entries. Resolve the
        # actual raw/st_mobile_ca resource rather than assuming a ZIP pathname.
        $aapt2 = Join-Path $SdkRoot 'build-tools\36.0.0\aapt2.exe'
        $resources = @(& $aapt2 dump resources $ApkPath 2>&1) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw 'Could not inspect APK resource mapping.' }
        $mapping = [regex]::Matches($resources, '(?m)^\s*resource 0x[0-9a-fA-F]+ raw/st_mobile_ca\r?\n\s*\(\) \(file\) (res/[^\r\n]+)')
        if ($mapping.Count -ne 1) { throw 'APK must have one default raw/st_mobile_ca resource.' }
        $entry = $zip.GetEntry($mapping[0].Groups[1].Value.Trim())
        if (-not $entry) {
            throw 'Built APK does not contain its mapped raw/st_mobile_ca certificate'
        }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $extractPath, $true)
    } finally {
        $zip.Dispose()
    }

    $gatewayHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $GatewayCaPath).Hash
    $apkHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $extractPath).Hash
    if ($gatewayHash -ne $apkHash) {
        throw "Embedded Android CA does not match active gateway CA in built APK. gateway=$gatewayHash apk=$apkHash"
    }
    Remove-UnderTools $extractDir
}

function Get-AndroidVersionMetadata {
    $buildGradlePath = Join-Path $AndroidRoot 'app\build.gradle'
    $buildGradle = Get-Content -LiteralPath $buildGradlePath -Raw
    $versionCodeMatch = [regex]::Match($buildGradle, 'versionCode\s*=?\s*(\d+)')
    $versionNameMatch = [regex]::Match($buildGradle, "versionName\s*=?\s*'([^']+)'")
    if (-not $versionCodeMatch.Success -or -not $versionNameMatch.Success) {
        throw "Could not read versionCode/versionName from $buildGradlePath"
    }
    return @{
        VersionCode = [int]$versionCodeMatch.Groups[1].Value
        VersionName = $versionNameMatch.Groups[1].Value
    }
}

function Write-UpdateManifest {
    $metadata = Get-AndroidVersionMetadata
    New-Item -ItemType Directory -Force -Path $UpdateRoot | Out-Null
    Copy-Item -LiteralPath $ApkPath -Destination $UpdateApkPath -Force
    $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $UpdateApkPath).Hash.ToLowerInvariant()
    $manifest = [ordered]@{
        versionCode = $metadata.VersionCode
        versionName = $metadata.VersionName
        apkUrl = "$GitHubRawUpdateBase/$UpdateApkName"
        sha256 = $sha256
        packageName = 'app.sillytavern.securemobile'
        releasedAt = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $json = ($manifest | ConvertTo-Json -Depth 4) + [Environment]::NewLine
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($UpdateManifestPath, $json, $utf8NoBom)

    $readback = Get-Content -LiteralPath $UpdateManifestPath -Raw | ConvertFrom-Json
    if ($readback.versionCode -ne $metadata.VersionCode -or $readback.sha256 -ne $sha256 -or $readback.apkUrl -ne "$GitHubRawUpdateBase/$UpdateApkName") {
        throw "Update manifest readback did not match built APK metadata"
    }
    Get-Item $UpdateApkPath, $UpdateManifestPath | Select-Object FullName, Length, LastWriteTime
}

function Assert-ReleaseApk {
    $policy = Get-Content -LiteralPath $SigningPolicyPath -Raw | ConvertFrom-Json
    $signer = Join-Path $SdkRoot 'build-tools\36.0.0\apksigner.bat'
    $signerOutput = @(& $signer verify --print-certs $ApkPath 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'Release APK signature verification failed.' }
    $digests = @($signerOutput | ForEach-Object {
        if ([string]$_ -match '^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$') { $Matches[1].ToLowerInvariant() }
    })
    if ($digests.Count -ne 1 -or $digests[0] -cne $policy.certificateSha256) {
        throw 'Release APK signing identity differs from the installed-app compatibility signer. Updater artifacts were not replaced.'
    }
    $aapt = Join-Path $SdkRoot 'build-tools\36.0.0\aapt.exe'
    $badging = @(& $aapt dump badging $ApkPath 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($badging -match '^application-debuggable')) {
        throw 'Release APK must be readable and non-debuggable.'
    }
    $metadata = Get-AndroidVersionMetadata
    $package = @($badging | Where-Object { $_ -match '^package: ' }) -join ''
    $expected = "package: name='$($policy.packageName)' versionCode='$($metadata.VersionCode)' versionName='$($metadata.VersionName)'"
    if (-not $package.StartsWith($expected, [System.StringComparison]::Ordinal)) {
        throw 'Release APK package/version differs from source metadata.'
    }
    Write-Host "Verified non-debuggable release and compatible signing certificate: $($digests[0])"
}

Sync-GatewayCa
$javaOutput = @(Ensure-Jdk)
$java = $javaOutput | Where-Object { [string]$_ -match '\\bin\\java\.exe$' } | Select-Object -Last 1
if (-not $java) {
    throw "Could not resolve extracted JDK java.exe from Ensure-Jdk output: $($javaOutput -join ' | ')"
}
$env:JAVA_HOME = $JdkRoot
$env:PATH = "$(Join-Path $JdkRoot 'bin');$env:PATH"
& $java -version

Ensure-AndroidSdk | Out-Null
$gradleOutput = @(Ensure-Gradle)
$gradle = $gradleOutput | Where-Object { [string]$_ -match '\\bin\\gradle\.bat$' } | Select-Object -Last 1
if (-not $gradle) {
    throw "Could not resolve extracted Gradle executable from Ensure-Gradle output: $($gradleOutput -join ' | ')"
}

Write-Host 'Building signed non-debuggable release APK'
Assert-GradleDependencyVerification
& $gradle -p $AndroidRoot --no-daemon --console=plain --dependency-verification strict :app:assembleRelease
if ($LASTEXITCODE -ne 0) {
    throw "Gradle failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path $ApkPath)) {
    throw "APK not found at $ApkPath"
}

Assert-ApkCaMatchesGateway
Assert-ReleaseApk
Write-UpdateManifest
Get-Item $ApkPath | Select-Object FullName, Length, LastWriteTime
