[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "auto-re-agent\tools")
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$SignerVersion = "1.3.0"
$SignerSha256 = "e1299fd6fcf4da527dd53735b56127e8ea922a321128123b9c32d619bba1d835"
$FridaVersion = "17.16.4"
$JadxVersion = "1.5.6"
$JadxSha256 = "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"
$DumperVersion = "6.7.46"
$DumperSha256 = "f5fc60dfc5c034c1ff3fc651514416ebd47658a63493207734537fd25fa2dea2"
$PlatformToolsVersion = "37.0.1"
$PlatformToolsSha256 = "45f4d63113e895ebde0c90f194099a4676b6ac653bd28d54314a9e022bbc1a99"

$Gadgets = @(
    @{
        Name = "frida-gadget-17.16.4-android-arm.so.xz"
        Sha256 = "1b19ce187c15d9892d4e737417a1b2a2f6f34ed11e105f1c28fd6b4e3df144a2"
    },
    @{
        Name = "frida-gadget-17.16.4-android-arm64.so.xz"
        Sha256 = "b1775f01dcd1224d16815b777c3df61fd12908411b24370e39dcf954dc855fcc"
    },
    @{
        Name = "frida-gadget-17.16.4-android-x86.so.xz"
        Sha256 = "95c1598baf82906dc901f46658aa1a924705260fcec3a964c656a6b851e42d74"
    },
    @{
        Name = "frida-gadget-17.16.4-android-x86_64.so.xz"
        Sha256 = "0c4aad82c88660bda9ae2f7c7fe30b4820fd7ba6ae7b4b340eb59e29a43622de"
    }
)

function Assert-Command {
    param([Parameter(Mandatory)][string]$Name)
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "Required prerequisite '$Name' is not on PATH. See README.md#android-one-time-setup."
    }
    return $command.Source
}

function Get-VerifiedFile {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$Sha256
    )
    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        $existing = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($existing -eq $Sha256) {
            return $existing
        }
    }
    Invoke-WebRequest -Uri $Uri -OutFile $Destination -UseBasicParsing
    $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256) {
        throw "SHA-256 mismatch for $Destination expected=$Sha256 actual=$actual"
    }
    return $actual
}

function Add-UserPathEntry {
    param([Parameter(Mandatory)][string]$Entry)
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @($userPath -split ";" | Where-Object { $_ })
    if ($parts -notcontains $Entry) {
        $updated = (($parts + $Entry) -join ";") + ";"
        [Environment]::SetEnvironmentVariable("Path", $updated, "User")
    }
}

$null = Assert-Command "apktool"
$null = Assert-Command "java"
$fridaCommand = Assert-Command "frida"
$hostFridaVersion = (& $fridaCommand --version).Trim()
if ($hostFridaVersion -ne $FridaVersion) {
    throw "Installed Frida is $hostFridaVersion, but this setup pins Gadget $FridaVersion. Update them together."
}

$resolvedInstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$tempRoot = Join-Path $env:TEMP ("re-agent-tools-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $resolvedInstallRoot, $tempRoot | Out-Null

try {
    $signerDir = Join-Path $resolvedInstallRoot "uber-apk-signer\$SignerVersion"
    $gadgetDir = Join-Path $resolvedInstallRoot "frida-gadget\$FridaVersion"
    $jadxDir = Join-Path $resolvedInstallRoot "jadx\$JadxVersion"
    $dumperDir = Join-Path $resolvedInstallRoot "il2cpp-dumper\$DumperVersion"
    New-Item -ItemType Directory -Force -Path $signerDir, $gadgetDir, $jadxDir, $dumperDir | Out-Null

    $signerJar = Join-Path $signerDir "uber-apk-signer-$SignerVersion.jar"
    $signerHash = Get-VerifiedFile `
        "https://github.com/patrickfav/uber-apk-signer/releases/download/v$SignerVersion/uber-apk-signer-$SignerVersion.jar" `
        $signerJar `
        $SignerSha256

    $gadgetHashes = [ordered]@{}
    foreach ($gadget in $Gadgets) {
        $destination = Join-Path $gadgetDir $gadget.Name
        $uri = "https://github.com/frida/frida/releases/download/$FridaVersion/$($gadget.Name)"
        $gadgetHashes[$gadget.Name] = Get-VerifiedFile $uri $destination $gadget.Sha256
    }

    $platformZip = Join-Path $tempRoot "platform-tools-latest-windows.zip"
    $platformHash = Get-VerifiedFile `
        "https://dl.google.com/android/repository/platform-tools-latest-windows.zip" `
        $platformZip `
        $PlatformToolsSha256
    Expand-Archive -LiteralPath $platformZip -DestinationPath $resolvedInstallRoot -Force
    $platformDir = Join-Path $resolvedInstallRoot "platform-tools"

    $jadxZip = Join-Path $tempRoot "jadx-$JadxVersion.zip"
    $jadxHash = Get-VerifiedFile `
        "https://github.com/skylot/jadx/releases/download/v$JadxVersion/jadx-$JadxVersion.zip" `
        $jadxZip `
        $JadxSha256
    Expand-Archive -LiteralPath $jadxZip -DestinationPath $jadxDir -Force

    $dumperZip = Join-Path $tempRoot "Il2CppDumper-win-v$DumperVersion.zip"
    $dumperHash = Get-VerifiedFile `
        "https://github.com/Perfare/Il2CppDumper/releases/download/v$DumperVersion/Il2CppDumper-win-v$DumperVersion.zip" `
        $dumperZip `
        $DumperSha256
    Expand-Archive -LiteralPath $dumperZip -DestinationPath $dumperDir -Force
    $dumperExe = Join-Path $dumperDir "Il2CppDumper.exe"

    [Environment]::SetEnvironmentVariable("RE_AGENT_TOOLS_DIR", $resolvedInstallRoot, "User")
    [Environment]::SetEnvironmentVariable("RE_AGENT_APK_SIGNER_JAR", $signerJar, "User")
    [Environment]::SetEnvironmentVariable("RE_AGENT_FRIDA_GADGET_DIR", $gadgetDir, "User")
    [Environment]::SetEnvironmentVariable("RE_AGENT_FRIDA_GADGET_VERSION", $FridaVersion, "User")
    [Environment]::SetEnvironmentVariable("RE_AGENT_IL2CPP_DUMPER", $dumperExe, "User")
    Add-UserPathEntry $platformDir
    Add-UserPathEntry (Join-Path $jadxDir "bin")
    Add-UserPathEntry $dumperDir

    $manifest = [ordered]@{
        installed_at = (Get-Date).ToString("o")
        root = $resolvedInstallRoot
        signer = @{ version = $SignerVersion; path = $signerJar; sha256 = $signerHash }
        frida_gadget = @{ version = $FridaVersion; path = $gadgetDir; sha256 = $gadgetHashes }
        platform_tools = @{ version = $PlatformToolsVersion; path = $platformDir; archive_sha256 = $platformHash }
        jadx = @{ version = $JadxVersion; path = $jadxDir; archive_sha256 = $jadxHash }
        il2cpp_dumper = @{ version = $DumperVersion; path = $dumperDir; archive_sha256 = $dumperHash }
    }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content `
        -LiteralPath (Join-Path $resolvedInstallRoot "install-manifest.json") `
        -Encoding utf8

    Write-Host "[+] Android tools installed in $resolvedInstallRoot"
    Write-Host "[+] Open a new terminal, then run: re-agent doctor"
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
