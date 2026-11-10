<#
.SYNOPSIS
    Headless script to build a trimmed-down Windows 11 image for CI/CD automation.

.DESCRIPTION
    Automated build of a streamlined Windows 11 image (tiny11) without user interaction.
    Designed for GitHub Actions workflows and other CI/CD pipelines.
    Uses only Microsoft utilities like DISM, with oscdimg.exe from Windows ADK.

.PARAMETER ISO
    Drive letter of the mounted Windows 11 ISO (required, e.g., E)

.PARAMETER INDEX
    Windows image index to process (required, e.g., 1 for Home, 6 for Pro)

.PARAMETER SCRATCH
    Drive letter for scratch disk operations (optional, defaults to script root)

.PARAMETER SkipCleanup
    Skip cleanup of temporary files after ISO creation (optional, for debugging)

.PARAMETER AccountSetup
    How the local account is set up on first boot (optional, default 'auto-admin'):
      auto-admin - pre-create a local administrator called 'Admin', blank password,
                   auto-logon on first boot, OOBE skipped entirely.
      classic    - let OOBE run offline so the person installing creates their own
                   local account with their own name. No Microsoft account.

.EXAMPLE
    .\tiny11maker-headless.ps1 -ISO E -INDEX 1
    .\tiny11maker-headless.ps1 -ISO E -INDEX 6 -SCRATCH D
    .\tiny11maker-headless.ps1 -ISO E -INDEX 6 -AccountSetup classic

.NOTES
    Original Author: ntdevlabs
    Modified by: kelexine (https://github.com/kelexine)
    GitHub: https://github.com/kelexine/tiny11-automated
    Date: 2025-12-08
    
    License: MIT
    This is a headless automation-ready version designed for CI/CD pipelines.
#>

#---------[ Parameters ]---------#
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, HelpMessage="Drive letter of mounted Windows 11 ISO (e.g., E)")]
    [ValidatePattern('^[c-zC-Z]$')]
    [string]$ISO,
    
    [Parameter(Mandatory=$true, HelpMessage="Windows image index (1=Home, 6=Pro, etc.)")]
    [ValidateRange(1, 10)]
    [int]$INDEX,
    
    [Parameter(Mandatory=$false, HelpMessage="Scratch disk drive letter (defaults to script directory)")]
    [ValidatePattern('^[c-zC-Z]$')]
    [string]$SCRATCH,
    
    [Parameter(Mandatory=$false, HelpMessage="Skip cleanup of temporary files")]
    [switch]$SkipCleanup,

    [Parameter(Mandatory=$false, HelpMessage="Local account setup. 'auto-admin' (default) pre-creates a local 'Admin' account and skips OOBE. 'classic' runs OOBE so the person installing creates their own local account with their own name.")]
    [ValidateSet('auto-admin', 'classic')]
    [string]$AccountSetup = 'auto-admin'
)

#---------[ Error Handling ]---------#
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

#---------[ Configuration ]---------#
if (-not $SCRATCH) {
    $ScratchDisk = $PSScriptRoot -replace '[\\]+$', ''
} else {
    $ScratchDisk = $SCRATCH + ":"
}

$DriveLetter = $ISO + ":"
$wimFilePath = "$ScratchDisk\tiny11\sources\install.wim"
$scratchDir = "$ScratchDisk\scratchdir"
$tiny11Dir = "$ScratchDisk\tiny11"
$outputISO = "$PSScriptRoot\tiny11.iso"
$logFile = "$PSScriptRoot\tiny11_$(Get-Date -Format yyyyMMdd_HHmmss).log"

#---------[ Functions ]---------#
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Output $logMessage
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
}

function Get-TakeownYesAnswer {
    # takeown /R needs /D, otherwise it asks "Do you want to replace the directory permissions...? [Y/N]"
    # on the console for every folder the administrator cannot list (e.g. ProgramData\Microsoft\Windows
    # Defender Advanced Threat Protection, present only in Pro/Enterprise) and the build waits forever.
    # /D accepts only the "yes" letter of the system language: Y in English, T in Polish, J in German,
    # O in French... - "/D Y" is rejected on those systems. Probe once on an empty folder and cache it.
    $cached = Get-Variable -Name takeownYesAnswer -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($cached) { return $cached }

    $answer = 'Y'
    $probe = Join-Path ([IO.Path]::GetTempPath()) ('takeown-probe-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $probe -Force | Out-Null
    try {
        foreach ($candidate in @('Y', 'T', 'J', 'O', 'S', 'A', 'I', 'E', [string][char]0x414)) {
            & { $ErrorActionPreference = 'Continue'; & takeown.exe /F $probe /R /D $candidate 2>&1 | Out-Null }
            if ($LASTEXITCODE -eq 0) { $answer = $candidate; break }
        }
    } finally {
        Remove-Item -LiteralPath $probe -Recurse -Force -ErrorAction SilentlyContinue
    }
    Set-Variable -Name takeownYesAnswer -Scope Script -Value $answer
    return $answer
}

function Write-IsoAnswerFile {
    # Copies the unattend template to $Destination, rewriting the /IMAGE/INDEX
    # placeholder so the edition chosen with -INDEX is the one that actually gets
    # installed. The static template hard-codes index 1, so without this rewrite a
    # Pro/Education build would silently install Home.
    #
    # The content is parsed as XML before it is written: Windows Setup hard-fails on
    # a malformed answer file, and a rejected answer file is exactly how the OOBE /
    # local-account automation silently stops working.
    param(
        [Parameter(Mandatory=$true)][string]$Destination,
        [Parameter(Mandatory=$false)][string]$Template,
        [Parameter(Mandatory=$false)]
        [ValidateSet('auto-admin', 'classic')]
        [string]$AccountMode = 'auto-admin'
    )

    if (-not $Template) {
        $Template = @(
            (Join-Path $PSScriptRoot "autounattend.xml"),
            (Join-Path (Split-Path $PSScriptRoot -Parent) "autounattend.xml")
        ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    }

    if (-not $Template -or -not (Test-Path $Template)) {
        Write-Log "No unattend template found - OOBE will not be automated" "WARN"
        return
    }

    try {
        $content = Get-Content -LiteralPath $Template -Raw
        $content = [regex]::Replace(
            $content,
            '(<Key>/IMAGE/INDEX</Key>\s*<Value>)\d+(</Value>)',
            ('${1}' + $INDEX + '${2}')
        )

        # Account mode 'classic': drop the pre-created account, the auto-logon and
        # the first-logon cleanup so Windows Setup runs OOBE and the person
        # installing creates their own local account with their own name.
        #
        # Everything else in the template is kept, so the install stays fully
        # offline: DynamicUpdate stays off, the online-account screens stay hidden
        # and BypassNRO / DisableOnline stay set. The result is the classic
        # "create a local account" OOBE with no Microsoft account and no network.
        #
        # These three elements never nest inside an element of the same name in
        # the template, so a non-greedy block match is unambiguous. The result is
        # re-parsed as XML below, so a bad edit here fails the build loudly.
        if ($AccountMode -eq 'classic') {
            $content = [regex]::Replace($content, '(?s)\s*<UserAccounts>.*?</UserAccounts>', '')
            $content = [regex]::Replace($content, '(?s)\s*<AutoLogon>.*?</AutoLogon>', '')
            $content = [regex]::Replace($content, '(?s)\s*<FirstLogonCommands>.*?</FirstLogonCommands>', '')
        }

        # Throws if the template is not well-formed XML - we want that to be loud.
        $null = [xml]$content

        $destDir = Split-Path -Parent $Destination
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Force -Path $destDir | Out-Null
        }

        # UTF-8 without BOM - Setup is happier without a BOM on the answer file.
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($Destination, $content, $utf8NoBom)

        Write-Log "Wrote unattended answer file to $Destination (IMAGE/INDEX = $INDEX, account mode = $AccountMode)"
    } catch {
        Write-Log "Failed to write answer file to ${Destination}: $_" "ERROR"
        throw
    }
}

function Set-RegistryValue {
    param (
        [string]$path,
        [string]$name,
        [string]$type,
        [string]$value
    )
    try {
        if ($name) {
            & 'reg' 'add' $path '/v' $name '/t' $type '/d' $value '/f' | Out-Null
        } else {
            & 'reg' 'add' $path '/ve' '/t' $type '/d' $value '/f' | Out-Null
        }
        Write-Log "Set registry: $path\$name = $value"
    } catch {
        Write-Log "Error setting registry $path\$name : $_" "ERROR"
        throw
    }
}

function Remove-RegistryKey {
    param([string]$path)
    try {
        & 'reg' 'delete' $path '/f' 2>&1 | Out-Null
        Write-Log "Removed registry key: $path"
    } catch {
        Write-Log "Registry key not found or error: $path" "WARN"
    }
}

function Remove-RegistryValue {
    # Removes a single value from a registry key. $path is the full
    # "key\valueName" form (e.g. '...\Run\OneDriveSetup'), where everything
    # after the last backslash is the value name and the rest is the key.
    param([string]$path)
    $lastSlash = $path.LastIndexOf('\')
    if ($lastSlash -lt 0) {
        Write-Log "Invalid registry value path (missing key\value separator): $path" "WARN"
        return
    }
    $keyPath = $path.Substring(0, $lastSlash)
    $valueName = $path.Substring($lastSlash + 1)
    try {
        & 'reg' 'delete' $keyPath '/v' $valueName '/f' 2>&1 | Out-Null
        Write-Log "Removed registry value: $path"
    } catch {
        Write-Log "Registry value not found or error: $path" "WARN"
    }
}

function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    # Check admin rights
    $adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
    $myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)
    $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    
    if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
        Write-Log "Script must run as Administrator!" "ERROR"
        throw "Administrative privileges required"
    }
    
    # Check ISO mount
    if (-not (Test-Path "$DriveLetter\sources\boot.wim")) {
        Write-Log "boot.wim not found at $DriveLetter\sources\" "ERROR"
        throw "Invalid Windows 11 ISO mount point"
    }
    
    # Check for install.wim or install.esd
    if (-not (Test-Path "$DriveLetter\sources\install.wim") -and -not (Test-Path "$DriveLetter\sources\install.esd")) {
        Write-Log "No install.wim or install.esd found" "ERROR"
        throw "Windows installation files not found"
    }
    
    # Check disk space (minimum 15GB recommended)
    $disk = Get-PSDrive -Name $ScratchDisk[0] -ErrorAction SilentlyContinue
    if ($disk) {
        $freeGB = [math]::Round($disk.Free / 1GB, 2)
        Write-Log "Available space on ${ScratchDisk}: ${freeGB}GB"
        if ($freeGB -lt 15) {
            Write-Log "Low disk space warning: ${freeGB}GB (15GB+ recommended)" "WARN"
        }
    }
    
    Write-Log "Prerequisites check passed"
}

function Initialize-Directories {
    Write-Log "Initializing directories..."
    New-Item -ItemType Directory -Force -Path "$tiny11Dir\sources" | Out-Null
    New-Item -ItemType Directory -Force -Path $scratchDir | Out-Null
    Write-Log "Directories created"
}

function Convert-ESDToWIM {
    Write-Log "Converting install.esd to install.wim..."
    
    $esdPath = "$DriveLetter\sources\install.esd"
    $tempWimPath = "$tiny11Dir\sources\install.wim"
    
    # Validate index exists in ESD
    $images = Get-WindowsImage -ImagePath $esdPath
    $validIndices = $images.ImageIndex
    
    if ($INDEX -notin $validIndices) {
        Write-Log "Invalid index $INDEX. Available: $($validIndices -join ', ')" "ERROR"
        throw "Image index $INDEX not found in install.esd"
    }
    
    Write-Log "Exporting image index $INDEX from ESD (this may take 10-20 minutes)..."
    Export-WindowsImage -SourceImagePath $esdPath -SourceIndex $INDEX `
        -DestinationImagePath $tempWimPath -CompressionType Maximum -CheckIntegrity
    
    Write-Log "ESD conversion complete"
}

function Copy-WindowsFiles {
    Write-Log "Copying Windows installation files from $DriveLetter..."
    Copy-Item -Path "$DriveLetter\*" -Destination $tiny11Dir -Recurse -Force -ErrorAction SilentlyContinue
    
    # Remove read-only attribute and delete install.esd if present
    if (Test-Path "$tiny11Dir\sources\install.esd") {
        Set-ItemProperty -Path "$tiny11Dir\sources\install.esd" -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        Remove-Item "$tiny11Dir\sources\install.esd" -Force -ErrorAction SilentlyContinue
    }
    
    Write-Log "File copy complete"
}

function Resolve-ImageIndex {
    Write-Log "Resolving and validating image index $INDEX..."
    
    $sourceImagePath = ""
    if (Test-Path "$DriveLetter\sources\install.wim") {
        $sourceImagePath = "$DriveLetter\sources\install.wim"
    } elseif (Test-Path "$DriveLetter\sources\install.esd") {
        $sourceImagePath = "$DriveLetter\sources\install.esd"
    } else {
        throw "Windows installation files not found on ISO"
    }
    
    $images = Get-WindowsImage -ImagePath $sourceImagePath
    
    # Standard Microsoft index mapping for Consumer ISOs
    $expectedNames = @{
        1 = "Windows 11 Home"
        4 = "Windows 11 Education"
        6 = "Windows 11 Pro"
        7 = "Windows 11 Pro N"
    }
    
    $targetName = $expectedNames[$INDEX]
    
    if ($targetName) {
        $foundImage = $images | Where-Object { $_.ImageName -eq $targetName }
        if ($foundImage) {
            $actualIndex = $foundImage.ImageIndex
            if ($actualIndex -ne $INDEX) {
                Write-Log "Index shifted! Expected '$targetName' at $INDEX, but found at $actualIndex." "WARN"
                Write-Log "Automatically adjusting INDEX to $actualIndex."
                $script:INDEX = $actualIndex
            } else {
                Write-Log "Edition '$targetName' matched expected index $INDEX."
            }
        } else {
            Write-Log "Expected edition '$targetName' not found in ISO. Proceeding with literal index $INDEX." "WARN"
        }
    } else {
        Write-Log "No standard mapping for index $INDEX. Proceeding with literal index."
    }
    
    $validIndices = $images.ImageIndex
    
    if ($script:INDEX -notin $validIndices) {
        Write-Log "Invalid index $script:INDEX. Available indices:" "ERROR"
        $images | ForEach-Object { Write-Log "  Index $($_.ImageIndex): $($_.ImageName)" }
        throw "Image index $script:INDEX not found"
    }
    
    $selectedImage = $images | Where-Object { $_.ImageIndex -eq $script:INDEX }
    Write-Log "Selected: Index $script:INDEX - $($selectedImage.ImageName)"

    # kelexine: the list object from 'Get-WindowsImage -ImagePath' has no 'Version'
    # property - DISM only populates Version/SPBuild/Architecture on the detailed
    # per-index object returned by 'Get-WindowsImage -ImagePath ... -Index N'.
    # Re-query with -Index for build-number extraction. Wrapped in try/catch since
    # this must never hard-fail the build - CI has its own windows_build fallback.
    $script:DetectedImageName = $selectedImage.ImageName
    $script:DetectedFullVersion = ""
    try {
        $detailedImage = Get-WindowsImage -ImagePath $sourceImagePath -Index $script:INDEX
        if ($detailedImage -and ($detailedImage.PSObject.Properties.Match('Version').Count -gt 0)) {
            $script:DetectedFullVersion = $detailedImage.Version
        } else {
            Write-Log "Detailed image query for index $script:INDEX returned no 'Version' property." "WARN"
        }
    } catch {
        Write-Log "Failed to query detailed image info for build number detection: $_" "WARN"
    }

    if ($script:DetectedFullVersion -match '(\d+\.\d+)$') {
        $script:DetectedBuildNumber = $Matches[1]
        Write-Log "Detected Windows build number: $script:DetectedBuildNumber (full version: $script:DetectedFullVersion)"
    } else {
        $script:DetectedBuildNumber = ""
        Write-Log "Could not parse a build number from image version '$script:DetectedFullVersion'" "WARN"
    }
}

function Mount-WindowsImageFile {
    Write-Log "Mounting Windows image (Index: $INDEX)..."
    
    # Take ownership and set permissions
    & takeown /F $wimFilePath /A | Out-Null
    $adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
    & icacls $wimFilePath /grant "$($adminGroup.Value):(F)" | Out-Null
    
    Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
    
    Mount-WindowsImage -ImagePath $wimFilePath -Index $INDEX -Path $scratchDir
    Write-Log "Image mounted at $scratchDir"
}

function Get-ImageMetadata {
    Write-Log "Extracting image metadata..."
    
    # Get language
    $imageIntl = & dism /English /Get-Intl "/Image:$scratchDir"
    $languageLine = $imageIntl -split '\n' | Where-Object { $_ -match 'Default system UI language : ([a-zA-Z]{2}-[a-zA-Z]{2})' }
    
    if ($languageLine) {
        $languageCode = $Matches[1]
        Write-Log "Language: $languageCode"
    }
    
    # Get architecture
    $imageInfo = & dism /English /Get-WimInfo "/wimFile:$wimFilePath" "/index:$INDEX"
    $lines = $imageInfo -split '\r?\n'
    
    foreach ($line in $lines) {
        if ($line -like '*Architecture : *') {
            $script:architecture = $line -replace 'Architecture : ', ''
            if ($script:architecture -eq 'x64') {
                $script:architecture = 'amd64'
            }
            Write-Log "Architecture: $script:architecture"
            break
        }
    }
}

function Remove-BloatwareApps {
    Write-Log "Removing provisioned appx packages..."
    
    $packages = & dism /English "/image:$scratchDir" /Get-ProvisionedAppxPackages |
        ForEach-Object {
            if ($_ -match 'PackageName : (.*)') {
                $matches[1]
            }
        }
    
    $packagePrefixes = @(
        'AppUp.IntelManagementandSecurityStatus',
        'Clipchamp.Clipchamp',
        'DolbyLaboratories.DolbyAccess',
        'DolbyLaboratories.DolbyDigitalPlusDecoderOEM',
        'Microsoft.BingNews',
        'Microsoft.BingSearch',
        'Microsoft.BingWeather',
        'Microsoft.Copilot',
        'Microsoft.Windows.CrossDevice',
        'Microsoft.GamingApp',
        'Microsoft.GetHelp',
        'Microsoft.Getstarted',
        'Microsoft.Microsoft3DViewer',
        'Microsoft.MicrosoftOfficeHub',
        'Microsoft.MicrosoftSolitaireCollection',
        'Microsoft.MicrosoftStickyNotes',
        'Microsoft.MixedReality.Portal',
        'Microsoft.MSPaint',
        'Microsoft.Office.OneNote',
        'Microsoft.OfficePushNotificationUtility',
        'Microsoft.OutlookForWindows',
        'Microsoft.Paint',
        'Microsoft.People',
        'Microsoft.PowerAutomateDesktop',
        'Microsoft.SkypeApp',
        'Microsoft.StartExperiencesApp',
        'Microsoft.Todos',
        'Microsoft.Wallet',
        'Microsoft.Windows.DevHome',
        'Microsoft.Windows.Copilot',
        'Microsoft.Windows.Teams',
        'Microsoft.Windows.Photos',
        'Microsoft.ScreenSketch',
        'Microsoft.StorePurchaseApp',
        'Microsoft.MPEG2VideoExtension',
        'Microsoft.WebMediaExtensions',
        'MicrosoftWindows.Client.WebExperience',
        'Microsoft.WindowsAlarms',
        'Microsoft.WindowsCamera',
        'microsoft.windowscommunicationsapps',
        'Microsoft.WindowsFeedbackHub',
        'Microsoft.WindowsMaps',
        'Microsoft.WindowsSoundRecorder',
        'Microsoft.WindowsTerminal',
        'Microsoft.Xbox.TCUI',
        'Microsoft.XboxApp',
        'Microsoft.XboxGameOverlay',
        'Microsoft.XboxGamingOverlay',
        'Microsoft.XboxIdentityProvider',
        'Microsoft.XboxSpeechToTextOverlay',
        'Microsoft.YourPhone',
        'Microsoft.ZuneMusic',
        'Microsoft.ZuneVideo',
        'MicrosoftCorporationII.MicrosoftFamily',
        'MicrosoftCorporationII.QuickAssist',
        'MSTeams',
        'MicrosoftTeams',
        'Microsoft.549981C3F5F10',
        'Microsoft.Windows.AI',
        'Microsoft.Windows.AIFabric',
        'Microsoft.Windows.Recall',
        'Microsoft.Windows.CoreAI',
        'Microsoft.Recall'
    )
    
    $packagesToRemove = $packages | Where-Object {
        $packageName = $_
        $packagePrefixes | Where-Object { $packageName -like "*$_*" }
    }
    
    $removeCount = 0
    foreach ($package in $packagesToRemove) {
        Write-Log "Removing: $package"
        & dism /English "/image:$scratchDir" /Remove-ProvisionedAppxPackage "/PackageName:$package" | Out-Null
        $removeCount++
    }
    
    Write-Log "Removed $removeCount appx packages"
}

function Remove-EdgeAndOneDrive {
    Write-Log "Removing Microsoft Edge and Edge WebView..."
    
    $adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
    
    $edgePaths = @(
        "$scratchDir\Program Files (x86)\Microsoft\Edge",
        "$scratchDir\Program Files (x86)\Microsoft\EdgeUpdate",
        "$scratchDir\Program Files (x86)\Microsoft\EdgeCore",
        "$scratchDir\Program Files (x86)\Microsoft\EdgeWebView",
        "$scratchDir\Windows\System32\Microsoft-Edge-Webview"
    )
    
    foreach ($path in $edgePaths) {
        if (Test-Path $path) {
            Write-Log "Deleting Edge component: $path"
            & takeown /f $path /r /d $(Get-TakeownYesAnswer) /a | Out-Null
            & icacls $path /grant "$($adminGroup.Value):(F)" /T /C | Out-Null
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Remove Edge WebView directories inside WinSxS (covers amd64 and arm64)
    Write-Log "Removing Edge WebView assemblies from WinSxS..."
    $winSxSPaths = Get-ChildItem -Path "$scratchDir\Windows\WinSxS" -Filter "*microsoft-edge-webview_31bf3856ad364e35*" -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    foreach ($winSxSPath in $winSxSPaths) {
        if (Test-Path $winSxSPath) {
            Write-Log "Taking ownership and removing WinSxS WebView folder: $winSxSPath"
            & takeown /f $winSxSPath /r /d $(Get-TakeownYesAnswer) /a | Out-Null
            & icacls $winSxSPath /grant "$($adminGroup.Value):(F)" /T /C | Out-Null
            Remove-Item -Path $winSxSPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Log "Removing OneDrive..."
    $oneDrivePaths = @(
        "$scratchDir\Windows\System32\OneDriveSetup.exe",
        "$scratchDir\Windows\SysWOW64\OneDriveSetup.exe"
    )
    foreach ($path in $oneDrivePaths) {
        if (Test-Path $path) {
            Write-Log "Deleting OneDrive setup: $path"
            & takeown /f $path /a | Out-Null
            & icacls $path /grant "$($adminGroup.Value):(F)" /T /C | Out-Null
            Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Log "Edge, Edge WebView, and OneDrive removal complete"
    
    # Clean up other remnants
    Write-Log "Cleaning up other remnants (GameBar, Copilot)..."
    $otherRemnants = @(
        "$scratchDir\Windows\GameBarPresenceWriter",
        "$scratchDir\Windows\System32\SettingsHandlers_Copilot.dll"
    )
    foreach ($path in $otherRemnants) {
        if (Test-Path $path) {
            Write-Log "Deleting remnant: $path"
            & takeown /f $path /a | Out-Null
            & icacls $path /grant "$($adminGroup.Value):(F)" /T /C | Out-Null
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Apply-RegistryTweaks {
    Write-Log "Loading registry hives..."
    
    reg load HKLM\zCOMPONENTS "$scratchDir\Windows\System32\config\COMPONENTS" | Out-Null
    reg load HKLM\zDEFAULT "$scratchDir\Windows\System32\config\default" | Out-Null
    reg load HKLM\zNTUSER "$scratchDir\Users\Default\ntuser.dat" | Out-Null
    reg load HKLM\zSOFTWARE "$scratchDir\Windows\System32\config\SOFTWARE" | Out-Null
    reg load HKLM\zSYSTEM "$scratchDir\Windows\System32\config\SYSTEM" | Out-Null
    
    Write-Log "Applying registry tweaks..."
    
    # Bypass system requirements
    Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassCPUCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassRAMCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassSecureBootCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassStorageCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassTPMCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\MoSetup' 'AllowUpgradesWithUnsupportedTPMOrCPU' 'REG_DWORD' '1'
    
    # Disable sponsored apps
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'OemPreInstalledAppsEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'PreInstalledAppsEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SilentInstalledAppsEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'ContentDeliveryAllowed' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' 'ConfigureStartPins' 'REG_SZ' '{"pinnedList": [{}]}'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'FeatureManagementEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'PreInstalledAppsEverEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SoftLandingEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContentEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-310093Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338388Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338389Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338393Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353694Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353696Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SystemPaneSuggestionsEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' 'DisablePushToInstall' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' 'DontOfferThroughWUAU' 'REG_DWORD' '1'
    
    Remove-RegistryKey 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions'
    Remove-RegistryKey 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps'
    
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableConsumerAccountStateContent' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableCloudOptimizedContent' 'REG_DWORD' '1'
    
    # Out-of-the-box offline local account.
    # BypassNRO re-enables the "I don't have internet" path Microsoft removed from
    # the OOBE UI in 24H2+, and DisableOnline stops OOBE demanding a network
    # connection before it will continue. These are belt-and-braces - the real
    # guarantee is the pre-created local account in autounattend.xml.
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' 'BypassNRO' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' 'DisableOnline' 'REG_DWORD' '1'

    # Bake the answer file into the image too, so a later sysprep /generalize keeps
    # the same OOBE behaviour.
    Write-IsoAnswerFile -Destination "$scratchDir\Windows\System32\Sysprep\autounattend.xml" -AccountMode $AccountSetup
    
    # Disable reserved storage
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' 'ShippedWithReserves' 'REG_DWORD' '0'
    
    # Disable BitLocker
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' 'PreventDeviceEncryption' 'REG_DWORD' '1'
    
    # Disable Chat icon
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' 'ChatIcon' 'REG_DWORD' '3'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarMn' 'REG_DWORD' '0'
    
    # Remove Edge registries
    Remove-RegistryKey "HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"
    Remove-RegistryKey "HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update"
    
    # Disable OneDrive folder backup
    Set-RegistryValue "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" "REG_DWORD" "1"
    
    # Remove OneDrive from Run keys (prevent auto-install on first login)
    Remove-RegistryValue "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDriveSetup"
    Remove-RegistryValue "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSetup"
    
    # Disable telemetry
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' 'HasAccepted' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' 'Enabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' 'HarvestContacts' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' 'AcceptedPrivacyPolicy' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' 'Start' 'REG_DWORD' '4'
    
    # Prevent DevHome and Outlook installation
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' 'workCompleted' 'REG_DWORD' '1'
    Remove-RegistryKey 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate'
    Remove-RegistryKey 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate'
    
    # Disable Copilot
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Edge' 'HubsSidebarEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 'REG_DWORD' '1'
    
    # Disable AI features (Recall, AI Fabric, Windows AI)
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'TurnOffWindowsAI' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zNTUSER\Software\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 'REG_DWORD' '1'
    
    # Enhanced telemetry removal
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DoNotShowFeedbackNotifications' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowDeviceNameInTelemetry' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack' 'ShowedToastAtLevel' 'REG_DWORD' '1'
    
    # Gaming optimization: Increase VRAM allocation
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\DirectDraw' 'EmulationOnly' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Direct3D' 'DisableVidMemVBs' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\GraphicsDrivers' 'DpiMapIommuContiguous' 'REG_DWORD' '1'
    
    # Prevent Teams installation
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Teams' 'DisableInstallation' 'REG_DWORD' '1'
    
    # Prevent new Outlook installation
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Mail' 'PreventRun' 'REG_DWORD' '1'

    # Easter Egg / Branding
    Write-Log "Adding Easter Egg branding..."
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'legalnoticecaption' 'REG_SZ' 'Tiny11 Automated'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'legalnoticetext' 'REG_SZ' 'This image was built using Tiny11 Automated by kelexine. Enjoy your lightweight Windows experience!'
    
    # Desktop Context Menu Link
    Set-RegistryValue 'HKLM\zSOFTWARE\Classes\DesktopBackground\Shell\Tiny11Info' 'MUIVerb' 'REG_SZ' 'Tiny11 Automated Info'
    Set-RegistryValue 'HKLM\zSOFTWARE\Classes\DesktopBackground\Shell\Tiny11Info' 'Icon' 'REG_SZ' 'shell32.dll,22'
    Set-RegistryValue 'HKLM\zSOFTWARE\Classes\DesktopBackground\Shell\Tiny11Info' 'Position' 'REG_SZ' 'Bottom'
    Set-RegistryValue 'HKLM\zSOFTWARE\Classes\DesktopBackground\Shell\Tiny11Info\command' '' 'REG_SZ' 'explorer.exe "https://github.com/kelexine/tiny11-automated"'

    Write-Log "Registry tweaks applied"
}

function Remove-ScheduledTasks {
    Write-Log "Removing telemetry scheduled tasks..."
    
    $tasksPath = "$scratchDir\Windows\System32\Tasks"
    $tasksToRemove = @(
        "$tasksPath\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "$tasksPath\Microsoft\Windows\Customer Experience Improvement Program",
        "$tasksPath\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "$tasksPath\Microsoft\Windows\Chkdsk\Proxy",
        "$tasksPath\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    )
    
    foreach ($task in $tasksToRemove) {
        if (Test-Path $task) {
            Remove-Item -Path $task -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Removed task: $task"
        }
    }
    
    Write-Log "Scheduled tasks removed"
}

function Remove-NonEssentialServices {
    Write-Log "Disabling non-essential services (minimal for standard build)..."
    
    # Standard build: Only disable diagnostic and telemetry services
    # This preserves maximum compatibility while removing privacy/performance drains
    $servicesToDisable = @(
        'DiagTrack',           # Connected User Experiences and Telemetry
        'WerSvc',              # Windows Error Reporting
        'PcaSvc',              # Program Compatibility Assistant
        'SysMain'              # Superfetch (not needed on SSDs)
    )
    
    foreach ($service in $servicesToDisable) {
        Write-Log "Disabling service: $service"
        try {
            Set-RegistryValue "HKLM\zSYSTEM\ControlSet001\Services\$service" 'Start' 'REG_DWORD' '4'
        } catch {
            Write-Log "Could not disable service $service : $_" "WARN"
        }
    }
    
    Write-Log "Non-essential services disabled"
}

function Apply-PerformanceTweaks {
    # Author: kelexine (https://github.com/kelexine)
    # Bakes performance optimizations into the offline image via registry.
    # Covers: Memory, CPU/Scheduler, Storage (NTFS), Network (TCP), Gaming, Boot time.
    # Profile: Conservative — safe for desktop and dev workstation use.
    Write-Log "Applying performance optimizations (desktop/dev profile)..."

    # ── Memory Management ──────────────────────────────────────────────────
    # Keep default paging for kernel drivers — safe for variable-RAM desktop systems
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\Session Manager\Memory Management' 'DisablePagingExecutive'  'REG_DWORD' '0'
    # Workstation memory model (0 = workstation, not server)
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\Session Manager\Memory Management' 'LargeSystemCache'        'REG_DWORD' '0'
    # Skip zeroing page file on shutdown — saves 30-60 s per reboot cycle
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\Session Manager\Memory Management' 'ClearPageFileAtShutdown' 'REG_DWORD' '0'
    # SysMain is disabled — match prefetcher state to prevent orphaned background I/O
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters' 'EnablePrefetcher' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters' 'EnableSuperfetch' 'REG_DWORD' '0'

    # ── CPU / Thread Scheduler ─────────────────────────────────────────────
    # 38 (0x26): foreground boost ON + variable short quanta — gaming and desktop sweet spot
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\PriorityControl' 'Win32PrioritySeparation' 'REG_DWORD' '38'

    # ── MMCSS (Multimedia Class Scheduler) ────────────────────────────────
    # Disable network throttling during multimedia/game workloads
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' 'NetworkThrottlingIndex' 'REG_DWORD' '0xffffffff'
    # 20 = default; reserves 20% CPU headroom for background tasks (safe for desktop)
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' 'SystemResponsiveness'   'REG_DWORD' '20'
    # MMCSS Games class — moderate GPU/CPU priority balanced for gaming alongside other workloads
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' 'GPU Priority'        'REG_DWORD' '2'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' 'Priority'            'REG_DWORD' '6'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' 'Scheduling Category' 'REG_SZ'    'Medium'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' 'SFIO Priority'       'REG_SZ'    'High'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' 'Latency Sensitive'   'REG_SZ'    'True'

    # ── Storage / NTFS ────────────────────────────────────────────────────
    # Disable 8.3 short filename generation — pure legacy overhead on modern systems
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\FileSystem' 'NtfsDisable8dot3NameCreation' 'REG_DWORD' '1'
    # Disable last-access timestamp update on every file read — eliminates per-read metadata writes
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\FileSystem' 'NtfsDisableLastAccessUpdate'  'REG_DWORD' '1'
    # Allow NTFS more memory for its internal metadata cache
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\FileSystem' 'NtfsMemoryUsage'              'REG_DWORD' '2'
    # Ensure SSD TRIM delete notifications are not suppressed
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\FileSystem' 'DisableDeleteNotification'    'REG_DWORD' '0'

    # ── Network / TCP ─────────────────────────────────────────────────────
    # Shrink TIME_WAIT from 240 s → 30 s (recycles ports faster after connection close)
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\Tcpip\Parameters' 'TcpTimedWaitDelay' 'REG_DWORD' '30'
    # Expand ephemeral port range to near-maximum
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\Tcpip\Parameters' 'MaxUserPort'       'REG_DWORD' '65534'
    # RFC 1323: TCP window scaling + timestamps (better throughput on high-bandwidth links)
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\Tcpip\Parameters' 'Tcp1323Opts'       'REG_DWORD' '1'
    # TTL 64 (Linux/BSD default): consistent cross-platform behaviour
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\Tcpip\Parameters' 'DefaultTTL'        'REG_DWORD' '64'
    # Disable WSD (Web Services on Devices) network probe overhead
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\Tcpip\Parameters' 'EnableWsd'         'REG_DWORD' '0'
    # Per-interface Nagle + delayed-ACK disable — deferred to first boot (adapter GUIDs unknown offline)
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' 'PerfTuneNagle' 'REG_SZ' `
        'powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces | ForEach-Object { Set-ItemProperty $_.PSPath TCPNoDelay 1 -Type DWord -ErrorAction SilentlyContinue; Set-ItemProperty $_.PSPath TcpAckFrequency 1 -Type DWord -ErrorAction SilentlyContinue; Set-ItemProperty $_.PSPath TCPDelAckTicks 0 -Type DWord -ErrorAction SilentlyContinue }"'

    # ── Gaming ────────────────────────────────────────────────────────────
    # Hardware Accelerated GPU Scheduling (HAGS) — reduces CPU↔GPU submission latency
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\GraphicsDrivers' 'HwSchMode'   'REG_DWORD' '2'
    # Raise GPU TDR timeout: default 2 s causes false "GPU hung" errors under sustained load
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\GraphicsDrivers' 'TdrDelay'    'REG_DWORD' '10'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\GraphicsDrivers' 'TdrDdiDelay' 'REG_DWORD' '10'
    # Disable Xbox Game DVR / Game Bar capture overlay
    Set-RegistryValue 'HKLM\zNTUSER\SYSTEM\GameConfigStore' 'GameDVR_Enabled'                        'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\SYSTEM\GameConfigStore' 'GameDVR_FSEBehaviorMode'                'REG_DWORD' '2'
    Set-RegistryValue 'HKLM\zNTUSER\SYSTEM\GameConfigStore' 'GameDVR_HonorUserFSEBehaviorMode'       'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zNTUSER\SYSTEM\GameConfigStore' 'GameDVR_DXGIHonorFSEWindowsCompatible'  'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zNTUSER\SYSTEM\GameConfigStore' 'GameDVR_EFSEBehaviorMode'               'REG_DWORD' '0'
    # Enable Game Mode — Windows auto-prioritizes detected game processes
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\GameBar' 'AllowAutoGameMode'   'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\GameBar' 'AutoGameModeEnabled' 'REG_DWORD' '1'

    # ── Boot Time ─────────────────────────────────────────────────────────
    # Remove Explorer shell extension load stagger (default 5 s; now immediate)
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize' 'StartupDelayInMSec' 'REG_DWORD' '0'
    # Remove chkdsk countdown at boot — runs immediately if volume is flagged, skips otherwise
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\Session Manager' 'AutoChkTimeOut' 'REG_DWORD' '0'
    # Fast Startup (HiberBoot) ON — kernel hibernation gives faster cold boots on desktop
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\Session Manager\Power' 'HiberbootEnabled' 'REG_DWORD' '1'
    # BCD tweaks — cannot modify BCD store offline; deferred to first boot via RunOnce
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' 'PerfTuneBCD' 'REG_SZ' `
        'powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& bcdedit /set timeout 10 2>&1 | Out-Null"'

    Write-Log "Performance optimizations applied (desktop/dev profile)"
}

function Unload-RegistryHives {
    Write-Log "Unloading registry hives..."
    
    reg unload HKLM\zCOMPONENTS | Out-Null
    reg unload HKLM\zDEFAULT | Out-Null
    reg unload HKLM\zNTUSER | Out-Null
    reg unload HKLM\zSOFTWARE | Out-Null
    reg unload HKLM\zSYSTEM | Out-Null
    
    Write-Log "Registry hives unloaded"
}

function Optimize-WindowsImage {
    Write-Log "Cleaning up Windows image (this may take 10-15 minutes)..."
    & dism.exe /Image:$scratchDir /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
    Write-Log "Image cleanup complete"
}

function Dismount-AndExport {
    Write-Log "Dismounting install.wim..."
    Dismount-WindowsImage -Path $scratchDir -Save
    
    Write-Log "Exporting image with maximum compression (this may take 15-20 minutes)..."
    $tempWim = "$tiny11Dir\sources\install2.wim"
    & Dism.exe /Export-Image /SourceImageFile:$wimFilePath /SourceIndex:$INDEX `
        /DestinationImageFile:$tempWim /Compress:recovery | Out-Null
    
    # Never delete the source image if the export above failed. A failed export that
    # still deletes install.wim leaves the ISO with no install image at all, and
    # Windows Setup reports that as "A media driver your computer needs is missing"
    # - which looks like a USB or driver fault and hides the real cause.
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tempWim)) {
        throw "DISM /Export-Image failed (exit code $LASTEXITCODE). Refusing to delete $wimFilePath."
    }

    Remove-Item -Path $wimFilePath -Force
    Rename-Item -Path $tempWim -NewName "install.wim"
    
    Write-Log "Install.wim export complete"
}

function Process-BootImage {
    Write-Log "Processing boot.wim..."
    
    $bootWimPath = "$tiny11Dir\sources\boot.wim"
    
    # Take ownership
    $adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
    & takeown /F $bootWimPath /A | Out-Null
    & icacls $bootWimPath /grant "$($adminGroup.Value):(F)" | Out-Null
    Set-ItemProperty -Path $bootWimPath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
    
    Write-Log "Mounting boot.wim (Index 2)..."
    Mount-WindowsImage -ImagePath $bootWimPath -Index 2 -Path $scratchDir
    
    Write-Log "Loading boot image registry..."
    reg load HKLM\zCOMPONENTS "$scratchDir\Windows\System32\config\COMPONENTS" | Out-Null
    reg load HKLM\zDEFAULT "$scratchDir\Windows\System32\config\default" | Out-Null
    reg load HKLM\zNTUSER "$scratchDir\Users\Default\ntuser.dat" | Out-Null
    reg load HKLM\zSOFTWARE "$scratchDir\Windows\System32\config\SOFTWARE" | Out-Null
    reg load HKLM\zSYSTEM "$scratchDir\Windows\System32\config\SYSTEM" | Out-Null
    
    Write-Log "Applying system requirement bypasses to boot image..."
    Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassCPUCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassRAMCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassSecureBootCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassStorageCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassTPMCheck' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\Setup\MoSetup' 'AllowUpgradesWithUnsupportedTPMOrCPU' 'REG_DWORD' '1'
    
    Unload-RegistryHives
    
    Write-Log "Dismounting boot.wim..."
    Dismount-WindowsImage -Path $scratchDir -Save
    
    Write-Log "Boot image processing complete"
}

function Create-TinyISO {
    Write-Log "Creating ISO image..."
    
    # The answer file at the ISO root is the one Windows Setup auto-detects when
    # booting the media. Write-IsoAnswerFile also pins the edition index into it.
    Write-IsoAnswerFile -Destination "$tiny11Dir\autounattend.xml" -AccountMode $AccountSetup
    
    # Guard: an ISO with no usable install image produces exactly the symptom
    # "A media driver your computer needs is missing" when Setup looks for its media,
    # which is easy to misread as a USB or driver fault. Fail the build here rather
    # than shipping it.
    $installImages = @("$tiny11Dir\sources\install.wim", "$tiny11Dir\sources\install.esd") |
        Where-Object { Test-Path $_ }

    if (-not $installImages) {
        throw "No install.wim or install.esd in $tiny11Dir\sources - the image export step failed. Refusing to build an ISO that Setup cannot install from."
    }

    foreach ($img in $installImages) {
        $imgMB = [math]::Round((Get-Item $img).Length / 1MB, 1)
        Write-Log "Install image $([System.IO.Path]::GetFileName($img)): ${imgMB}MB"
        if ($imgMB -lt 500) {
            throw "Install image $img is only ${imgMB}MB - it looks truncated. Refusing to build the ISO."
        }
    }

    # A leftover export would confuse Setup's media detection.
    foreach ($stray in @('install2.wim', 'install2.esd')) {
        $strayPath = Join-Path "$tiny11Dir\sources" $stray
        if (Test-Path $strayPath) {
            Write-Log "Removing leftover $stray from sources\" "WARN"
            Remove-Item -Path $strayPath -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Determine oscdimg.exe location
    $hostArchitecture = $Env:PROCESSOR_ARCHITECTURE
    $ADKDepTools = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\$hostArchitecture\Oscdimg"
    $localOSCDIMGPath = "$PSScriptRoot\oscdimg.exe"
    
    if (Test-Path "$ADKDepTools\oscdimg.exe") {
        Write-Log "Using oscdimg.exe from Windows ADK"
        $OSCDIMG = "$ADKDepTools\oscdimg.exe"
    } else {
        Write-Log "ADK not found, downloading oscdimg.exe..."
        $url = "https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe"
        
        if (-not (Test-Path $localOSCDIMGPath)) {
            Invoke-WebRequest -Uri $url -OutFile $localOSCDIMGPath -UseBasicParsing
            Write-Log "Downloaded oscdimg.exe"
        }
        
        $OSCDIMG = $localOSCDIMGPath
    }
    
    # ---- ISO container --------------------------------------------------------
    # -u2        ISO9660 + Joliet + UDF, the layout Microsoft's own retail media
    #            uses. ISO9660 alone cannot hold a >4 GB file, so the UDF layer is
    #            what carries install.wim.
    # -udfver150 UDF 1.50 rather than 1.02. UDF 1.02 cannot describe a single file
    #            larger than 4 GB and a Standard install.wim can exceed that. This
    #            is a robustness fix only - it is NOT what made Ventoy fail. See
    #            "Booting a Tiny11 ISO from Ventoy" in README.md for that.
    Write-Log "Building bootable ISO (this may take 5-10 minutes)..."
    & $OSCDIMG '-m' '-o' '-u2' '-udfver150' `
        "-bootdata:2#p0,e,b$tiny11Dir\boot\etfsboot.com#pEF,e,b$tiny11Dir\efi\microsoft\boot\efisys.bin" `
        $tiny11Dir $outputISO | Out-Null
    
    if (Test-Path $outputISO) {
        $isoSize = [math]::Round((Get-Item $outputISO).Length / 1GB, 2)
        Write-Log "ISO created successfully: $outputISO (${isoSize}GB)"
    } else {
        throw "ISO creation failed"
    }
}

function Write-BuildInfo {
    # kelexine: emits build metadata JSON so CI can read the real Windows build number
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    try {
        $buildInfo = @{
            windows_build = $script:DetectedBuildNumber
            full_version  = $script:DetectedFullVersion
            image_name    = $script:DetectedImageName
            image_index   = $INDEX
            generated_at  = (Get-Date -Format 'o')
        }
        $buildInfo | ConvertTo-Json | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Log "Build info written to $OutputPath"
    } catch {
        Write-Log "Failed to write build info to $OutputPath : $_" "WARN"
    }
}

function Invoke-Cleanup {
    if ($SkipCleanup) {
        Write-Log "Skipping cleanup (SkipCleanup flag set)" "WARN"
        return
    }
    
    Write-Log "Performing cleanup..."
    
    # Remove temporary directories
    Remove-Item -Path $tiny11Dir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $scratchDir -Recurse -Force -ErrorAction SilentlyContinue
    
    # Remove downloaded files
    Remove-Item -Path "$PSScriptRoot\oscdimg.exe" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$PSScriptRoot\autounattend.xml" -Force -ErrorAction SilentlyContinue
    
    # Verify cleanup
    $remainingItems = @()
    if (Test-Path $tiny11Dir) { $remainingItems += "tiny11 folder" }
    if (Test-Path $scratchDir) { $remainingItems += "scratchdir folder" }
    
    if ($remainingItems.Count -gt 0) {
        Write-Log "Cleanup incomplete: $($remainingItems -join ', ') still exist" "WARN"
    } else {
        Write-Log "Cleanup complete"
    }
}

#---------[ Main Execution ]---------#
try {
    Write-Log "=== Tiny11 Headless Builder Started ===" "INFO"
    Write-Log "Author: kelexine (https://github.com/kelexine)"
    Write-Log "Parameters: ISO=$ISO, INDEX=$INDEX, SCRATCH=$ScratchDisk, AccountSetup=$AccountSetup"
    
    Test-Prerequisites
    
    Resolve-ImageIndex
    
    # Handle install.esd conversion if needed
    if (Test-Path "$DriveLetter\sources\install.esd") {
        Write-Log "Found install.esd, conversion required"
        Initialize-Directories
        Convert-ESDToWIM
        Copy-WindowsFiles
        Write-Log "Resetting INDEX to 1 since ESD was exported to a new WIM"
        $script:INDEX = 1
    } else {
        Write-Log "Found install.wim, no conversion needed"
        Initialize-Directories
        Copy-WindowsFiles
    }
    
    Mount-WindowsImageFile
    Get-ImageMetadata
    
    # Customization phase
    Remove-BloatwareApps
    Remove-EdgeAndOneDrive
    Apply-RegistryTweaks
    Apply-PerformanceTweaks
    Remove-ScheduledTasks
    Remove-NonEssentialServices
    Unload-RegistryHives
    
    # Finalization phase
    Optimize-WindowsImage
    Dismount-AndExport
    Process-BootImage
    Create-TinyISO
    Write-BuildInfo -OutputPath "$PSScriptRoot\tiny11-buildinfo.json"
    
    # Cleanup
    Invoke-Cleanup
    
    Write-Log "=== Tiny11 Build Completed Successfully ===" "INFO"
    Write-Log "Output: $outputISO"
    
    exit 0
    
} catch {
    Write-Log "FATAL ERROR: $_" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    
    # Emergency cleanup
    try {
        Get-WindowsImage -Mounted | ForEach-Object {
            Write-Log "Emergency dismount: $($_.Path)" "WARN"
            Dismount-WindowsImage -Path $_.Path -Discard -ErrorAction SilentlyContinue
        }
        
        Unload-RegistryHives -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Emergency cleanup failed: $_" "ERROR"
    }
    
    exit 1
}
