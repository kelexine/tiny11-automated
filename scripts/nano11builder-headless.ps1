<#
.SYNOPSIS
    Headless script to build a minimized Windows 11 Nano image for CI/CD automation.

.DESCRIPTION
    Automated build of an extremely streamlined Windows 11 Nano image without user interaction.
    This is the most aggressive Windows 11 optimization, removing drivers, fonts, services,
    and more. NOT suitable for any regular use - designed for rapid testing in VMs only.

.PARAMETER ISO
    Drive letter of the mounted Windows 11 ISO (required, e.g., E)

.PARAMETER INDEX
    Windows image index to process (required, e.g., 1 for Home, 6 for Pro)

.PARAMETER SCRATCH
    Drive letter for scratch disk operations (optional, defaults to script root)

.PARAMETER SkipCleanup
    Skip cleanup of temporary files after ISO creation (optional, for debugging)

.EXAMPLE
    .\nano11builder-headless.ps1 -ISO E -INDEX 1
    .\nano11builder-headless.ps1 -ISO E -INDEX 6 -SCRATCH D -SkipCleanup

.NOTES
    Original Author: ntdevlabs
    Modified by: kelexine (https://github.com/kelexine)
    GitHub: https://github.com/kelexine/tiny11-automated
    Date: 2025-12-13

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
    [switch]$SkipCleanup
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
$wimFilePath = "$ScratchDisk\nano11\sources\install.wim"
$scratchDir = "$ScratchDisk\scratchdir"
$nano11Dir = "$ScratchDisk\nano11"
$outputISO = "$PSScriptRoot\nano11.iso"
$logFile = "$PSScriptRoot\nano11_$(Get-Date -Format yyyyMMdd_HHmmss).log"

# Initialize admin identifiers for permission operations
try {
    $adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
} catch {
    Write-Warning "Failed to resolve Administrator group SID. Defaulting to 'Administrators'."
    $adminGroup = [PSCustomObject]@{ Value = "Administrators" }
}

#---------[ Helper Functions ]---------#
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Output $logMessage
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
}

function Set-RegistryValue {
    param (
        [string]$path,
        [string]$name,
        [string]$type,
        [string]$value
    )
    try {
        & 'reg' 'add' $path '/v' $name '/t' $type '/d' $value '/f' | Out-Null
        Write-Log "Set registry: $path\$name = $value"
    } catch {
        Write-Log "Error setting registry $path\$name : $_" "WARN"
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

#---------[ Core Functions ]---------#
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."

    # Check admin rights
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

    # Check disk space (minimum 30GB recommended for Nano build)
    $disk = Get-PSDrive -Name $ScratchDisk[0] -ErrorAction SilentlyContinue
    if ($disk) {
        $freeGB = [math]::Round($disk.Free / 1GB, 2)
        Write-Log "Available space on ${ScratchDisk}: ${freeGB}GB"
        if ($freeGB -lt 30) {
            Write-Log "Low disk space warning: ${freeGB}GB (30GB+ recommended for Nano build)" "WARN"
        }
    }

    Write-Log "Prerequisites check passed"
}

function Initialize-Directories {
    Write-Log "Initializing directories..."
    New-Item -ItemType Directory -Force -Path "$nano11Dir\sources" | Out-Null
    New-Item -ItemType Directory -Force -Path $scratchDir | Out-Null
    Write-Log "Directories created"
}

function Convert-ESDToWIM {
    Write-Log "Converting install.esd to install.wim..."

    $esdPath = "$DriveLetter\sources\install.esd"
    $tempWimPath = "$nano11Dir\sources\install.wim"

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
    Copy-Item -Path "$DriveLetter\*" -Destination $nano11Dir -Recurse -Force -ErrorAction SilentlyContinue

    # Remove install.esd if present
    if (Test-Path "$nano11Dir\sources\install.esd") {
        Remove-Item "$nano11Dir\sources\install.esd" -Force -ErrorAction SilentlyContinue
    }

    Write-Log "File copy complete"
}

function Validate-ImageIndex {
    Write-Log "Validating image index $INDEX..."

    $images = Get-WindowsImage -ImagePath $wimFilePath
    $validIndices = $images.ImageIndex

    if ($INDEX -notin $validIndices) {
        Write-Log "Invalid index $INDEX. Available indices:" "ERROR"
        $images | ForEach-Object { Write-Log "  Index $($_.ImageIndex): $($_.ImageName)" }
        throw "Image index $INDEX not found"
    }

    $selectedImage = $images | Where-Object { $_.ImageIndex -eq $INDEX }
    Write-Log "Selected: Index $INDEX - $($selectedImage.ImageName)"
}

function Mount-WindowsImageFile {
    Write-Log "Mounting Windows image (Index: $INDEX)..."

    # Take ownership and set permissions
    & takeown /F $wimFilePath /A | Out-Null
    & icacls $wimFilePath /grant "$($adminGroup.Value):(F)" | Out-Null

    Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue

    & dism /English "/mount-image" "/imagefile:$wimFilePath" "/index:$INDEX" "/mountdir:$scratchDir"
    Write-Log "Image mounted at $scratchDir"
}

function Take-OwnershipOfFolders {
    Write-Log "Taking ownership of critical folders..."
    
    $foldersToOwn = @(
        "$scratchDir\Windows\System32\DriverStore\FileRepository",
        "$scratchDir\Windows\Fonts",
        "$scratchDir\Windows\Web",
        "$scratchDir\Windows\Help",
        "$scratchDir\Windows\Cursors",
        "$scratchDir\Program Files (x86)\Microsoft",
        "$scratchDir\Program Files\WindowsApps",
        "$scratchDir\Windows\System32\Microsoft-Edge-Webview",
        "$scratchDir\Windows\System32\Recovery",
        "$scratchDir\Windows\WinSxS",
        "$scratchDir\Windows\assembly",
        "$scratchDir\ProgramData\Microsoft\Windows Defender",
        "$scratchDir\Windows\System32\InputMethod",
        "$scratchDir\Windows\Speech",
        "$scratchDir\Windows\Temp"
    )
    
    $filesToOwn = @(
        "$scratchDir\Windows\System32\OneDriveSetup.exe"
    )
    
    foreach ($folder in $foldersToOwn) {
        if (Test-Path $folder) {
            Write-Log "Taking ownership: $folder"
            & takeown.exe /F $folder /R /D Y 2>&1 | Out-Null
            & icacls.exe $folder /grant "$($adminGroup.Value):(F)" /T /C 2>&1 | Out-Null
        }
    }
    
    foreach ($file in $filesToOwn) {
        if (Test-Path $file) {
            Write-Log "Taking ownership: $file"
            & takeown.exe /F $file /D Y 2>&1 | Out-Null
            & icacls.exe $file /grant "$($adminGroup.Value):(F)" /C 2>&1 | Out-Null
        }
    }
    
    Write-Log "Ownership taken"
}

function Get-ImageMetadata {
    Write-Log "Extracting image metadata..."

    # Get language
    $imageIntl = & dism /English /Get-Intl "/Image:$scratchDir"
    $languageLine = $imageIntl -split '\n' | Where-Object { $_ -match 'Default system UI language : ([a-zA-Z]{2}-[a-zA-Z]{2})' }

    if ($languageLine) {
        $script:languageCode = $Matches[1]
        Write-Log "Language: $script:languageCode"
    } else {
        Write-Log "Language code not found, using default" "WARN"
        $script:languageCode = "en-US"
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

    if (-not $script:architecture) {
        Write-Log "Architecture not found, defaulting to amd64" "WARN"
        $script:architecture = 'amd64'
    }
}

#---------[ Nano11-Specific Removal Functions ]---------#
function Remove-BloatwareApps {
    Write-Log "Removing provisioned appx packages (extended nano11 list)..."

    $packagesToRemove = Get-AppxProvisionedPackage -Path $scratchDir | Where-Object {
        $_.PackageName -like '*Zune*' -or
        $_.PackageName -like '*Bing*' -or
        $_.PackageName -like '*Clipchamp*' -or
        $_.PackageName -like '*Gaming*' -or
        $_.PackageName -like '*People*' -or
        $_.PackageName -like '*PowerAutomate*' -or
        $_.PackageName -like '*Teams*' -or
        $_.PackageName -like '*Todos*' -or
        $_.PackageName -like '*YourPhone*' -or
        $_.PackageName -like '*SoundRecorder*' -or
        $_.PackageName -like '*Solitaire*' -or
        $_.PackageName -like '*FeedbackHub*' -or
        $_.PackageName -like '*Maps*' -or
        $_.PackageName -like '*OfficeHub*' -or
        $_.PackageName -like '*Help*' -or
        $_.PackageName -like '*Family*' -or
        $_.PackageName -like '*Alarms*' -or
        $_.PackageName -like '*CommunicationsApps*' -or
        $_.PackageName -like '*Copilot*' -or
        $_.PackageName -like '*CompatibilityEnhancements*' -or
        $_.PackageName -like '*AV1VideoExtension*' -or
        $_.PackageName -like '*AVCEncoderVideoExtension*' -or
        $_.PackageName -like '*HEIFImageExtension*' -or
        $_.PackageName -like '*HEVCVideoExtension*' -or
        $_.PackageName -like '*MicrosoftStickyNotes*' -or
        $_.PackageName -like '*OutlookForWindows*' -or
        $_.PackageName -like '*RawImageExtension*' -or
        $_.PackageName -like '*SecHealthUI*' -or
        $_.PackageName -like '*VP9VideoExtensions*' -or
        $_.PackageName -like '*WebpImageExtension*' -or
        $_.PackageName -like '*DevHome*' -or
        $_.PackageName -like '*Photos*' -or
        $_.PackageName -like '*Camera*' -or
        $_.PackageName -like '*QuickAssist*' -or
        $_.PackageName -like '*CoreAI*' -or
        $_.PackageName -like '*PeopleExperienceHost*' -or
        $_.PackageName -like '*PinningConfirmationDialog*' -or
        $_.PackageName -like '*SecureAssessmentBrowser*' -or
        $_.PackageName -like '*Paint*' -or
        $_.PackageName -like '*Notepad*'
    }

    $removeCount = 0
    foreach ($package in $packagesToRemove) {
        Write-Log "Removing: $($package.DisplayName)"
        Remove-AppxProvisionedPackage -Path $scratchDir -PackageName $package.PackageName -ErrorAction SilentlyContinue
        $removeCount++
    }

    # Clean up leftover WindowsApps folders
    Write-Log "Cleaning leftover WindowsApps folders..."
    foreach ($package in $packagesToRemove) {
        $folderPath = Join-Path "$scratchDir\Program Files\WindowsApps" $package.PackageName
        if (Test-Path $folderPath) {
            Remove-Item $folderPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Log "Removed $removeCount appx packages"
}

function Remove-SystemPackages {
    Write-Log "Removing system packages (extended nano11 list)..."

    $packagePatterns = @(
        # Legacy Components & Optional Apps
        "Microsoft-Windows-InternetExplorer-Optional-Package~",
        "Microsoft-Windows-MediaPlayer-Package~",
        "Microsoft-Windows-WordPad-FoD-Package~",
        "Microsoft-Windows-StepsRecorder-Package~",
        "Microsoft-Windows-MSPaint-FoD-Package~",
        "Microsoft-Windows-SnippingTool-FoD-Package~",
        "Microsoft-Windows-TabletPCMath-Package~",
        "Microsoft-Windows-Xps-Xps-Viewer-Opt-Package~",
        "Microsoft-Windows-PowerShell-ISE-FOD-Package~",
        "OpenSSH-Client-Package~",
        
        # Language & Input Features
        "Microsoft-Windows-LanguageFeatures-Handwriting-$($script:languageCode)-Package~",
        "Microsoft-Windows-LanguageFeatures-OCR-$($script:languageCode)-Package~",
        "Microsoft-Windows-LanguageFeatures-Speech-$($script:languageCode)-Package~",
        "Microsoft-Windows-LanguageFeatures-TextToSpeech-$($script:languageCode)-Package~",
        "*IME-ja-jp*",
        "*IME-ko-kr*",
        "*IME-zh-cn*",
        "*IME-zh-tw*",
        
        # Core OS Features
        "Windows-Defender-Client-Package~",
        "Microsoft-Windows-Search-Engine-Client-Package~",
        "Microsoft-Windows-Kernel-LA57-FoD-Package~",
        
        # Security & Identity
        "Microsoft-Windows-Hello-Face-Package~",
        "Microsoft-Windows-Hello-BioEnrollment-Package~",
        "Microsoft-Windows-BitLocker-DriveEncryption-FVE-Package~",
        "Microsoft-Windows-TPM-WMI-Provider-Package~",
        
        # Accessibility Tools
        "Microsoft-Windows-Narrator-App-Package~",
        "Microsoft-Windows-Magnifier-App-Package~",
        
        # Miscellaneous Features
        "Microsoft-Windows-Printing-PMCPPC-FoD-Package~",
        "Microsoft-Windows-WebcamExperience-Package~",
        "Microsoft-Media-MPEG2-Decoder-Package~",
        "Microsoft-Windows-Wallpaper-Content-Extended-FoD-Package~"
    )

    $allPackages = & dism /image:$scratchDir /Get-Packages /Format:Table
    $allPackages = $allPackages -split "`n" | Select-Object -Skip 1

    $removeCount = 0
    foreach ($packagePattern in $packagePatterns) {
        $packagesToRemove = $allPackages | Where-Object { $_ -like "$packagePattern*" }
        foreach ($package in $packagesToRemove) {
            $packageIdentity = ($package -split "\s+")[0]
            if ($packageIdentity) {
                Write-Log "Removing package: $packageIdentity"
                & dism /image:$scratchDir /Remove-Package /PackageName:$packageIdentity /Quiet /NoRestart 2>&1 | Out-Null
                $removeCount++
            }
        }
    }

    Write-Log "Removed $removeCount system packages"
}

function Remove-NativeImages {
    Write-Log "Removing pre-compiled .NET assemblies (Native Images)..."
    $nativeImagesPath = "$scratchDir\Windows\assembly\NativeImages_*"
    Remove-Item -Path $nativeImagesPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log ".NET Native Images removed"
}

function Slim-DriverStore {
    Write-Log "Slimming the DriverStore (removing non-essential driver classes)..."
    
    $driverRepo = "$scratchDir\Windows\System32\DriverStore\FileRepository"
    $patternsToRemove = @(
        'prn*',      # Printer drivers
        'scan*',     # Scanner drivers
        'mfd*',      # Multi-function device drivers
        'wscsmd.inf*', # Smartcard readers
        'tapdrv*',   # Tape drives
        'rdpbus.inf*', # Remote Desktop virtual bus
        'tdibth.inf*'  # Bluetooth Personal Area Network
    )

    $removeCount = 0
    Get-ChildItem -Path $driverRepo -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $driverFolder = $_.Name
        foreach ($pattern in $patternsToRemove) {
            if ($driverFolder -like $pattern) {
                Write-Log "Removing driver: $driverFolder"
                Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                $removeCount++
                break
            }
        }
    }

    Write-Log "Removed $removeCount driver packages"
}

function Reduce-Fonts {
    Write-Log "Reducing fonts (keeping only essentials)..."
    
    $fontsPath = "$scratchDir\Windows\Fonts"
    if (Test-Path $fontsPath) {
        # Keep essential fonts, remove the rest
        Get-ChildItem -Path $fontsPath -Exclude "segoe*.*", "tahoma*.*", "marlett.ttf", "8541oem.fon", "segui*.*", "consol*.*", "lucon*.*", "calibri*.*", "arial*.*", "times*.*", "cou*.*", "8*.*" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        
        # Remove CJK fonts explicitly
        Get-ChildItem -Path $fontsPath -Include "mingli*", "msjh*", "msyh*", "malgun*", "meiryo*", "yugoth*", "segoeuihistoric.ttf" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Log "Fonts reduced"
}

function Clean-InputMethods {
    Write-Log "Cleaning input methods (removing CJK)..."
    
    $inputMethodPaths = @(
        "$scratchDir\Windows\System32\InputMethod\CHS",
        "$scratchDir\Windows\System32\InputMethod\CHT",
        "$scratchDir\Windows\System32\InputMethod\JPN",
        "$scratchDir\Windows\System32\InputMethod\KOR"
    )

    foreach ($path in $inputMethodPaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Log "Input methods cleaned"
}

function Remove-MiscellaneousFiles {
    Write-Log "Performing aggressive file deletions..."
    
    # Speech TTS
    Remove-Item -Path "$scratchDir\Windows\Speech\Engines\TTS" -Recurse -Force -ErrorAction SilentlyContinue
    
    # Defender definitions
    Remove-Item -Path "$scratchDir\ProgramData\Microsoft\Windows Defender\Definition Updates" -Recurse -Force -ErrorAction SilentlyContinue
    
    # Temp files
    Remove-Item -Path "$scratchDir\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    
    # Web, Help, Cursors
    Remove-Item -Path "$scratchDir\Windows\Web" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$scratchDir\Windows\Help" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$scratchDir\Windows\Cursors" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Log "Miscellaneous files removed"
}

function Remove-EdgeAndOneDrive {
    Write-Log "Removing Microsoft Edge and OneDrive..."

    # Remove Edge paths
    Remove-Item -Path "$scratchDir\Program Files (x86)\Microsoft\Edge*" -Recurse -Force -ErrorAction SilentlyContinue
    
    # Remove Edge WebView from WinSxS
    if ($script:architecture -eq 'amd64') {
        $folderPath = Get-ChildItem -Path "$scratchDir\Windows\WinSxS" -Filter "amd64_microsoft-edge-webview_31bf3856ad364e35*" -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        if ($folderPath) {
            Remove-Item -Path $folderPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Remove-Item -Path "$scratchDir\Windows\System32\Microsoft-Edge-Webview" -Recurse -Force -ErrorAction SilentlyContinue
    
    # Remove OneDrive
    Remove-Item -Path "$scratchDir\Windows\System32\OneDriveSetup.exe" -Force -ErrorAction SilentlyContinue

    Write-Log "Edge and OneDrive removed"
}

function Remove-WinRE {
    Write-Log "Removing Windows Recovery Environment..."
    
    $winRE = "$scratchDir\Windows\System32\Recovery\winre.wim"
    if (Test-Path $winRE) {
        Remove-Item -Path $winRE -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -Path $winRE -ItemType File -Force | Out-Null
    }

    Write-Log "WinRE removed"
}

function Optimize-WinSxS {
    Write-Log "Optimizing WinSxS folder..."

    $sourceDirectory = "$scratchDir\Windows\WinSxS"
    $destinationDirectory = "$scratchDir\Windows\WinSxS_edit"

    New-Item -Path $destinationDirectory -ItemType Directory -Force | Out-Null

    $dirsToCopy = @()

    if ($script:architecture -eq "amd64") {
        $dirsToCopy = @(
            "x86_microsoft.windows.common-controls_6595b64144ccf1df_*",
            "x86_microsoft.windows.gdiplus_6595b64144ccf1df_*",
            "x86_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*",
            "x86_microsoft.windows.isolationautomation_6595b64144ccf1df_*",
            "x86_microsoft-windows-s..ngstack-onecorebase_31bf3856ad364e35_*",
            "x86_microsoft-windows-s..stack-termsrv-extra_31bf3856ad364e35_*",
            "x86_microsoft-windows-servicingstack_31bf3856ad364e35_*",
            "x86_microsoft-windows-servicingstack-inetsrv_*",
            "x86_microsoft-windows-servicingstack-onecore_*",
            "amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*",
            "amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*",
            "amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*",
            "amd64_microsoft.windows.common-controls_6595b64144ccf1df_*",
            "amd64_microsoft.windows.gdiplus_6595b64144ccf1df_*",
            "amd64_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*",
            "amd64_microsoft.windows.isolationautomation_6595b64144ccf1df_*",
            "amd64_microsoft-windows-s..stack-inetsrv-extra_31bf3856ad364e35_*",
            "amd64_microsoft-windows-s..stack-msg.resources_31bf3856ad364e35_*",
            "amd64_microsoft-windows-s..stack-termsrv-extra_31bf3856ad364e35_*",
            "amd64_microsoft-windows-servicingstack_31bf3856ad364e35_*",
            "amd64_microsoft-windows-servicingstack-inetsrv_31bf3856ad364e35_*",
            "amd64_microsoft-windows-servicingstack-msg_31bf3856ad364e35_*",
            "amd64_microsoft-windows-servicingstack-onecore_31bf3856ad364e35_*",
            "Catalogs",
            "FileMaps",
            "Fusion",
            "InstallTemp",
            "Manifests",
            "x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*",
            "x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*",
            "x86_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*"
        )
    } elseif ($script:architecture -eq "arm64") {
        $dirsToCopy = @(
            "arm64_microsoft-windows-servicingstack-onecore_31bf3856ad364e35_*",
            "Catalogs",
            "FileMaps",
            "Fusion",
            "InstallTemp",
            "Manifests",
            "SettingsManifests",
            "Temp",
            "x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*",
            "x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*",
            "x86_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*",
            "x86_microsoft.windows.common-controls_6595b64144ccf1df_*",
            "x86_microsoft.windows.gdiplus_6595b64144ccf1df_*",
            "arm_microsoft.windows.common-controls_6595b64144ccf1df_*",
            "arm64_microsoft.windows.common-controls_6595b64144ccf1df_*",
            "arm64_microsoft-windows-servicingstack_31bf3856ad364e35_*"
        )
    }

    foreach ($dir in $dirsToCopy) {
        $sourceDirs = Get-ChildItem -Path $sourceDirectory -Filter $dir -Directory -ErrorAction SilentlyContinue
        foreach ($sourceDir in $sourceDirs) {
            $destDir = Join-Path -Path $destinationDirectory -ChildPath $sourceDir.Name
            Write-Log "Copying: $($sourceDir.Name)"
            Copy-Item -Path $sourceDir.FullName -Destination $destDir -Recurse -Force
        }
    }

    Write-Log "Replacing WinSxS with minimal version..."
    Remove-Item -Path $sourceDirectory -Recurse -Force
    Rename-Item -Path $destinationDirectory -NewName "WinSxS"

    Write-Log "WinSxS optimization complete"
}

#---------[ Registry Functions ]---------#
function Load-RegistryHives {
    Write-Log "Loading registry hives..."

    reg load HKLM\zCOMPONENTS "$scratchDir\Windows\System32\config\COMPONENTS" 2>&1 | Out-Null
    reg load HKLM\zDEFAULT "$scratchDir\Windows\System32\config\default" 2>&1 | Out-Null
    reg load HKLM\zNTUSER "$scratchDir\Users\Default\ntuser.dat" 2>&1 | Out-Null
    reg load HKLM\zSOFTWARE "$scratchDir\Windows\System32\config\SOFTWARE" 2>&1 | Out-Null
    reg load HKLM\zSYSTEM "$scratchDir\Windows\System32\config\SYSTEM" 2>&1 | Out-Null

    Write-Log "Registry hives loaded"
}

function Unload-RegistryHives {
    Write-Log "Unloading registry hives..."

    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    Start-Sleep -Seconds 3

    reg unload HKLM\zCOMPONENTS 2>&1 | Out-Null
    reg unload HKLM\zDEFAULT 2>&1 | Out-Null
    reg unload HKLM\zNTUSER 2>&1 | Out-Null
    reg unload HKLM\zSOFTWARE 2>&1 | Out-Null
    reg unload HKLM\zSYSTEM 2>&1 | Out-Null

    Write-Log "Registry hives unloaded"
}

function Apply-RegistryTweaks {
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
    Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SystemPaneSuggestionsEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' 'DisablePushToInstall' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' 'DontOfferThroughWUAU' 'REG_DWORD' '1'

    Remove-RegistryKey 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions'
    Remove-RegistryKey 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps'

    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableConsumerAccountStateContent' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableCloudOptimizedContent' 'REG_DWORD' '1'

    # Enable local accounts on OOBE
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' 'BypassNRO' 'REG_DWORD' '1'

    # Copy autounattend-nano.xml as autounattend.xml
    $nanoAutoUnattend = Join-Path (Split-Path $PSScriptRoot -Parent) "autounattend-nano.xml"
    if (Test-Path $nanoAutoUnattend) {
        Copy-Item -Path $nanoAutoUnattend -Destination "$scratchDir\Windows\System32\Sysprep\autounattend.xml" -Force
        Write-Log "Copied autounattend-nano.xml to Sysprep"
    }

    # Disable reserved storage
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' 'ShippedWithReserves' 'REG_DWORD' '0'

    # Disable BitLocker
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' 'PreventDeviceEncryption' 'REG_DWORD' '1'

    # Disable Chat icon
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' 'ChatIcon' 'REG_DWORD' '3'
    Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarMn' 'REG_DWORD' '0'

    # Remove Edge registries
    Remove-RegistryKey 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge'
    Remove-RegistryKey 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update'

    # Disable OneDrive folder backup
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive' 'DisableFileSyncNGSC' 'REG_DWORD' '1'

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
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' 'workCompleted' 'REG_DWORD' '1'
    Remove-RegistryKey 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate'
    Remove-RegistryKey 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate'

    # Disable Copilot
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Edge' 'HubsSidebarEnabled' 'REG_DWORD' '0'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 'REG_DWORD' '1'

    # Prevent Teams installation
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Teams' 'DisableInstallation' 'REG_DWORD' '1'

    # Prevent new Outlook installation
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Mail' 'PreventRun' 'REG_DWORD' '1'

    # Disable Windows Update
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' 'StopWUPostOOBE1' 'REG_SZ' 'net stop wuauserv'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' 'StopWUPostOOBE2' 'REG_SZ' 'sc stop wuauserv'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' 'StopWUPostOOBE3' 'REG_SZ' 'sc config wuauserv start= disabled'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DoNotConnectToWindowsUpdateInternetLocations' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DisableWindowsUpdateAccess' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer' 'REG_SZ' 'localhost'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUStatusServer' 'REG_SZ' 'localhost'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'UpdateServiceUrlAlternate' 'REG_SZ' 'localhost'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'UseWUServer' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' 'DisableOnline' 'REG_DWORD' '1'
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\wuauserv' 'Start' 'REG_DWORD' '4'

    # Delete WaaS services
    Remove-RegistryKey 'HKLM\zSYSTEM\ControlSet001\Services\WaaSMedicSVC'
    Remove-RegistryKey 'HKLM\zSYSTEM\ControlSet001\Services\UsoSvc'

    # Disable Windows Defender
    Write-Log "Disabling Windows Defender services..."
    $servicePaths = @("WinDefend", "WdNisSvc", "WdNisDrv", "WdFilter", "Sense")
    foreach ($path in $servicePaths) {
        Set-RegistryValue "HKLM\zSYSTEM\ControlSet001\Services\$path" "Start" "REG_DWORD" "4"
    }

    # Hide settings pages
    Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'SettingsPageVisibility' 'REG_SZ' 'hide:virus;windowsupdate'

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
        }
    }

    Write-Log "Scheduled tasks removed"
}

function Remove-Services {
    Write-Log "Removing non-essential services (nano11-specific)..."

    # Load SYSTEM hive separately for service removal
    reg load HKLM\zSYSTEM "$scratchDir\Windows\System32\config\SYSTEM" 2>&1 | Out-Null

    $servicesToRemove = @(
        'Spooler',
        'PrintNotify',
        'Fax',
        'RemoteRegistry',
        'diagsvc',
        'WerSvc',
        'PcaSvc',
        'MapsBroker',
        'WalletService',
        'BthAvctpSvc',
        'BluetoothUserService',
        'wuauserv',
        'UsoSvc',
        'WaaSMedicSvc'
    )

    foreach ($service in $servicesToRemove) {
        Write-Log "Removing service: $service"
        & 'reg' 'delete' "HKLM\zSYSTEM\ControlSet001\Services\$service" /f 2>&1 | Out-Null
    }

    reg unload HKLM\zSYSTEM 2>&1 | Out-Null

    Write-Log "Services removed"
}

#---------[ Finalization Functions ]---------#
function Optimize-WindowsImage {
    Write-Log "Cleaning up Windows image (this may take 10-15 minutes)..."
    & dism.exe /Image:$scratchDir /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1 | Out-Null
    Write-Log "Image cleanup complete"
}

function Dismount-AndExport {
    Write-Log "Dismounting install.wim..."
    & dism /English /unmount-image "/mountdir:$scratchDir" /commit

    Write-Log "Exporting image with maximum compression..."
    $tempWim = "$nano11Dir\sources\install2.wim"
    & Dism.exe /English /Export-Image /SourceImageFile:$wimFilePath /SourceIndex:$INDEX /DestinationImageFile:$tempWim /Compress:max

    Remove-Item -Path $wimFilePath -Force
    Rename-Item -Path $tempWim -NewName "install.wim"

    Write-Log "Install.wim export complete"
}

function Process-BootImage {
    Write-Log "Processing boot.wim (nano11 shrinking)..."

    $bootWimPath = "$nano11Dir\sources\boot.wim"

    # Take ownership
    & takeown /F $bootWimPath /A 2>&1 | Out-Null
    & icacls $bootWimPath /grant "$($adminGroup.Value):(F)" 2>&1 | Out-Null
    Set-ItemProperty -Path $bootWimPath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue

    # Export only index 2 (setup image)
    Write-Log "Exporting boot.wim index 2..."
    $newBootWimPath = "$nano11Dir\sources\boot_new.wim"
    & dism /English /Export-Image /SourceImageFile:$bootWimPath /SourceIndex:2 /DestinationImageFile:$newBootWimPath

    # Mount the new boot image
    Write-Log "Mounting boot image for modifications..."
    & dism /English /mount-image "/imagefile:$newBootWimPath" /index:1 "/mountdir:$scratchDir"

    # Load registry and apply bypasses
    reg load HKLM\zDEFAULT "$scratchDir\Windows\System32\config\default" 2>&1 | Out-Null
    reg load HKLM\zNTUSER "$scratchDir\Users\Default\ntuser.dat" 2>&1 | Out-Null
    reg load HKLM\zSOFTWARE "$scratchDir\Windows\System32\config\SOFTWARE" 2>&1 | Out-Null
    reg load HKLM\zSYSTEM "$scratchDir\Windows\System32\config\SYSTEM" 2>&1 | Out-Null

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
    Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' 'PreventDeviceEncryption' 'REG_DWORD' '1'

    # Unload registry
    reg unload HKLM\zNTUSER 2>&1 | Out-Null
    reg unload HKLM\zDEFAULT 2>&1 | Out-Null
    reg unload HKLM\zSOFTWARE 2>&1 | Out-Null
    reg unload HKLM\zSYSTEM 2>&1 | Out-Null

    Start-Sleep -Seconds 5

    # Dismount boot image
    Write-Log "Dismounting boot image..."
    & dism /English /unmount-image "/mountdir:$scratchDir" /commit

    # Replace original boot.wim with shrunk version
    Remove-Item -Path $bootWimPath -Force
    $finalBootWimPath = "$nano11Dir\sources\boot_final.wim"
    & dism /English /Export-Image /SourceImageFile:$newBootWimPath /SourceIndex:1 /DestinationImageFile:$finalBootWimPath /Compress:max
    Remove-Item -Path $newBootWimPath -Force
    Rename-Item -Path $finalBootWimPath -NewName "boot.wim"

    Write-Log "Boot image processing complete"
}

function Convert-ToESD {
    Write-Log "Converting to ESD format for maximum compression..."
    $esdPath = "$nano11Dir\sources\install.esd"
    & dism /Export-Image /SourceImageFile:$wimFilePath /SourceIndex:1 /DestinationImageFile:$esdPath /Compress:recovery
    Remove-Item $wimFilePath -Force -ErrorAction SilentlyContinue
    Write-Log "ESD conversion complete"
}

function Clean-IsoRoot {
    Write-Log "Cleaning ISO root (keeping only essentials)..."
    
    $keepList = @("boot", "efi", "sources", "bootmgr", "bootmgr.efi", "setup.exe", "autounattend.xml")
    Get-ChildItem -Path $nano11Dir | Where-Object { $_.Name -notin $keepList } | ForEach-Object {
        Write-Log "Removing from ISO root: $($_.Name)"
        Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Log "ISO root cleaned"
}

function Create-NanoISO {
    Write-Log "Creating ISO image..."

    # Copy autounattend-nano.xml as autounattend.xml to ISO root
    $nanoAutoUnattend = Join-Path (Split-Path $PSScriptRoot -Parent) "autounattend-nano.xml"
    if (Test-Path $nanoAutoUnattend) {
        Copy-Item -Path $nanoAutoUnattend -Destination "$nano11Dir\autounattend.xml" -Force
        Write-Log "Copied autounattend-nano.xml to ISO root as autounattend.xml"
    }

    # Verify boot files
    $bootFiles = @(
        "$nano11Dir\boot\etfsboot.com",
        "$nano11Dir\efi\microsoft\boot\efisys.bin"
    )
    foreach ($bootFile in $bootFiles) {
        if (-not (Test-Path $bootFile)) {
            throw "Required boot file not found: $bootFile"
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
        }
        $OSCDIMG = $localOSCDIMGPath
    }

    Write-Log "Building bootable ISO..."
    & $OSCDIMG '-m' '-o' '-u2' '-udfver102' `
        "-bootdata:2#p0,e,b$nano11Dir\boot\etfsboot.com#pEF,e,b$nano11Dir\efi\microsoft\boot\efisys.bin" `
        $nano11Dir $outputISO

    if (Test-Path $outputISO) {
        $isoSize = [math]::Round((Get-Item $outputISO).Length / 1GB, 2)
        Write-Log "ISO created successfully: $outputISO (${isoSize}GB)"
    } else {
        throw "ISO creation failed"
    }
}

function Invoke-Cleanup {
    if ($SkipCleanup) {
        Write-Log "Skipping cleanup (SkipCleanup flag set)" "WARN"
        return
    }

    Write-Log "Performing cleanup..."

    # Ensure image is unmounted
    & dism /English /unmount-image "/mountdir:$scratchDir" /discard 2>&1 | Out-Null

    Remove-Item -Path $nano11Dir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $scratchDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$PSScriptRoot\oscdimg.exe" -Force -ErrorAction SilentlyContinue

    Write-Log "Cleanup complete"
}

#---------[ Main Execution ]---------#
try {
    Write-Log "=== Nano11 Headless Builder Started ===" "INFO"
    Write-Log "Author: kelexine (https://github.com/kelexine)"
    Write-Log "Parameters: ISO=$ISO, INDEX=$INDEX, SCRATCH=$ScratchDisk"
    Write-Log "WARNING: This creates the most minimal Windows 11 image - FOR TESTING ONLY!"

    Test-Prerequisites
    Initialize-Directories

    # Handle install.esd conversion if needed
    if (Test-Path "$DriveLetter\sources\install.esd") {
        Write-Log "Found install.esd, conversion required"
        Convert-ESDToWIM
        Copy-WindowsFiles
    } else {
        Write-Log "Found install.wim, no conversion needed"
        Copy-WindowsFiles
    }

    Validate-ImageIndex
    Mount-WindowsImageFile
    Take-OwnershipOfFolders
    Get-ImageMetadata

    # Customization phase
    Remove-BloatwareApps
    Remove-SystemPackages
    Remove-NativeImages
    Slim-DriverStore
    Reduce-Fonts
    Clean-InputMethods
    Remove-MiscellaneousFiles
    Remove-EdgeAndOneDrive
    Remove-WinRE

    # Registry phase
    Load-RegistryHives
    Apply-RegistryTweaks
    Remove-ScheduledTasks
    Unload-RegistryHives

    # Service removal (separate registry operation)
    Remove-Services

    # WinSxS optimization
    Optimize-WinSxS

    # Finalization phase
    Dismount-AndExport
    Process-BootImage
    Convert-ToESD
    Clean-IsoRoot
    Create-NanoISO

    # Cleanup
    Invoke-Cleanup

    Write-Log "=== Nano11 Build Completed Successfully ===" "INFO"
    Write-Log "Output: $outputISO"
    Write-Log "WARNING: This is AN EXTREMELY MINIMAL build - NOT for daily use!"

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

        @("zCOMPONENTS", "zDEFAULT", "zNTUSER", "zSOFTWARE", "zSYSTEM") | ForEach-Object {
            reg unload "HKLM\$_" 2>$null
        }
    } catch {
        Write-Log "Emergency cleanup failed: $_" "ERROR"
    }

    exit 1
}
