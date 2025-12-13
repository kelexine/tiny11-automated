if ((Get-ExecutionPolicy) -eq 'Restricted') {
    Write-Host "Your current PowerShell Execution Policy is set to Restricted, which prevents scripts from running. Do you want to change it to RemoteSigned? (yes/no)"
    $response = Read-Host
    if ($response -eq 'yes') {
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false
    } else {
        Write-Host "The script cannot be run without changing the execution policy. Exiting..."
        exit
    }
}

# Check and run the script as admin if required
$adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if (! $myWindowsPrincipal.IsInRole($adminRole))
{
    Write-Host "Restarting nano11 image creator as admin in a new window, you can close this one."
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($newProcess);
    exit
}

Start-Transcript -Path "$PSScriptRoot\nano11.log" 
# Ask the user for input
Write-Host "Welcome to nano11 builder!"
Write-Host "This script generates a significantly reduced Windows 11 image. However, it's not suitable for regular use due to its lack of serviceability - you can't add languages, updates, or features post-creation. nano11 is not a full Windows 11 substitute but a rapid testing or development tool, potentially useful for VM environments."
Write-Host "Do you want to continue? (y/n)"
$input = Read-Host

if ($input -eq 'y') {
    Write-Host "Off we go..."
Start-Sleep -Seconds 3
Clear-Host

$mainOSDrive = $env:SystemDrive
New-Item -ItemType Directory -Force -Path "$mainOSDrive\nano11\sources" 
$DriveLetter = Read-Host "Please enter the drive letter for the Windows 11 image"
$DriveLetter = $DriveLetter + ":"

if ((Test-Path "$DriveLetter\sources\boot.wim") -eq $false -or (Test-Path "$DriveLetter\sources\install.wim") -eq $false) {
    if ((Test-Path "$DriveLetter\sources\install.esd") -eq $true) {
        Write-Host "Found install.esd, converting to install.wim..."
        &  'dism' '/English' "/Get-WimInfo" "/wimfile:$DriveLetter\sources\install.esd"
        $index = Read-Host "Please enter the image index"
        Write-Host 'Converting install.esd to install.wim. This may take a while...'
        & 'DISM' /Export-Image /SourceImageFile:"$DriveLetter\sources\install.esd" /SourceIndex:$index /DestinationImageFile:"$mainOSDrive\nano11\sources\install.wim" /Compress:max /CheckIntegrity
    } else {
        Write-Host "Can't find Windows OS Installation files in the specified Drive Letter.. Exiting."
        exit
    }
}

Write-Host "Copying Windows image..."
Copy-Item -Path "$DriveLetter\*" -Destination "$mainOSDrive\nano11" -Recurse -Force > null
Remove-Item "$mainOSDrive\nano11\sources\install.esd" -ErrorAction SilentlyContinue 

Write-Host "Getting image information:"
&  'dism' '/English' "/Get-WimInfo" "/wimfile:$mainOSDrive\nano11\sources\install.wim"
$index = Read-Host "Please enter the image index"
Write-Host "Mounting Windows image. This may take a while."
$wimFilePath = "$($env:SystemDrive)\nano11\sources\install.wim" 
& takeown "/F" $wimFilePath 
& icacls $wimFilePath "/grant" "$($adminGroup.Value):(F)"
try {
    Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false -ErrorAction Stop
} catch {
    # This block will catch the error and suppress it.
}
New-Item -ItemType Directory -Force -Path "$mainOSDrive\scratchdir" 
& dism /English "/mount-image" "/imagefile:$($env:SystemDrive)\nano11\sources\install.wim" "/index:$index" "/mountdir:$($env:SystemDrive)\scratchdir"

# --- Proactively take ownership of all target folders for install.wim ---
$scratchDir = "$($env:SystemDrive)\scratchdir"
$foldersToOwn = @( "$scratchDir\Windows\System32\DriverStore\FileRepository", "$scratchDir\Windows\Fonts", "$scratchDir\Windows\Web", "$scratchDir\Windows\Help", "$scratchDir\Windows\Cursors", "$scratchDir\Program Files (x86)\Microsoft", "$scratchDir\Program Files\WindowsApps", "$scratchDir\Windows\System32\Microsoft-Edge-Webview", "$scratchDir\Windows\System32\Recovery", "$scratchDir\Windows\WinSxS", "$scratchDir\Windows\assembly", "$scratchDir\ProgramData\Microsoft\Windows Defender", "$scratchDir\Windows\System32\InputMethod", "$scratchDir\Windows\Speech", "$scratchDir\Windows\Temp" )
$filesToOwn = @( "$scratchDir\Windows\System32\OneDriveSetup.exe" )
foreach ($folder in $foldersToOwn) { if (Test-Path $folder) { Write-Host "Taking ownership of folder: $folder"; & takeown.exe /F $folder /R /D Y ; & icacls.exe $folder /grant "$($adminGroup.Value):(F)" /T /C  } }
foreach ($file in $filesToOwn) { if (Test-Path $file) { Write-Host "Taking ownership of file: $file"; & takeown.exe /F $file /D Y ; & icacls.exe $file /grant "$($adminGroup.Value):(F)" /C  } }

$imageIntl = & dism /English /Get-Intl "/Image:$scratchDir"
$languageLine = $imageIntl -split '\n' | Where-Object { $_ -match 'Default system UI language : ([a-zA-Z]{2}-[a-zA-Z]{2})' }
if ($languageLine) { $languageCode = $Matches[1]; Write-Host "Default system UI language code: $languageCode" } else { Write-Host "Default system UI language code not found." }
$imageInfo = & 'dism' '/English' '/Get-WimInfo' "/wimFile:$wimFilePath" "/index:$index"
$lines = $imageInfo -split '\r?\n'
foreach ($line in $lines) { if ($line -like '*Architecture : *') { $architecture = $line -replace 'Architecture : ',''; if ($architecture -eq 'x64') { $architecture = 'amd64' }; Write-Host "Architecture: $architecture"; break } }
if (-not $architecture) { Write-Host "Architecture information not found." }
Write-Host "Removing provisioned AppX packages (bloatware)..."
$packagesToRemove = Get-AppxProvisionedPackage -Path $scratchDir | Where-Object { $_.PackageName -like '*Zune*' -or $_.PackageName -like '*Bing*' -or $_.PackageName -like '*Clipchamp*' -or $_.PackageName -like '*Gaming*' -or $_.PackageName -like '*People*' -or $_.PackageName -like '*PowerAutomate*' -or $_.PackageName -like '*Teams*' -or $_.PackageName -like '*Todos*' -or $_.PackageName -like '*YourPhone*' -or $_.PackageName -like '*SoundRecorder*' -or $_.PackageName -like '*Solitaire*' -or $_.PackageName -like '*FeedbackHub*' -or $_.PackageName -like '*Maps*' -or $_.PackageName -like '*OfficeHub*' -or $_.PackageName -like '*Help*' -or $_.PackageName -like '*Family*' -or $_.PackageName -like '*Alarms*' -or $_.PackageName -like '*CommunicationsApps*' -or $_.PackageName -like '*Copilot*' -or $_.PackageName -like '*CompatibilityEnhancements*' -or $_.PackageName -like '*AV1VideoExtension*' -or $_.PackageName -like '*AVCEncoderVideoExtension*' -or $_.PackageName -like '*HEIFImageExtension*' -or $_.PackageName -like '*HEVCVideoExtension*' -or $_.PackageName -like '*MicrosoftStickyNotes*' -or $_.PackageName -like '*OutlookForWindows*' -or $_.PackageName -like '*RawImageExtension*' -or $_.PackageName -like '*SecHealthUI*' -or $_.PackageName -like '*VP9VideoExtensions*' -or $_.PackageName -like '*WebpImageExtension*' -or $_.PackageName -like '*DevHome*' -or $_.PackageName -like '*Photos*' -or $_.PackageName -like '*Camera*' -or $_.PackageName -like '*QuickAssist*' -or $_.PackageName -like '*CoreAI*'  -or $_.PackageName -like '*PeopleExperienceHost*' -or $_.PackageName -like '*PinningConfirmationDialog*' -or $_.PackageName -like '*SecureAssessmentBrowser*' -or $_.PackageName -like '*Paint*' -or $_.PackageName -like '*Notepad*'  }
foreach ($package in $packagesToRemove) { write-host "Removing: $($package.DisplayName)"; Remove-AppxProvisionedPackage -Path $scratchDir -PackageName $package.PackageName }

Write-Host "Attempting to remove leftover WindowsApps folders..."
foreach ($package in $packagesToRemove) { $folderPath = Join-Path "$scratchDir\Program Files\WindowsApps" $package.PackageName; if (Test-Path $folderPath) { Write-Host "Deleting folder: $($package.PackageName)"; Remove-Item $folderPath -Recurse -Force -ErrorAction SilentlyContinue } }

Write-Host "Removing of system apps complete! Now proceeding to removal of system packages..."
Start-Sleep -Seconds 1
Clear-Host

$scratchDir = "$($env:SystemDrive)\scratchdir"
$packagePatterns = @(
    # --- Legacy Components & Optional Apps ---
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

    # --- Language & Input Features (Assumes primary language only) ---
    "Microsoft-Windows-LanguageFeatures-Handwriting-$languageCode-Package~",
    "Microsoft-Windows-LanguageFeatures-OCR-$languageCode-Package~",
    "Microsoft-Windows-LanguageFeatures-Speech-$languageCode-Package~",
    "Microsoft-Windows-LanguageFeatures-TextToSpeech-$languageCode-Package~",
    "*IME-ja-jp*",
    "*IME-ko-kr*",
    "*IME-zh-cn*",
    "*IME-zh-tw*",

    # --- Core OS Features (Removal is aggressive and will break functionality) ---
    "Windows-Defender-Client-Package~",
    "Microsoft-Windows-Search-Engine-Client-Package~",
    "Microsoft-Windows-Kernel-LA57-FoD-Package~",

    # --- Security & Identity (Breaks these features) ---
    "Microsoft-Windows-Hello-Face-Package~",
    "Microsoft-Windows-Hello-BioEnrollment-Package~",
    "Microsoft-Windows-BitLocker-DriveEncryption-FVE-Package~",
    "Microsoft-Windows-TPM-WMI-Provider-Package~",

    # --- Accessibility Tools ---
    "Microsoft-Windows-Narrator-App-Package~",
    "Microsoft-Windows-Magnifier-App-Package~",

    # --- Miscellaneous Features ---
    "Microsoft-Windows-Printing-PMCPPC-FoD-Package~",
    "Microsoft-Windows-WebcamExperience-Package~",
    "Microsoft-Media-MPEG2-Decoder-Package~",
    "Microsoft-Windows-Wallpaper-Content-Extended-FoD-Package~"
)

$allPackages = & dism /image:$scratchDir /Get-Packages /Format:Table
$allPackages = $allPackages -split "`n" | Select-Object -Skip 1

foreach ($packagePattern in $packagePatterns) {
    # Filter the packages to remove
    $packagesToRemove = $allPackages | Where-Object { $_ -like "$packagePattern*" }

    foreach ($package in $packagesToRemove) {
        # Extract the package identity
        $packageIdentity = ($package -split "\s+")[0]

        Write-Host "Removing $packageIdentity..."
        & dism /image:$scratchDir /Remove-Package /PackageName:$packageIdentity 
    }
}
Write-Host "Removing pre-compiled .NET assemblies (Native Images)..."
Remove-Item -Path "$scratchDir\Windows\assembly\NativeImages_*" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Performing aggressive manual file deletions..."
$winDir = "$scratchDir\Windows"
Write-Host "Slimming the DriverStore... (removing non-essential driver classes)"
$driverRepo = Join-Path -Path $winDir -ChildPath "System32\DriverStore\FileRepository"
$patternsToRemove = @(
    'prn*',      # Printer drivers (e.g., prnms001.inf, prnge001.inf)
    'scan*',     # Scanner drivers
    'mfd*',      # Multi-function device drivers
    'wscsmd.inf*', # Smartcard readers
    'tapdrv*',   # Tape drives
    'rdpbus.inf*', # Remote Desktop virtual bus
    'tdibth.inf*'  # Bluetooth Personal Area Network
)

# Get all driver packages and remove the ones matching the patterns
Get-ChildItem -Path $driverRepo -Directory | ForEach-Object {
    $driverFolder = $_.Name
    foreach ($pattern in $patternsToRemove) {
        if ($driverFolder -like $pattern) {
            Write-Host "Removing non-essential driver package: $driverFolder"
            Remove-Item -Path $_.FullName -Recurse -Force
            break # Move to the next folder once a match is found
        }
    }
}
$fontsPath = Join-Path -Path $winDir -ChildPath "Fonts"
if (Test-Path $fontsPath) { Get-ChildItem -Path $fontsPath -Exclude "segoe*.*", "tahoma*.*", "marlett.ttf", "8541oem.fon", "segui*.*", "consol*.*", "lucon*.*", "calibri*.*", "arial*.*", "times*.*", "cou*.*", "8*.*" | Remove-Item -Recurse -Force; Get-ChildItem -Path $fontsPath -Include "mingli*", "msjh*", "msyh*", "malgun*", "meiryo*", "yugoth*", "segoeuihistoric.ttf" | Remove-Item -Recurse -Force }
Remove-Item -Path (Join-Path -Path $winDir -ChildPath "Speech\Engines\TTS") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$scratchDir\ProgramData\Microsoft\Windows Defender\Definition Updates" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$scratchDir\Windows\System32\InputMethod\CHS" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path "$scratchDir\Windows\System32\InputMethod\CHT" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path "$scratchDir\Windows\System32\InputMethod\JPN" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path "$scratchDir\Windows\System32\InputMethod\KOR" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$scratchDir\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path -Path $winDir -ChildPath "Web") -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path (Join-Path -Path $winDir -ChildPath "Help") -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path (Join-Path -Path $winDir -ChildPath "Cursors") -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Removing Edge, WinRE, and OneDrive..."
Remove-Item -Path "$scratchDir\Program Files (x86)\Microsoft\Edge*" -Recurse -Force 
if ($architecture -eq 'amd64') { $folderPath = Get-ChildItem -Path "$scratchDir\Windows\WinSxS" -Filter "amd64_microsoft-edge-webview_31bf3856ad364e35*" -Directory | Select-Object -ExpandProperty FullName } 
if ($folderPath) { Remove-Item -Path $folderPath -Recurse -Force  }
Remove-Item -Path "$scratchDir\Windows\System32\Microsoft-Edge-Webview" -Recurse -Force
Remove-Item -Path "$scratchDir\Windows\System32\Recovery\winre.wim" -Recurse -Force
New-Item -Path "$scratchDir\Windows\System32\Recovery\winre.wim" -ItemType File -Force
Remove-Item -Path "$scratchDir\Windows\System32\OneDriveSetup.exe" -Force 
& 'dism' '/English' "/image:$scratchDir" '/Cleanup-Image' '/StartComponentCleanup' '/ResetBase' 

Write-Host "Taking ownership of the WinSxS folder. This might take a while..."
& 'takeown' '/f' "$mainOSDrive\scratchdir\Windows\WinSxS" '/r'
& 'icacls' "$mainOSDrive\scratchdir\Windows\WinSxS" '/grant' "$($adminGroup.Value):(F)" '/T' '/C'
Write-host "Complete!"
$folderPath = Join-Path -Path $mainOSDrive -ChildPath "\scratchdir\Windows\WinSxS_edit"
$sourceDirectory = "$mainOSDrive\scratchdir\Windows\WinSxS"
$destinationDirectory = "$mainOSDrive\scratchdir\Windows\WinSxS_edit"
New-Item -Path $folderPath -ItemType Directory
if ($architecture -eq "amd64") {
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
        "x86_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*",
        "x86_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*"
    )
 # Copy each directory
   foreach ($dir in $dirsToCopy) {
        $sourceDirs = Get-ChildItem -Path $sourceDirectory -Filter $dir -Directory
        foreach ($sourceDir in $sourceDirs) {
            $destDir = Join-Path -Path $destinationDirectory -ChildPath $sourceDir.Name
            Write-Host "Copying $sourceDir.FullName to $destDir"
            Copy-Item -Path $sourceDir.FullName -Destination $destDir -Recurse -Force
        }
    }
}
 elseif ($architecture -eq "arm64") {
     $dirsToCopy = @(
        "arm64_microsoft-windows-servicingstack-onecore_31bf3856ad364e35_*",
        "Catalogs"
        "FileMaps"
        "Fusion"
        "InstallTemp"
        "Manifests"
        "SettingsManifests"
        "Temp"
        "x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*"
        "x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*"
        "x86_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*"
        "x86_microsoft.windows.common-controls_6595b64144ccf1df_*"
        "x86_microsoft.windows.gdiplus_6595b64144ccf1df_*"
        "x86_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*"
        "x86_microsoft.windows.isolationautomation_6595b64144ccf1df_*"
        "arm_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*"
        "arm_microsoft.windows.common-controls_6595b64144ccf1df_*"
        "arm_microsoft.windows.gdiplus_6595b64144ccf1df_*"
        "arm_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*"
        "arm_microsoft.windows.isolationautomation_6595b64144ccf1df_*"
        "arm64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*"
        "arm64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*"
        "arm64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*"
        "arm64_microsoft.windows.common-controls_6595b64144ccf1df_*"
        "arm64_microsoft.windows.gdiplus_6595b64144ccf1df_*"
        "arm64_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*"
        "arm64_microsoft.windows.isolationautomation_6595b64144ccf1df_*"
        "arm64_microsoft-windows-servicing-adm_31bf3856ad364e35_*"
        "arm64_microsoft-windows-servicingcommon_31bf3856ad364e35_*"
        "arm64_microsoft-windows-servicing-onecore-uapi_31bf3856ad364e35_*"
        "arm64_microsoft-windows-servicingstack_31bf3856ad364e35_*"
        "arm64_microsoft-windows-servicingstack-inetsrv_31bf3856ad364e35_*"
        "arm64_microsoft-windows-servicingstack-msg_31bf3856ad364e35_*"
    )
}
foreach ($dir in $dirsToCopy) {
        $sourceDirs = Get-ChildItem -Path $sourceDirectory -Filter $dir -Directory
        foreach ($sourceDir in $sourceDirs) {
            $destDir = Join-Path -Path $destinationDirectory -ChildPath $sourceDir.Name
            Write-Host "Copying $sourceDir.FullName to $destDir"
            Copy-Item -Path $sourceDir.FullName -Destination $destDir -Recurse -Force
        }
    }  


Write-Host "Deleting WinSxS. This may take a while..."
        Remove-Item -Path $mainOSDrive\scratchdir\Windows\WinSxS -Recurse -Force

Rename-Item -Path $mainOSDrive\scratchdir\Windows\WinSxS_edit -NewName $mainOSDrive\scratchdir\Windows\WinSxS
Write-Host "Complete!"

reg load HKLM\zCOMPONENTS $ScratchDisk\scratchdir\Windows\System32\config\COMPONENTS | Out-Null
reg load HKLM\zDEFAULT $ScratchDisk\scratchdir\Windows\System32\config\default | Out-Null
reg load HKLM\zNTUSER $ScratchDisk\scratchdir\Users\Default\ntuser.dat | Out-Null
reg load HKLM\zSOFTWARE $ScratchDisk\scratchdir\Windows\System32\config\SOFTWARE | Out-Null
reg load HKLM\zSYSTEM $ScratchDisk\scratchdir\Windows\System32\config\SYSTEM | Out-Null
Write-Host "Bypassing system requirements(on the system image):"
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassCPUCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassRAMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassSecureBootCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassStorageCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassTPMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\MoSetup' '/v' 'AllowUpgradesWithUnsupportedTPMOrCPU' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "Disabling Sponsored Apps:"
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'OemPreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'PreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SilentInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' '/v' 'DisableWindowsConsumerFeatures' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'ContentDeliveryAllowed' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' '/v' 'ConfigureStartPins' '/t' 'REG_SZ' '/d' '{"pinnedList": [{}]}' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'ContentDeliveryAllowed' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'ContentDeliveryAllowed' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'FeatureManagementEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'OemPreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'PreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'PreInstalledAppsEverEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SilentInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SoftLandingEnabled' '/t' 'REG_DWORD' '/d' '0' '/f'| Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContentEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-310093Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-338388Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-338389Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-338393Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-353694Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-353696Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContentEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SystemPaneSuggestionsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' '/v' 'DisablePushToInstall' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' '/v' 'DontOfferThroughWUAU' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' '/v' 'DisableConsumerAccountStateContent' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' '/v' 'DisableCloudOptimizedContent' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "Enabling Local Accounts on OOBE:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' '/v' 'BypassNRO' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$ScratchDisk\scratchdir\Windows\System32\Sysprep\autounattend.xml" -Force | Out-Null
Write-Host "Disabling Reserved Storage:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' '/v' 'ShippedWithReserves' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
Write-Host "Disabling BitLocker Device Encryption"
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' '/v' 'PreventDeviceEncryption' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "Disabling Chat icon:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' '/v' 'ChatIcon' '/t' 'REG_DWORD' '/d' '3' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' '/v' 'TaskbarMn' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
Write-Host "Removing Edge related registries"
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" /f | Out-Null
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" /f | Out-Null
Write-Host "Disabling OneDrive folder backup"
& 'reg' 'add' "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" '/v' 'DisableFileSyncNGSC' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "Disabling Telemetry:"
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' '/v' 'Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' '/v' 'TailoredExperiencesWithDiagnosticDataEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' '/v' 'HasAccepted' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' '/v' 'Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' '/v' 'RestrictImplicitInkCollection' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' '/v' 'RestrictImplicitTextCollection' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' '/v' 'HarvestContacts' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' '/v' 'AcceptedPrivacyPolicy' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' '/v' 'AllowTelemetry' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' '/v' 'Start' '/t' 'REG_DWORD' '/d' '4' '/f' | Out-Null
Write-Host "Prevents installation or DevHome and Outlook:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' '/v' 'workCompleted' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' '/v' 'workCompleted' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate' '/f' | Out-Null
Write-Host "Disabling Copilot"
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' '/v' 'TurnOffWindowsCopilot' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Edge' '/v' 'HubsSidebarEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer' '/v' 'DisableSearchBoxSuggestions' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "Prevents installation of Teams:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Teams' '/v' 'DisableInstallation' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "Prevent installation of New Outlook":
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Mail' '/v' 'PreventRun' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
$tasksPath = "C:\scratchdir\Windows\System32\Tasks"

Write-Host "Deleting scheduled task definition files..."

# Application Compatibility Appraiser
Remove-Item -Path "$tasksPath\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" -Force -ErrorAction SilentlyContinue

# Customer Experience Improvement Program (removes the entire folder and all tasks within it)
Remove-Item -Path "$tasksPath\Microsoft\Windows\Customer Experience Improvement Program" -Recurse -Force -ErrorAction SilentlyContinue

# Program Data Updater
Remove-Item -Path "$tasksPath\Microsoft\Windows\Application Experience\ProgramDataUpdater" -Force -ErrorAction SilentlyContinue

# Chkdsk Proxy
Remove-Item -Path "$tasksPath\Microsoft\Windows\Chkdsk\Proxy" -Force -ErrorAction SilentlyContinue

# Windows Error Reporting (QueueReporting)
Remove-Item -Path "$tasksPath\Microsoft\Windows\Windows Error Reporting\QueueReporting" -Force -ErrorAction SilentlyContinue

Write-Host "Task files have been deleted."
Write-Host "Disabling Windows Update..."
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'StopWUPostOOBE1' '/t' 'REG_SZ' '/d' 'net stop wuauserv' '/f'
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'StopWUPostOOBE2' '/t' 'REG_SZ' '/d' 'sc stop wuauserv' '/f'
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'StopWUPostOOBE3' '/t' 'REG_SZ' '/d' 'sc config wuauserv start= disabled' '/f'
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'DisbaleWUPostOOBE1' '/t' 'REG_SZ' '/d' 'reg add HKLM\SYSTEM\CurrentControlSet\Services\wuauserv /v Start /t REG_DWORD /d 4 /f' '/f'
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'DisbaleWUPostOOBE2' '/t' 'REG_SZ' '/d' 'reg add HKLM\SYSTEM\ControlSet001\Services\wuauserv /v Start /t REG_DWORD /d 4 /f' '/f'
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'DoNotConnectToWindowsUpdateInternetLocations' '/t' 'REG_DWORD' '/d' '1' '/f'
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'DisableWindowsUpdateAccess' '/t' 'REG_DWORD' '/d' '1' '/f' 
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'WUServer' '/t' 'REG_SZ' '/d' 'localhost' '/f' 
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'WUStatusServer' '/t' 'REG_SZ' '/d' 'localhost' '/f' 
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'UpdateServiceUrlAlternate' '/t' 'REG_SZ' '/d' 'localhost' '/f' 
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' '/v' 'UseWUServer' '/t' 'REG_DWORD' '/d' '1' '/f' 
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' '/v' 'DisableOnline' '/t' 'REG_DWORD' '/d' '1' '/f' 
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Services\wuauserv' '/v' 'Start' '/t' 'REG_DWORD' '/d' '4' '/f' 
& 'reg' 'delete' 'HKLM\zSYSTEM\ControlSet001\Services\WaaSMedicSVC' '/f'
& 'reg' 'delete' 'HKLM\zSYSTEM\ControlSet001\Services\UsoSvc' '/f'
& 'reg' 'add' 'HKEY_LOCAL_MACHINE\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' '/v' 'NoAutoUpdate' '/t' 'REG_DWORD' '/d' '1' '/f'
Write-Host "Disabling Windows Defender"
$servicePaths = @(
    "WinDefend",
    "WdNisSvc",
    "WdNisDrv",
    "WdFilter",
    "Sense"
)

foreach ($path in $servicePaths) {
    Set-ItemProperty -Path "HKLM:\zSYSTEM\ControlSet001\Services\$path" -Name "Start" -Value 4
}
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' '/v' 'SettingsPageVisibility' '/t' 'REG_SZ' '/d' 'hide:virus;windowsupdate' '/f' 
Write-Host "Tweaking complete!"
Write-Host "Unmounting Registry..."
reg unload HKLM\zCOMPONENTS >null
reg unload HKLM\zDEFAULT >null
reg unload HKLM\zNTUSER >null
reg unload HKLM\zSOFTWARE
reg unload HKLM\zSYSTEM >null

Write-Host "Loading registry hives to remove services..."
reg load HKLM\zSYSTEM "$scratchDir\Windows\System32\config\SYSTEM" | Out-Null
$servicesToRemove = @( 
    'Spooler', 
    'PrintNotify', 
    'Fax', 
    'RemoteRegistry', 
    'diagsvc', 
    'WerSvc', 
    'PcaSvc', 
    #'DPS', 
    # 'Audiosrv', # CRITICAL: Removing this is a likely cause of boot failure.
    # 'AudioEndpointBuilder', # CRITICAL: Dependency for Audiosrv.
    'MapsBroker', 
    'WalletService', 
    'BthAvctpSvc', 
    'BluetoothUserService', 
    # 'WbioSrvc', # RISKY: Can cause logon screen to hang.
    'wuauserv', 
    'UsoSvc', 
    'WaaSMedicSvc' 
)
foreach ($service in $servicesToRemove) { Write-Host "Removing service: $service"; & 'reg' 'delete' "HKLM\zSYSTEM\ControlSet001\Services\$service" /f | Out-Null }
reg unload HKLM\zSYSTEM 

Write-Host "Cleaning up and unmounting install.wim..."
& 'dism' '/English' "/image:$scratchDir" '/Cleanup-Image' '/StartComponentCleanup' '/ResetBase' 
& 'dism' '/English' '/unmount-image' "/mountdir:$scratchDir" '/commit'
& 'dism' '/English' '/Export-Image' "/SourceImageFile:$mainOSDrive\nano11\sources\install.wim" "/SourceIndex:$index" "/DestinationImageFile:$mainOSDrive\nano11\sources\install2.wim" '/compress:max'
Remove-Item -Path "$mainOSDrive\nano11\sources\install.wim" -Force 
Rename-Item -Path "$mainOSDrive\nano11\sources\install2.wim" -NewName "install.wim" 

Write-Host "Shrinking boot.wim..."
$bootWimPath = "$($env:SystemDrive)\nano11\sources\boot.wim" 
Write-Host "Taking ownership of $bootWimPath..."
& takeown "/F" $bootWimPath
& icacls $bootWimPath "/grant" "$($adminGroup.Value):(F)"
try {
    Set-ItemProperty -Path $bootWimPath -Name IsReadOnly -Value $false -ErrorAction Stop
} catch {
}
Write-Host "Exporting modified setup image (index 2) from boot.wim..."
$newBootWimPath = "$($env:SystemDrive)\nano11\sources\boot_new.wim"
$finalBootWimPath = "$($env:SystemDrive)\nano11\sources\boot_final.wim"
& 'dism' '/English' '/Export-Image' "/SourceImageFile:$bootWimPath" '/SourceIndex:2' "/DestinationImageFile:$newBootWimPath"
& 'dism' '/English' '/mount-image' "/imagefile:$newbootWimPath" '/index:1' "/mountdir:$scratchDir"
reg load HKLM\zDEFAULT $ScratchDisk\scratchdir\Windows\System32\config\default | Out-Null
reg load HKLM\zNTUSER $ScratchDisk\scratchdir\Users\Default\ntuser.dat | Out-Null
reg load HKLM\zSOFTWARE $ScratchDisk\scratchdir\Windows\System32\config\SOFTWARE | Out-Null
reg load HKLM\zSYSTEM $ScratchDisk\scratchdir\Windows\System32\config\SYSTEM | Out-Null
Write-Host "Bypassing system requirements(on the system image):"
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassCPUCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassRAMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassSecureBootCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassStorageCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassTPMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\MoSetup' '/v' 'AllowUpgradesWithUnsupportedTPMOrCPU' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "Disabling BitLocker Device Encryption"
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' '/v' 'PreventDeviceEncryption' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "Tweaking complete!"
Write-Host "Unmounting Registry..."
reg unload HKLM\zNTUSER
reg unload HKLM\zDEFAULT
reg unload HKLM\zSOFTWARE
reg unload HKLM\zSYSTEM >null
Start-Sleep -Seconds 10
& 'dism' '/English' '/unmount-image' "/mountdir:$scratchDir" '/commit'
& takeown "/F" $bootWimPath
& icacls $bootWimPath "/grant" "$($adminGroup.Value):(F)"
Remove-Item -Path $bootWimPath -Force
& 'dism' '/English' '/Export-Image' "/SourceImageFile:$newBootWimPath" '/SourceIndex:1' "/DestinationImageFile:$finalBootWimPath" '/compress:max'
Remove-Item -Path $newBootWimPath -Force
Rename-Item -Path $finalBootWimPath -NewName "boot.wim"

Clear-Host
Write-Host "Exporting final image to highly compressed ESD format..."
& dism /Export-Image /SourceImageFile:"$mainOSdrive\nano11\sources\install.wim" /SourceIndex:1 /DestinationImageFile:"$mainOSdrive\nano11\sources\install.esd" /Compress:recovery
Remove-Item "$mainOSdrive\nano11\sources\install.wim"  2>&1

Write-Host "Performing final cleanup of installation folder root..."
$isoRoot = "$mainOSDrive\nano11"
$keepList = @("boot", "efi", "sources", "bootmgr", "bootmgr.efi", "setup.exe", "autounattend.xml")
Get-ChildItem -Path $isoRoot | Where-Object { $_.Name -notin $keepList } | ForEach-Object {
    Write-Host "Removing non-essential file/folder from ISO root: $($_.Name)"
    Remove-Item -Path $_.FullName -Recurse -Force
}

Write-Host "Creating bootable ISO image..."
$OSCDIMG = "$PSScriptRoot\oscdimg.exe"
if (-not (Test-Path $OSCDIMG)) { $url = "https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe"; Invoke-WebRequest -Uri $url -OutFile $OSCDIMG }
& "$OSCDIMG" '-m' '-o' '-u2' '-udfver102' "-bootdata:2#p0,e,b$mainOSdrive\nano11\boot\etfsboot.com#pEF,e,b$mainOSdrive\nano11\efi\microsoft\boot\efisys.bin" "$mainOSdrive\nano11" "$PSScriptRoot\nano11.iso"

Write-Host "Creation completed! Your ISO is named nano11.iso"
Read-Host "Press Enter to perform cleanup and exit."
& 'dism' '/English' '/unmount-image' "/mountdir:$scratchDir" '/discard'
Remove-Item -Path "$mainOSdrive\nano11" -Recurse -Force 
Remove-Item -Path "$mainOSdrive\scratchdir" -Recurse -Force 
Stop-Transcript
exit
}
else {
    Write-Host "You chose not to continue. The script will now exit."
    exit
}