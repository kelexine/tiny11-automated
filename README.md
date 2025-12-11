# Tiny11 Automated Builder

[![Build Tiny11](https://github.com/kelexine/tiny11-automated/actions/workflows/build-tiny11.yml/badge.svg)](https://github.com/kelexine/tiny11-automated/actions/workflows/build-tiny11.yml)
[![Build Tiny11 Core](https://github.com/kelexine/tiny11-automated/actions/workflows/build-tiny11-core.yml/badge.svg)](https://github.com/kelexine/tiny11-automated/actions/workflows/build-tiny11-core.yml)

Automated tools for creating streamlined Windows 11 images with CI/CD support.

## 📋 Overview

Tiny11 Automated Builder provides PowerShell scripts to create minimized Windows 11 ISO images by removing bloatware, disabling telemetry, and optimizing system components. Both interactive and headless (CI/CD) versions are available.

**🙏 Attribution**: This project is based on the original tiny11 builder by [ntdevlabs](https://github.com/ntdevlabs). The headless versions were created to enable automated CI/CD builds while preserving all original functionality.

**⚠️ Important Legal Notice**: These scripts are for educational and testing purposes only. You must have a valid Windows license. Using modified Windows images may violate Microsoft's terms of service.

## 🚀 Quick Start

### For CI/CD (GitHub Actions)
1. Fork this repository
2. Go to Actions tab
3. Select workflow:
   - **Build Tiny11** - Standard trimmed Windows 11
   - **Build Tiny11 Core** - Ultra-minimal Windows 11 Core
4. Click "Run workflow" and fill parameters
5. Download ISO from Releases or Artifacts

### For Manual Use
```powershell
# Standard Tiny11
.\tiny11maker-headless.ps1 -ISO E -INDEX 1

# Tiny11 Core (more aggressive)
.\tiny11coremaker-headless.ps1 -ISO E -INDEX 1

# With .NET 3.5 (Core only)
.\tiny11coremaker-headless.ps1 -ISO E -INDEX 1 -ENABLE_DOTNET35
```

## 📁 Available Scripts

### Standard Builder
- `tiny11maker-BASE.ps1` - Original interactive script (ntdevlabs)
- `tiny11maker-headless.ps1` - Automated version for CI/CD

### Core Builder (Ultra-Minimal)
- `tiny11Coremaker-BASE.ps1` - Original interactive script (ntdevlabs)
- `tiny11coremaker-headless.ps1` - Automated version for CI/CD

## ⚠️ Version Comparison

### Tiny11 (Standard)
- ✅ Removes 40+ Windows apps
- ✅ Disables telemetry and tracking
- ✅ Bypasses system requirements (CPU/RAM/TPM)
- ✅ Removes Edge and OneDrive
- ✅ Registry optimizations
- ✅ Windows Update disabled
- ✅ Full WinSxS component store
- ✅ Windows Recovery Environment intact
- ✅ Suitable for daily use (with caution)

### Tiny11 Core (Ultra-Minimal)
⚠️ **WARNING: For testing/VM only!**
- ✅ Everything from Standard, plus:
- ❌ **WinSxS aggressively minimized** (cannot add features/updates)
- ❌ **WinRE removed** (no recovery environment)
- ❌ **Windows Defender disabled**
- ❌ **Update services disabled**
- ⚠️ **Cannot service after creation**
- ✅ **Smallest possible Windows 11**
- ✅ **Perfect for disposable VMs**
- ✅ **Fast testing environments**

## 🔧 Parameters

### Standard Headless Parameters
```powershell
.\tiny11maker-headless.ps1
    -ISO <string>              # Drive letter of mounted Windows ISO (e.g., E)
    -INDEX <int>               # Image index (1=Home, 6=Pro, etc.)
    [-SCRATCH <string>]        # Scratch disk (defaults to script directory)
    [-SkipCleanup]             # Skip cleanup for debugging
```

### Core Headless Parameters
```powershell
.\tiny11coremaker-headless.ps1
    -ISO <string>              # Drive letter of mounted Windows ISO
    -INDEX <int>               # Image index
    [-SCRATCH <string>]        # Scratch disk
    [-SkipCleanup]             # Skip cleanup
    [-ENABLE_DOTNET35]         # Enable .NET Framework 3.5 (Core only!)
```

## 🏗️ GitHub Actions Workflows

### Build Tiny11 (Standard)
Workflow: `.github/workflows/build-tiny11.yml`

**Inputs:**
- `windows_iso_url` - Windows 11 ISO download URL
- `image_index` - Windows edition (1, 4, 6, 7)
- `release_tag` - Tag name for release
- `skip_cleanup` - Debug mode

### Build Tiny11 Core (Ultra-Minimal)
Workflow: `.github/workflows/build-tiny11-core.yml`

**Inputs:**
- `windows_iso_url` - Windows 11 ISO download URL
- `image_index` - Windows edition
- `release_tag` - Tag name for release
- `skip_cleanup` - Debug mode
- **`enable_dotnet35`** - Enable .NET 3.5 (Core only)

## 📦 What Gets Removed?

### Apps Removed (49 total)
- Microsoft Teams, OneDrive, Edge
- Xbox apps and gaming overlays
- Clipchamp, Paint 3D, Photos
- Weather, News, Maps, Camera
- Skype, Sticky Notes, Cortana
- Office Hub, Power Automate
- DevHome, Outlook for Windows
- And 30+ more...

### System Packages Removed (12)
- Internet Explorer
- Windows Media Player
- WordPad, Math Input Panel
- Steps Recorder
- LA57 compatibility
- Language features (OCR, Speech, etc.)
- Windows Defender

### Registry Optimizations
- System requirement bypasses (TPM/CPU/RAM/SecureBoot)
- Telemetry completely disabled
- Sponsored apps blocked
- Reserved storage disabled
- BitLocker disabled
- Chat icon removed
- OneDrive backup disabled
- Copilot disabled
- Teams installation blocked
- New Outlook blocked
- Windows Update disabled

## 💾 Requirements

### For Building
- **Windows 10/11** (PowerShell 5.1+)
- **Administrator rights** (script will prompt if not)
- **Disk space:**
  - Standard: 25GB+ free
  - Core: 40GB+ free
- **Windows ADK** (for oscdimg.exe) or internet connection

### For Running Built ISOs
- **Hardware:**
  - CPU: Any x64/ARM64 (requirements bypassed)
  - RAM: 2GB+ (requirements bypassed)
  - TPM: Not required (bypassed)
  - SecureBoot: Not required (bypassed)
- **Virtualization:** VMware, VirtualBox, Hyper-V supported

## 🔍 Examples

### Manual Build
```powershell
# Mount Windows ISO first, then:
.\tiny11maker-headless.ps1 -ISO E -INDEX 1

# Core with .NET 3.5
.\tiny11coremaker-headless.ps1 -ISO E -INDEX 6 -ENABLE_DOTNET35

# Custom scratch disk
.\tiny11maker-headless.ps1 -ISO E -INDEX 1 -SCRATCH D -SkipCleanup
```

### GitHub Actions
1. **Trigger workflow manually**
2. **Use default ISO URL** or provide your own
3. **Select edition:**
   - `1` = Windows 11 Home
   - `4` = Windows 11 Education
   - `6` = Windows 11 Pro
   - `7` = Windows 11 Pro N
4. **Set release tag** (e.g., `tiny11-25h2-v1.0`)
5. **Wait for completion** (30-80 minutes)
6. **Download from Releases** or workflow artifacts

## 📊 Build Times

Typical build durations on GitHub Actions:
- **Download:** 5-15 minutes (depends on ISO size)
- **Standard Tiny11:** 45-80 minutes
- **Tiny11 Core:** 30-45 minutes (WinSxS optimization)

## 🐛 Troubleshooting

### "Script must run as Administrator"
- Run PowerShell as Administrator
- Or let script auto-elevate (will restart as admin)

### "Insufficient disk space"
- Free up disk space
- Use `-SCRATCH` parameter for alternate drive
- Core builds need 40GB+ due to WinSxS optimization

### ISO creation fails
- Check Windows ADK is installed
- Or ensure internet connection for oscdimg.exe download
- Verify antivirus isn't blocking the script

### Build failures in GitHub Actions
- Check workflow logs for specific errors
- Enable `skip_cleanup` for debugging
- Verify ISO URL is accessible

## 🔐 Security Considerations

⚠️ **Please read carefully:**

1. **Modified Windows images** may have security implications
2. **Windows Defender is removed** - use third-party AV
3. **Updates are disabled** - manually enable if needed
4. **Use at your own risk** - not for production systems
5. **Legitimate use only** - valid Windows license required
6. **Privacy** - Telemetry disabled, but still exercise caution

## 📝 License

- Original scripts (ntdevlabs): [MIT License](https://github.com/ntdevlabs/tiny11builder/blob/main/LICENSE)
- Headless modifications (kelexine): MIT License
- See individual files for copyright notices

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Test your changes
4. Submit pull request

## ⚖️ Disclaimer

This tool is provided "as is" without warranty. The authors are not responsible for:
- System damage from using modified Windows images
- Violation of Microsoft's terms of service
- Any legal issues from using this software

Use responsibly and at your own risk.

## 🔗 Links

- **Original Project:** https://github.com/ntdevlabs/tiny11builder
- **This Repository:** https://github.com/kelexine/tiny11-automated
- **Issues:** https://github.com/kelexine/tiny11-automated/issues
- **Releases:** https://github.com/kelexine/tiny11-automated/releases

---

**Made with ❤️ for the Windows community**