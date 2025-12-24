# Contributing to Tiny11 Automated

Thank you for your interest in contributing to Tiny11 Automated! This project has reached **2,000+ downloads** and maintains a **100% build success rate** thanks to careful automation.

**Author:** kelexine  
**GitHub:** https://github.com/kelexine/tiny11-automated

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Project Architecture](#project-architecture)
- [Development Workflow](#development-workflow)
- [Testing Guidelines](#testing-guidelines)
- [Submission Guidelines](#submission-guidelines)
- [Community](#community)

---

## 🤝 Code of Conduct

This project follows a simple principle: **Be respectful, be constructive, be helpful.**

- Treat all contributors with respect
- Provide constructive feedback
- Focus on what's best for the project and users
- No spam, harassment, or off-topic discussions

---

## 🚀 Getting Started

### Prerequisites

- **Windows 10/11** (PowerShell 5.1+)
- **Administrator privileges** (required for DISM operations)
- **30GB+ free disk space** (for builds)
- **Git** for version control
- **Valid Windows 11 ISO** for testing

### Fork & Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/tiny11-automated.git
cd tiny11-automated
```

### Set Up Development Environment

```powershell
# Allow script execution
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Verify you have required tools
Get-Command dism
Get-Command oscdimg  # Or internet connection to download
```

---

## 🏗️ Project Architecture

### Repository Structure

```
tiny11-automated/
├── .github/
│   └── workflows/          # GitHub Actions CI/CD
│       ├── build-tiny11.yml
│       ├── build-tiny11-core.yml
│       └── build-nano11.yml
├── scripts/
│   ├── tiny11maker-BASE.ps1          # Original interactive (ntdevlabs)
│   ├── tiny11maker-headless.ps1      # Automated version
│   ├── tiny11Coremaker-BASE.ps1      # Core interactive
│   ├── tiny11coremaker-headless.ps1  # Core automated
│   ├── nano11builder-BASE.ps1        # Nano interactive
│   └── nano11builder-headless.ps1    # Nano automated
├── autounattend.xml         # OOBE bypass for Standard/Core
├── autounattend-nano.xml    # OOBE bypass for Nano
├── README.md
├── SOURCEFORGE_README.md
└── .gitignore
```

### Build Variants

1. **Tiny11 Standard** - Removes bloatware, keeps serviceability
2. **Tiny11 Core** - Ultra-minimal, WinSxS cleaned, non-serviceable
3. **Nano11** - EXTREME minimal, drivers/fonts removed, VM-only

### Automation Flow

```
1. GitHub Actions trigger (manual/scheduled)
   ↓
2. Download Windows 11 ISO
   ↓
3. Verify ISO checksum
   ↓
4. Mount ISO and extract
   ↓
5. Remove bloatware/packages
   ↓
6. Apply registry tweaks
   ↓
7. Optimize and compress
   ↓
8. Generate new ISO
   ↓
9. Create checksums (SHA256, MD5, SHA512)
   ↓
10. Upload to SourceForge
   ↓
11. Discord notifications
```

---

## 💻 Development Workflow

### Branch Strategy

- `main` - Production-ready code only
- `develop` - Integration branch for features
- `feature/your-feature` - Your feature branch
- `hotfix/issue-name` - Urgent fixes

### Making Changes

1. **Create a feature branch**
   ```bash
   git checkout -b feature/improve-disk-space-handling
   ```

2. **Make your changes**
   - Follow existing code style
   - Add comments for complex logic
   - Update documentation if needed

3. **Test locally**
   ```powershell
   # Test with actual ISO
   .\scripts\tiny11maker-headless.ps1 -ISO E -INDEX 1 -SkipCleanup
   
   # Verify ISO boots in VM
   # Check removed components
   # Validate checksums
   ```

4. **Commit with clear messages**
   ```bash
   git commit -m "feat: Add disk space pre-flight check
   
   - Check available space before build
   - Throw error if insufficient
   - Suggest alternative scratch drive"
   ```

5. **Push and create PR**
   ```bash
   git push origin feature/improve-disk-space-handling
   ```

### Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `refactor:` Code refactoring
- `perf:` Performance improvement
- `test:` Adding tests
- `chore:` Maintenance tasks

**Examples:**
```
feat: Add .NET 3.5 support to Core variant

- New -ENABLE_DOTNET35 parameter
- Preserves .NET packages during cleanup
- Updates documentation

Closes #42
```

---

## 🧪 Testing Guidelines

### What to Test

Since builds take 40+ minutes, focus testing on:

1. **Parameter validation**
   - Invalid drive letters
   - Out-of-range image indices
   - Missing ISO files

2. **Error handling**
   - Insufficient disk space
   - Missing prerequisites
   - Network failures

3. **Output verification**
   - ISO file exists
   - Checksums are valid
   - File size is reasonable

### Local Testing Checklist

Before submitting a PR:

- [ ] Script runs without errors
- [ ] Generated ISO boots in VM (VirtualBox/Hyper-V)
- [ ] Removed components are actually removed
- [ ] Registry tweaks are applied
- [ ] Checksums are generated correctly
- [ ] No regressions in existing functionality

### VM Testing (Recommended)

```powershell
# Quick VM test script
$isoPath = ".\tiny11.iso"

# Create new VM in Hyper-V
New-VM -Name "Tiny11-Test" -MemoryStartupBytes 2GB -Generation 2

# Attach ISO
Set-VMDvdDrive -VMName "Tiny11-Test" -Path $isoPath

# Boot and verify
Start-VM -Name "Tiny11-Test"
```

---

## 📥 Submission Guidelines

### Pull Request Process

1. **Ensure your PR:**
   - Solves a real problem
   - Doesn't break existing functionality
   - Includes clear description
   - Has been tested locally

2. **PR Template:**
   ```markdown
   ## Description
   Brief description of changes
   
   ## Motivation
   Why is this change needed?
   
   ## Changes Made
   - List of changes
   
   ## Testing Done
   - How you tested
   
   ## Screenshots (if applicable)
   
   ## Checklist
   - [ ] Code tested locally
   - [ ] Documentation updated
   - [ ] No breaking changes
   ```

3. **Review Process:**
   - Maintainer will review within 3-5 days
   - Address feedback promptly
   - Be open to suggestions
   - CI/CD tests must pass

4. **After Merge:**
   - Your contribution will be in the next release
   - You'll be credited in release notes
   - Delete your feature branch

### What Gets Accepted

✅ **Good PRs:**
- Bug fixes with clear reproduction steps
- Performance improvements with benchmarks
- New features that fit project scope
- Documentation improvements
- Code quality enhancements

❌ **Rejected PRs:**
- Breaking changes without discussion
- Features out of scope
- Code without testing
- Poor code quality
- Plagiarized code

---

## 💡 Areas for Contribution

### High Priority
- [ ] Multi-language ISO support
- [ ] GUI for non-technical users
- [ ] Plugin system for custom modifications
- [ ] Improved error messages
- [ ] Performance optimizations

### Medium Priority
- [ ] Additional Windows versions (10, Server)
- [ ] Alternative compression methods
- [ ] Better progress indicators
- [ ] Rollback mechanisms
- [ ] Configuration file support

### Low Priority
- [ ] Web-based dashboard
- [ ] Telemetry (opt-in)
- [ ] Auto-update checker
- [ ] Theme customization
- [ ] Extended documentation

### Good First Issues

Look for issues tagged `good first issue`:
- Documentation typos
- README improvements
- Adding code comments
- Simple bug fixes
- Test additions

---

## 🌐 Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Discord Server**: [Tiny11 Auto-Builder](https://discord.gg/YOUR_INVITE) (Real-time chat)
- **SourceForge**: [Download releases](https://sourceforge.net/projects/tiny-11-releases/)

### Getting Help

- Check existing issues before creating new ones
- Use issue templates
- Provide clear reproduction steps
- Include system information
- Be patient and respectful

### Recognition

Contributors are recognized in:
- Release notes
- CONTRIBUTORS.md file
- Project README
- Special Discord role (if applicable)

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the same MIT License that covers this project.

---

## 🙏 Acknowledgments

- **ntdevlabs** - Original tiny11builder creator
- **kelexine** - Automation and CI/CD implementation
- **All contributors** - Community improvements

---

## 📞 Questions?

- **Author**: kelexine
- **GitHub**: https://github.com/kelexine
- **Email**: [Your contact if desired]
- **Discord**: [Your Discord if desired]

---

**Thank you for contributing to Tiny11 Automated!** 🎉

Every contribution, no matter how small, helps thousands of users worldwide get a better Windows experience.
