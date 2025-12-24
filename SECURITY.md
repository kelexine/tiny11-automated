# Security Policy

**Project**: Tiny11 Automated  
**Author**: kelexine  
**GitHub**: https://github.com/kelexine/tiny11-automated

---

## 🔒 Security Overview

Tiny11 Automated creates modified Windows 11 ISO images with **2,000+ downloads** and growing. Security is paramount as users trust our builds for their systems.

### Our Security Commitments

✅ **ISO Integrity** - All source ISOs are checksum-verified  
✅ **Build Transparency** - Open-source scripts, auditable process  
✅ **Release Checksums** - SHA256, SHA512, MD5 for every release  
✅ **No Malware** - Clean builds, no backdoors, no telemetry to us  
✅ **Regular Updates** - Security patches from community  

---

## 🐛 Reporting a Vulnerability

### What Qualifies as a Security Issue?

**Critical:**
- ISO checksum verification bypass
- Malicious code injection in build process
- Credential leaks in workflows
- Supply chain attack vectors
- Backdoor introduction

**High:**
- Privilege escalation in scripts
- Unverified external downloads
- Insecure file permissions
- Information disclosure

**Medium:**
- Missing input validation
- Weak error handling
- Insufficient logging

### How to Report

**DO NOT** create public GitHub issues for security vulnerabilities!

**Instead:**

1. **Email (Preferred)**:
   - Send to: frankiekelechi@gmail.com
   - Subject: `[SECURITY] Tiny11 Vulnerability Report`
   - Include: Detailed description, reproduction steps, impact assessment

2. **Private GitHub Security Advisory**:
   - Go to: Security → Advisories → New Draft Advisory
   - Fill in details
   - kelexine will be notified automatically

3. **Discord (For Urgent Issues)**:
   - DM kelexine directly
   - Use `[SECURITY]` prefix
   - Do not post in public channels

### What to Include

```markdown
## Vulnerability Description
Clear description of the security issue

## Impact
Who/what is affected? How severe?

## Reproduction Steps
1. Step one
2. Step two
3. Observe the issue

## Proof of Concept
Code, screenshots, or logs demonstrating the issue

## Suggested Fix (Optional)
How you think it should be fixed

## Your Information (Optional)
Name/handle for credit (if desired)
```

---

## 🕐 Response Timeline

| Stage | Timeline | Description |
|-------|----------|-------------|
| **Acknowledgment** | 24-48 hours | Confirm we received your report |
| **Initial Assessment** | 3-5 days | Evaluate severity and impact |
| **Fix Development** | 1-2 weeks | Develop and test fix |
| **Release** | 2-4 weeks | Deploy fix and notify users |
| **Public Disclosure** | 30 days | After fix is released |

**Critical vulnerabilities** (RCE, credential leaks) will be expedited.

---

## 🏆 Security Researcher Recognition

We value security researchers who help keep our users safe:

### Hall of Fame

Contributors who responsibly disclose vulnerabilities:

- *Your name could be here!*

### Rewards

While we cannot offer monetary bounties, we provide:
- Public recognition (if desired)
- Credit in release notes
- Special contributor badge
- Detailed thank-you in SECURITY.md
- Lifetime acknowledgment in project

---

## 🔐 Security Best Practices for Users

### Verify Your Downloads

**Always verify checksums before using Tiny11 ISOs:**

```powershell
# Windows PowerShell
Get-FileHash -Path "Tiny11-*.iso" -Algorithm SHA256

# Compare with official checksum from:
# - GitHub Release page
# - SourceForge release notes
# - Discord #release-notification
```

```bash
# Linux
sha256sum Tiny11-*.iso

# Mac
shasum -a 256 Tiny11-*.iso
```

### Safe Installation

1. **Test in VM first** - Use VirtualBox/Hyper-V before bare metal
2. **Backup data** - Always backup before installing modified Windows
3. **Verify source** - Only download from official sources:
   - GitHub: https://github.com/kelexine/tiny11-automated
   - SourceForge: https://sourceforge.net/projects/tiny-11-releases/
4. **Check signatures** - Verify release authenticity
5. **Keep updated** - Use latest releases for security patches

### Red Flags

⚠️ **DO NOT USE** if you notice:
- Checksum mismatch
- Download from unofficial site
- Missing release notes
- Suspicious file sizes
- Unknown files in ISO
- Disabled antivirus warnings

---

## 🛡️ Our Security Measures

### Build Process Security

1. **Source Verification**
   - ISOs checksummed before building
   - Only official Microsoft ISOs accepted
   - Download sources whitelisted

2. **Clean Build Environment**
   - Fresh GitHub Actions runners
   - No persistent storage
   - Isolated build containers

3. **Code Review**
   - All PRs reviewed by maintainer
   - No auto-merge for code changes
   - Community audit encouraged

4. **Release Integrity**
   - Automated checksum generation
   - Multiple hash algorithms (SHA256, SHA512, MD5)
   - Signed releases (planned)

### Workflow Security

```yaml
# Our workflows use:
- Minimal permissions (contents: read/write only)
- No third-party action secrets
- Explicit GITHUB_TOKEN scopes
- Checksum verification steps
- Secure artifact upload
```

### Secret Management

- No hardcoded credentials
- GitHub Secrets for webhooks
- SourceForge tokens rotated regularly
- No API keys in public repos

---

## 📋 Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| Latest Release | ✅ Yes | Always use latest |
| Previous Release | ⚠️ Limited | Security updates only |
| Older Releases | ❌ No | Upgrade immediately |

**Always use the latest release** for security and features.

---

## 🔄 Security Updates

### How We Notify Users

When security issues are fixed:

1. **GitHub Security Advisory** - Published after fix
2. **Release Notes** - Detailed changelog
3. **Discord #release-notification** - Immediate alert
4. **SourceForge Update** - New files posted
5. **README Badge** - Version update

### Staying Informed

- ⭐ **Star the repo** - Get release notifications
- 📺 **Watch releases** - GitHub "Custom" → Releases only
- 🔔 **Join Discord** - Real-time alerts
- 📧 **Email notifications** - SourceForge updates

---

## ⚖️ Responsible Disclosure Policy

### Our Commitment

- We will not take legal action against security researchers
- Responsible disclosure is appreciated and rewarded
- Public disclosure coordinated after fixes deployed
- Credit given unless you prefer anonymity

### Your Responsibility

- Allow reasonable time for fixes (30 days minimum)
- Do not exploit vulnerabilities beyond proof-of-concept
- Do not access user data or disrupt services
- Communicate clearly and professionally

---

## 🚨 Known Security Considerations

### By Design

These are intentional design decisions users should understand:

1. **Modified Windows Images**
   - Not supported by Microsoft
   - May violate ToS (use at own risk)
   - No official security patches from MS

2. **Disabled Features**
   - Windows Defender removed (Core/Nano variants)
   - Windows Update disabled by default
   - TPM/SecureBoot bypassed

3. **Registry Modifications**
   - System requirements bypassed
   - Telemetry disabled
   - Some security features removed

**Recommendation**: Use third-party antivirus and manually enable updates if needed.

---

## 📞 Security Contacts

- **Email**: frankiekelechi@gmail.com
- **GitHub**: @kelexine
- **Discord**: kelexine (Direct Message)
- **Security Advisory**: GitHub → Security tab

**Response Hours**: UTC+1 (Africa/Lagos timezone)  
**Expected Response**: 24-48 hours

---

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Microsoft Security Response Center](https://msrc.microsoft.com/)
- [GitHub Security Best Practices](https://docs.github.com/en/code-security)

---

## 🙏 Acknowledgments

Thank you to all security researchers who help keep Tiny11 Automated safe for 2,000+ users worldwide.

**Your vigilance protects our community.**

---

*Last Updated: December 24, 2025*  
*Version: 1.0.0*
