<#
.SYNOPSIS
    Unit tests for Windows build-number extraction in the *-headless.ps1 builder scripts.
    Author: kelexine (https://github.com/kelexine)
    Run: Invoke-Pester ./tests/Test-BuildNumberParsing.Tests.ps1

.NOTES
    Pester 5 requires helper functions and path resolution to live inside BeforeAll:
    code at the top level of a test file runs during discovery, so anything it defines
    (or any $PSScriptRoot it reads) is not visible to the It blocks at run time.

    The -ForEach data, on the other hand, is consumed during discovery, so it must be
    built in BeforeDiscovery. Built in BeforeAll it is still $null when the It blocks
    are generated, and Pester 5 then silently generates no tests at all for them.
#>

BeforeAll {
    # Mirror of the extraction block the builders use. The builders run their whole
    # build at load time, so their internals cannot be dot-sourced for a direct unit
    # test - keep this in sync with the '(\d+\.\d+)$' capture in the *-headless.ps1 files.
    function Get-TestBuildNumber {
        param([string]$FullVersion)
        if ($FullVersion -match '(\d+\.\d+)$') {
            return $Matches[1]
        }
        return ""
    }
}

BeforeDiscovery {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:Scripts = @(
        'scripts\tiny11maker-headless.ps1',
        'scripts\tiny11coremaker-headless.ps1',
        'scripts\nano11builder-headless.ps1'
    ) | ForEach-Object {
        $full = Join-Path $script:RepoRoot $_
        # Hashtable (not [pscustomobject]): Pester 5 turns hashtable keys into the
        # $scriptName / $scriptPath / $content variables and the `<scriptName>` title token.
        @{
            scriptName = Split-Path -Leaf $full
            scriptPath = $full
            content    = if (Test-Path -LiteralPath $full) { Get-Content -LiteralPath $full -Raw } else { '' }
        }
    }
}

Describe "Windows build number extraction" {

    It "extracts [build].[ubr] from a standard 4-segment version string" {
        Get-TestBuildNumber -FullVersion "10.0.26200.8655" | Should -Be "26200.8655"
    }

    It "extracts correctly for an older Windows 11 build" {
        Get-TestBuildNumber -FullVersion "10.0.22631.4602" | Should -Be "22631.4602"
    }

    It "extracts correctly when the UBR is a single digit" {
        Get-TestBuildNumber -FullVersion "10.0.26100.1" | Should -Be "26100.1"
    }

    It "matches the whole string for a bare 2-segment version" {
        # Anchored only at the end, so "10.0" is itself a valid \d+\.\d+ match.
        # Not expected in practice (Get-WindowsImage.Version is always 4-segment).
        Get-TestBuildNumber -FullVersion "10.0" | Should -Be "10.0"
    }

    It "returns an empty string for a completely empty version" {
        Get-TestBuildNumber -FullVersion "" | Should -Be ""
    }

    It "returns an empty string for non-numeric garbage" {
        Get-TestBuildNumber -FullVersion "not-a-version" | Should -Be ""
    }

    It "is resilient to a trailing 5th segment by still capturing the last two" {
        Get-TestBuildNumber -FullVersion "10.0.26200.8655.1" | Should -Be "8655.1"
    }
}

Describe "Consistency across all three maker scripts" {

    It "<scriptName> contains the build-number capture block" -ForEach $script:Scripts {
        $scriptPath | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $scriptPath | Should -BeTrue
        $content | Should -Match ([regex]::Escape('$script:DetectedBuildNumber'))
        $content | Should -Match ([regex]::Escape("'(\d+\.\d+)$'"))
    }

    It "<scriptName> defines Write-BuildInfo" -ForEach $script:Scripts {
        $content | Should -Match "function Write-BuildInfo"
    }
}

Describe "Regression: basic image list object has no 'Version' property" {
    # kelexine: 'Get-WindowsImage -ImagePath $x' (no -Index) returns the basic
    # list object (ImageIndex/ImageName/ImageDescription/ImageSize only). Under
    # Set-StrictMode -Version Latest, reading .Version off that object throws
    # "The property 'Version' cannot be found on this object." This regressed
    # a real CI run (nano11, index 6, Pro) - see commit fixing this file.

    It "<scriptName> does not read .Version directly off the basic list object" -ForEach $script:Scripts {
        # The buggy pattern: assigning DetectedFullVersion straight from
        # $selectedImage (the Where-Object-filtered list entry).
        $content | Should -Not -Match ([regex]::Escape('$script:DetectedFullVersion = $selectedImage.Version'))
    }

    It "<scriptName> re-queries Get-WindowsImage with -Index for the detailed object" -ForEach $script:Scripts {
        $content | Should -Match ([regex]::Escape('Get-WindowsImage -ImagePath $sourceImagePath -Index $script:INDEX'))
    }

    It "<scriptName> guards the detailed re-query in a try/catch so a DISM failure can't hard-crash the build" -ForEach $script:Scripts {
        $pattern = '(?s)try\s*\{[^}]*Get-WindowsImage -ImagePath \$sourceImagePath -Index \$script:INDEX.*?\}\s*catch\s*\{'
        $content | Should -Match $pattern
    }

    It "<scriptName> verifies the 'Version' property exists before reading it" -ForEach $script:Scripts {
        $content | Should -Match ([regex]::Escape("PSObject.Properties.Match('Version')"))
    }

    It "simulated fix: detailed per-index object exposes Version, basic list object does not" {
        # Mirrors the real DISM cmdlet shapes without requiring DISM/Windows.
        function Get-WindowsImage {
            param([string]$ImagePath, [int]$Index)
            if ($PSBoundParameters.ContainsKey('Index')) {
                return [pscustomobject]@{
                    ImageIndex = $Index
                    ImageName  = "Windows 11 Pro"
                    Version    = "10.0.26200.8655"
                }
            }
            return @([pscustomobject]@{
                ImageIndex = 6
                ImageName  = "Windows 11 Pro"
                # Intentionally no Version property - matches real DISM basic list output.
            })
        }

        $images = Get-WindowsImage -ImagePath "fake.esd"
        $selectedImage = $images | Where-Object { $_.ImageIndex -eq 6 }

        # The bug: this property genuinely does not exist on the basic object.
        $selectedImage.PSObject.Properties.Match('Version').Count | Should -Be 0

        # The fix: re-querying with -Index returns an object that does have it.
        $detailedImage = Get-WindowsImage -ImagePath "fake.esd" -Index 6
        $detailedImage.PSObject.Properties.Match('Version').Count | Should -Be 1
        $detailedImage.Version | Should -Be "10.0.26200.8655"
    }
}
