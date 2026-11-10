<#
.SYNOPSIS
    Unit tests for the local-account setup modes and the Defender removal switch
    added to the *-headless.ps1 builders.
    Author: kelexine (https://github.com/kelexine)
    Run: Invoke-Pester ./tests/Test-AccountAndDefender.Tests.ps1
#>

BeforeAll {
    # The builders run their whole build at load time, so their internals cannot be
    # dot-sourced for a direct unit test. Mirror the answer-file transform here the
    # same way Test-BuildNumberParsing.Tests.ps1 mirrors the build-number regex,
    # and keep the two in sync.
    function Invoke-AnswerFileTransform {
        param(
            [Parameter(Mandatory = $true)][string]$Content,
            [Parameter(Mandatory = $true)][int]$Index,
            [Parameter(Mandatory = $false)]
            [ValidateSet('auto-admin', 'classic')]
            [string]$AccountMode = 'auto-admin'
        )

        $c = [regex]::Replace(
            $Content,
            '(<Key>/IMAGE/INDEX</Key>\s*<Value>)\d+(</Value>)',
            ('${1}' + $Index + '${2}')
        )

        if ($AccountMode -eq 'classic') {
            $c = [regex]::Replace($c, '(?s)\s*<UserAccounts>.*?</UserAccounts>', '')
            $c = [regex]::Replace($c, '(?s)\s*<AutoLogon>.*?</AutoLogon>', '')
            $c = [regex]::Replace($c, '(?s)\s*<FirstLogonCommands>.*?</FirstLogonCommands>', '')
        }

        return $c
    }

    $script:RepoRoot   = Split-Path -Parent $PSScriptRoot
    $script:Template   = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'autounattend.xml') -Raw
    $script:CorePath   = Join-Path $script:RepoRoot 'scripts\tiny11coremaker-headless.ps1'
    $script:CoreFlow   = Join-Path $script:RepoRoot '.github\workflows\build-tiny11-core.yml'
    $script:StdFlow    = Join-Path $script:RepoRoot '.github\workflows\build-tiny11.yml'
}

Describe "Answer file: auto-admin account mode (default)" {

    BeforeAll {
        $script:AutoAdmin = Invoke-AnswerFileTransform -Content $script:Template -Index 6
    }

    It "keeps the pre-created local Admin account" {
        $script:AutoAdmin | Should -Match '<Name>Admin</Name>'
        $script:AutoAdmin | Should -Match '<Group>Administrators</Group>'
    }

    It "keeps auto-logon on first boot" {
        $script:AutoAdmin | Should -Match '<AutoLogon>'
    }

    It "rewrites /IMAGE/INDEX to the requested edition" {
        $script:AutoAdmin | Should -Match '<Key>/IMAGE/INDEX</Key>\s*<Value>6</Value>'
    }

    It "remains well-formed XML" {
        { [xml]$script:AutoAdmin } | Should -Not -Throw
    }
}

Describe "Answer file: classic account mode" {

    BeforeAll {
        $script:Classic = Invoke-AnswerFileTransform -Content $script:Template -Index 6 -AccountMode 'classic'
    }

    It "drops the pre-created account" {
        $script:Classic | Should -Not -Match '<UserAccounts>'
        $script:Classic | Should -Not -Match '<LocalAccounts>'
    }

    It "drops auto-logon" {
        $script:Classic | Should -Not -Match '<AutoLogon>'
    }

    It "drops the first-logon cleanup command" {
        $script:Classic | Should -Not -Match '<FirstLogonCommands>'
    }

    It "keeps OOBE so the user can create their own account" {
        $script:Classic | Should -Match '<OOBE>'
        $script:Classic | Should -Match 'HideOnlineAccountScreens'
    }

    It "keeps the install offline (no Microsoft account path)" {
        $script:Classic | Should -Match '<Enable>false</Enable>'
        $script:Classic | Should -Match 'BypassNRO'
        $script:Classic | Should -Match 'DisableOnline'
    }

    It "still rewrites /IMAGE/INDEX" {
        $script:Classic | Should -Match '<Key>/IMAGE/INDEX</Key>\s*<Value>6</Value>'
    }

    It "remains well-formed XML with the Shell-Setup component intact" {
        { [xml]$script:Classic } | Should -Not -Throw
        $doc = [xml]$script:Classic
        $ns = New-Object System.Xml.XmlNamespaceManager -ArgumentList $doc.NameTable
        $ns.AddNamespace('u', 'urn:schemas-microsoft-com:unattend')
        $doc.SelectSingleNode("//u:component[@name='Microsoft-Windows-Shell-Setup']", $ns) | Should -Not -BeNullOrEmpty
        $doc.SelectSingleNode("//u:component[@name='Microsoft-Windows-Shell-Setup']/u:UserAccounts", $ns) | Should -BeNullOrEmpty
    }
}

Describe "Builders expose the account-setup switch" {

    It "tiny11maker-headless.ps1 declares -AccountSetup and wires it into every answer-file write" {
        $content = Get-Content -Path (Join-Path $script:RepoRoot 'scripts\tiny11maker-headless.ps1') -Raw

        $content | Should -Match ([regex]::Escape('[string]$AccountSetup'))
        $content | Should -Match ([regex]::Escape("[ValidateSet('auto-admin', 'classic')]"))

        $calls = ([regex]::Matches($content, 'Write-IsoAnswerFile -Destination')).Count
        $wired = ([regex]::Matches($content, '-AccountMode \$AccountSetup')).Count
        $calls | Should -BeGreaterThan 0
        $wired | Should -Be $calls
    }

    It "tiny11coremaker-headless.ps1 declares -AccountSetup and wires it into every answer-file write" {
        $content = Get-Content -Path (Join-Path $script:RepoRoot 'scripts\tiny11coremaker-headless.ps1') -Raw

        $content | Should -Match ([regex]::Escape('[string]$AccountSetup'))
        $content | Should -Match ([regex]::Escape("[ValidateSet('auto-admin', 'classic')]"))

        $calls = ([regex]::Matches($content, 'Write-IsoAnswerFile -Destination')).Count
        $wired = ([regex]::Matches($content, '-AccountMode \$AccountSetup')).Count
        $calls | Should -BeGreaterThan 0
        $wired | Should -Be $calls
    }
}

Describe "Core builder exposes the Defender removal switch" {

    BeforeAll {
        $script:Core = Get-Content -Path $script:CorePath -Raw
    }

    It "declares a -RemoveDefender switch" {
        $script:Core | Should -Match ([regex]::Escape('[switch]$RemoveDefender'))
    }

    It "defines the payload and registry removal functions" {
        $script:Core | Should -Match 'function Remove-DefenderPayload'
        $script:Core | Should -Match 'function Remove-DefenderRegistry'
    }

    It "targets the Defender antimalware service and the Security app" {
        $script:Core | Should -Match ([regex]::Escape("'WinDefend'"))
        $script:Core | Should -Match 'SecHealthUI'
    }

    It "deletes the service keys instead of only setting Start=4" {
        $script:Core | Should -Match ([regex]::Escape('Remove-Item -Path $serviceKey -Recurse -Force'))
    }

    It "gates both halves behind -RemoveDefender in the main execution" {
        # The gate widened when Core-Gaming landed: a -GamingProfile build always
        # removes Defender, so the condition is now
        # 'if ($RemoveDefender -or $GamingProfile)'. Accept any condition that
        # starts with -RemoveDefender rather than pinning the old single-flag form.
        $script:Core | Should -Match '(?s)if\s*\(\s*\$RemoveDefender\b[^)]*\)\s*\{\s*Remove-DefenderPayload'
        $script:Core | Should -Match '(?s)if\s*\(\s*\$RemoveDefender\b[^)]*\)\s*\{\s*Remove-DefenderRegistry'
    }

    It "runs the payload half before the registry hives are loaded" {
        $mainStart = $script:Core.IndexOf('#---------[ Main Execution ]---------')
        $mainStart | Should -BeGreaterThan 0

        # Drop comment lines first: the explanatory comment above the call also
        # names Load-RegistryHives, and would otherwise be found before the real
        # call site.
        $main = ($script:Core.Substring($mainStart) -split "`r?`n" |
            Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

        $payloadAt = $main.IndexOf('Remove-DefenderPayload')
        $loadAt = $main.IndexOf('Load-RegistryHives')
        $payloadAt | Should -BeGreaterThan 0
        $loadAt | Should -BeGreaterThan 0
        $payloadAt | Should -BeLessThan $loadAt
    }
}

Describe "Workflows expose the new toggles" {

    It "build-tiny11-core.yml declares remove_defender and account_setup" {
        $content = Get-Content -Path $script:CoreFlow -Raw
        $content | Should -Match 'remove_defender:'
        $content | Should -Match 'account_setup:'
        $content | Should -Match ([regex]::Escape('-RemoveDefender:$removeDefender'))
        $content | Should -Match ([regex]::Escape('-AccountSetup $accountSetup'))
    }

    It "build-tiny11.yml declares account_setup" {
        $content = Get-Content -Path $script:StdFlow -Raw
        $content | Should -Match 'account_setup:'
        $content | Should -Match ([regex]::Escape('-AccountSetup $accountSetup'))
    }
}

Describe "Builder scripts encoding (Windows PowerShell 5.1 compatibility)" {

    It "preserves UTF-8 BOM on builder scripts containing non-ASCII characters" {
        $builderFiles = @(
            'tiny11coremaker-headless.ps1',
            'nano11builder-headless.ps1',
            'tiny11maker-headless.ps1'
        )
        foreach ($file in $builderFiles) {
            $path = Join-Path $script:RepoRoot "scripts\$file"
            $bytes = [System.IO.File]::ReadAllBytes($path)
            ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeTrue -Because "$file must have UTF-8 BOM for PowerShell 5.1 compatibility"
        }
    }
}
