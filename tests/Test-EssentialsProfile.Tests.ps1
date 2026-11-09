<#
.SYNOPSIS
    Pester tests for the Tiny11 Core-Gaming essentials pass.

.DESCRIPTION
    Validates the essentials layer: the JSON schema, the safety guard that keeps
    boot-critical services out of the profile, and the wiring between the data, the
    engine, the Core builder and the first-boot payload.

    These tests do NOT build an ISO and do NOT touch the registry - they are pure
    static validation plus a few in-memory calls to the engine, so they run anywhere
    Pester is available (including ubuntu-latest via pwsh).

.EXAMPLE
    Invoke-Pester -Path tests/Test-EssentialsProfile.Tests.ps1
#>

BeforeAll {
    Set-StrictMode -Version Latest
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $configDir = Join-Path $repoRoot 'config'
    $scriptsDir = Join-Path $repoRoot 'scripts'

    $profilePath = Join-Path $configDir 'essentials_profile.json'
    $modulePath = Join-Path $scriptsDir 'essentials-profile.ps1'
    $builderPath = Join-Path $scriptsDir 'tiny11coremaker-headless.ps1'
    $firstBootPath = Join-Path $scriptsDir 'gaming-firstboot.ps1'
    $reportPath = Join-Path $scriptsDir 'Tiny11-Report.ps1'
    $workflowPath = Join-Path $repoRoot '.github/workflows/build-tiny11-core-gaming.yml'

    $profile = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
    $builderRaw = Get-Content -LiteralPath $builderPath -Raw
    $firstBootRaw = Get-Content -LiteralPath $firstBootPath -Raw
    $workflowRaw = Get-Content -LiteralPath $workflowPath -Raw

    # The engine is dot-sourced for real - these tests exercise the shipped functions,
    # not a copy of them.
    . $modulePath
    Initialize-EssentialsModule -LogFile $null -ProfileDirectory $configDir

    function Get-MainCallIndex {
        param([string]$Content, [string]$Name)
        $mainIndex = $Content.IndexOf('#---------[ Main Execution ]')
        if ($mainIndex -lt 0) { return -1 }
        $pattern = "(?m)^[ \t]+$([regex]::Escape($Name))\b"
        $match = [regex]::Match($Content.Substring($mainIndex), $pattern)
        if (-not $match.Success) { return -1 }
        return $mainIndex + $match.Index
    }
}

Describe 'Essentials profile JSON' {

    It 'parses and identifies itself' {
        $profile.profile | Should -Be 'tiny11-essentials'
        $profile.schemaVersion | Should -Be 1
    }

    It 'declares all four hive prefixes' {
        $names = $profile.hivePrefixes.PSObject.Properties.Name
        $names | Should -Contain 'SYSTEM'
        $names | Should -Contain 'SOFTWARE'
        $names | Should -Contain 'NTUSER'
        $names | Should -Contain 'DEFAULT'
    }

    It 'has registry, services and firstBoot blocks' {
        @($profile.registry).Count | Should -BeGreaterThan 0
        @($profile.services).Count | Should -BeGreaterThan 0
        $profile.firstBoot | Should -Not -BeNullOrEmpty
    }

    It 'names the source checkbox on every entry' {
        # The whole point of the layer is that each row can be traced back to a ticked
        # box. An entry without an item name is untraceable.
        foreach ($e in @($profile.registry) + @($profile.deleteKeys) + @($profile.services)) {
            $e.item | Should -Not -BeNullOrEmpty
        }
    }

    It 'uses only known hives' {
        $hives = $profile.hivePrefixes.PSObject.Properties.Name
        foreach ($e in @($profile.registry) + @($profile.deleteKeys)) {
            $hives | Should -Contain $e.hive
        }
    }

    It 'uses only supported registry types' {
        $allowed = @('REG_DWORD', 'REG_SZ', 'REG_EXPAND_SZ', 'REG_QWORD', 'REG_BINARY')
        foreach ($e in @($profile.registry)) {
            $allowed | Should -Contain $e.type
        }
    }

    It 'sets services to manual or disabled only' {
        foreach ($s in @($profile.services)) {
            $s.start | Should -BeIn @(3, 4)
        }
    }

    It 'does not list the same service twice' {
        $names = @($profile.services | ForEach-Object { $_.name })
        $dupes = $names | Group-Object | Where-Object { $_.Count -gt 1 }
        @($dupes).Count | Should -Be 0
    }

    It 'never lists a boot-critical service' {
        foreach ($s in @($profile.services)) {
            Test-EssentialsProtectedService -Name $s.name | Should -BeFalse
        }
    }

    It 'covers every checked item from the source list' {
        $expected = @(
            'Activity History - Disable',
            'BitLocker - Disable',
            'Delivery Optimization - Disable',
            'End Task With Right Click - Enable',
            'File Explorer Automatic Folder Discovery - Disable',
            'Hibernation - Disable',
            'Location Tracking - Disable',
            'Microsoft OneDrive - Remove',
            'Microsoft Store Recommended Search Results - Disable',
            'Prevent Device Companion Apps',
            'Right-Click Menu Previous Layout - Enable',
            'Services - Set to Manual',
            'Start Menu Previous Layout - Enable',
            'Telemetry - Disable',
            'Widgets - Remove',
            'Windows AI - Disable And Remove',
            'Windows Platform Binary Table (WPBT) - Disable'
        )

        $present = @($profile.registry) + @($profile.deleteKeys) + @($profile.services) |
            ForEach-Object { $_.item } | Select-Object -Unique

        foreach ($item in $expected) {
            $present | Should -Contain $item
        }
    }

    It 'accounts for all 20 ticked boxes - 17 essential plus 3 advanced' {
        # The screenshot had exactly 20 boxes ticked. Coverage is computed from the data,
        # so this asserts the real total rather than a number maintained by hand.
        $coverage = @(Get-EssentialsCoverage -Profile $profile)
        $items = @($coverage | ForEach-Object { $_.Item } | Select-Object -Unique)

        $items.Count | Should -Be 20

        $inData = @($coverage | Where-Object { $_.Owner -eq 'data' } | ForEach-Object { $_.Item } | Select-Object -Unique)
        $elsewhere = @($coverage | Where-Object { $_.Owner -ne 'data' } | ForEach-Object { $_.Item } | Select-Object -Unique)

        $inData.Count | Should -Be 17
        $elsewhere.Count | Should -Be 3
    }

    It 'records where each of the three offloaded items is handled' {
        $elsewhere = @($profile.handledElsewhere)

        $elsewhere.Count | Should -Be 3
        @($elsewhere | ForEach-Object { $_.item }) | Should -Contain 'ConsumerFeatures - Disable'
        @($elsewhere | ForEach-Object { $_.item }) | Should -Contain 'Restore Point - Create'
        @($elsewhere | ForEach-Object { $_.item }) | Should -Contain 'Temporary Files - Remove'

        foreach ($e in $elsewhere) {
            $e.by | Should -BeIn @('core', 'firstBoot', 'gaming')
            $e.where | Should -Not -BeNullOrEmpty
            $e.evidence | Should -Not -BeNullOrEmpty
        }
    }

    It 'never claims the same box through two different mechanisms' {
        $dataItems = @(@($profile.registry) + @($profile.deleteKeys) + @($profile.services) |
            ForEach-Object { $_.item } | Select-Object -Unique)
        $elsewhereItems = @($profile.handledElsewhere | ForEach-Object { $_.item })

        foreach ($item in $elsewhereItems) {
            $dataItems | Should -Not -Contain $item
        }
    }

    It 'rejects a profile that claims one box twice' {
        $bad = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
        $bad.handledElsewhere = @([pscustomobject]@{
            item = 'Activity History - Disable'; by = 'core'; where = 'somewhere'; evidence = 'x'
        })
        $problems = Test-EssentialsProfile -Profile $bad
        ($problems -join ' ') | Should -Match 'also listed in handledElsewhere'
    }

    It 'enables the first-boot operations it claims' {
        $profile.firstBoot.hibernateOff | Should -BeTrue
        $profile.firstBoot.cleanTemp | Should -BeTrue
        $profile.firstBoot.restorePoint | Should -BeTrue
        $profile.firstBoot.reportProcessCount | Should -BeTrue
    }
}

Describe 'Essentials engine' {

    It 'validates the shipped profile with no problems' {
        $problems = Test-EssentialsProfile -Profile $profile
        @($problems).Count | Should -Be 0
    }

    It 'rejects a profile that tries to disable a boot-critical service' {
        $bad = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
        $bad.services = @([pscustomobject]@{ item = 'test'; name = 'RpcSs'; start = 4 })
        $problems = Test-EssentialsProfile -Profile $bad
        @($problems).Count | Should -BeGreaterThan 0
        ($problems -join ' ') | Should -Match 'boot-critical'
    }

    It 'rejects an unknown hive' {
        $bad = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
        $bad.registry = @([pscustomobject]@{ item = 'test'; hive = 'NOPE'; path = 'X'; name = 'Y'; type = 'REG_DWORD'; value = '1' })
        $problems = Test-EssentialsProfile -Profile $bad
        ($problems -join ' ') | Should -Match 'unknown hive'
    }

    It 'rejects an unsupported registry type' {
        $bad = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
        $bad.registry = @([pscustomobject]@{ item = 'test'; hive = 'SOFTWARE'; path = 'X'; name = 'Y'; type = 'REG_NONSENSE'; value = '1' })
        $problems = Test-EssentialsProfile -Profile $bad
        ($problems -join ' ') | Should -Match 'unsupported type'
    }

    It 'rejects a service start value that is not manual or disabled' {
        $bad = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
        $bad.services = @([pscustomobject]@{ item = 'test'; name = 'AJRouter'; start = 2 })
        $problems = Test-EssentialsProfile -Profile $bad
        ($problems -join ' ') | Should -Match 'start=2'
    }

    It 'guards the services Windows cannot boot without' {
        foreach ($name in @('RpcSs', 'DcomLaunch', 'LSM', 'Power', 'PlugPlay', 'EventLog', 'Schedule', 'Winmgmt')) {
            Test-EssentialsProtectedService -Name $name | Should -BeTrue
        }
        Test-EssentialsProtectedService -Name 'AJRouter' | Should -BeFalse
    }

    It 'imports the profile as a single object, not an array' {
        # The log function must not write to the output stream - if it does, the
        # caller's profile becomes [string, profile] and every property lookup breaks.
        $imported = Import-EssentialsProfile -Path $profilePath
        $imported.GetType().Name | Should -Be 'PSCustomObject'
        @($imported.registry).Count | Should -BeGreaterThan 0
    }

    It 'writes a manifest with a section per item' {
        $out = Join-Path ([IO.Path]::GetTempPath()) "essentials-manifest-test-$PID.md"
        try {
            New-EssentialsManifest -Profile $profile -Destination $out
            Test-Path -LiteralPath $out | Should -BeTrue
            $md = Get-Content -LiteralPath $out -Raw

            $md | Should -Match '# Tiny11 Core-Gaming - Essentials pass'
            $md | Should -Match 'not toggleable'

            # Coverage table first: 20 rows, one per ticked box.
            $md | Should -Match '## Coverage'
            $md | Should -Match '20 item\(s\): 17 applied by this layer, 3 handled elsewhere'

            $coverageRows = [regex]::Matches($md, '(?m)^\| \d+ \| ').Count
            $coverageRows | Should -Be 20

            # Detail section per item the layer writes, plus the offloaded ones.
            $itemSections = [regex]::Matches($md, '(?m)^### ').Count
            $itemSections | Should -Be 17
            $md | Should -Match '## Handled elsewhere'
        } finally {
            if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force }
        }
    }
}

Describe 'Builder wiring' {

    It 'dot-sources the essentials engine only under -GamingProfile' {
        $builderRaw | Should -Match "essentials-profile\.ps1"
        $builderRaw | Should -Match 'Gaming profile requested but the essentials engine was not found'
    }

    It 'imports the profile inside the -GamingProfile block' {
        $builderRaw | Should -Match 'Import-EssentialsProfile'
        $builderRaw | Should -Match 'Initialize-EssentialsModule'
    }

    It 'applies registry tweaks before the performance and gaming passes' {
        $essentials = Get-MainCallIndex -Content $builderRaw -Name 'Invoke-EssentialsRegistryTweaks'
        $perf = Get-MainCallIndex -Content $builderRaw -Name 'Apply-PerformanceTweaks'
        $gaming = Get-MainCallIndex -Content $builderRaw -Name 'Invoke-GamingRegistryTweaks'

        $essentials | Should -BeGreaterThan 0
        $perf | Should -BeGreaterThan 0
        $gaming | Should -BeGreaterThan 0
        $essentials | Should -BeLessThan $perf
        $perf | Should -BeLessThan $gaming
    }

    It 'applies service tweaks before the gaming service pass' {
        $essentials = Get-MainCallIndex -Content $builderRaw -Name 'Invoke-EssentialsServiceTweaks'
        $gaming = Get-MainCallIndex -Content $builderRaw -Name 'Invoke-GamingServiceTweaks'

        $essentials | Should -BeGreaterThan 0
        $gaming | Should -BeGreaterThan 0
        $essentials | Should -BeLessThan $gaming
    }

    It 'stages the essentials payload and the report script' {
        $builderRaw | Should -Match 'essentials_profile\.json'
        $builderRaw | Should -Match 'New-EssentialsManifest'
        $builderRaw | Should -Match 'Tiny11-Report\.ps1'
    }
}

Describe 'Not toggleable' {

    It 'has no workflow input for the essentials layer' {
        # The workflow is at GitHub's 25-input cap, and the layer is meant to be part
        # of the build rather than an option. If a toggle is ever added, this test
        # should fail and force the conversation.
        $inputsBlock = [regex]::Match($workflowRaw, '(?ms)^on:.*?^env:').Value
        $inputsBlock | Should -Not -BeNullOrEmpty
        $inputsBlock | Should -Not -Match '(?m)^\s{6}essentials'

        # And it must never be passed to the builder as a switch.
        $workflowRaw | Should -Not -Match '\-Essentials\b'
    }

    It 'validates the essentials profile before the ISO download' {
        # The step is referenced by name, and it must sit before the download step.
        $validate = $workflowRaw.IndexOf('Validate essentials profile')
        $download = $workflowRaw.IndexOf('Download Windows 11 ISO')
        if ($download -lt 0) { $download = $workflowRaw.IndexOf('Resolve Windows 11 ISO') }
        $validate | Should -BeGreaterThan 0
        if ($download -gt 0) { $validate | Should -BeLessThan $download }
    }

    It 'is not gated on a group in the first-boot script' {
        # Invoke-EssentialsFirstBoot must be called directly, never inside a
        # Test-GroupEnabled block.
        $callIndex = $firstBootRaw.IndexOf('Invoke-EssentialsFirstBoot -ConfigPath')
        $callIndex | Should -BeGreaterThan 0

        $before = $firstBootRaw.Substring([Math]::Max(0, $callIndex - 400), [Math]::Min(400, $callIndex))
        $before | Should -Not -Match 'Test-GroupEnabled[^\r\n]*\r?\n[^\r\n]*Invoke-EssentialsFirstBoot'
    }

    It 'does not read a group flag inside the essentials first-boot function' {
        $start = $firstBootRaw.IndexOf('function Invoke-EssentialsFirstBoot')
        $start | Should -BeGreaterThan 0
        $end = $firstBootRaw.IndexOf('#---------[ Main ]', $start)
        $body = $firstBootRaw.Substring($start, $end - $start)
        $body | Should -Not -Match 'Test-GroupEnabled'
    }
}

Describe 'First-boot stage' {

    It 'defines the essentials stage' {
        $firstBootRaw | Should -Match 'function Invoke-EssentialsFirstBoot'
        $firstBootRaw | Should -Match 'essentials_profile\.json'
    }

    It 'turns hibernation off with powercfg' {
        $firstBootRaw | Should -Match 'powercfg -hibernate off'
    }

    It 'creates a restore point best-effort' {
        $firstBootRaw | Should -Match 'Checkpoint-Computer'
        $firstBootRaw | Should -Match 'Enable-ComputerRestore'
    }

    It 'reports the process count' {
        $firstBootRaw | Should -Match 'Get-Process'
    }

    It 'runs before the power scheme so powercfg cannot reset it' {
        $essentials = $firstBootRaw.IndexOf('Invoke-EssentialsFirstBoot -ConfigPath')
        $power = $firstBootRaw.IndexOf('New-GamingPowerScheme -ConfigPath')
        $essentials | Should -BeGreaterThan 0
        $power | Should -BeGreaterThan 0
        $essentials | Should -BeLessThan $power
    }
}

Describe 'Report script' {

    It 'exists and parses' {
        Test-Path -LiteralPath $reportPath | Should -BeTrue
        $errs = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($reportPath, [ref]$null, [ref]$errs)
        @($errs).Count | Should -Be 0
    }

    It 'checks the essentials registry values' {
        $raw = Get-Content -LiteralPath $reportPath -Raw
        $raw | Should -Match 'EnableActivityFeed'
        $raw | Should -Match 'TaskbarEndTask'
        $raw | Should -Match 'DisableWpbtExecution'
    }

    It 'reports a process count' {
        $raw = Get-Content -LiteralPath $reportPath -Raw
        $raw | Should -Match 'Get-Process'
    }
}
