<#
.SYNOPSIS
    Tiny11 Core-Gaming essentials engine.

.DESCRIPTION
    Dot-sourced by tiny11coremaker-headless.ps1 on a -GamingProfile build and applied
    unconditionally - there is no group flag, no workflow input, and no way to turn a
    single item off. It reproduces the post-install debloat pass that would otherwise
    have to be run by hand on every fresh install.

    Every tweak is data-driven from config/essentials_profile.json. This module only
    knows how to APPLY the data - it never hardcodes a registry path or a service name,
    and every entry in the JSON carries the name of the checkbox it implements so the
    file can be audited item by item.

    Application order (driven by the builder):
      1. Invoke-EssentialsRegistryTweaks   (hives loaded)
      2. Invoke-EssentialsServiceTweaks    (hives loaded)
      3. Invoke-EssentialsFirstBoot        (on the target machine, via SetupComplete.cmd)

    Everything is best-effort: one missing service or one unavailable key logs a warning
    and continues. A partially applied essentials pass is still a working image, and a
    90-minute build should never fail over a single registry value.

.NOTES
    Author: kelexine (https://github.com/kelexine)
    License: MIT
#>

$script:EssentialsLogFile = $null
$script:EssentialsProfileDir = $null
$script:EssentialsStats = @{ registry = 0; deleteKeys = 0; services = 0; failed = 0 }

#---------[ Logging / helpers ]---------#

function Initialize-EssentialsModule {
    param(
        [string]$LogFile,
        [string]$ProfileDirectory
    )
    if ($LogFile) { $script:EssentialsLogFile = $LogFile }
    if ($ProfileDirectory) { $script:EssentialsProfileDir = $ProfileDirectory }
}

function Write-EssentialsLog {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [essentials/$Level] $Message"

    # Write-Host, not Write-Output: Import-EssentialsProfile must return exactly one
    # object. Anything this function emits to the output stream would be captured
    # alongside the profile and turn the caller's $profile into an array, which then
    # breaks every PSObject.Properties lookup in this module. Write-Host still reaches
    # the console and the CI log.
    Write-Host $line

    if ($script:EssentialsLogFile) {
        Add-Content -LiteralPath $script:EssentialsLogFile -Value $line -ErrorAction SilentlyContinue
    }
}

function Get-EssentialsProp {
    param(
        $Object,
        [string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    if ($null -eq $prop.Value) { return $Default }
    return $prop.Value
}

function Get-EssentialsConfigPath {
    param([string]$FileName)
    if (-not $script:EssentialsProfileDir) { return $null }
    $candidate = Join-Path $script:EssentialsProfileDir $FileName
    if (Test-Path -LiteralPath $candidate) { return $candidate }
    return $null
}

#---------[ Import / validate ]---------#

function Import-EssentialsProfile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Essentials profile not found: $Path"
    }

    $profile = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json

    # @() - an empty problem list comes back from the function as $null, and the builders
    # run under Set-StrictMode -Version Latest, where $null.Count throws.
    $problems = @(Test-EssentialsProfile -Profile $profile)
    if ($problems.Count -gt 0) {
        throw "Essentials profile $Path is invalid:`n  - $($problems -join "`n  - ")"
    }

    Write-EssentialsLog "Loaded essentials profile '$($profile.profile)' (schema $($profile.schemaVersion))"
    return $profile
}

function Test-EssentialsProfile {
    <#
        Returns an array of human-readable problems. Empty means valid.
        This runs before the ISO is downloaded, so a typo costs seconds rather than an
        hour-long build.
    #>
    param($Profile)

    $problems = @()

    if (-not (Get-EssentialsProp $Profile 'profile')) {
        $problems += "missing 'profile' name"
    }
    if (-not (Get-EssentialsProp $Profile 'hivePrefixes')) {
        $problems += "missing 'hivePrefixes'"
    }

    $hives = @()
    $prefixes = Get-EssentialsProp $Profile 'hivePrefixes'
    if ($prefixes) {
        foreach ($p in $prefixes.PSObject.Properties) { $hives += $p.Name }
    }

    $validTypes = @('REG_DWORD', 'REG_SZ', 'REG_EXPAND_SZ', 'REG_QWORD', 'REG_BINARY')

    $index = 0
    foreach ($entry in @(Get-EssentialsProp $Profile 'registry' @())) {
        $index++
        $label = "registry[$index]"
        $hive = Get-EssentialsProp $entry 'hive'
        $path = Get-EssentialsProp $entry 'path'
        $type = Get-EssentialsProp $entry 'type'

        if (-not (Get-EssentialsProp $entry 'item')) { $problems += "$label has no 'item' (which checkbox does it implement?)" }
        if (-not $hive) { $problems += "$label has no 'hive'" }
        elseif ($hives -notcontains $hive) { $problems += "$label uses unknown hive '$hive'" }
        if (-not $path) { $problems += "$label has no 'path'" }
        if ($type -and $validTypes -notcontains $type) { $problems += "$label has unsupported type '$type'" }
        if (-not $type) { $problems += "$label has no 'type'" }
    }

    $index = 0
    foreach ($entry in @(Get-EssentialsProp $Profile 'deleteKeys' @())) {
        $index++
        $label = "deleteKeys[$index]"
        $hive = Get-EssentialsProp $entry 'hive'
        if (-not $hive) { $problems += "$label has no 'hive'" }
        elseif ($hives -notcontains $hive) { $problems += "$label uses unknown hive '$hive'" }
        if (-not (Get-EssentialsProp $entry 'path')) { $problems += "$label has no 'path'" }
    }

    $index = 0
    foreach ($svc in @(Get-EssentialsProp $Profile 'services' @())) {
        $index++
        $label = "services[$index]"
        $name = Get-EssentialsProp $svc 'name'
        $start = Get-EssentialsProp $svc 'start' -1
        if (-not $name) { $problems += "$label has no 'name'" }
        if ($start -notin @(3, 4)) { $problems += "$label '$name' has start=$start (expected 3 manual or 4 disabled)" }
        if ($name -and (Test-EssentialsProtectedService -Name $name)) {
            $problems += "$label '$name' is a boot-critical service and must not be touched"
        }
    }

    # Items that are covered by something else. Recorded in data rather than in prose so
    # the file itself accounts for every box that was ticked, and so a test can assert
    # the total without hardcoding it a second time.
    $knownOwners = @('core', 'firstBoot', 'gaming')
    $index = 0
    foreach ($entry in @(Get-EssentialsProp $Profile 'handledElsewhere' @())) {
        $index++
        $label = "handledElsewhere[$index]"
        $item = Get-EssentialsProp $entry 'item'
        $by = Get-EssentialsProp $entry 'by'
        if (-not $item) { $problems += "$label has no 'item'" }
        if (-not $by) { $problems += "$label has no 'by'" }
        elseif ($knownOwners -notcontains $by) { $problems += "$label '$item' has unknown owner '$by'" }
        if (-not (Get-EssentialsProp $entry 'where')) { $problems += "$label '$item' does not say where it is handled" }
    }

    # The same box must not be applied here AND listed as handled elsewhere - that is
    # how a layer ends up with two sources of truth for one setting. One box legitimately
    # needs several mechanisms (BitLocker is a registry value *and* a disabled service),
    # so only the data-vs-handledElsewhere overlap is a conflict.
    $dataItems = @(
        @(@(Get-EssentialsProp $Profile 'registry' @()) | ForEach-Object { Get-EssentialsProp $_ 'item' }) +
        @(@(Get-EssentialsProp $Profile 'deleteKeys' @()) | ForEach-Object { Get-EssentialsProp $_ 'item' }) +
        @(@(Get-EssentialsProp $Profile 'services' @()) | ForEach-Object { Get-EssentialsProp $_ 'item' })
    ) | Where-Object { $_ } | Select-Object -Unique

    $elsewhereItems = @(@(Get-EssentialsProp $Profile 'handledElsewhere' @()) |
        ForEach-Object { Get-EssentialsProp $_ 'item' } | Where-Object { $_ } | Select-Object -Unique)

    foreach ($overlap in @($dataItems | Where-Object { $elsewhereItems -contains $_ })) {
        $problems += "'$overlap' is applied here and also listed in handledElsewhere - pick one"
    }

    return $problems
}

function Get-EssentialsCoverage {
    <#
        The full list of ticked boxes, with the disposition of each. This is what makes
        "all 20 are covered" checkable instead of asserted - the manifest and the tests
        both read it.
    #>
    param($Profile)

    $coverage = @()

    foreach ($e in @(Get-EssentialsProp $Profile 'registry' @())) {
        $item = Get-EssentialsProp $e 'item'
        if ($item) {
            $name = Get-EssentialsProp $e 'name' ''
            $label = if ($name) { $name } else { '(default)' }
            $coverage += [pscustomobject]@{ Item = $item; Owner = 'data'; Where = "$($e.hive)\$($e.path)\$label" }
        }
    }
    foreach ($e in @(Get-EssentialsProp $Profile 'deleteKeys' @())) {
        $item = Get-EssentialsProp $e 'item'
        if ($item) { $coverage += [pscustomobject]@{ Item = $item; Owner = 'data'; Where = "$($e.hive)\$($e.path) (deleted)" } }
    }
    foreach ($e in @(Get-EssentialsProp $Profile 'services' @())) {
        $item = Get-EssentialsProp $e 'item'
        if ($item) { $coverage += [pscustomobject]@{ Item = $item; Owner = 'data'; Where = "service $($e.name)" } }
    }
    foreach ($e in @(Get-EssentialsProp $Profile 'handledElsewhere' @())) {
        $item = Get-EssentialsProp $e 'item'
        if ($item) { $coverage += [pscustomobject]@{ Item = $item; Owner = (Get-EssentialsProp $e 'by'); Where = (Get-EssentialsProp $e 'where') } }
    }

    return $coverage
}

#---------[ Service safety guard ]---------#

function Test-EssentialsProtectedService {
    <#
        Services Windows cannot start without. A profile edit that tries to disable one
        of these is rejected at validation time rather than producing an unbootable
        image - the whole point of keeping the list here instead of trusting the JSON.
    #>
    param([string]$Name)

    $protected = @(
        'RpcSs', 'RpcEptMapper', 'DcomLaunch', 'LSM', 'Power', 'PlugPlay',
        'ProfSvc', 'gpsvc', 'SamSs', 'EventLog', 'Schedule', 'Winmgmt',
        'Themes', 'AudioSrv', 'AudioEndpointBuilder', 'CryptSvc', 'KeyIso',
        'Dnscache', 'Dhcp', 'NlaSvc', 'netprofm', 'nsi', 'BFE', 'mpssvc',
        'Wcmsvc', 'SystemEventsBroker', 'BrokerInfrastructure', 'StateRepository',
        'UserManager', 'TrustedInstaller', 'ESENT', 'W32Time', 'TermService',
        'SessionEnv', 'UmRdpService', 'Winlogon', 'Wlansvc'
    )

    return ($protected -contains $Name)
}

#---------[ Registry ]---------#

function Get-EssentialsHivePrefixMap {
    param($Profile)
    $map = @{}
    foreach ($prop in $Profile.hivePrefixes.PSObject.Properties) {
        $map[$prop.Name] = $prop.Value
    }
    return $map
}

function ConvertTo-EssentialsProviderPath {
    # HKLM\zNTUSER\Software\... -> Registry::HKEY_LOCAL_MACHINE\zNTUSER\Software\...
    param([string]$KeyPath)

    if ($KeyPath -match '^HKLM\\(.+)$') {
        return "Registry::HKEY_LOCAL_MACHINE\$($matches[1])"
    }
    if ($KeyPath -match '^HKCU\\(.+)$') {
        return "Registry::HKEY_CURRENT_USER\$($matches[1])"
    }
    return $null
}

function Test-EssentialsRegistryKeyExists {
    # Test-Path instead of "reg query": a missing key is an expected result, but reg.exe reports
    # it on stderr, and Windows PowerShell 5.1 turns redirected native stderr into a terminating
    # error when $ErrorActionPreference = 'Stop' (as in the builders), even with 2>$null.
    param([string]$KeyPath)
    $psPath = ConvertTo-EssentialsProviderPath -KeyPath $KeyPath
    if (-not $psPath) { return $false }
    return [bool](Test-Path -LiteralPath $psPath -ErrorAction SilentlyContinue)
}

function Set-EssentialsRegistryValue {
    param(
        [string]$KeyPath,
        [string]$Name,
        [string]$Type,
        [string]$Value
    )

    if ([string]::IsNullOrEmpty($Name)) {
        # The default value of a key. reg.exe drops an empty /d argument, so this goes
        # through the provider instead - it is the only reliable way to write REG_SZ "".
        $psPath = ConvertTo-EssentialsProviderPath -KeyPath $KeyPath
        if (-not $psPath) { throw "cannot convert $KeyPath to a provider path" }
        if (-not (Test-Path -LiteralPath $psPath)) {
            New-Item -Path $psPath -Force | Out-Null
        }
        Set-ItemProperty -LiteralPath $psPath -Name '(Default)' -Value $Value -Type String -Force
        return
    }

    & reg add $KeyPath /v $Name /t $Type /d $Value /f | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "reg add failed for $KeyPath\$Name (exit $LASTEXITCODE)"
    }
}

function Invoke-EssentialsRegistryTweaks {
    param($Profile)

    $prefixMap = Get-EssentialsHivePrefixMap -Profile $Profile
    $applied = 0
    $failed = 0

    Write-EssentialsLog "Applying essentials registry tweaks..."

    foreach ($entry in @(Get-EssentialsProp $Profile 'registry' @())) {
        $hive = Get-EssentialsProp $entry 'hive'
        $path = Get-EssentialsProp $entry 'path'
        $name = Get-EssentialsProp $entry 'name' ''
        $type = Get-EssentialsProp $entry 'type'
        $value = Get-EssentialsProp $entry 'value' ''
        $item = Get-EssentialsProp $entry 'item'
        $note = Get-EssentialsProp $entry 'note'

        $keyPath = "$($prefixMap[$hive])\$path"
        $label = "$hive\$path\$name"

        try {
            Set-EssentialsRegistryValue -KeyPath $keyPath -Name $name -Type $type -Value $value
            $applied++
            $suffix = ''
            if ($note) { $suffix = "  ($note)" }
            Write-EssentialsLog "  set $label = '$value'  [$item]$suffix"
        } catch {
            $failed++
            Write-EssentialsLog "  FAILED $label : $_" 'WARN'
        }
    }

    # Keys that must not exist at all. Deleting is best-effort - a key that is already
    # absent is the desired end state, not an error.
    $deleted = 0
    foreach ($entry in @(Get-EssentialsProp $Profile 'deleteKeys' @())) {
        $hive = Get-EssentialsProp $entry 'hive'
        $path = Get-EssentialsProp $entry 'path'
        $item = Get-EssentialsProp $entry 'item'

        $keyPath = "$($prefixMap[$hive])\$path"

        if (-not (Test-EssentialsRegistryKeyExists -KeyPath $keyPath)) {
            Write-EssentialsLog "  key already absent $hive\$path  [$item]"
            continue
        }

        & { $ErrorActionPreference = 'Continue'; & reg delete $keyPath /f 2>&1 | Out-Null }
        if ($LASTEXITCODE -eq 0) {
            $deleted++
            Write-EssentialsLog "  deleted key $hive\$path  [$item]"
        } else {
            $failed++
            Write-EssentialsLog "  FAILED to delete $hive\$path  [$item]" 'WARN'
        }
    }

    $script:EssentialsStats.registry = $applied
    $script:EssentialsStats.deleteKeys = $deleted
    $script:EssentialsStats.failed = $failed
    Write-EssentialsLog "Registry: $applied value(s) set, $deleted key(s) deleted, $failed failure(s)"
}

#---------[ Services ]---------#

function Invoke-EssentialsServiceTweaks {
    param($Profile)

    $prefixMap = Get-EssentialsHivePrefixMap -Profile $Profile
    $systemRoot = "$($prefixMap['SYSTEM'])\ControlSet001\Services"
    $applied = 0
    $missing = 0

    Write-EssentialsLog "Applying essentials service tweaks..."

    foreach ($svc in @(Get-EssentialsProp $Profile 'services' @())) {
        $name = Get-EssentialsProp $svc 'name'
        $start = Get-EssentialsProp $svc 'start' 4
        $note = Get-EssentialsProp $svc 'note'

        if (Test-EssentialsProtectedService -Name $name) {
            Write-EssentialsLog "  REFUSED $name - boot-critical service" 'WARN'
            continue
        }

        $keyPath = "$systemRoot\$name"

        # Never create a service key that does not exist - that would leave a bogus
        # entry in the registry of the finished image.
        if (-not (Test-EssentialsRegistryKeyExists -KeyPath $keyPath)) {
            $missing++
            Write-EssentialsLog "  skip $name (not present in this image)"
            continue
        }

        try {
            Set-EssentialsRegistryValue -KeyPath $keyPath -Name 'Start' -Type 'REG_DWORD' -Value "$start"
            $applied++
            $kind = if ($start -eq 4) { 'disable' } else { 'manual ' }
            $suffix = ''
            if ($note) { $suffix = "  ($note)" }
            Write-EssentialsLog "  $kind $name (Start=$start)$suffix"
        } catch {
            Write-EssentialsLog "  FAILED to set $name : $_" 'WARN'
        }
    }

    $script:EssentialsStats.services = $applied
    Write-EssentialsLog "Services: $applied set, $missing not present in this image"
}

#---------[ Manifest ]---------#

function New-EssentialsManifest {
    <#
        Writes the audit trail that travels with the image. Grouped by source checkbox so
        a reader can check the finished ISO against the list they ticked.
    #>
    param(
        $Profile,
        [string]$Destination
    )

    $lines = @()
    $lines += '# Tiny11 Core-Gaming - Essentials pass'
    $lines += ''
    $lines += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $lines += ''
    $lines += 'This layer is **not toggleable**. A Core-Gaming build always applies it.'
    $lines += 'Every row names the checkbox it implements from the post-install debloat list.'
    $lines += ''

    # Coverage first: one row per ticked box, computed from the data rather than
    # maintained by hand. This is the answer to "did all of them make it in".
    $coverage = @(Get-EssentialsCoverage -Profile $Profile)
    $grouped = @($coverage | Group-Object Item | Sort-Object Name)
    $inData = @($grouped | Where-Object { $_.Group[0].Owner -eq 'data' })
    $elsewhere = @($grouped | Where-Object { $_.Group[0].Owner -ne 'data' })

    $lines += '## Coverage'
    $lines += ''
    $lines += "**$($grouped.Count) item(s): $($inData.Count) applied by this layer, $($elsewhere.Count) handled elsewhere.**"
    $lines += ''
    $lines += '| # | Source item | Handled by | Where |'
    $lines += '|---|---|---|---|'
    $n = 0
    foreach ($g in $grouped) {
        $n++
        $owner = switch ($g.Group[0].Owner) {
            'data'      { 'this layer' }
            'core'      { 'Core build' }
            'firstBoot' { 'first boot' }
            default     { $g.Group[0].Owner }
        }
        $whereList = @(@($g.Group | ForEach-Object { $_.Where }) | Select-Object -Unique)
        # "Services - Set to Manual" alone spans 58 entries. Keep the summary table
        # readable and let the detail section below carry the full list.
        $where = if ($whereList.Count -gt 4) {
            "$($whereList.Count) entries - see below"
        } else {
            $whereList -join '; '
        }
        $lines += "| $n | $($g.Name) | $owner | ``$where`` |"
    }
    $lines += ''

    $lines += '## What this layer writes'
    $lines += ''

    foreach ($g in $inData) {
        $item = $g.Name
        $lines += "### $item"
        $lines += ''

        $rows = @()
        foreach ($e in @(Get-EssentialsProp $Profile 'registry' @())) {
            if ((Get-EssentialsProp $e 'item') -ne $item) { continue }
            $name = Get-EssentialsProp $e 'name' ''
            $label = if ($name) { $name } else { '(default)' }
            $rows += "| ``$($e.hive)\$($e.path)`` | $label | $($e.type) | ``$($e.value)`` |"
        }
        foreach ($e in @(Get-EssentialsProp $Profile 'deleteKeys' @())) {
            if ((Get-EssentialsProp $e 'item') -ne $item) { continue }
            $rows += "| ``$($e.hive)\$($e.path)`` | _(key)_ | deleted | - |"
        }
        foreach ($e in @(Get-EssentialsProp $Profile 'services' @())) {
            if ((Get-EssentialsProp $e 'item') -ne $item) { continue }
            $kind = if ($e.start -eq 4) { 'disabled' } else { 'manual' }
            $rows += "| ``service`` | ``$($e.name)`` | $kind | Start=$($e.start) |"
        }

        if ($rows.Count -gt 0) {
            $lines += '| Key | Value | Type | Set to |'
            $lines += '|---|---|---|---|'
            $lines += $rows
            $lines += ''
        }
    }

    if ($elsewhere.Count -gt 0) {
        $lines += '## Handled elsewhere'
        $lines += ''
        $lines += 'These boxes were ticked too, but the work is done by something that already'
        $lines += 'owns it. Repeating it here would be two sources of truth for one setting.'
        $lines += ''
        $lines += '| Item | Handled by | Where | Evidence |'
        $lines += '|---|---|---|---|'
        foreach ($e in @(Get-EssentialsProp $Profile 'handledElsewhere' @())) {
            $item = Get-EssentialsProp $e 'item'
            $by = Get-EssentialsProp $e 'by'
            $owner = switch ($by) {
                'core'      { 'Core build' }
                'firstBoot' { 'first boot' }
                'gaming'    { 'gaming profile' }
                default     { $by }
            }
            $lines += "| $item | $owner | $(Get-EssentialsProp $e 'where') | $(Get-EssentialsProp $e 'evidence') |"
        }
        $lines += ''
    }

    $firstBoot = Get-EssentialsProp $Profile 'firstBoot'
    if ($firstBoot) {
        $lines += '## Applied at first boot (needs a live OS)'
        $lines += ''
        $lines += '| Action | Why it cannot be offline |'
        $lines += '|---|---|'
        if ((Get-EssentialsProp $firstBoot 'hibernateOff' $false)) {
            $lines += '| `powercfg -hibernate off` | Deletes hiberfil.sys; the file only exists on an installed system |'
        }
        if ((Get-EssentialsProp $firstBoot 'cleanTemp' $false)) {
            $lines += '| Temp cleanup | There is no populated %TEMP% in install.wim |'
        }
        if ((Get-EssentialsProp $firstBoot 'restorePoint' $false)) {
            $lines += '| System Restore point | Needs a running VSS and a real system volume |'
        }
        if ((Get-EssentialsProp $firstBoot 'reportProcessCount' $false)) {
            $lines += '| Process count report | Only meaningful on the target machine |'
        }
        $lines += ''
    }

    $lines += '## Deliberately not implemented'
    $lines += ''
    $lines += 'The **Customize Preferences** column (theme, taskbar layout, scrollbars, num lock,'
    $lines += 'S3 sleep, ...) is cosmetic and is not part of this layer. The two settings from it'
    $lines += 'that affect performance - Game Mode and mouse acceleration - are already handled by'
    $lines += 'the gaming profile, which is the authoritative source for those.'
    $lines += ''

    $content = ($lines -join "`r`n") + "`r`n"
    $dir = Split-Path -Parent $Destination
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    $content | Out-File -FilePath $Destination -Encoding UTF8 -Force

    Write-EssentialsLog "Manifest written to $Destination"
}

function Get-EssentialsStats {
    return $script:EssentialsStats
}
