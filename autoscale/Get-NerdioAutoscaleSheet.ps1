<#
.SYNOPSIS
    Reads your Azure Virtual Desktop scaling plans and prints exactly what to
    enter in Nerdio Manager's "Create Auto-Scale Profile" screen so day-one
    behavior matches what Azure is doing today. Run in Azure Cloud Shell
    (PowerShell). Read-only. One command.

.DESCRIPTION
    An Azure scaling plan and NME auto-scale describe the same job in two
    different languages. This script translates behavior-for-behavior:
      1. Inventories every scaling plan tenant-wide via Azure Resource Graph
         (pooled plans translated; personal plans listed for a later phase).
      2. Reads each plan's schedules (ramp-up / peak / ramp-down / off-peak,
         capacity thresholds, minimum host percentages, force-logoff settings).
      3. Reads each assigned host pool's facts: registered session hosts,
         max session limit, load balancing, Start VM on connect.
      4. Produces ONE plain-text sheet per host pool, written in the same order
         as NME's Create Auto-Scale Profile screen - copy it line by line.
         Weekend/secondary schedules become additional pre-stage schedules on
         the same profile ("Use multiple schedules"). Anything Azure did that
         NME expresses differently is called out in a NOTES section on the
         sheet - nothing is translated silently.
      5. Writes the sheets to a .txt, a per-schedule review table to a .csv,
         and triggers Cloud Shell browser downloads of both.

    The philosophy is day-one mimicry: transfer the scaling behavior as-is,
    then optimize with Nerdio's telemetry once it has data. The sheet never
    invents settings a plan didn't have - NME capabilities with no scaling-plan
    equivalent stay at their defaults.

    Nothing is modified anywhere - every call is a read.

.PARAMETER SubscriptionId
    Optional subscription ID(s) to scope to. Default: every subscription you can see.
.PARAMETER OutFile
    Output sheet file name. Default nme-autoscale-sheet-<timestamp>.txt.
    The review CSV takes the same name with -review.csv.
.PARAMETER SkipDownload
    Skip the Cloud Shell auto-download (files still written to the session).

.EXAMPLE
    iex (irm 'https://raw.githubusercontent.com/dclawrence003/NME/main/autoscale/Get-NerdioAutoscaleSheet.ps1')

.EXAMPLE
    # Download first to pass parameters (or to read the code before running it):
    irm 'https://raw.githubusercontent.com/dclawrence003/NME/main/autoscale/Get-NerdioAutoscaleSheet.ps1' -OutFile ./autoscale.ps1
    ./autoscale.ps1 -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

.NOTES
    v0.1 (2026-08-04). First release. Sibling of modeler/Get-NerdioModelerJson.ps1
    (same skeleton: Resource Graph over REST, Cloud Shell auto-download).

    TRANSLATION RULES (the short version - the README has the full reasoning):
    - Trigger = Available sessions, always. Azure's capacity threshold counts
      active + disconnected sessions against available-host capacity; NME's
      Available-sessions trigger uses the same accounting. Scale out: up to 2
      hosts when available sessions < X for 5 min, where
      X = ceil(BaseHosts x SessionLimit x (100 - threshold%) / 100).
      Scale in: up to 1 host when available sessions > X + SessionLimit
      (one full host of headroom) for 15 min.
    - Base capacity = all registered hosts (a power-management plan never
      creates hosts) and Burst = 0 for the same reason.
    - Min active = ceil(rampDownMinimumHostsPct x base); when schedules
      disagree, the HIGHEST wins (never below what the plan guaranteed).
    - Scale-in aggressiveness maps 1:1 from ramp-down behavior:
      ZeroSessions -> Low, ZeroActiveSessions -> Medium,
      force logoff -> High + Messaging (wait minutes + message, verbatim).
    - Each Azure schedule = one pre-stage schedule: its days, its ramp-up
      start, ceil(rampUpMinimumHostsPct x base) hosts, and a scale-in delay
      spanning ramp-up start -> ramp-down start (holds the daytime floor the
      way Azure's ramp-up minimum persists through peak).
    - Load balancing = the plan's ramp-up/peak algorithm. Azure's per-phase
      LB switches have no single-field NME equivalent - noted on the sheet,
      revisit at optimization (rolling drain windows are that lever).
    - exclusionTag: NME excludes per host, not by tag - the sheet names the
      currently-tagged hosts to exclude manually.
    - Dynamic autoscaling (create/delete) plans are flagged for manual review;
      their Base/Burst math is different by nature.

    ACCESS: Reader on the subscription(s). No Log Analytics, no NME API.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)] [string[]] $SubscriptionId = @(),
    [Parameter(Mandatory = $false)] [string]   $OutFile        = "",
    [Parameter(Mandatory = $false)] [switch]   $SkipDownload
)

$ErrorActionPreference = 'Stop'
$script:Version = 'v0.1'
if ([string]::IsNullOrEmpty($OutFile)) { $OutFile = "nme-autoscale-sheet-$(Get-Date -Format 'yyyyMMdd-HHmm').txt" }
$csvDir  = [IO.Path]::GetDirectoryName($OutFile)
$csvBase = [IO.Path]::GetFileNameWithoutExtension($OutFile) + '-review.csv'
$csvFile = if ([string]::IsNullOrEmpty($csvDir)) { $csvBase } else { [IO.Path]::Combine($csvDir, $csvBase) }

function Write-Info { param([string]$m) Write-Host "[i] $m" -ForegroundColor Gray }
function Write-Ok   { param([string]$m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2{ param([string]$m) Write-Host "[!] $m" -ForegroundColor Yellow }

# --- Cloud Shell detection + auto-download (same pattern as the modeler tool) ---
$script:IsCloudShell = (-not [string]::IsNullOrEmpty($env:ACC_CLOUD)) -or ($env:AZUREPS_HOST_ENVIRONMENT -like "cloud-shell*")
function Invoke-CloudShellDownload {
    param([string]$Path)
    if (-not $script:IsCloudShell) { Write-Info "Not running in Cloud Shell - file saved at: $Path"; return }
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        download $Path
        Write-Ok "Browser download triggered for $Path"
    } catch {
        Write-Warn2 "Auto-download unavailable. Use the Cloud Shell 'Manage files -> Download' toolbar button and enter: $Path"
    }
}

# --- Resource Graph via REST (no extra modules; pages through results) ---
function Invoke-ArgQuery {
    param([string]$Query)
    $all = @()
    $skip = $null
    do {
        $body = @{ query = $Query; options = @{ resultFormat = 'objectArray' } }
        if ($SubscriptionId.Count -gt 0) { $body.subscriptions = $SubscriptionId }
        if ($skip) { $body.options.'$skipToken' = $skip }
        $resp = Invoke-AzRestMethod -Method POST -Path "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01" -Payload ($body | ConvertTo-Json -Depth 6)
        if ($resp.StatusCode -ne 200) { throw "Resource Graph query failed (HTTP $($resp.StatusCode)): $($resp.Content)" }
        $parsed = $resp.Content | ConvertFrom-Json
        $all += @($parsed.data)
        $skip = $parsed.'$skipToken'
    } while ($skip)
    return $all
}

# --- small formatters -------------------------------------------------------------
function Get-Ceil  { param([double]$x) [int][Math]::Ceiling($x) }
function Format-Time { param($h, $m) '{0}:{1:d2}' -f [int]$h, [int]$m }
function Format-LB {
    param([string]$s)
    switch -Regex ($s) {
        '^(?i)DepthFirst$'   { 'Depth First'; break }
        '^(?i)BreadthFirst$' { 'Breadth First'; break }
        default              { if ([string]::IsNullOrEmpty($s)) { '(not set)' } else { $s } }
    }
}
function Format-Days {
    param($days)
    if ($null -eq $days -or @($days).Count -eq 0) { return '(none)' }
    (@($days) | ForEach-Object { $d = "$_"; if ($d.Length -ge 3) { $d.Substring(0, 3) } else { $d } }) -join ', '
}

if (-not (Get-AzContext)) { throw "No Azure context. In Cloud Shell this is automatic; locally run Connect-AzAccount first." }

# ------------------------------------------------------------------- 1. scaling plans
Write-Info "[1/5] Inventorying scaling plans via Resource Graph..."
$planRows = Invoke-ArgQuery -Query @"
resources
| where type =~ 'microsoft.desktopvirtualization/scalingplans'
| project id, name, resourceGroup, subscriptionId,
          timeZone = tostring(properties.timeZone),
          exclusionTag = tostring(properties.exclusionTag),
          poolType = tostring(properties.hostPoolType),
          scalingMethod = tostring(properties.scalingMethod),
          refs = properties.hostPoolReferences
"@
$pooledPlans   = @($planRows | Where-Object { $_.poolType -match '^(?i)Pooled$' })
$personalPlans = @($planRows | Where-Object { $_.poolType -notmatch '^(?i)Pooled$' })
Write-Ok "Found $($planRows.Count) scaling plan(s): $($pooledPlans.Count) pooled, $($personalPlans.Count) personal/other."
if ($planRows.Count -eq 0) {
    Write-Warn2 "No scaling plans found. Nothing to translate - if plans exist, check -SubscriptionId scope and Reader access."
}

# ------------------------------------------------------------------- 2. schedules
Write-Info "[2/5] Reading pooled schedules..."
$schedRows = Invoke-ArgQuery -Query @"
desktopvirtualizationresources
| where type =~ 'microsoft.desktopvirtualization/scalingplans/pooledschedules'
| project id, name, props = properties
"@
# planId = schedule id up to /pooledschedules
$schedByPlan = @{}
foreach ($s in $schedRows) {
    $idL = "$($s.id)".ToLowerInvariant()
    $cut = $idL.IndexOf('/pooledschedules')
    if ($cut -lt 0) { continue }
    $planIdL = $idL.Substring(0, $cut)
    if (-not $schedByPlan.ContainsKey($planIdL)) { $schedByPlan[$planIdL] = New-Object System.Collections.Generic.List[object] }
    $p = $s.props
    $days = @($p.daysOfWeek)
    $schedByPlan[$planIdL].Add([pscustomobject]@{
        Name        = $s.name
        Days        = $days
        DayCount    = $days.Count
        RuH = [int]$p.rampUpStartTime.hour;   RuM = [int]$p.rampUpStartTime.minute
        RdH = [int]$p.rampDownStartTime.hour; RdM = [int]$p.rampDownStartTime.minute
        RuLB = "$($p.rampUpLoadBalancingAlgorithm)"
        PkLB = "$($p.peakLoadBalancingAlgorithm)"
        RdLB = "$($p.rampDownLoadBalancingAlgorithm)"
        OpLB = "$($p.offPeakLoadBalancingAlgorithm)"
        RuMinPct = [int]$p.rampUpMinimumHostsPct
        RdMinPct = [int]$p.rampDownMinimumHostsPct
        RuT      = [int]$p.rampUpCapacityThresholdPct
        RdT      = [int]$p.rampDownCapacityThresholdPct
        ForceLogoff = [bool]$p.rampDownForceLogoffUsers
        StopWhen    = "$($p.rampDownStopHostsWhen)"
        WaitMins    = [int]$p.rampDownWaitTimeMinutes
        Notify      = "$($p.rampDownNotificationMessage)"
    })
}
Write-Ok "Found $($schedRows.Count) pooled schedule(s) across $($schedByPlan.Keys.Count) plan(s)."

# ------------------------------------------------------------------- 3. pools + hosts
Write-Info "[3/5] Reading host pools and counting registered session hosts..."
$poolRows = Invoke-ArgQuery -Query @"
resources
| where type =~ 'microsoft.desktopvirtualization/hostpools'
| project id, name, resourceGroup, subscriptionId,
          maxSessionLimit = toint(properties.maxSessionLimit),
          loadBalancerType = tostring(properties.loadBalancerType),
          startVMOnConnect = tobool(properties.startVMOnConnect),
          hostPoolType = tostring(properties.hostPoolType)
"@
$poolById = @{}
foreach ($hp in $poolRows) { $poolById["$($hp.id)".ToLowerInvariant()] = $hp }

$shRows = Invoke-ArgQuery -Query @"
desktopvirtualizationresources
| where type =~ 'microsoft.desktopvirtualization/hostpools/sessionhosts'
| project id, vmId = tolower(tostring(properties.resourceId))
"@
$hostsByPool = @{}   # poolIdL -> @{ Count = n; VmIds = [list] }
foreach ($sh in $shRows) {
    $idL = "$($sh.id)".ToLowerInvariant()
    $cut = $idL.IndexOf('/sessionhosts')
    if ($cut -lt 0) { continue }
    $poolIdL = $idL.Substring(0, $cut)
    if (-not $hostsByPool.ContainsKey($poolIdL)) { $hostsByPool[$poolIdL] = @{ Count = 0; VmIds = New-Object System.Collections.Generic.List[string] } }
    $hostsByPool[$poolIdL].Count++
    if (-not [string]::IsNullOrEmpty($sh.vmId)) { $hostsByPool[$poolIdL].VmIds.Add($sh.vmId) }
}
Write-Ok "Found $($poolRows.Count) host pool(s); session hosts registered in $($hostsByPool.Keys.Count) of them."

# --- 3b. VM tags, only when an enabled pooled plan carries an exclusionTag --------
$tagLookupVmIds = New-Object System.Collections.Generic.List[string]
foreach ($plan in $pooledPlans) {
    if ([string]::IsNullOrEmpty($plan.exclusionTag)) { continue }
    foreach ($ref in @($plan.refs)) {
        if (-not [bool]$ref.scalingPlanEnabled) { continue }
        $poolIdL = "$($ref.hostPoolArmPath)".ToLowerInvariant()
        if ($hostsByPool.ContainsKey($poolIdL)) { $tagLookupVmIds.AddRange($hostsByPool[$poolIdL].VmIds) }
    }
}
$vmTagKeys = @{}   # vmIdL -> @{ Name = vmName; TagKeys = [string[]] }
if ($tagLookupVmIds.Count -gt 0) {
    Write-Info "      Exclusion tag in use - resolving tags on $($tagLookupVmIds.Count) session-host VM(s)..."
    $unique = @($tagLookupVmIds | Sort-Object -Unique)
    for ($i = 0; $i -lt $unique.Count; $i += 100) {
        $chunk = $unique[$i..([Math]::Min($i + 99, $unique.Count - 1))]
        $inList = ($chunk | ForEach-Object { "'$_'" }) -join ','
        $vmRows = Invoke-ArgQuery -Query @"
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where tolower(id) in~ ($inList)
| project id, name, tags
"@
        foreach ($vm in $vmRows) {
            $keys = @()
            if ($null -ne $vm.tags) { $keys = @($vm.tags.PSObject.Properties.Name) }
            $vmTagKeys["$($vm.id)".ToLowerInvariant()] = @{ Name = $vm.name; TagKeys = $keys }
        }
    }
}

# ------------------------------------------------------------------- 4. translate
Write-Info "[4/5] Translating plans into NME auto-scale sheets..."

function Field { param([string]$label, [string]$value) ("$label ").PadRight(30, '.') + ' ' + $value }

$sheets = New-Object System.Collections.Generic.List[string]
$review = New-Object System.Collections.Generic.List[object]
$referencedPoolIds = @{}
$sheetCount = 0
$skipCount  = 0

foreach ($plan in ($pooledPlans | Sort-Object name)) {
    $planIdL = "$($plan.id)".ToLowerInvariant()
    $scheds = if ($schedByPlan.ContainsKey($planIdL)) {
        @($schedByPlan[$planIdL] | Sort-Object -Property @{Expression='DayCount';Descending=$true}, @{Expression='Name';Descending=$false})
    } else { @() }
    $dynamicFlag = (-not [string]::IsNullOrEmpty($plan.scalingMethod)) -and ($plan.scalingMethod -notmatch '^(?i)Powers?Manage$')

    foreach ($ref in (@($plan.refs) | Sort-Object { "$($_.hostPoolArmPath)" })) {
        $poolIdL = "$($ref.hostPoolArmPath)".ToLowerInvariant()
        $referencedPoolIds[$poolIdL] = $true
        $enabled = [bool]$ref.scalingPlanEnabled
        $pool = $poolById[$poolIdL]

        if ($null -eq $pool) {
            $poolName = ($poolIdL -split '/')[-1]
            $sheets.Add(("=" * 64))
            $sheets.Add("HOST POOL: $poolName")
            $sheets.Add("Scaling plan: $($plan.name) - POOL NOT VISIBLE to this account/scope.")
            $sheets.Add("The plan references it, but it isn't in the subscriptions read here.")
            $sheets.Add("Re-run with -SubscriptionId covering that pool's subscription.")
            $sheets.Add(("=" * 64)); $sheets.Add("")
            $review.Add([pscustomobject]@{ Plan=$plan.name; Schedule=''; Days=''; Pool=$poolName; RG=''; EnabledOnPool=$enabled
                SessionHosts=''; SessionLimit=''; MinActive=''; PreStageHosts=''; ScaleOutBelow=''; ScaleInAbove=''
                Aggressiveness=''; ScaleInDelay=''; ProfileLB=''; StartVMOnConnect=''; TimeZone=$plan.timeZone
                Flags='pool not visible in current scope' })
            continue
        }

        if (-not $enabled) {
            $skipCount++
            $sheets.Add(("=" * 64))
            $sheets.Add("HOST POOL: $($pool.name)   ($($pool.resourceGroup))")
            $sheets.Add("Scaling plan: $($plan.name) - ASSIGNED BUT NOT ENABLED on this pool.")
            $sheets.Add("Azure is not scaling this pool today, so day-one mimicry needs no")
            $sheets.Add("NME profile here. If it should have been enabled, use another sheet")
            $sheets.Add("from this plan as the template - the numbers scale with host count.")
            $sheets.Add(("=" * 64)); $sheets.Add("")
            $review.Add([pscustomobject]@{ Plan=$plan.name; Schedule='(all)'; Days=''; Pool=$pool.name; RG=$pool.resourceGroup; EnabledOnPool=$false
                SessionHosts=''; SessionLimit=''; MinActive=''; PreStageHosts=''; ScaleOutBelow=''; ScaleInAbove=''
                Aggressiveness=''; ScaleInDelay=''; ProfileLB=''; StartVMOnConnect=''; TimeZone=$plan.timeZone
                Flags='SKIP - assigned but not enabled' })
            continue
        }

        $B = 0; $vmIds = @()
        if ($hostsByPool.ContainsKey($poolIdL)) { $B = $hostsByPool[$poolIdL].Count; $vmIds = @($hostsByPool[$poolIdL].VmIds) }
        $L = 0; if ($null -ne $pool.maxSessionLimit) { $L = [int]$pool.maxSessionLimit }
        $svoc = [bool]$pool.startVMOnConnect
        $svocText = if ($svoc) { 'ON' } else { 'OFF' }

        if ($scheds.Count -eq 0) {
            $sheets.Add(("=" * 64))
            $sheets.Add("HOST POOL: $($pool.name)   ($($pool.resourceGroup))")
            $sheets.Add("Scaling plan: $($plan.name) - NO POOLED SCHEDULES FOUND on the plan.")
            $sheets.Add("Nothing to translate. Add schedules in Azure or configure NME fresh.")
            $sheets.Add(("=" * 64)); $sheets.Add("")
            $review.Add([pscustomobject]@{ Plan=$plan.name; Schedule='(none)'; Days=''; Pool=$pool.name; RG=$pool.resourceGroup; EnabledOnPool=$true
                SessionHosts=$B; SessionLimit=$L; MinActive=''; PreStageHosts=''; ScaleOutBelow=''; ScaleInAbove=''
                Aggressiveness=''; ScaleInDelay=''; ProfileLB=''; StartVMOnConnect=$svocText; TimeZone=$plan.timeZone
                Flags='plan has no pooled schedules' })
            continue
        }

        # --- per-schedule math -----------------------------------------------------
        $calc = @(foreach ($s in $scheds) {
            $minActive = Get-Ceil ($B * $s.RdMinPct / 100.0)
            $preStage  = Get-Ceil ($B * $s.RuMinPct / 100.0)
            $x         = Get-Ceil ($B * $L * (100.0 - $s.RuT) / 100.0)
            $spanMins  = ($s.RdH * 60 + $s.RdM) - ($s.RuH * 60 + $s.RuM)
            if ($spanMins -le 0) { $spanMins += 1440 }
            [pscustomobject]@{
                S = $s; MinActive = $minActive; PreStage = $preStage
                ScaleOutBelow = $x; ScaleInAbove = $x + $L
                DelayH = [int][Math]::Floor($spanMins / 60); DelayM = $spanMins % 60
                Aggr = if ($s.ForceLogoff) { 'High' } elseif ($s.StopWhen -match '^(?i)ZeroActiveSessions$') { 'Medium' } else { 'Low' }
                AggrWhy = if ($s.ForceLogoff) { 'plan forces logoff in ramp-down' }
                          elseif ($s.StopWhen -match '^(?i)ZeroActiveSessions$') { 'plan stops hosts at zero ACTIVE sessions' }
                          else { 'plan stops hosts only when completely empty' }
            }
        })
        $prim = $calc[0]
        $p = $prim.S
        $profMinActive = ($calc | Measure-Object -Property MinActive -Maximum).Maximum
        $raisedBy = $null
        if ($profMinActive -gt $prim.MinActive) { $raisedBy = ($calc | Where-Object { $_.MinActive -eq $profMinActive } | Select-Object -First 1).S.Name }
        $profLB = Format-LB $p.RuLB

        # --- notes -----------------------------------------------------------------
        $notes = New-Object System.Collections.Generic.List[string]
        $flags = New-Object System.Collections.Generic.List[string]
        if ($dynamicFlag) {
            $notes.Add("DYNAMIC plan (scalingMethod '$($plan.scalingMethod)') - it creates/deletes hosts. Base/Burst math on this sheet assumes power management only. Review manually before trusting it.")
            $flags.Add('dynamic plan - manual review')
        }
        if ($B -eq 0) {
            $notes.Add("NO REGISTERED SESSION HOSTS found for this pool - every host-count number on this sheet is 0. Register hosts (or fix scope) and re-run.")
            $flags.Add('0 session hosts')
        }
        if ($L -le 0) {
            $notes.Add("Pool has no max session limit set - the Available-sessions math needs one. Set 'Session limit per host' in NME to your real per-host capacity, then size the trigger: scale out below (base x limit) minus your buffer seats; scale in one host's worth above that.")
            $flags.Add('no session limit')
        }
        if ($raisedBy) {
            $notes.Add("Min active host capacity uses $profMinActive from schedule '$raisedBy' (higher than the primary schedule's $($prim.MinActive)) - never guarantee less than the plan did.")
            $flags.Add("min active raised by '$raisedBy'")
        }
        $lbSet = @($p.RuLB, $p.PkLB, $p.RdLB, $p.OpLB) | Where-Object { -not [string]::IsNullOrEmpty($_) } | Sort-Object -Unique
        if ($lbSet.Count -gt 1) {
            $notes.Add("Azure switches load balancing per phase (ramp-up $(Format-LB $p.RuLB) / peak $(Format-LB $p.PkLB) / ramp-down $(Format-LB $p.RdLB) / off-peak $(Format-LB $p.OpLB)). NME uses one value - this sheet uses the ramp-up/peak algorithm. Rolling Drain Mode is the NME-native lever for phase switches; revisit at optimization.")
            $flags.Add('per-phase LB in plan')
        }
        if ([Math]::Abs($p.RdT - $p.RuT) -gt 10) {
            $notes.Add("Ramp-down capacity threshold ($($p.RdT)%) differs from ramp-up ($($p.RuT)%) by more than 10 points. The trigger uses ramp-up's $($p.RuT)% all day; evening scale-in will run slightly $(if ($p.RdT -gt $p.RuT) { 'later' } else { 'earlier' }) than Azure's.")
            $flags.Add('ramp thresholds differ >10pts')
        }
        foreach ($c in ($calc | Select-Object -Skip 1)) {
            $s2 = $c.S
            if (($s2.ForceLogoff -ne $p.ForceLogoff) -or ($s2.StopWhen -ne $p.StopWhen)) {
                $notes.Add("Schedule '$($s2.Name)' ramps down differently ($(if ($s2.ForceLogoff) { 'forces logoff' } else { "stops at $($s2.StopWhen)" }) vs primary's $(if ($p.ForceLogoff) { 'forced logoff' } else { $p.StopWhen })). NME aggressiveness is one profile-wide value - the primary schedule's wins day one.")
                $flags.Add("schedules disagree on ramp-down")
            }
            if ([Math]::Abs($s2.RuT - $p.RuT) -gt 10) {
                $notes.Add("Schedule '$($s2.Name)' capacity threshold ($($s2.RuT)%) differs from primary ($($p.RuT)%) by more than 10 points. The single trigger uses primary's.")
                $flags.Add("thresholds differ across schedules")
            }
        }
        if (-not [string]::IsNullOrEmpty($plan.exclusionTag)) {
            $tagged = @()
            foreach ($vmIdL in $vmIds) {
                if ($vmTagKeys.ContainsKey($vmIdL)) {
                    $entry = $vmTagKeys[$vmIdL]
                    if (@($entry.TagKeys) | Where-Object { $_ -ieq $plan.exclusionTag }) { $tagged += $entry.Name }
                }
            }
            if ($tagged.Count -gt 0) {
                $notes.Add("Plan exclusion tag '$($plan.exclusionTag)': NME excludes per host, not by tag. Exclude these currently-tagged hosts from auto-scale in NME: $($tagged -join ', ').")
                $flags.Add("exclude $($tagged.Count) tagged host(s)")
            } else {
                $notes.Add("Plan has exclusion tag '$($plan.exclusionTag)' but no currently-registered session host carries it. Nothing to exclude today; remember the tag's intent when adding hosts.")
            }
        }
        if ($profMinActive -eq 0 -and -not $svoc) {
            $notes.Add("Overnight floor is 0 hosts and Start VM on connect is OFF (matching Azure today) - the first off-hours user has nothing to log into until pre-stage. Same behavior as the plan; flagging so it's a choice, not a surprise.")
        }

        # --- the sheet -------------------------------------------------------------
        $sheetLines = New-Object System.Collections.Generic.List[string]
        $sheetLines.Add(("=" * 64))
        $sheetLines.Add("HOST POOL: $($pool.name)   ($($pool.resourceGroup))")
        $sheetLines.Add("Scaling plan: $($plan.name)  |  Time zone: $($plan.timeZone)")
        $sheetLines.Add("   (enter all times below in that time zone - no conversion)")
        $sheetLines.Add("Pool facts: $B session hosts | MaxSessionLimit $L | pool LB $($pool.loadBalancerType) | StartVMOnConnect $svocText")
        $sheetLines.Add(("-" * 64))
        $sheetLines.Add("CREATE AUTO-SCALE PROFILE")
        $sheetLines.Add((Field 'Auto-scale mode' 'Shared'))
        $sheetLines.Add((Field 'Name' "$($plan.name)-mimic   (suggestion)"))
        $sheetLines.Add((Field 'Session limit per host' "$L"))
        $sheetLines.Add((Field 'Load balancing' "$profLB   (plan ramp-up/peak algorithm)"))
        $sheetLines.Add((Field 'Start VM on connect' "$svocText   (pool's current setting)"))
        $sheetLines.Add((Field 'Measure type' 'Count   (default)'))
        $sheetLines.Add((Field 'Active host defined as' 'AVD agent Available   (default)'))
        $sheetLines.Add((Field 'Base host pool capacity' "$B   (all existing hosts)"))
        $minActiveExplain = "(ramp-down min $($p.RdMinPct)% x $B$(if ($raisedBy) { "; raised by schedule '$raisedBy'" }))"
        $sheetLines.Add((Field 'Min active host capacity' "$profMinActive   $minActiveExplain"))
        $sheetLines.Add((Field 'Burst beyond base capacity' '0   (plan never creates hosts)'))
        $sheetLines.Add((Field 'Trigger type' 'Available sessions'))
        $sheetLines.Add("  Scale out: up to 2 hosts if available sessions < $($prim.ScaleOutBelow)  for 5 min")
        $sheetLines.Add("             (keep $(100 - $p.RuT)% of $B x $L = $($prim.ScaleOutBelow) seats free - plan threshold $($p.RuT)%)")
        $sheetLines.Add("  Scale in:  up to 1 host  if available sessions > $($prim.ScaleInAbove)  for 15 min")
        $sheetLines.Add("             (the $($prim.ScaleOutBelow)-seat buffer + one full host of $L)")
        $sheetLines.Add((Field 'Scale in hosts only from' 'Any'))
        $sheetLines.Add((Field 'Scale in aggressiveness' "$($prim.Aggr)   ($($prim.AggrWhy))"))
        if ($p.ForceLogoff) {
            $sheetLines.Add((Field 'Messaging' "warn $($p.WaitMins) min before scale-in (pick nearest dropdown value)"))
            $sheetLines.Add("  Message: $($p.Notify)")
        } else {
            $sheetLines.Add((Field 'Messaging' 'n/a   (plan does not force logoff; never fires at Low/Medium)'))
        }
        $sheetLines.Add((Field 'Rolling drain mode' 'OFF   (day one; the optimization lever later)'))
        $sheetLines.Add((Field 'Auto-heal broken hosts' 'OFF   (day one)'))
        $preStageHead = if ($scheds.Count -gt 1) { "ON - enable 'Use multiple schedules', add each block below" } else { 'ON' }
        $sheetLines.Add((Field 'Pre-stage hosts' $preStageHead))
        $i = 0
        foreach ($c in $calc) {
            $i++
            $s = $c.S
            $tag = if ($i -eq 1) { 'primary' } else { 'additional' }
            $sheetLines.Add("  [Pre-stage schedule $i of $($calc.Count) - '$($s.Name)' ($tag)]")
            $sheetLines.Add("    Work days: $(Format-Days $s.Days)")
            $sheetLines.Add("    Start of work hours: $(Format-Time $s.RuH $s.RuM)   (ramp-up start)")
            $sheetLines.Add("    Hosts to be active by start: $($c.PreStage)   (ramp-up min $($s.RuMinPct)% x $B)")
            $sheetLines.Add("    Scale-in delay: $($c.DelayH) h $($c.DelayM) min   (holds floor $(Format-Time $s.RuH $s.RuM) -> $(Format-Time $s.RdH $s.RdM) ramp-down)")
        }
        if ($notes.Count -gt 0) {
            $sheetLines.Add("NOTES")
            foreach ($n in $notes) { $sheetLines.Add("- $n") }
        }
        $sheetLines.Add(("=" * 64))
        $sheetLines.Add("")
        $sheets.AddRange($sheetLines)
        $sheetCount++

        # --- review rows (one per schedule) ---------------------------------------
        foreach ($c in $calc) {
            $s = $c.S
            $review.Add([pscustomobject]@{
                Plan = $plan.name; Schedule = $s.Name; Days = (Format-Days $s.Days)
                Pool = $pool.name; RG = $pool.resourceGroup; EnabledOnPool = $true
                SessionHosts = $B; SessionLimit = $L
                MinActive = $c.MinActive; PreStageHosts = $c.PreStage
                ScaleOutBelow = $c.ScaleOutBelow; ScaleInAbove = $c.ScaleInAbove
                Aggressiveness = "$($c.Aggr)"; ScaleInDelay = "$($c.DelayH)h$($c.DelayM)m"
                ProfileLB = $profLB; StartVMOnConnect = $svocText; TimeZone = $plan.timeZone
                Flags = ($flags -join '; ')
            })
        }
    }
}

# --- personal plans + pools with no plan ------------------------------------------
foreach ($pp in $personalPlans) {
    foreach ($ref in @($pp.refs)) { $referencedPoolIds["$($ref.hostPoolArmPath)".ToLowerInvariant()] = $true }
    $review.Add([pscustomobject]@{ Plan=$pp.name; Schedule='(personal)'; Days=''; Pool="($(@($pp.refs).Count) pool(s))"; RG=$pp.resourceGroup; EnabledOnPool=''
        SessionHosts=''; SessionLimit=''; MinActive=''; PreStageHosts=''; ScaleOutBelow=''; ScaleInAbove=''
        Aggressiveness=''; ScaleInDelay=''; ProfileLB=''; StartVMOnConnect=''; TimeZone=$pp.timeZone
        Flags='personal plan - not translated (pooled first)' })
}
$noPlanPools = @($poolRows | Where-Object { -not $referencedPoolIds.ContainsKey("$($_.id)".ToLowerInvariant()) } | Sort-Object name)

if ($personalPlans.Count -gt 0) {
    $sheets.Add("PERSONAL SCALING PLANS (not translated - this tool does pooled plans first)")
    foreach ($pp in $personalPlans) { $sheets.Add("- $($pp.name)  ($(@($pp.refs).Count) pool reference(s), time zone $($pp.timeZone))") }
    $sheets.Add("")
}
if ($noPlanPools.Count -gt 0) {
    $sheets.Add("HOST POOLS WITH NO SCALING PLAN ($($noPlanPools.Count)) - nothing to mimic; configure NME auto-scale fresh on these:")
    foreach ($np in $noPlanPools) { $sheets.Add("- $($np.name)  ($($np.resourceGroup), $($np.hostPoolType))") }
    $sheets.Add("")
}

# ------------------------------------------------------------------- 5. output
Write-Info "[5/5] Writing files..."
$header = @(
    "NME AUTO-SCALE SHEETS  -  generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') by Get-NerdioAutoscaleSheet.ps1 $script:Version",
    "Day-one mimicry of Azure scaling plans. One sheet per host pool.",
    "",
    "HOW TO USE",
    " 1. In NME, open the host pool's Auto-scale settings.",
    " 2. Enter each sheet line top to bottom. Text in (parentheses) explains",
    "    where a number came from - don't type it into NME.",
    " 3. If a sheet shows more than one pre-stage schedule, turn ON",
    "    'Use multiple schedules' and add every block.",
    " 4. Read each sheet's NOTES - anything Azure did that NME expresses",
    "    differently is called out there. Nothing is translated silently.",
    " 5. The Alternative Schedule tab in NME is for holidays/exceptions -",
    "    weekends are handled by the pre-stage schedules above, not there.",
    "",
    ""
)
($header + $sheets) -join "`n" | Out-File -FilePath $OutFile -Encoding utf8NoBOM
Write-Ok "Sheets written: $OutFile ($sheetCount profile sheet(s))"
if ($review.Count -gt 0) {
    $review | Export-Csv -Path $csvFile -NoTypeInformation -Encoding utf8NoBOM
    Write-Ok "Review table written: $csvFile ($($review.Count) row(s))"
} else {
    Write-Warn2 "No plan/pool rows to review - CSV not written."
}

if ($review.Count -gt 0) {
    $review |
        Select-Object @{n='Plan';e={$_.Plan}}, @{n='Schedule';e={$_.Schedule}}, @{n='Pool';e={$_.Pool}},
                      @{n='Hosts';e={$_.SessionHosts}}, @{n='Limit';e={$_.SessionLimit}},
                      @{n='MinAct';e={$_.MinActive}}, @{n='PreStage';e={$_.PreStageHosts}},
                      @{n='OutLt';e={$_.ScaleOutBelow}}, @{n='InGt';e={$_.ScaleInAbove}},
                      @{n='Aggr';e={$_.Aggressiveness}}, @{n='Delay';e={$_.ScaleInDelay}}, @{n='Flags';e={$_.Flags}} |
        Format-Table -AutoSize | Out-String -Width 300 | Write-Host
}

Write-Host ""
Write-Ok "Pooled plans translated: $($pooledPlans.Count) | profile sheets: $sheetCount | assigned-but-not-enabled: $skipCount | personal plans listed: $($personalPlans.Count)"
if ($noPlanPools.Count -gt 0) {
    $preview = ($noPlanPools | Select-Object -First 10 | ForEach-Object { $_.name }) -join ', '
    $more = if ($noPlanPools.Count -gt 10) { " (+$($noPlanPools.Count - 10) more - full list in the .txt)" } else { '' }
    Write-Info "Pools with no scaling plan: $($noPlanPools.Count) - $preview$more"
}
Write-Info "Sheets are day-one mimicry. Once NME runs and gathers telemetry, optimize from there."

if (-not $SkipDownload) {
    Invoke-CloudShellDownload -Path $OutFile
    Invoke-CloudShellDownload -Path $csvFile
} else {
    Write-Info "Downloads skipped (-SkipDownload). Files remain in the session: $OutFile, $csvFile"
}
