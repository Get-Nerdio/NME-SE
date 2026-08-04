<#
.SYNOPSIS
    Creates two TEST Azure scaling plans for exercising the scaling-plan ->
    NME auto-scale translator (Get-NerdioAutoscaleSheet.ps1). Run in Azure
    Cloud Shell (PowerShell). This script CREATES resources (test plans + one
    VM tag) - it is not read-only like the translator itself.

.DESCRIPTION
    RUN IT
     1. Cloud Shell (PowerShell mode) > Manage files > Upload > this file.
     2. ./Create-TestScalingPlans.ps1
     3. When done testing: ./Create-TestScalingPlans.ps1 -Remove

    WHAT IT CREATES (in resource group NME-Resources, southcentralus by default)
     - nme-test-power   : power-management plan, exclusion tag 'noscale'.
         Weekday schedule (Mon-Fri): ramp-up 7:00 / min 20% / threshold 75% /
         Breadth First; ramp-down 18:00 / min 10% / threshold 60% / Depth
         First / FORCE LOGOFF with a 15-min warning message.
         Weekend schedule (Sat-Sun): ramp-up 9:00 / min 40% / threshold 75%;
         ramp-down 17:00 / min 40% / no force logoff / stop at zero ACTIVE.
         Assigned to two eligible pools: first ENABLED, second assigned but
         NOT enabled (exercises the translator's SKIP path).
     - nme-test-dynamic : dynamic-autoscaling plan (scalingMethod
         CreateDeletePowerManage, api 2024-11-01-preview). Dynamic plans can
         only attach to pools with session host configuration (managementType
         'Automated'); if none exists the plan is created UNASSIGNED - the
         translator should still list and flag it.
     - Tags the first session-host VM of the power plan's pool with
       'noscale' so the translator's named-host exclusion list has a hit
       (skip with -SkipVmTag).

    POOL SELECTION - automatic: pooled host pools in the target region, in
    the same subscription as the resource group, NOT already referenced by
    any scaling plan (Azure allows one plan per pool), preferring pools with
    the most registered session hosts. Override with -PowerPool / -SecondPool
    / -DynamicPool (pool names).

    Nothing here touches production behavior by itself: the plans only act on
    pools they are ASSIGNED+ENABLED on, and the enabled assignment goes to a
    pool that had no scaling plan at all. Still - this is for demo/test
    tenants. -Remove deletes both plans (the VM tag stays; it is inert).

.PARAMETER ResourceGroup
    Resource group for the plans. Default NME-Resources.
.PARAMETER Location
    Region for the plans (pools must be in the same region). Default southcentralus.
.PARAMETER TimeZone
    Windows time zone ID for both plans. Default 'Central Standard Time'.
.PARAMETER PowerPool
    Pool NAME for the power plan's enabled reference. Default: auto-pick.
.PARAMETER SecondPool
    Pool NAME for the assigned-but-not-enabled reference. Default: auto-pick.
.PARAMETER DynamicPool
    Pool NAME for the dynamic plan. Default: auto-pick an 'Automated'
    (session host configuration) pool; unassigned if none.
.PARAMETER SkipVmTag
    Don't tag a session-host VM with 'noscale'.
.PARAMETER Remove
    Delete both test plans and exit.

.NOTES
    v1.1 (2026-08-04). scalingMethod + createDelete sizing now set on the
    dynamic plan's SCHEDULE - a live GET showed that's where the service
    stores it; the v1.0 plan-level attempt was silently discarded and the
    plan came out as PowerManage. Plan-level property kept too (harmless).
    If this PUT now fails, that's Azure refusing dynamic on a classic pool -
    the error prints verbatim and that result is informative by itself.
    v1.0 (2026-08-04). Companion test fixture for dclawrence003/NME autoscale.
    api-version 2024-11-01-preview everywhere (scalingMethod requires it; the
    2025-10-10 stable surface does not expose it).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)] [string] $ResourceGroup = 'NME-Resources',
    [Parameter(Mandatory = $false)] [string] $Location      = 'southcentralus',
    [Parameter(Mandatory = $false)] [string] $TimeZone      = 'Central Standard Time',
    [Parameter(Mandatory = $false)] [string] $PowerPool     = '',
    [Parameter(Mandatory = $false)] [string] $SecondPool    = '',
    [Parameter(Mandatory = $false)] [string] $DynamicPool   = '',
    [Parameter(Mandatory = $false)] [switch] $SkipVmTag,
    [Parameter(Mandatory = $false)] [switch] $Remove
)

$ErrorActionPreference = 'Stop'
$Api           = '2024-11-01-preview'
$PowerPlanName = 'nme-test-power'
$DynPlanName   = 'nme-test-dynamic'
$ExclusionTag  = 'noscale'

function Write-Info { param([string]$m) Write-Host "[i] $m" -ForegroundColor Gray }
function Write-Ok   { param([string]$m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2{ param([string]$m) Write-Host "[!] $m" -ForegroundColor Yellow }

function Get-ArmError {
    param($resp)
    try { return (($resp.Content | ConvertFrom-Json).error.message) } catch { return "$($resp.Content)" }
}

function Invoke-ArgQuery {
    param([string]$Query)
    $all = @(); $skip = $null
    do {
        $body = @{ query = $Query; options = @{ resultFormat = 'objectArray' } }
        if ($skip) { $body.options.'$skipToken' = $skip }
        $resp = Invoke-AzRestMethod -Method POST -Path "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01" -Payload ($body | ConvertTo-Json -Depth 6)
        if ($resp.StatusCode -ne 200) { throw "Resource Graph query failed (HTTP $($resp.StatusCode)): $(Get-ArmError $resp)" }
        $parsed = $resp.Content | ConvertFrom-Json
        $all += @($parsed.data)
        $skip = $parsed.'$skipToken'
    } while ($skip)
    return $all
}

if (-not (Get-AzContext)) { throw "No Azure context. In Cloud Shell this is automatic; locally run Connect-AzAccount first." }

# ------------------------------------------------------------------ find the RG
Write-Info "[1/5] Locating resource group '$ResourceGroup'..."
$rgRows = Invoke-ArgQuery -Query @"
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions/resourcegroups'
| where name =~ '$ResourceGroup'
| project id, subscriptionId, location
"@
if ($rgRows.Count -eq 0) { throw "Resource group '$ResourceGroup' not found in any visible subscription. Create it first or pass -ResourceGroup." }

# ------------------------------------------------------------------ removal path
if ($Remove) {
    foreach ($rg in $rgRows) {
        foreach ($planName in @($PowerPlanName, $DynPlanName)) {
            $path = "/subscriptions/$($rg.subscriptionId)/resourceGroups/$ResourceGroup/providers/Microsoft.DesktopVirtualization/scalingPlans/$planName`?api-version=$Api"
            $resp = Invoke-AzRestMethod -Method DELETE -Path $path
            if ($resp.StatusCode -in 200, 202, 204) { Write-Ok "Deleted $planName (sub $($rg.subscriptionId))" }
            elseif ($resp.StatusCode -eq 404) { Write-Info "$planName not present in sub $($rg.subscriptionId) - nothing to delete." }
            else { Write-Warn2 "Delete $planName failed (HTTP $($resp.StatusCode)): $(Get-ArmError $resp)" }
        }
    }
    Write-Info "The 'noscale' VM tag (if applied) was left in place - it is inert without a plan."
    return
}

# ------------------------------------------------------------------ discovery
Write-Info "[2/5] Finding eligible host pools ($Location, pooled, not already on a scaling plan)..."
$pools = Invoke-ArgQuery -Query @"
resources
| where type =~ 'microsoft.desktopvirtualization/hostpools'
| where location =~ '$Location'
| project id, name, resourceGroup, subscriptionId,
          poolType = tostring(properties.hostPoolType),
          mgmt = tostring(properties.managementType),
          maxSessionLimit = toint(properties.maxSessionLimit)
"@
$refRows = Invoke-ArgQuery -Query @"
resources
| where type =~ 'microsoft.desktopvirtualization/scalingplans'
| mv-expand ref = properties.hostPoolReferences
| project refPool = tolower(tostring(ref.hostPoolArmPath))
"@
$referenced = @{}
foreach ($r in $refRows) { if ($r.refPool) { $referenced[$r.refPool] = $true } }
$shRows = Invoke-ArgQuery -Query @"
desktopvirtualizationresources
| where type =~ 'microsoft.desktopvirtualization/hostpools/sessionhosts'
| project id, vmId = tolower(tostring(properties.resourceId))
"@
$hostsByPool = @{}
foreach ($sh in $shRows) {
    $idL = "$($sh.id)".ToLowerInvariant()
    $cut = $idL.IndexOf('/sessionhosts')
    if ($cut -lt 0) { continue }
    $poolIdL = $idL.Substring(0, $cut)
    if (-not $hostsByPool.ContainsKey($poolIdL)) { $hostsByPool[$poolIdL] = @{ Count = 0; VmIds = New-Object System.Collections.Generic.List[string] } }
    $hostsByPool[$poolIdL].Count++
    if ($sh.vmId) { $hostsByPool[$poolIdL].VmIds.Add($sh.vmId) }
}

# same-subscription pairing: prefer the RG instance whose subscription has the most eligible pools
$best = $null
foreach ($rg in $rgRows) {
    $elig = @($pools | Where-Object {
        $_.subscriptionId -eq $rg.subscriptionId -and
        $_.poolType -match '^(?i)Pooled$' -and
        -not $referenced.ContainsKey("$($_.id)".ToLowerInvariant())
    } | Sort-Object -Property @{Expression={ if ($hostsByPool.ContainsKey("$($_.id)".ToLowerInvariant())) { $hostsByPool["$($_.id)".ToLowerInvariant()].Count } else { 0 } };Descending=$true})
    if ($null -eq $best -or $elig.Count -gt $best.Elig.Count) { $best = @{ Rg = $rg; Elig = $elig } }
}
$rgSub  = $best.Rg.subscriptionId
$elig   = $best.Elig
if ($elig.Count -eq 0) {
    throw "No eligible pool found: need a POOLED host pool in $Location, in subscription $rgSub (where '$ResourceGroup' lives), not already assigned to a scaling plan. Free up a pool (Azure allows one plan per pool) or pass -PowerPool."
}

function Resolve-PoolByName {
    param([string]$Name, [string]$Purpose)
    $hit = @($pools | Where-Object { $_.name -ieq $Name -and $_.subscriptionId -eq $rgSub })
    if ($hit.Count -eq 0) { throw "-$Purpose '$Name': no pool with that name in $Location / subscription $rgSub." }
    if ($referenced.ContainsKey("$($hit[0].id)".ToLowerInvariant())) { throw "-$Purpose '$Name': that pool already has a scaling plan (one per pool). Pick another or remove its plan." }
    return $hit[0]
}

$poolMain = if ($PowerPool)  { Resolve-PoolByName $PowerPool  'PowerPool' }  else { $elig[0] }
$poolSkip = if ($SecondPool) { Resolve-PoolByName $SecondPool 'SecondPool' } else { if ($elig.Count -ge 2) { @($elig | Where-Object { $_.id -ne $poolMain.id })[0] } else { $null } }
$autoPools = @($elig | Where-Object { $_.mgmt -match '^(?i)Automated$' -and $_.id -ne $poolMain.id -and ($null -eq $poolSkip -or $_.id -ne $poolSkip.id) })
$poolDyn  = if ($DynamicPool) { Resolve-PoolByName $DynamicPool 'DynamicPool' } else { if ($autoPools.Count -ge 1) { $autoPools[0] } else { $null } }

$mainHosts = if ($hostsByPool.ContainsKey("$($poolMain.id)".ToLowerInvariant())) { $hostsByPool["$($poolMain.id)".ToLowerInvariant()].Count } else { 0 }
Write-Ok "Power plan pool: $($poolMain.name) ($mainHosts session host(s), limit $($poolMain.maxSessionLimit))"
if ($poolSkip) { Write-Ok "Assigned-not-enabled pool: $($poolSkip.name)" } else { Write-Warn2 "Only one eligible pool - the SKIP path (assigned-but-not-enabled) won't be exercised." }
if ($poolDyn)  { Write-Ok "Dynamic plan pool: $($poolDyn.name) (managementType Automated)" }
else { Write-Warn2 "No unreferenced 'Automated' (session host configuration) pool - dynamic plan will be created UNASSIGNED. That's expected on classic-pool tenants; the translator should still list + flag it." }
if ($mainHosts -eq 0) { Write-Warn2 "$($poolMain.name) has no registered session hosts - translator output will flag 0-host math. Fine for structure testing." }
if ($null -eq $poolMain.maxSessionLimit -or $poolMain.maxSessionLimit -le 0) { Write-Warn2 "$($poolMain.name) has no max session limit - set one for meaningful trigger math." }

# ------------------------------------------------------------------ payload builders
function New-Time { param([int]$h, [int]$m) @{ hour = $h; minute = $m } }
$weekdaySched = @{
    daysOfWeek = @('Monday','Tuesday','Wednesday','Thursday','Friday')
    rampUpStartTime = New-Time 7 0;   rampUpLoadBalancingAlgorithm = 'BreadthFirst'
    rampUpMinimumHostsPct = 20;       rampUpCapacityThresholdPct = 75
    peakStartTime = New-Time 9 0;     peakLoadBalancingAlgorithm = 'BreadthFirst'
    rampDownStartTime = New-Time 18 0; rampDownLoadBalancingAlgorithm = 'DepthFirst'
    rampDownMinimumHostsPct = 10;     rampDownCapacityThresholdPct = 60
    rampDownForceLogoffUsers = $true; rampDownWaitTimeMinutes = 15
    rampDownNotificationMessage = 'Test scaling plan: please save your work and log off. Hosts stop in 15 minutes.'
    rampDownStopHostsWhen = 'ZeroSessions'
    offPeakStartTime = New-Time 20 0; offPeakLoadBalancingAlgorithm = 'DepthFirst'
}
$weekendSched = @{
    daysOfWeek = @('Saturday','Sunday')
    rampUpStartTime = New-Time 9 0;   rampUpLoadBalancingAlgorithm = 'BreadthFirst'
    rampUpMinimumHostsPct = 40;       rampUpCapacityThresholdPct = 75
    peakStartTime = New-Time 10 0;    peakLoadBalancingAlgorithm = 'BreadthFirst'
    rampDownStartTime = New-Time 17 0; rampDownLoadBalancingAlgorithm = 'BreadthFirst'
    rampDownMinimumHostsPct = 40;     rampDownCapacityThresholdPct = 75
    rampDownForceLogoffUsers = $false; rampDownWaitTimeMinutes = 0
    rampDownNotificationMessage = ''
    rampDownStopHostsWhen = 'ZeroActiveSessions'
    offPeakStartTime = New-Time 19 0; offPeakLoadBalancingAlgorithm = 'BreadthFirst'
}
$dynSched = @{
    # Live GET (2026-08-04) showed the service stores scalingMethod per SCHEDULE
    # with a createDelete sizing block - plan-level scalingMethod was silently
    # discarded. Set it here, where it actually lives.
    scalingMethod = 'CreateDeletePowerManage'
    createDelete = @{ rampUpMinimumHostPoolSize = 1; rampUpMaximumHostPoolSize = 5
                      rampDownMinimumHostPoolSize = 0; rampDownMaximumHostPoolSize = 5 }
    daysOfWeek = @('Monday','Tuesday','Wednesday','Thursday','Friday')
    rampUpStartTime = New-Time 8 0;   rampUpLoadBalancingAlgorithm = 'BreadthFirst'
    rampUpMinimumHostsPct = 10;       rampUpCapacityThresholdPct = 80
    peakStartTime = New-Time 9 0;     peakLoadBalancingAlgorithm = 'BreadthFirst'
    rampDownStartTime = New-Time 19 0; rampDownLoadBalancingAlgorithm = 'BreadthFirst'
    rampDownMinimumHostsPct = 10;     rampDownCapacityThresholdPct = 80
    rampDownForceLogoffUsers = $false; rampDownWaitTimeMinutes = 0
    rampDownNotificationMessage = ''
    rampDownStopHostsWhen = 'ZeroActiveSessions'
    offPeakStartTime = New-Time 21 0; offPeakLoadBalancingAlgorithm = 'BreadthFirst'
}

function Publish-ScalingPlan {
    param([string]$Name, [hashtable]$Properties, [hashtable[]]$NamedSchedules)
    $planPath = "/subscriptions/$rgSub/resourceGroups/$ResourceGroup/providers/Microsoft.DesktopVirtualization/scalingPlans/$Name`?api-version=$Api"
    $body = @{ location = $Location; tags = @{ purpose = 'nme-translator-test' }; properties = $Properties } | ConvertTo-Json -Depth 12
    $resp = Invoke-AzRestMethod -Method PUT -Path $planPath -Payload $body
    if ($resp.StatusCode -notin 200, 201) {
        Write-Warn2 "Create $Name failed (HTTP $($resp.StatusCode)): $(Get-ArmError $resp)"
        return $false
    }
    Write-Ok "Plan $Name created/updated."
    # Also PUT each schedule as a pooledSchedules child resource - this is the
    # surface the portal writes and the translator reads via Resource Graph.
    foreach ($ns in $NamedSchedules) {
        $schedPath = "/subscriptions/$rgSub/resourceGroups/$ResourceGroup/providers/Microsoft.DesktopVirtualization/scalingPlans/$Name/pooledSchedules/$($ns.name)`?api-version=$Api"
        $schedBody = @{ properties = $ns.sched } | ConvertTo-Json -Depth 12
        $sResp = Invoke-AzRestMethod -Method PUT -Path $schedPath -Payload $schedBody
        if ($sResp.StatusCode -in 200, 201) { Write-Ok "  Schedule '$($ns.name)' written." }
        else { Write-Warn2 "  Schedule '$($ns.name)' failed (HTTP $($sResp.StatusCode)): $(Get-ArmError $sResp)" }
    }
    return $true
}

# ------------------------------------------------------------------ power plan
Write-Info "[3/5] Creating $PowerPlanName (power management)..."
$powerRefs = @(@{ hostPoolArmPath = $poolMain.id; scalingPlanEnabled = $true })
if ($poolSkip) { $powerRefs += @{ hostPoolArmPath = $poolSkip.id; scalingPlanEnabled = $false } }
$powerProps = @{
    timeZone = $TimeZone; hostPoolType = 'Pooled'; exclusionTag = $ExclusionTag
    friendlyName = 'NME translator test - power management'
    description = "Test fixture created $(Get-Date -Format 'yyyy-MM-dd') for Get-NerdioAutoscaleSheet.ps1. Safe to delete (-Remove)."
    hostPoolReferences = $powerRefs
    schedules = @(
        (@{ name = 'Weekdays' } + $weekdaySched),
        (@{ name = 'Weekend' }  + $weekendSched)
    )
}
$powerOk = Publish-ScalingPlan -Name $PowerPlanName -Properties $powerProps -NamedSchedules @(
    @{ name = 'Weekdays'; sched = $weekdaySched },
    @{ name = 'Weekend';  sched = $weekendSched }
)

# ------------------------------------------------------------------ dynamic plan
Write-Info "[4/5] Creating $DynPlanName (dynamic autoscaling)..."
$dynProps = @{
    timeZone = $TimeZone; hostPoolType = 'Pooled'
    scalingMethod = 'CreateDeletePowerManage'
    friendlyName = 'NME translator test - dynamic autoscaling'
    description = "Test fixture created $(Get-Date -Format 'yyyy-MM-dd') for Get-NerdioAutoscaleSheet.ps1. Safe to delete (-Remove)."
    hostPoolReferences = @(if ($poolDyn) { @{ hostPoolArmPath = $poolDyn.id; scalingPlanEnabled = $true } })
    schedules = @((@{ name = 'Weekdays' } + $dynSched))
}
$dynOk = Publish-ScalingPlan -Name $DynPlanName -Properties $dynProps -NamedSchedules @(
    @{ name = 'Weekdays'; sched = $dynSched }
)
if (-not $dynOk) {
    Write-Warn2 "If the error above mentions scalingMethod or api-version, the preview surface may have moved - tell Claude and we'll re-pin it."
}

# ------------------------------------------------------------------ VM tag
Write-Info "[5/5] Exclusion-tag test hit..."
if ($SkipVmTag) {
    Write-Info "Skipped (-SkipVmTag)."
} else {
    $mainKey = "$($poolMain.id)".ToLowerInvariant()
    $vmId = $null
    if ($hostsByPool.ContainsKey($mainKey) -and $hostsByPool[$mainKey].VmIds.Count -gt 0) { $vmId = $hostsByPool[$mainKey].VmIds[0] }
    if ($vmId) {
        $tagPath = "$vmId/providers/Microsoft.Resources/tags/default?api-version=2021-04-01"
        $tagBody = @{ operation = 'Merge'; properties = @{ tags = @{ $ExclusionTag = 'true' } } } | ConvertTo-Json -Depth 5
        $tResp = Invoke-AzRestMethod -Method PATCH -Path $tagPath -Payload $tagBody
        if ($tResp.StatusCode -eq 200) { Write-Ok "Tagged $((($vmId -split '/')[-1])) with '$ExclusionTag' - the translator should name it for manual exclusion." }
        else { Write-Warn2 "VM tag failed (HTTP $($tResp.StatusCode)): $(Get-ArmError $tResp). Not fatal - the exclusion note just won't name a host." }
    } else {
        Write-Warn2 "No session-host VM found in $($poolMain.name) to tag - the exclusion note won't name a host."
    }
}

# ------------------------------------------------------------------ summary
Write-Host ""
Write-Ok "Done. What the translator run should now show:"
Write-Info "  - $($poolMain.name): full sheet - High aggressiveness + 15-min message, weekend pre-stage block,"
Write-Info "    min-active raised by 'Weekend' (pools with 3+ hosts), per-phase LB note, 75-vs-60 threshold note,"
Write-Info "    schedules-disagree note$(if (-not $SkipVmTag) { ", and the tagged host named for exclusion" })."
if ($poolSkip) { Write-Info "  - $($poolSkip.name): SKIP block (assigned but not enabled)." }
if ($poolDyn)  { Write-Info "  - $($poolDyn.name): sheet flagged 'dynamic plan - manual review'." }
else { Write-Info "  - $DynPlanName : listed as unassigned + flagged dynamic (needs translator v0.1.1+)." }
Write-Info "Run it:  iex (irm 'https://raw.githubusercontent.com/dclawrence003/NME/main/autoscale/Get-NerdioAutoscaleSheet.ps1')"
Write-Info "Clean up when finished:  ./Create-TestScalingPlans.ps1 -Remove"
