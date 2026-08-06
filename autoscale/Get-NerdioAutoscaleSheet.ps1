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
      4. Produces ONE profile card per host pool, laid out like NME's
         Create Auto-Scale Profile screen, in a single self-contained HTML
         page - just the values to enter, in screen order. Weekend/secondary
         schedules become additional pre-stage schedules on the same card
         ("Use multiple schedules"). Anything Azure did that NME expresses
         differently is called out in a compact Notes list on the card -
         nothing is translated silently.
      5. Writes the HTML page plus a per-schedule review .csv, and triggers
         Cloud Shell browser downloads of both.

    The philosophy is day-one mimicry: transfer the scaling behavior as-is,
    then optimize with Nerdio's telemetry once it has data. The sheet never
    invents settings a plan didn't have - NME capabilities with no scaling-plan
    equivalent stay at their defaults.

    Nothing is modified anywhere - every call is a read.

.PARAMETER SubscriptionId
    Optional subscription ID(s) to scope to. Default: every subscription you can see.
.PARAMETER OutFile
    Output HTML file name. Default nme-autoscale-profiles-<timestamp>.html.
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
    v0.4 (2026-08-06). Raw decision data (plans, schedules, pools, host counts,
    tagged VMs) exported as <name>-rawdata.json inside the zip, so adjustments
    can be re-derived offline without asking for another run.
    v0.3 (2026-08-05). One-file handoff: console output captured (transcript,
    ANSI-stripped) and packaged with the HTML + review CSV into a single zip -
    one download, one file to send back. Degrades to individual downloads if
    transcription or zipping is unavailable.
    v0.2.2 (2026-08-04). Dynamic detection moved to where the service actually
    stores scalingMethod: per SCHEDULE (with a createDelete sizing block, now
    printed in the note when populated). Plan-level check kept as well.
    v0.2.1 (2026-08-04). Schedule names from the ARM list come back as
    "plan/schedule" - now displayed as just the schedule name.
    v0.2 (2026-08-04). Output is now a self-contained HTML page styled like
    NME's Create Auto-Scale Profile screen (plus the review CSV). Schedules
    and plan properties are read DIRECTLY from each plan over ARM
    (api 2024-11-01-preview): Azure Resource Graph's child-resource table
    does not carry pooled schedules, which left v0.1 output empty on live
    tenants; direct reads also surface scalingMethod, so dynamic-autoscaling
    plans are detected reliably.
    v0.1.1 (2026-08-04). Pooled plans with no host pool references are now
    listed and flagged (previously they were invisible in the output).
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
$script:Version = 'v0.4'
if ([string]::IsNullOrEmpty($OutFile)) { $OutFile = "nme-autoscale-profiles-$(Get-Date -Format 'yyyyMMdd-HHmm').html" }
$csvDir  = [IO.Path]::GetDirectoryName($OutFile)
$csvBase = [IO.Path]::GetFileNameWithoutExtension($OutFile) + '-review.csv'
$csvFile = if ([string]::IsNullOrEmpty($csvDir)) { $csvBase } else { [IO.Path]::Combine($csvDir, $csvBase) }

function Write-Info { param([string]$m) Write-Host "[i] $m" -ForegroundColor Gray }
function Write-Ok   { param([string]$m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2{ param([string]$m) Write-Host "[!] $m" -ForegroundColor Yellow }

# --- console transcript: captured into the output zip so one run = one file back ---
$script:TranscriptFile = ($OutFile -replace '\.html$', '') + '-console.log'
$script:TranscriptOn = $false
try { Start-Transcript -Path $script:TranscriptFile -Force | Out-Null; $script:TranscriptOn = $true }
catch { Write-Warn2 "Console transcript unavailable ($($_.Exception.Message)) - the zip will omit the run log." }

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

# ------------------------------------------------------------------- 2. schedules (direct ARM reads)
# Resource Graph's child-resource table does NOT carry pooled schedules, and its
# plan projection can miss preview-only properties (scalingMethod). So each plan
# is read directly - plans are few, so this stays fast at any tenant size.
Write-Info "[2/5] Reading each plan's schedules and full properties (direct ARM)..."
$SpApi = '2024-11-01-preview'
$schedByPlan = @{}
$schedTotal = 0
function Add-ScheduleRow {
    param([string]$PlanIdL, [string]$Name, $p)
    $Name = ($Name -split '/')[-1]   # ARM list returns child names as "plan/schedule"
    if (-not $schedByPlan.ContainsKey($PlanIdL)) { $schedByPlan[$PlanIdL] = New-Object System.Collections.Generic.List[object] }
    $days = @($p.daysOfWeek)
    $schedByPlan[$PlanIdL].Add([pscustomobject]@{
        Name        = $Name
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
        Method      = "$($p.scalingMethod)"                       # live schema: per SCHEDULE, not per plan
        CDRuMin = $p.createDelete.rampUpMinimumHostPoolSize;  CDRuMax = $p.createDelete.rampUpMaximumHostPoolSize
        CDRdMin = $p.createDelete.rampDownMinimumHostPoolSize; CDRdMax = $p.createDelete.rampDownMaximumHostPoolSize
    })
    $script:schedTotal++
}
foreach ($p in $planRows) {
    $idL = "$($p.id)".ToLowerInvariant()
    # refresh plan-level properties from the authoritative (preview) surface
    $resp = Invoke-AzRestMethod -Method GET -Path "$($p.id)?api-version=$SpApi"
    $det = $null
    if ($resp.StatusCode -eq 200) {
        $det = ($resp.Content | ConvertFrom-Json).properties
        if ($det.timeZone) { $p.timeZone = "$($det.timeZone)" }
        $p.exclusionTag = "$($det.exclusionTag)"
        if ($det.PSObject.Properties['scalingMethod']) { $p.scalingMethod = "$($det.scalingMethod)" }
        if ($null -ne $det.hostPoolReferences) { $p.refs = @($det.hostPoolReferences) }
    } else {
        Write-Warn2 "Could not read plan '$($p.name)' directly (HTTP $($resp.StatusCode)) - using Resource Graph values."
    }
    if ($p.poolType -notmatch '^(?i)Pooled$') { continue }
    $sResp = Invoke-AzRestMethod -Method GET -Path "$($p.id)/pooledSchedules?api-version=$SpApi"
    if ($sResp.StatusCode -eq 200) {
        foreach ($s in @((($sResp.Content | ConvertFrom-Json).value))) {
            if ($null -ne $s.properties) { Add-ScheduleRow -PlanIdL $idL -Name "$($s.name)" -p $s.properties }
        }
    } elseif ($null -ne $det -and $null -ne $det.schedules -and @($det.schedules).Count -gt 0) {
        # fallback: embedded schedules array on the plan resource
        foreach ($s in @($det.schedules)) { Add-ScheduleRow -PlanIdL $idL -Name "$($s.name)" -p $s }
    } else {
        Write-Warn2 "Could not list schedules for plan '$($p.name)' (HTTP $($sResp.StatusCode))."
    }
}
Write-Ok "Read $schedTotal pooled schedule(s) across $($schedByPlan.Keys.Count) plan(s)."

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
Write-Info "[4/5] Translating plans into NME auto-scale profile cards..."

function HtmlEnc { param($s) [System.Net.WebUtility]::HtmlEncode("$s") }
function Row { param([string]$label, [string]$valueHtml) "<div class='row'><div class='lbl'>$(HtmlEnc $label)</div><div class='val'>$valueHtml</div></div>" }
function TextRow { param([string]$label, [string]$value) Row $label (HtmlEnc $value) }
function Toggle { param([bool]$on) if ($on) { "<span class='tg on'>ON</span>" } else { "<span class='tg off'>OFF</span>" } }
function AggrPill { param([string]$a) "<span class='pill $($a.ToLowerInvariant())'>$(HtmlEnc $a)</span>" }
function DayChips {
    param($days)
    (@($days) | ForEach-Object { $d = "$_"; "<span class='chip'>$(HtmlEnc $(if ($d.Length -ge 3) { $d.Substring(0,3) } else { $d }))</span>" }) -join ''
}

$cards  = New-Object System.Collections.Generic.List[string]   # full profile cards
$stubs  = New-Object System.Collections.Generic.List[string]   # skips / not-visible / no-schedules / unassigned
$review = New-Object System.Collections.Generic.List[object]
$referencedPoolIds = @{}
$sheetCount = 0
$skipCount  = 0

foreach ($plan in ($pooledPlans | Sort-Object name)) {
    $planIdL = "$($plan.id)".ToLowerInvariant()
    $scheds = if ($schedByPlan.ContainsKey($planIdL)) {
        @($schedByPlan[$planIdL] | Sort-Object -Property @{Expression='DayCount';Descending=$true}, @{Expression='Name';Descending=$false})
    } else { @() }
    # dynamic detection: the live service stores scalingMethod per SCHEDULE (with a
    # createDelete sizing block); some surfaces also expose it per plan - check both.
    $planLevelDynamic  = (-not [string]::IsNullOrEmpty($plan.scalingMethod)) -and ($plan.scalingMethod -notmatch '^(?i)Powers?Manage$')
    $schedLevelDynamic = @($scheds | Where-Object { $_.Method -match '(?i)CreateDelete' })
    $dynamicFlag = $planLevelDynamic -or ($schedLevelDynamic.Count -gt 0)

    if (@($plan.refs).Count -eq 0) {
        $stubs.Add("<!--stub-unassigned:$($plan.name)--><div class='stub'><b>Scaling plan $(HtmlEnc $plan.name)</b> ($(HtmlEnc $plan.resourceGroup)) &mdash; no host pools assigned. Azure is not scaling anything with it; nothing to enter in NME.$(if ($dynamicFlag) { " <span class='pill high'>DYNAMIC plan</span> If you assign it later, review its card manually." })</div>")
        $unassignedFlags = @('no host pools assigned')
        if ($dynamicFlag) { $unassignedFlags += 'dynamic plan - manual review' }
        $review.Add([pscustomobject]@{ Plan=$plan.name; Schedule='(none assigned)'; Days=''; Pool=''; RG=$plan.resourceGroup; EnabledOnPool=''
            SessionHosts=''; SessionLimit=''; MinActive=''; PreStageHosts=''; ScaleOutBelow=''; ScaleInAbove=''
            Aggressiveness=''; ScaleInDelay=''; ProfileLB=''; StartVMOnConnect=''; TimeZone=$plan.timeZone
            Flags=($unassignedFlags -join '; ') })
        continue
    }

    foreach ($ref in (@($plan.refs) | Sort-Object { "$($_.hostPoolArmPath)" })) {
        $poolIdL = "$($ref.hostPoolArmPath)".ToLowerInvariant()
        $referencedPoolIds[$poolIdL] = $true
        $enabled = [bool]$ref.scalingPlanEnabled
        $pool = $poolById[$poolIdL]

        if ($null -eq $pool) {
            $poolName = ($poolIdL -split '/')[-1]
            $stubs.Add("<!--stub-ghost:$poolName--><div class='stub'><b>$(HtmlEnc $poolName)</b> &mdash; referenced by plan $(HtmlEnc $plan.name) but not visible in the current scope. Re-run with -SubscriptionId covering that pool's subscription.</div>")
            $review.Add([pscustomobject]@{ Plan=$plan.name; Schedule=''; Days=''; Pool=$poolName; RG=''; EnabledOnPool=$enabled
                SessionHosts=''; SessionLimit=''; MinActive=''; PreStageHosts=''; ScaleOutBelow=''; ScaleInAbove=''
                Aggressiveness=''; ScaleInDelay=''; ProfileLB=''; StartVMOnConnect=''; TimeZone=$plan.timeZone
                Flags='pool not visible in current scope' })
            continue
        }

        if (-not $enabled) {
            $skipCount++
            $stubs.Add("<!--stub-skip:$($pool.name)--><div class='stub'><b>$(HtmlEnc $pool.name)</b> ($(HtmlEnc $pool.resourceGroup)) &mdash; plan $(HtmlEnc $plan.name) is assigned but NOT enabled. Azure is not scaling this pool today; day-one mimicry needs no NME profile here.</div>")
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
            $noSchedFlags = @('plan has no pooled schedules')
            if ($dynamicFlag) { $noSchedFlags += 'dynamic plan - manual review' }
            $stubs.Add("<!--stub-nosched:$($pool.name)--><div class='stub'><b>$(HtmlEnc $pool.name)</b> ($(HtmlEnc $pool.resourceGroup)) &mdash; plan $(HtmlEnc $plan.name) has no pooled schedules. Nothing to translate; add schedules in Azure or configure NME fresh.$(if ($dynamicFlag) { " <span class='pill high'>DYNAMIC plan</span>" })</div>")
            $review.Add([pscustomobject]@{ Plan=$plan.name; Schedule='(none)'; Days=''; Pool=$pool.name; RG=$pool.resourceGroup; EnabledOnPool=$true
                SessionHosts=$B; SessionLimit=$L; MinActive=''; PreStageHosts=''; ScaleOutBelow=''; ScaleInAbove=''
                Aggressiveness=''; ScaleInDelay=''; ProfileLB=''; StartVMOnConnect=$svocText; TimeZone=$plan.timeZone
                Flags=($noSchedFlags -join '; ') })
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
            $dynMethod = if ($planLevelDynamic) { $plan.scalingMethod } else { $schedLevelDynamic[0].Method }
            $cdBits = @()
            foreach ($ds in $schedLevelDynamic) {
                $sizes = @()
                if ($null -ne $ds.CDRuMin -or $null -ne $ds.CDRuMax) { $sizes += "ramp-up pool size $($ds.CDRuMin)-$($ds.CDRuMax)" }
                if ($null -ne $ds.CDRdMin -or $null -ne $ds.CDRdMax) { $sizes += "ramp-down $($ds.CDRdMin)-$($ds.CDRdMax)" }
                if ($sizes.Count -gt 0) { $cdBits += "'$($ds.Name)': $($sizes -join ', ')" }
            }
            $cdText = if ($cdBits.Count -gt 0) { " Plan create/delete sizing - $($cdBits -join '; ')." } else { '' }
            $notes.Add("DYNAMIC plan (scalingMethod '$dynMethod') - it creates/deletes hosts. Base/Burst on this card assume power management only.$cdText Review manually before trusting it.")
            $flags.Add('dynamic plan - manual review')
        }
        if ($B -eq 0) {
            $notes.Add("NO REGISTERED SESSION HOSTS found for this pool - every host-count number on this card is 0. Register hosts (or fix scope) and re-run.")
            $flags.Add('0 session hosts')
        }
        if ($L -le 0) {
            $notes.Add("Pool has no max session limit set - the Available-sessions math needs one. Set 'Session limit per host' in NME to your real per-host capacity, then size the trigger: scale out below (base x limit) minus your buffer seats; scale in one host's worth above that.")
            $flags.Add('no session limit')
        } elseif ($L -gt 1000) {
            $notes.Add("Max session limit is $L - that looks like a placeholder, not a real per-host capacity. The trigger numbers use it verbatim; set the real limit and re-run for meaningful values.")
            $flags.Add('session limit looks like a placeholder')
        }
        if ($raisedBy) {
            $notes.Add("Min active host capacity uses $profMinActive from schedule '$raisedBy' (higher than the primary schedule's $($prim.MinActive)) - never guarantee less than the plan did.")
            $flags.Add("min active raised by '$raisedBy'")
        }
        $lbSet = @($p.RuLB, $p.PkLB, $p.RdLB, $p.OpLB) | Where-Object { -not [string]::IsNullOrEmpty($_) } | Sort-Object -Unique
        if ($lbSet.Count -gt 1) {
            $notes.Add("Azure switches load balancing per phase (ramp-up $(Format-LB $p.RuLB) / peak $(Format-LB $p.PkLB) / ramp-down $(Format-LB $p.RdLB) / off-peak $(Format-LB $p.OpLB)). NME uses one value - this card uses the ramp-up/peak algorithm. Rolling Drain Mode is the NME-native lever for phase switches; revisit at optimization.")
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

        # --- the profile card ------------------------------------------------------
        $cl = New-Object System.Collections.Generic.List[string]
        $cl.Add("<!--card:$($pool.name)-->")
        $cl.Add("<div class='card'>")
        $cl.Add("<div class='card-head'><div class='pool'>$(HtmlEnc $pool.name)<span class='rg'>$(HtmlEnc $pool.resourceGroup)</span></div><div class='fromplan'>from scaling plan <b>$(HtmlEnc $plan.name)</b> &middot; time zone $(HtmlEnc $plan.timeZone) &mdash; enter times as shown</div></div>")
        $cl.Add("<div class='sec'>Profile</div>")
        $cl.Add((Row 'Auto-scale' (Toggle $true)))
        $cl.Add((TextRow 'Profile name' "$($plan.name)-mimic"))
        $cl.Add("<div class='sec'>Host pool properties</div>")
        $cl.Add((TextRow 'Session limit per host' "$L"))
        $cl.Add((TextRow 'Load balancing' $profLB))
        $cl.Add((Row 'Start VM on connect' (Toggle $svoc)))
        $cl.Add("<div class='sec'>Host pool sizing</div>")
        $cl.Add((TextRow 'Measure type' 'Count'))
        $cl.Add((TextRow 'Active host defined as' 'AVD agent Available'))
        $cl.Add((TextRow 'Base host pool capacity' "$B"))
        $minActiveHtml = "$profMinActive" + $(if ($raisedBy) { " <span class='why'>raised by schedule $(HtmlEnc $raisedBy)</span>" } else { '' })
        $cl.Add((Row 'Min active host capacity' $minActiveHtml))
        $cl.Add((TextRow 'Burst beyond base capacity' '0'))
        $cl.Add("<div class='sec'>Scaling logic</div>")
        $cl.Add((TextRow 'Trigger type' 'Available sessions'))
        $cl.Add("<div class='logic out'>$(HtmlEnc "Scale out: start up to 2 hosts if available sessions < $($prim.ScaleOutBelow) for 5 minutes")</div>")
        $cl.Add("<div class='logic in'>$(HtmlEnc "Scale in: stop up to 1 host if available sessions > $($prim.ScaleInAbove) for 15 minutes")</div>")
        $cl.Add("<div class='sec'>Scale-in restrictions</div>")
        $cl.Add((TextRow 'Stop/remove hosts only from' 'Any'))
        $cl.Add((Row 'Scale-in aggressiveness' (AggrPill $prim.Aggr)))
        if ($p.ForceLogoff) {
            $cl.Add("<div class='sec'>Messaging</div>")
            $cl.Add((TextRow 'Warn users before scale-in' "$($p.WaitMins) minutes (pick nearest dropdown value)"))
            $cl.Add((TextRow 'Message' $p.Notify))
        }
        $cl.Add("<div class='sec'>Pre-stage hosts</div>")
        $cl.Add((Row 'Pre-stage hosts' (Toggle $true)))
        $cl.Add((Row 'Use multiple schedules' (Toggle ($calc.Count -gt 1))))
        $i = 0
        foreach ($ce in $calc) {
            $i++
            $s = $ce.S
            $cl.Add("<div class='sched'>")
            $cl.Add("<div class='sched-head'>Schedule $i of $($calc.Count) &mdash; $(HtmlEnc $s.Name)$(if ($i -eq 1) { ' (primary)' })</div>")
            $cl.Add((Row 'Work days' (DayChips $s.Days)))
            $cl.Add((TextRow 'Start of work hours' (Format-Time $s.RuH $s.RuM)))
            $cl.Add((TextRow 'Hosts to be active by start' "$($ce.PreStage)"))
            $cl.Add((TextRow 'Scale-in delay' "$($ce.DelayH) h $($ce.DelayM) min"))
            $cl.Add("</div>")
        }
        if ($notes.Count -gt 0) {
            $cl.Add("<div class='notes'><div class='notes-t'>Notes</div><ul>")
            foreach ($n in $notes) { $cl.Add("<li>$(HtmlEnc $n)</li>") }
            $cl.Add("</ul></div>")
        }
        $cl.Add("</div>")
        $cards.Add(($cl -join "`n"))
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
$personalHtml = New-Object System.Collections.Generic.List[string]
foreach ($pp in $personalPlans) {
    foreach ($ref in @($pp.refs)) { $referencedPoolIds["$($ref.hostPoolArmPath)".ToLowerInvariant()] = $true }
    $personalHtml.Add("<div class='stub'><b>$(HtmlEnc $pp.name)</b> &mdash; personal scaling plan ($(@($pp.refs).Count) pool reference(s), time zone $(HtmlEnc $pp.timeZone)). Not translated - this tool does pooled plans first.</div>")
    $review.Add([pscustomobject]@{ Plan=$pp.name; Schedule='(personal)'; Days=''; Pool="($(@($pp.refs).Count) pool(s))"; RG=$pp.resourceGroup; EnabledOnPool=''
        SessionHosts=''; SessionLimit=''; MinActive=''; PreStageHosts=''; ScaleOutBelow=''; ScaleInAbove=''
        Aggressiveness=''; ScaleInDelay=''; ProfileLB=''; StartVMOnConnect=''; TimeZone=$pp.timeZone
        Flags='personal plan - not translated (pooled first)' })
}
$noPlanPools = @($poolRows | Where-Object { -not $referencedPoolIds.ContainsKey("$($_.id)".ToLowerInvariant()) } | Sort-Object name)

# ------------------------------------------------------------------- 5. output
Write-Info "[5/5] Writing files..."
$css = @'
body{font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#f0f2f5;color:#172b4d;margin:0;padding:24px 12px}
.top{max-width:760px;margin:0 auto 20px}
h1{font-size:21px;margin:0 0 4px}
.sub{color:#6b778c;font-size:12.5px;margin-bottom:10px}
.how{background:#deebff;border-left:3px solid #0052cc;padding:10px 12px;font-size:13px;border-radius:0 6px 6px 0}
.card,.stubs,.plist{max-width:760px;margin:0 auto 18px;background:#fff;border-radius:10px;padding:20px 24px;box-shadow:0 1px 3px rgba(9,30,66,.13)}
.card-head{border-bottom:2px solid #ebecf0;padding-bottom:10px;margin-bottom:6px}
.pool{font-size:17px;font-weight:700}
.rg{font-weight:400;color:#6b778c;font-size:12px;margin-left:8px}
.fromplan{color:#6b778c;font-size:12.5px;margin-top:3px}
.sec{text-transform:uppercase;letter-spacing:.08em;font-size:11px;color:#6b778c;font-weight:700;margin:16px 0 2px;border-bottom:1px solid #ebecf0;padding-bottom:3px}
.row{display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid #f4f5f7;gap:12px}
.lbl{font-size:13px;color:#42526e}
.val{font-size:13.5px;font-weight:600;text-align:right}
.why{font-weight:400;color:#974f0c;font-size:11.5px;margin-left:6px}
.tg{display:inline-block;font-size:11px;font-weight:700;border-radius:10px;padding:2px 10px;background:#dfe1e6;color:#42526e}
.tg.on{background:#e3fcef;color:#006644}
.pill{display:inline-block;font-size:11.5px;font-weight:700;border-radius:10px;padding:2px 10px}
.pill.low{background:#deebff;color:#0747a6}
.pill.medium{background:#fff0b3;color:#7f5f01}
.pill.high{background:#ffebe6;color:#bf2600}
.chip{display:inline-block;background:#deebff;color:#0747a6;border-radius:4px;padding:1px 7px;margin-left:4px;font-size:11.5px;font-weight:600}
.logic{font-size:13px;padding:6px 10px;margin:6px 0;border-left:3px solid #0052cc;background:#fafbfc;border-radius:0 4px 4px 0}
.logic.in{border-left-color:#6b778c}
.sched{background:#f7f8fa;border-radius:8px;padding:8px 14px;margin:8px 0}
.sched-head{font-size:12.5px;font-weight:700;color:#42526e;padding:4px 0}
.sched .row{border-bottom:1px solid #ebecf0}
.notes{background:#fffae6;border-left:3px solid #ffab00;border-radius:0 6px 6px 0;padding:10px 14px;margin-top:16px}
.notes-t{font-weight:700;font-size:12.5px;margin-bottom:4px}
.notes ul{margin:0;padding-left:18px}
.notes li{font-size:12.5px;margin:4px 0;color:#42526e}
.stub{font-size:13px;color:#42526e;padding:8px 0;border-bottom:1px solid #f4f5f7}
.stub:last-child{border-bottom:none}
.h2{font-size:14px;font-weight:700;margin:0 0 6px}
details{max-width:760px;margin:0 auto 18px;background:#fff;border-radius:10px;padding:14px 24px;box-shadow:0 1px 3px rgba(9,30,66,.13)}
summary{cursor:pointer;font-size:13.5px;font-weight:600}
.np{font-size:12.5px;color:#42526e;padding:4px 0}
.foot{max-width:760px;margin:8px auto;color:#97a0af;font-size:11.5px;text-align:center}
'@
$doc = New-Object System.Collections.Generic.List[string]
$doc.Add("<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>NME Auto-Scale Profiles</title><style>$css</style></head><body>")
$doc.Add("<div class='top'><h1>NME Auto-Scale Profiles</h1><div class='sub'>Day-one mimicry of your Azure scaling plans &middot; generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') by Get-NerdioAutoscaleSheet.ps1 $script:Version</div>")
$doc.Add("<div class='how'>One card per host pool. Key each card into NME's Create Auto-Scale Profile for that pool, top to bottom &mdash; toggles, pills, and chips read exactly as the NME controls do. If a card shows more than one pre-stage schedule, turn on Use multiple schedules and add every block. Notes call out anything Azure expressed differently. The Alternative Schedule tab stays reserved for holidays.</div></div>")
foreach ($c in $cards) { $doc.Add($c) }
if ($stubs.Count -gt 0) {
    $doc.Add("<div class='stubs'><div class='h2'>Nothing to enter for these</div>")
    foreach ($s in $stubs) { $doc.Add($s) }
    $doc.Add("</div>")
}
if ($personalHtml.Count -gt 0) {
    $doc.Add("<div class='plist'><div class='h2'>Personal scaling plans</div>")
    foreach ($s in $personalHtml) { $doc.Add($s) }
    $doc.Add("</div>")
}
if ($noPlanPools.Count -gt 0) {
    $doc.Add("<details><summary>$($noPlanPools.Count) host pool(s) have no scaling plan &mdash; nothing to mimic; configure NME auto-scale fresh (click to expand)</summary>")
    foreach ($np in $noPlanPools) { $doc.Add("<div class='np'>$(HtmlEnc $np.name) &nbsp;($(HtmlEnc $np.resourceGroup), $(HtmlEnc $np.hostPoolType))</div>") }
    $doc.Add("</details>")
}
$doc.Add("<div class='foot'>Read-only report &middot; every call behind it is a GET or a query</div>")
$doc.Add("</body></html>")
($doc -join "`n") | Out-File -FilePath $OutFile -Encoding utf8NoBOM
Write-Ok "Profiles written: $OutFile ($sheetCount profile card(s))"
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
Write-Ok "Pooled plans translated: $($pooledPlans.Count) | profile cards: $sheetCount | assigned-but-not-enabled: $skipCount | personal plans listed: $($personalPlans.Count)"
if ($noPlanPools.Count -gt 0) {
    $preview = ($noPlanPools | Select-Object -First 10 | ForEach-Object { $_.name }) -join ', '
    $more = if ($noPlanPools.Count -gt 10) { " (+$($noPlanPools.Count - 10) more - full list in the HTML)" } else { '' }
    Write-Info "Pools with no scaling plan: $($noPlanPools.Count) - $preview$more"
}
Write-Info "Open the HTML and key each card into NME. Cards are day-one mimicry; optimize with Nerdio telemetry after."

# ---- raw decision data: everything read, so adjustments never need a re-run ------
$rawFile = ($OutFile -replace '\.html$', '') + '-rawdata.json'
try {
    $raw = [ordered]@{
        meta = [ordered]@{ tool = 'Get-NerdioAutoscaleSheet.ps1'; version = $script:Version; generatedUtc = [DateTime]::UtcNow.ToString('o'); parameters = [ordered]@{ SubscriptionId = @($SubscriptionId) } }
        scalingPlans = @($planRows)
        schedulesByPlan = @($schedByPlan.Keys | ForEach-Object { [ordered]@{ planId = $_; schedules = @($schedByPlan[$_]) } })
        hostPools = @($poolRows)
        sessionHostsByPool = @($hostsByPool.Keys | ForEach-Object { [ordered]@{ poolId = $_; count = $hostsByPool[$_].Count; vmIds = @($hostsByPool[$_].VmIds) } })
        taggedVms = @($vmTagKeys.Keys | ForEach-Object { [ordered]@{ vmId = $_; name = $vmTagKeys[$_].Name; tagKeys = @($vmTagKeys[$_].TagKeys) } })
    }
    $raw | ConvertTo-Json -Depth 12 | Out-File -FilePath $rawFile -Encoding utf8NoBOM
    Write-Ok "Raw decision data written: $rawFile - adjustments can be re-derived from the zip without another run."
} catch { Write-Warn2 "Raw data export failed ($($_.Exception.Message)) - zip will carry the standard outputs only." }

# ---- one-file handoff: zip = profile HTML + review CSV + console log ---------------
$zipFile = ($OutFile -replace '\.html$', '') + '.zip'
if ($script:TranscriptOn) {
    try { Stop-Transcript | Out-Null } catch { }
    $script:TranscriptOn = $false
    try {
        $rawLog = Get-Content -LiteralPath $script:TranscriptFile -Raw
        Set-Content -LiteralPath $script:TranscriptFile -Value ($rawLog -replace "`e\[[0-9;]*[A-Za-z]", '') -Encoding utf8
    } catch { }
}
$zipOk = $false
try {
    $zipItems = @(@($OutFile, $csvFile, $rawFile, $script:TranscriptFile) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    Compress-Archive -Path $zipItems -DestinationPath $zipFile -Force
    $zipOk = $true
    Write-Ok "Packaged into one file: $zipFile (profile HTML + review CSV + console log)"
    Write-Info "Send that single zip back - it carries the profiles, the review table, and the full run log."
} catch {
    Write-Warn2 "Could not build the zip ($($_.Exception.Message)) - files download individually."
}
if (-not $SkipDownload) {
    if ($zipOk) { Invoke-CloudShellDownload -Path $zipFile }
    else { Invoke-CloudShellDownload -Path $OutFile; Invoke-CloudShellDownload -Path $csvFile }
} else {
    Write-Info "Downloads skipped (-SkipDownload). In the session: $(if ($zipOk) { $zipFile } else { \"$OutFile, $csvFile\" })"
}
