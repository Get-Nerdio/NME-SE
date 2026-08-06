<#
.SYNOPSIS
    Builds a Nerdio Modeler import JSON from an AVD environment's ACTUAL usage and
    configuration. Run in Azure Cloud Shell (PowerShell). Read-only. One command.

.DESCRIPTION
    What it does, in order:
      1. Inventories ALL host pools tenant-wide via Azure Resource Graph.
      2. Reads each pool's diagnostic settings and discovers EVERY Log Analytics
         workspace receiving AVD telemetry - no workspace hunting, multi-workspace
         handled automatically.
      3. Pulls session concurrency (WVDConnections) from each workspace:
         users.total = observed PEAK CONCURRENT; work days/hours = observed;
         off-hours + weekend load folded into the Modeler's overtime fields
         (additional-hours applies across all 7 days).
      4. Enriches VM size/disk/image per pool from Resource Graph.
      5. Prints a per-pool review table + flags, writes the schema-4 import JSON,
         and triggers a Cloud Shell browser download of the file.
      6. Pulls last month's ACTUAL spend for those VMs + disks (Cost Management
         Query API, per resource group) and prints it beside the model inputs —
         skipped cleanly wherever cost visibility isn't granted.

    Pools without telemetry still land in the JSON, named "(no usage data)".
    Nothing is modified anywhere - every call is a read.

.PARAMETER ModelName
    Model name shown inside the Nerdio Modeler. Default "AVD Environment - Actuals".
.PARAMETER LookbackDays
    Days of usage history to analyze. Default 30.
.PARAMETER TimeZone
    IANA time zone for work-hours math (the environment's local zone), e.g.
    America/New_York, America/Chicago, Europe/London. Default America/New_York.
.PARAMETER SubscriptionId
    Optional subscription ID(s) to scope to. Default: every subscription you can see.
.PARAMETER OutFile
    Output file name. Default modeler-import-<timestamp>.json.
.PARAMETER SkipDownload
    Skip the Cloud Shell auto-download (file still written to the session).
.PARAMETER SkipCosts
    Skip the Cost Management actual-spend pull entirely.

.EXAMPLE
    # Quick run (Cloud Shell, defaults):
    iex (irm 'https://raw.githubusercontent.com/dclawrence003/NME/main/modeler/Get-NerdioModelerJson.ps1')

.EXAMPLE
    # Inspect-then-run form (security-conscious), with options:
    irm 'https://raw.githubusercontent.com/dclawrence003/NME/main/modeler/Get-NerdioModelerJson.ps1' -OutFile ./modeler.ps1
    # read it, then:
    ./modeler.ps1 -TimeZone 'America/Chicago' -ModelName 'Contoso - Actuals'

.NOTES
    v0.10 (2026-08-05). One-file handoff: the run's console output is captured
    (transcript, ANSI-stripped) and packaged with the JSON + review CSV into
    modeler-import-<ts>.zip - one download, one file to send back. Degrades
    to individual downloads if transcription or zipping is unavailable.
    v0.9.1 (2026-08-05). storageType emitted exactly from the storage itself -
    dropdown enum decoded (1=Files Premium LRS, 2=Files Premium ZRS, 3/4/5=ANF
    Standard/Premium/Ultra): LRS/ZRS from the account SKU, ANF tier from the
    volume's service level. The Modeler has no standard-Files option, so
    standard shares model as Premium LRS on USED GB (flagged, conservative).
    v0.9 (2026-08-05). FSLogix profile storage, modeled from the cost surface:
    discovers Azure Files shares (provisioned + used via share stats) and SMB
    ANF volumes, maps shares to pools from StorageFileLogs usernames when the
    tenant ships file diagnostics to Log Analytics, and adds ONE dummy
    deployment per profile store (users=1, profileSizeGb=measured GB, B2s for
    1h/week - compute noise ~zero). Storage is priced once per share, never
    per pool, so users in multiple pools can't double-count profile GB.
    Premium/ANF model PROVISIONED (today's bill); standard models USED.
    storageType emitted as 1 pending the Modeler dropdown enum - verify tier.
    All paths skip-graceful; no candidates = model unchanged.
    v0.8.1 (2026-08-05). ActualMo column now always present in the review CSV
    (Export-Csv takes columns from the first row; a costless first pool was
    silently dropping the column for every pool). Empty ActualMo = cost pull
    skipped for that pool's scope.
    v0.8 (2026-08-05). Work window and work days now qualify by REGULAR load:
    hourly averages include the silent slots, and days count by their share of
    the busiest day's user-hours - so a handful of off-hours logins lands in
    the overtime fields instead of stretching the work window to 24h. New
    flags: genuine round-the-clock presence; usage too sparse for a window.
    Field-driven fix from the first real-customer run.
    v0.7 (2026-08-04). Language pass for customer-facing use; default ModelName
    is now "AVD Environment - Actuals".
    v0.6 (2026-08-04). Adds model-vs-actual: last month's ACTUAL spend for the
    session-host VMs + disks via the Cost Management Query API, shown as an
    ActualMo column in the review table.
    COST PULL REQUIREMENTS + SKIP BEHAVIOR: succeeds with the same Reader access
    the script already needs (any of Owner / Contributor / Reader / Cost Management
    Reader at RG or subscription scope). When it fails, it is almost never RBAC —
    it is billing-side policy: CSP subscriptions without customer cost visibility,
    EA enrollments where the admin disabled "view charges", or sponsored/legacy
    offers. Every such scope is SKIPPED with one warning line; the model, review
    table, JSON, and download are never affected. -SkipCosts disables the pull.
    Review table shows each pool's resource group, and the run ends with the list
    of resource groups holding session-host VMs (the Cost Management filter list).
    Requires: Azure Cloud Shell (PowerShell) or local PS7 with Az
    modules + Connect-AzAccount. Needs Reader on the subscriptions and Log Analytics
    Reader on the discovered workspaces.
    v0.4 REPORTING RULES (per real Modeler UI bounds):
    - SKUs reported EXACTLY as found, never mapped. workload.type = 5 (Custom),
      which accepts any AVD SKU.
    - Density (maxUsersPerVCpu) = OBSERVED peak concurrent users on a single host
      (capped at the configured session limit), so the model reflects how they
      actually pack hosts, not what they allow. Falls back to session limit /
      vCPUs when there's no telemetry (flagged); last resort 1.0, flagged.
      UI max 10. Both numbers appear in the review grid (PerHostPeak vs Limit) —
      the gap between them is density headroom Nerdio can reclaim.
    - Disk type reported as found (Premium_LRS / StandardSSD_LRS / Standard_LRS all
      valid). Disk size snapped UP to the Modeler's offered tiers
      (128/256/512/1024/2048/4096 GB) only when the actual size isn't offered.
      stoppedDiskType always Standard_LRS (disk switching is the Nerdio feature
      being modeled).
    - Work window cannot cross midnight (UI max 23:45): trimmed only at that
      boundary. users.total floored to 1 on zero-utilization pools (name carries
      "(no usage data)"). overtimeHours 0 when overtime disabled.
    Every adjustment is visible in the Flags column.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)] [string]   $ModelName      = "AVD Environment - Actuals",
    [Parameter(Mandatory = $false)] [int]      $LookbackDays   = 30,
    [Parameter(Mandatory = $false)] [string]   $TimeZone       = "America/New_York",
    [Parameter(Mandatory = $false)] [string[]] $SubscriptionId = @(),
    [Parameter(Mandatory = $false)] [string]   $OutFile        = "",
    [Parameter(Mandatory = $false)] [switch]   $SkipDownload,
    [Parameter(Mandatory = $false)] [switch]   $SkipCosts
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($OutFile)) { $OutFile = "modeler-import-$(Get-Date -Format 'yyyyMMdd-HHmm').json" }

function Write-Info { param([string]$m) Write-Host "[i] $m" -ForegroundColor Gray }
function Write-Ok   { param([string]$m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2{ param([string]$m) Write-Host "[!] $m" -ForegroundColor Yellow }

# --- console transcript: captured into the output zip so one run = one file back ---
$script:TranscriptFile = ($OutFile -replace '\.json$', '') + '-console.log'
$script:TranscriptOn = $false
try { Start-Transcript -Path $script:TranscriptFile -Force | Out-Null; $script:TranscriptOn = $true }
catch { Write-Warn2 "Console transcript unavailable ($($_.Exception.Message)) - the zip will omit the run log." }

# --- Cloud Shell detection + auto-download (same pattern as Test-NmeDeploymentReadiness) ---
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

# --- Cost Management Query API, one RG scope at a time (skip-safe; see .NOTES) ---
function Get-ActualCostRows {
    param([string]$Scope, [string]$CostType = 'ActualCost')
    $body = @{
        type = $CostType
        timeframe = 'TheLastMonth'
        dataset = @{
            aggregation = @{ totalCost = @{ name = 'Cost'; function = 'Sum' } }
            grouping = @(@{ type = 'Dimension'; name = 'ResourceId' })
            filter = @{ dimensions = @{ name = 'ServiceName'; operator = 'In'; values = @('Virtual Machines', 'Storage') } }
        }
    } | ConvertTo-Json -Depth 8
    $rows = @(); $nextUri = $null; $first = $true
    while ($first -or $nextUri) {
        $resp = $null
        foreach ($try in 1..2) {
            $resp = if ($nextUri) { Invoke-AzRestMethod -Method POST -Uri $nextUri -Payload $body }
                    else { Invoke-AzRestMethod -Method POST -Path "$Scope/providers/Microsoft.CostManagement/query?api-version=2023-03-01" -Payload $body }
            if ($resp.StatusCode -ne 429) { break }
            Start-Sleep -Seconds 20   # Cost Management throttles aggressively; one polite retry
        }
        if ($resp.StatusCode -ne 200) {
            $msg = ''
            try { $msg = "$((($resp.Content | ConvertFrom-Json).error.message))" } catch { $msg = "$($resp.Content)" }
            if ($msg.Length -gt 160) { $msg = $msg.Substring(0, 160) + '...' }
            return @{ ok = $false; status = "HTTP $($resp.StatusCode) - $msg"; rows = @() }
        }
        $parsed = $resp.Content | ConvertFrom-Json
        $cols = @($parsed.properties.columns.name)
        $ci = [array]::IndexOf($cols, 'Cost'); $ri = [array]::IndexOf($cols, 'ResourceId'); $cu = [array]::IndexOf($cols, 'Currency')
        foreach ($r in $parsed.properties.rows) {
            $rows += [pscustomobject]@{
                Cost = [double]$r[$ci]
                ResourceId = ("$($r[$ri])").ToLower()
                Currency = $(if ($cu -ge 0) { "$($r[$cu])" } else { '' })
            }
        }
        $nextUri = $parsed.properties.nextLink
        $first = $false
    }
    return @{ ok = $true; rows = $rows }
}

if (-not (Get-AzContext)) { throw "No Azure context. In Cloud Shell this is automatic; locally run Connect-AzAccount first." }

# ------------------------------------------------------------------------- 1. pools
Write-Info "[1/8] Inventorying host pools via Resource Graph..."
$pools = Invoke-ArgQuery -Query @"
resources
| where type =~ 'microsoft.desktopvirtualization/hostpools'
| project id, name, resourceGroup, location, subscriptionId,
          hostPoolType = tostring(properties.hostPoolType),
          maxSessionLimit = toint(properties.maxSessionLimit),
          preferredAppGroupType = tostring(properties.preferredAppGroupType),
          startVMOnConnect = tobool(properties.startVMOnConnect)
"@
if ($pools.Count -eq 0) { throw "No host pools visible. Check subscription access (Reader) or -SubscriptionId scope." }
Write-Ok "Found $($pools.Count) host pool(s)."

# ------------------------------------------------------------- 2. session host -> VM
Write-Info "[2/8] Mapping session hosts to VMs..."
$sessionHosts = Invoke-ArgQuery -Query @"
desktopvirtualizationresources
| where type =~ 'microsoft.desktopvirtualization/hostpools/sessionhosts'
| project id, vmId = tolower(tostring(properties.resourceId))
| where isnotempty(vmId)
"@
$poolVmIds = @{}   # poolIdLower -> [vmId,...]
foreach ($sh in $sessionHosts) {
    $idx = $sh.id.ToLower().IndexOf('/sessionhosts')
    if ($idx -lt 1) { continue }
    $poolKey = $sh.id.Substring(0, $idx).ToLower()
    if (-not $poolVmIds.ContainsKey($poolKey)) { $poolVmIds[$poolKey] = [System.Collections.Generic.List[string]]::new() }
    $poolVmIds[$poolKey].Add($sh.vmId)
}
$allVmIds = @($poolVmIds.Values | ForEach-Object { $_ } | Select-Object -Unique)
$vmSpecs = @{}
for ($i = 0; $i -lt $allVmIds.Count; $i += 100) {
    $chunk = $allVmIds[$i..([Math]::Min($i + 99, $allVmIds.Count - 1))]
    $inList = ($chunk | ForEach-Object { "'$_'" }) -join ','
    $vms = Invoke-ArgQuery -Query @"
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where tolower(id) in~ ($inList)
| project id = tolower(id),
          vmSize = tostring(properties.hardwareProfile.vmSize),
          ephemeral = isnotempty(properties.storageProfile.osDisk.diffDiskSettings),
          imageId = tostring(properties.storageProfile.imageReference.id),
          osDiskId = tolower(tostring(properties.storageProfile.osDisk.managedDisk.id))
"@
    foreach ($vm in $vms) { $vmSpecs[$vm.id] = $vm }
}
$allDiskIds = @($vmSpecs.Values | Where-Object { $_.osDiskId } | ForEach-Object { $_.osDiskId } | Select-Object -Unique)
$diskSpecs = @{}
for ($i = 0; $i -lt $allDiskIds.Count; $i += 100) {
    $chunk = $allDiskIds[$i..([Math]::Min($i + 99, $allDiskIds.Count - 1))]
    $inList = ($chunk | ForEach-Object { "'$_'" }) -join ','
    $disks = Invoke-ArgQuery -Query @"
resources
| where type =~ 'microsoft.compute/disks'
| where tolower(id) in~ ($inList)
| project id = tolower(id), diskSizeGb = toint(properties.diskSizeGB), diskSku = tostring(sku.name)
"@
    foreach ($d in $disks) { $diskSpecs[$d.id] = $d }
}
Write-Ok "VM specs resolved for $($vmSpecs.Count) session host VM(s)."

# ------------------------------------------- 3. discover diagnostic workspaces per pool
Write-Info "[3/8] Discovering Log Analytics workspaces from host pool diagnostic settings..."
$workspaceIds = @{}   # workspaceResourceId -> $true
foreach ($p in $pools) {
    try {
        $resp = Invoke-AzRestMethod -Method GET -Path "$($p.id)/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
        if ($resp.StatusCode -eq 200) {
            foreach ($ds in (($resp.Content | ConvertFrom-Json).value)) {
                if ($ds.properties.workspaceId) { $workspaceIds[$ds.properties.workspaceId.ToLower()] = $true }
            }
        }
    } catch { }
}
if ($workspaceIds.Count -eq 0) {
    Write-Warn2 "No host pool sends diagnostics to any Log Analytics workspace. Usage fields will be defaulted for every pool (WORKSPACE CHECK: FAIL)."
} else {
    Write-Ok "Found $($workspaceIds.Count) diagnostic workspace(s)."
}

# ------------------------------------------------------------- 4. usage per workspace
Write-Info "[4/8] Querying $LookbackDays days of WVDConnections concurrency..."
$telemetryKql = @'
let LookbackDays = __LOOKBACK__d;
let LocalTimeZone = '__TZ__';
let WorkHourFloorPct = 0.20;
let WorkDayFloorPct = 0.25;
let WeeksObserved = todouble(LookbackDays / 7d);
let ConnRaw = union isfuzzy=true (datatable(TimeGenerated:datetime, State:string, CorrelationId:string, UserName:string, SessionHostName:string, _ResourceId:string)[]), (WVDConnections | project TimeGenerated, State, CorrelationId, UserName, SessionHostName, _ResourceId);
let Sessions = ConnRaw | where TimeGenerated > ago(LookbackDays) | where State == 'Connected' | project CorrelationId, UserName, SessionHostName, HostPoolId = tolower(_ResourceId), StartTime = TimeGenerated | join kind=leftouter (ConnRaw | where TimeGenerated > ago(LookbackDays) | where State == 'Completed' | project CorrelationId, EndTime = TimeGenerated) on CorrelationId | project-away CorrelationId1 | extend EndTime = coalesce(EndTime, min_of(StartTime + 12h, now())) | where EndTime > StartTime;
let Buckets = Sessions | extend Slots = range(bin(StartTime, 15m), bin(EndTime, 15m), 15m) | mv-expand Slot = Slots to typeof(datetime) | summarize ConcurrentUsers = dcount(UserName) by HostPoolId, Slot;
let PeakPerHost = Sessions | extend Slots = range(bin(StartTime, 15m), bin(EndTime, 15m), 15m) | mv-expand Slot = Slots to typeof(datetime) | summarize HostConcurrent = dcount(UserName) by HostPoolId, SessionHostName, Slot | summarize HostPeak = max(HostConcurrent) by HostPoolId, SessionHostName | summarize PeakUsersPerHost = max(HostPeak) by HostPoolId;
let Peaks = Buckets | summarize PeakConcurrentUsers = max(ConcurrentUsers) by HostPoolId;
let DayLoads = Buckets | extend DowN = toint(dayofweek(datetime_utc_to_local(Slot, LocalTimeZone)) / 1d) | summarize DayUH = sum(todouble(ConcurrentUsers)) * 0.25 by HostPoolId, DowN;
let WorkDays = DayLoads | join kind=inner (DayLoads | summarize MaxDayUH = max(DayUH) by HostPoolId) on HostPoolId | where DayUH >= MaxDayUH * WorkDayFloorPct | extend ModelerDay = tolong(iff(DowN == 0, 7, DowN)) | summarize WorkDaysList = array_sort_asc(make_list(ModelerDay)) by HostPoolId;
let WorkWindow = Buckets | extend LocalSlot = datetime_utc_to_local(Slot, LocalTimeZone) | extend LocalHour = hourofday(LocalSlot), DowN = toint(dayofweek(LocalSlot) / 1d) | extend ModelerDay = tolong(iff(DowN == 0, 7, DowN)) | join kind=inner WorkDays on HostPoolId | where set_has_element(WorkDaysList, ModelerDay) | extend NWorkDays = todouble(array_length(WorkDaysList)) | summarize SumConcurrent = sum(todouble(ConcurrentUsers)), NWorkDays = take_any(NWorkDays) by HostPoolId, LocalHour | extend AvgConcurrent = SumConcurrent / (WeeksObserved * NWorkDays * 4.0) | join kind=inner Peaks on HostPoolId | where AvgConcurrent >= todouble(PeakConcurrentUsers) * WorkHourFloorPct | summarize StartHour = min(LocalHour), EndHour = max(LocalHour) by HostPoolId | extend WorkDurationMinutes = (EndHour - StartHour + 1) * 60;
let UsageTotals = Buckets | extend LocalSlot = datetime_utc_to_local(Slot, LocalTimeZone) | extend LocalHour = hourofday(LocalSlot), DowN = toint(dayofweek(LocalSlot) / 1d) | extend ModelerDay = tolong(iff(DowN == 0, 7, DowN)) | join kind=leftouter WorkDays on HostPoolId | join kind=leftouter WorkWindow on HostPoolId | extend InWindow = isnotnull(StartHour) and set_has_element(coalesce(WorkDaysList, dynamic([])), ModelerDay) and LocalHour >= StartHour and LocalHour <= EndHour | summarize TotalUH = sum(todouble(ConcurrentUsers)) * 0.25, InWindowUH = sumif(todouble(ConcurrentUsers), InWindow) * 0.25 by HostPoolId | extend WeeklyUH = round(TotalUH / WeeksObserved, 1), WeeklyInWindowUH = round(InWindowUH / WeeksObserved, 1) | extend WeeklyOffUH = round(WeeklyUH - WeeklyInWindowUH, 1);
Peaks
| join kind=leftouter WorkWindow on HostPoolId
| join kind=leftouter WorkDays on HostPoolId
| join kind=leftouter UsageTotals on HostPoolId
| join kind=leftouter PeakPerHost on HostPoolId
| project HostPoolId, PeakConcurrentUsers, StartHour, WorkDurationMinutes, WorkDaysJson = tostring(WorkDaysList), WeeklyOffUH, PeakUsersPerHost
'@
$telemetryKql = $telemetryKql.Replace('__LOOKBACK__', "$LookbackDays").Replace('__TZ__', $TimeZone)
$usage = @{}   # poolIdLower -> usage row (keep highest peak if seen in multiple workspaces)
$usageRows = 0
foreach ($wsId in $workspaceIds.Keys) {
    try {
        $wsResp = Invoke-AzRestMethod -Method GET -Path "$wsId`?api-version=2021-06-01"
        if ($wsResp.StatusCode -ne 200) { Write-Warn2 "Cannot read workspace $wsId (HTTP $($wsResp.StatusCode)) - skipping."; continue }
        $customerId = ($wsResp.Content | ConvertFrom-Json).properties.customerId
        $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $customerId -Query $telemetryKql
        foreach ($row in $result.Results) {
            $key = $row.HostPoolId.ToLower()
            $peak = [int]$row.PeakConcurrentUsers
            if (-not $usage.ContainsKey($key) -or $peak -gt [int]$usage[$key].PeakConcurrentUsers) { $usage[$key] = $row }
            $usageRows++
        }
        Write-Ok "Workspace $($wsId.Split('/')[-1]): usage for $(@($result.Results).Count) pool(s)."
    } catch {
        Write-Warn2 "Workspace $($wsId.Split('/')[-1]) query failed ($($_.Exception.Message)) - pools that only log there will show as no-telemetry."
    }
}

# ------------------------------------------ 5. FSLogix profile storage discovery
# FSLogix configuration (VHDLocations) lives in GPO/Intune - invisible to Azure.
# The COST surface is visible: profiles live on Azure Files shares / ANF volumes.
# Discover candidates, measure provisioned + used, and (when the tenant ships
# StorageFileLogs to Log Analytics) map shares to pools from observed usernames.
# Everything here is skip-graceful: no candidates -> model unchanged, note printed.
Write-Info "[5/8] Discovering FSLogix profile storage (Azure Files + ANF)..."
$profileStores = [System.Collections.Generic.List[object]]::new()
$profileNameRx = '(?i)prof|fslogix|upd|userdisk|usrprof'
try {
    $storAccts = Invoke-ArgQuery -Query @'
resources
| where type =~ 'microsoft.storage/storageaccounts'
| project id, name, resourceGroup, location, kind = tostring(kind), skuName = tostring(sku.name)
'@
    foreach ($sa in $storAccts) {
        $isPremiumFiles = $sa.kind -match '^(?i)FileStorage$'
        $shResp = Invoke-AzRestMethod -Method GET -Path "$($sa.id)/fileServices/default/shares?api-version=2023-01-01"
        if ($shResp.StatusCode -ne 200) { continue }   # no file service or not visible
        foreach ($sh in @((($shResp.Content | ConvertFrom-Json).value))) {
            $shName = "$($sh.name)"
            $smb = ($null -eq $sh.properties.enabledProtocols) -or ("$($sh.properties.enabledProtocols)" -match '(?i)smb')
            if (-not $smb) { continue }
            if (-not ($isPremiumFiles -or $shName -match $profileNameRx)) { continue }
            $usedGb = $null
            $stResp = Invoke-AzRestMethod -Method GET -Path "$($sa.id)/fileServices/default/shares/$($shName)?api-version=2023-01-01&`$expand=stats"
            if ($stResp.StatusCode -eq 200) {
                $stProps = ($stResp.Content | ConvertFrom-Json).properties
                if ($null -ne $stProps.shareUsageBytes) { $usedGb = [Math]::Round($stProps.shareUsageBytes / 1GB, 1) }
            }
            $provGb = if ($null -ne $sh.properties.shareQuota) { [int]$sh.properties.shareQuota } else { $null }
            # Modeler storage enum (dropdown order): 1=Files Premium LRS, 2=Files Premium ZRS,
            # 3=ANF Standard, 4=ANF Premium, 5=ANF Ultra. No standard-Files option exists.
            $isZrs = "$($sa.skuName)" -match '(?i)zrs'
            $profileStores.Add([pscustomobject]@{
                Kind = if ($isPremiumFiles) { "Azure Files Premium ($(if ($isZrs) { 'ZRS' } else { 'LRS' }))" } else { 'Azure Files Standard' }
                Account = $sa.name; Share = $shName; RG = $sa.resourceGroup; Region = $sa.location
                ProvisionedGb = $provGb; UsedGb = $usedGb
                NameMatch = [bool]($shName -match $profileNameRx)
                StorageTypeEnum = if ($isPremiumFiles -and $isZrs) { 2 } else { 1 }
                TierNote = if (-not $isPremiumFiles) { 'standard file share - the Modeler has no standard Files tier, so this is modeled as Azure Files Premium (LRS) on USED GB; slightly conservative' } else { '' }
                ServesPools = @()
            })
        }
    }
    $anfVols = Invoke-ArgQuery -Query @'
resources
| where type =~ 'microsoft.netapp/netappaccounts/capacitypools/volumes'
| project id, name, resourceGroup, location,
          provisionedBytes = tolong(properties.usageThreshold),
          protocols = properties.protocolTypes,
          serviceLevel = tostring(properties.serviceLevel)
'@
    foreach ($v in $anfVols) {
        $volName = ($v.name -split '/')[-1]
        $isSmb = ((@($v.protocols) | ForEach-Object { "$_" }) -join ',') -match '(?i)cifs|smb'
        if (-not $isSmb) { continue }
        $anfEnum = switch -Regex ("$($v.serviceLevel)") { '^(?i)standard$' { 3; break } '^(?i)premium$' { 4; break } '^(?i)ultra$' { 5; break } default { 4 } }
        $profileStores.Add([pscustomobject]@{
            Kind = "Azure NetApp Files $($v.serviceLevel)"
            Account = ($v.id -split '/')[-5] + '/' + ($v.id -split '/')[-3]
            Share = $volName; RG = $v.resourceGroup; Region = $v.location
            ProvisionedGb = [int][Math]::Round($v.provisionedBytes / 1GB); UsedGb = $null
            NameMatch = [bool]($volName -match $profileNameRx)
            StorageTypeEnum = $anfEnum
            TierNote = if ("$($v.serviceLevel)" -notmatch '^(?i)(standard|premium|ultra)$') { "ANF service level '$($v.serviceLevel)' unrecognized - modeled as ANF Premium; verify" } else { '' }
            ServesPools = @()
        })
    }
} catch {
    Write-Warn2 "Profile storage discovery failed ($($_.Exception.Message)) - continuing without FSLogix modeling."
}

# ---- share -> pool mapping from StorageFileLogs (only when the logs exist) -------
if ($profileStores.Count -gt 0 -and $workspaceIds.Keys.Count -gt 0) {
    Write-Info "      Checking Log Analytics for file-access logs (share -> pool mapping)..."
    $mapKql = @'
let LookbackDays = __LOOKBACK__d;
let FileOps = union isfuzzy=true (datatable(TimeGenerated:datetime, AccountName:string, ObjectKey:string)[]), (StorageFileLogs | project TimeGenerated, AccountName, ObjectKey);
let ShareUsers = FileOps | where TimeGenerated > ago(LookbackDays) | extend Parts = split(ObjectKey, '/') | extend Share = tolower(tostring(Parts[2])) | extend U1 = extract(@'(?i)Profiles?[_-]([^/\\.]+)\.vhdx?', 1, ObjectKey) | extend U2 = extract(@'(?i)/([^/]+?)_S-1-[0-9-]+', 1, ObjectKey) | extend UserGuess = tolower(coalesce(U1, U2)) | where isnotempty(UserGuess) and isnotempty(Share) | summarize by AccountName = tolower(AccountName), Share, UserGuess;
let PoolUsers = union isfuzzy=true (datatable(TimeGenerated:datetime, State:string, UserName:string, _ResourceId:string)[]), (WVDConnections | project TimeGenerated, State, UserName, _ResourceId) | where TimeGenerated > ago(LookbackDays) | where State == 'Connected' | summarize by HostPoolId = tolower(_ResourceId), UserGuess = tolower(tostring(split(UserName, '@')[0]));
ShareUsers | join kind=inner PoolUsers on UserGuess | summarize Overlap = dcount(UserGuess) by AccountName, Share, HostPoolId
'@
    $mapKql = $mapKql.Replace('__LOOKBACK__', "$LookbackDays")
    $mapRows = [System.Collections.Generic.List[object]]::new()
    foreach ($wsId in $workspaceIds.Keys) {
        try {
            $wsResp = Invoke-AzRestMethod -Method GET -Path "$wsId`?api-version=2021-06-01"
            if ($wsResp.StatusCode -ne 200) { continue }
            $customerId = ($wsResp.Content | ConvertFrom-Json).properties.customerId
            $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $customerId -Query $mapKql
            foreach ($row in @($result.Results)) { $mapRows.Add($row) }
        } catch { }
    }
    if ($mapRows.Count -gt 0) {
        $poolNameById = @{}
        foreach ($p in $pools) { $poolNameById["$($p.id)".ToLowerInvariant()] = $p.name }
        foreach ($ps in $profileStores) {
            $hits = @($mapRows | Where-Object { "$($_.AccountName)" -eq $ps.Account.ToLowerInvariant() -and "$($_.Share)" -eq $ps.Share.ToLowerInvariant() -and [int]$_.Overlap -ge 2 } |
                     Sort-Object { -[int]$_.Overlap })
            $ps.ServesPools = @($hits | ForEach-Object { $poolNameById["$($_.HostPoolId)".ToLowerInvariant()] } | Where-Object { $_ } | Select-Object -Unique -First 6)
        }
        Write-Ok "File-access logs found - $(@($profileStores | Where-Object { $_.ServesPools.Count -gt 0 }).Count) share(s) mapped to pools by observed users."
    } else {
        Write-Info "      No StorageFileLogs data (file-share diagnostics not enabled) - shares reported unmapped; confirm pool assignment with the AVD admin."
    }
}
if ($profileStores.Count -gt 0) {
    $profileStores | Select-Object Kind, Account, Share, Region, ProvisionedGb, UsedGb, @{n='ServesPools'; e={ $_.ServesPools -join ', ' }} |
        Format-Table -AutoSize | Out-String -Width 220 | Write-Host
    $gap = 0.0
    foreach ($ps in $profileStores) { if ($ps.Kind -notmatch 'Standard$' -and $null -ne $ps.ProvisionedGb -and $null -ne $ps.UsedGb) { $gap += [Math]::Max(0, $ps.ProvisionedGb - $ps.UsedGb) } }
    if ($gap -gt 0) { Write-Info "Provisioned-over-used gap across premium profile storage: $([Math]::Round($gap)) GB - the gap Nerdio storage auto-scale reclaims." }
} else {
    Write-Info "No FSLogix profile storage candidates found - fsLogix stays off in the model (add by hand in the Modeler if profiles live outside Azure's view)."
}

# --------------------------------------------------------------- 6. assemble the model
Write-Info "[6/8] Assembling deployments..."
$adminTasks = @'
{"0":[{"id":0,"isEnabled":true,"hoursWithoutNerdio":5,"hoursWithNerdio":0.5},{"id":1,"isEnabled":true,"hoursWithoutNerdio":2,"hoursWithNerdio":0.5},{"id":2,"isEnabled":true,"hoursWithoutNerdio":16,"hoursWithNerdio":4},{"id":3,"isEnabled":true,"hoursWithoutNerdio":20,"hoursWithNerdio":0.5},{"id":4,"isEnabled":false,"hoursWithoutNerdio":0,"hoursWithNerdio":2},{"id":5,"isEnabled":true,"hoursWithoutNerdio":16,"hoursWithNerdio":4}],"1":[{"id":6,"isEnabled":true,"hoursWithoutNerdio":5,"hoursWithNerdio":0.5},{"id":7,"isEnabled":true,"hoursWithoutNerdio":10,"hoursWithNerdio":2},{"id":8,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":0.5},{"id":9,"isEnabled":true,"hoursWithoutNerdio":2,"hoursWithNerdio":0.5},{"id":10,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":5}],"2":[{"id":11,"isEnabled":true,"hoursWithoutNerdio":10,"hoursWithNerdio":2.5},{"id":12,"isEnabled":true,"hoursWithoutNerdio":8,"hoursWithNerdio":0.5},{"id":13,"isEnabled":true,"hoursWithoutNerdio":10,"hoursWithNerdio":0.5},{"id":14,"isEnabled":true,"hoursWithoutNerdio":8,"hoursWithNerdio":2},{"id":15,"isEnabled":true,"hoursWithoutNerdio":5,"hoursWithNerdio":1},{"id":16,"isEnabled":true,"hoursWithoutNerdio":20,"hoursWithNerdio":2},{"id":17,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":0.5},{"id":18,"isEnabled":true,"hoursWithoutNerdio":10,"hoursWithNerdio":2},{"id":19,"isEnabled":true,"hoursWithoutNerdio":2.5,"hoursWithNerdio":0.5},{"id":20,"isEnabled":true,"hoursWithoutNerdio":8,"hoursWithNerdio":2},{"id":21,"isEnabled":true,"hoursWithoutNerdio":2,"hoursWithNerdio":0.5},{"id":22,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":0},{"id":23,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":0.5},{"id":24,"isEnabled":true,"hoursWithoutNerdio":5,"hoursWithNerdio":1},{"id":25,"isEnabled":true,"hoursWithoutNerdio":2,"hoursWithNerdio":1},{"id":26,"isEnabled":false,"hoursWithoutNerdio":0,"hoursWithNerdio":0.5}]}
'@ | ConvertFrom-Json
$globalSettings = '{"enterpriseDiscount":0,"windows365Discount":0,"azureType":1,"nerdioLicenseCost":{"type":0,"perUserCost":null,"windows365PerUserCost":null,"monthMinimumCost":null},"nerdioResourceCost":3}' | ConvertFrom-Json
$nameCounts = @{}
foreach ($p in $pools) { $nameCounts[$p.name] = 1 + ($nameCounts[$p.name] ?? 0) }
# Modeler disk-size tiers (from the UI dropdown); actual sizes snap UP to the nearest offered tier
$diskTiers = @(128, 256, 512, 1024, 2048, 4096)
$deployments = [System.Collections.Generic.List[object]]::new()
$review = [System.Collections.Generic.List[object]]::new()
foreach ($p in $pools) {
    $key = $p.id.ToLower()
    $u = $usage[$key]
    # representative VM spec = most common combo among the pool's hosts
    $spec = $null
    if ($poolVmIds.ContainsKey($key)) {
        $spec = $poolVmIds[$key] | ForEach-Object { $vmSpecs[$_] } | Where-Object { $_ } |
            Group-Object vmSize, ephemeral, imageId | Sort-Object Count -Descending | Select-Object -First 1 |
            ForEach-Object { $_.Group[0] }
    }
    $vmSize   = if ($spec -and $spec.vmSize) { $spec.vmSize } else { 'Standard_D4s_v5' }
    $vcpus    = [int]([regex]::Match($vmSize, '_[A-Za-z]+?(\d+)').Groups[1].Value); if ($vcpus -lt 1) { $vcpus = 4 }
    $disk     = if ($spec -and $spec.osDiskId -and $diskSpecs.ContainsKey($spec.osDiskId)) { $diskSpecs[$spec.osDiskId] } else { $null }
    $diskGbRaw = if ($disk -and $disk.diskSizeGb) { [int]$disk.diskSizeGb } else { 128 }
    $diskGb   = ($diskTiers | Where-Object { $_ -ge $diskGbRaw } | Select-Object -First 1); if (-not $diskGb) { $diskGb = 4096 }
    $diskSku  = if ($disk -and $disk.diskSku) { $disk.diskSku } else { 'Premium_LRS' }
    $limit    = if ($null -ne $p.maxSessionLimit) { [int]$p.maxSessionLimit } else { 0 }
    $experience = if ($p.hostPoolType -eq 'Personal') { 2 }
                  elseif ($p.preferredAppGroupType -eq 'RailApplications') { 4 }
                  elseif ($limit -eq 1) { 3 } else { 1 }
    $limitSane = ($limit -ge 1 -and $limit -lt 100)
    $obsPerHost = if ($u -and $u.PSObject.Properties['PeakUsersPerHost'] -and "$($u.PeakUsersPerHost)" -ne '') { [int]$u.PeakUsersPerHost } else { 0 }
    $density = 1.0
    $densityBasis = 'defaulted'
    if ($experience -eq 2) { $density = 1.0; $densityBasis = 'personal (1 user per VM)' }
    elseif ($obsPerHost -ge 1) {
        $usersPerHost = if ($limitSane) { [Math]::Min($obsPerHost, $limit) } else { $obsPerHost }
        $density = [Math]::Round($usersPerHost / [double]$vcpus, 2, [MidpointRounding]::AwayFromZero)
        $densityBasis = "observed per-host peak ($obsPerHost users/host)"
    }
    elseif ($limitSane) { $density = [Math]::Round($limit / [double]$vcpus, 2, [MidpointRounding]::AwayFromZero); $densityBasis = 'session limit (no per-host telemetry)' }
    if ($density -gt 10) { $density = 10; $densityBasis += '; capped at UI max 10' }
    $peak     = if ($u) { [int]$u.PeakConcurrentUsers } else { 0 }
    $startHr  = if ($u -and $u.StartHour -ne '' -and $null -ne $u.StartHour) { [int]$u.StartHour } else { 9 }
    $durationRaw = if ($u -and $u.WorkDurationMinutes -ne '' -and $null -ne $u.WorkDurationMinutes) { [int]$u.WorkDurationMinutes } else { 540 }
    # UI allows 12:00AM - 11:45PM and cannot cross midnight -> end time capped at 23:45
    $maxDur = 1425 - 60 * $startHr
    $duration = if ($durationRaw -gt $maxDur) { $maxDur } else { $durationRaw }
    $workDays = @(1,2,3,4,5)
    if ($u -and $u.WorkDaysJson) { try { $workDays = @(($u.WorkDaysJson | ConvertFrom-Json) | ForEach-Object { [int]$_ }) } catch { } }
    $offUH    = if ($u -and $u.WeeklyOffUH -ne '' -and $null -ne $u.WeeklyOffUH) { [double]$u.WeeklyOffUH } else { 0.0 }
    $otHours  = 1
    $otPct    = 0
    if ($peak -gt 0 -and $offUH -gt 0) {
        $raw = $offUH / 7.0 / $peak
        if ($raw -gt 1.0) { $otHours = [int][Math]::Ceiling($raw) }
        $otPct = [int][Math]::Min(100, [Math]::Round(100.0 * $offUH / 7.0 / ($peak * $otHours)))
    }
    $flags = @()
    if ($peak -eq 0) { $flags += 'no telemetry (users set to 1)' }
    if ($experience -ne 2 -and $obsPerHost -lt 1) {
        $flags += if ($limitSane) { 'density from session limit (no per-host telemetry)' }
                  else { 'no session limit and no per-host telemetry; density defaulted 1.0/vCPU' }
    }
    if (-not $spec) { $flags += 'VM spec defaulted' }
    if ($diskGb -ne $diskGbRaw) { $flags += "disk $($diskGbRaw)GB snapped up to $($diskGb)GB tier" }
    if ($duration -ne $durationRaw) { $flags += 'window trimmed to the 23:45 UI boundary' }
    if ($durationRaw -ge 1200) { $flags += "round-the-clock usage ($([Math]::Round($durationRaw/60.0,1))h window) - regular presence at nearly every hour; check for parked/service sessions" }
    if ($peak -gt 0 -and $u -and ($null -eq $u.StartHour -or "$($u.StartHour)" -eq '')) { $flags += 'usage too sparse to derive a window - defaulted 9:00+9h; all load lands in overtime' }
    $displayName = if ($nameCounts[$p.name] -gt 1) { "$($p.name) ($($p.resourceGroup))" } else { $p.name }
    $depName = if ($peak -eq 0) { "$displayName (no usage data)" } else { $displayName }
    $deployments.Add([ordered]@{
        mode = 'avd'
        name = $depName
        users = [ordered]@{ total = [Math]::Max(1, $peak); absentPercent = 0; overtimeEnabled = ($otPct -gt 0); overtimePercent = $otPct; overtimeHours = $(if ($otPct -gt 0) { $otHours } else { 0 }) }
        experience = $experience
        region = $p.location
        workload = [ordered]@{
            type = 5; vmSize = $vmSize
            disk = [ordered]@{ isEphemeral = [bool]($spec -and $spec.ephemeral); size = $diskGb; type = $diskSku }
            maxUsersPerVCpu = $density; stoppedDiskType = 'Standard_LRS'; rdpEgressGb = 10
        }
        image = if ($spec -and $spec.imageId) { [ordered]@{ type = 2; monthlyRunningHours = 6; vmSize = 'Standard_D2s_v5'; isCisHardenedImage = $false } }
                else { [ordered]@{ type = 1; isCisHardenedImage = $false } }
        autoScale = [ordered]@{ type = 0; workDays = $workDays; workStartHour = $startHr; workStartMinutes = 0; workDurationMinutes = $duration }
        fsLogix = [ordered]@{ enabled = $false }
        administrative = [ordered]@{ tasks = $adminTasks; hourlyRate = 100; isEnabled = $false }
        savings = [ordered]@{ reservedInstances = [ordered]@{ count = 0; years = 1 } }
    })
    $review.Add([pscustomobject]@{
        Pool = $displayName; RG = $p.resourceGroup; Type = $p.hostPoolType; Exp = $experience; Region = $p.location
        VmSize = $vmSize; Limit = $limit; Density = $density; PerHostPeak = $obsPerHost
        PeakUsers = $peak; Window = "$startHr`:00+$([Math]::Round($duration/60.0,2))h"; Days = ($workDays -join ',')
        Overtime = "$otPct% x $($otHours)h"; Flags = ($flags -join '; ')
    })
}
# ---- FSLogix dummy deployments: one per profile store ----------------------------
# Priced once per share (never per pool - the same user in two pools would double-
# count profile GB). users=1 + profileSizeGb=measured keeps license/compute noise
# at zero; compute floor is a B2s for one hour on Mondays. Import-tested shape.
$shareNameCounts = @{}
foreach ($ps in $profileStores) { $shareNameCounts[$ps.Share] = 1 + ($shareNameCounts[$ps.Share] ?? 0) }
foreach ($ps in $profileStores) {
    # premium/ANF bill provisioned; standard bills used - model what they pay today
    $gb = if ($ps.Kind -match '(?i)Premium|NetApp') { $ps.ProvisionedGb ?? $ps.UsedGb } else { $ps.UsedGb ?? $ps.ProvisionedGb }
    $storeLabel = if ($shareNameCounts[$ps.Share] -gt 1) { "$($ps.Account)/$($ps.Share)" } else { $ps.Share }
    if ($null -eq $gb -or [double]$gb -lt 1) {
        $review.Add([pscustomobject]@{
            Pool = "FSLogix: $storeLabel"; RG = $ps.RG; Type = $ps.Kind; Exp = '-'; Region = $ps.Region
            VmSize = '-'; Limit = '-'; Density = '-'; PerHostPeak = '-'
            PeakUsers = '-'; Window = '-'; Days = '-'; Overtime = '-'
            Flags = 'profile storage candidate found but size unreadable - not modeled; check access to share stats'
        })
        continue
    }
    $gbInt = [int][Math]::Max(1, [Math]::Round([double]$gb))
    $servesNote = if ($ps.ServesPools.Count -gt 0) { "serves: $($ps.ServesPools -join ', ')" } else { 'pools not mapped - confirm with the AVD admin which pools use this share' }
    $nameServes = if ($ps.ServesPools.Count -gt 0) { " ($(@($ps.ServesPools | Select-Object -First 3) -join ', ')$(if ($ps.ServesPools.Count -gt 3) { " +$($ps.ServesPools.Count - 3)" }))" } else { '' }
    $deployments.Add([ordered]@{
        mode = 'avd'
        name = "FSLogix - $storeLabel$nameServes"
        users = [ordered]@{ total = 1; absentPercent = 0; overtimeEnabled = $false; overtimePercent = 0; overtimeHours = 0 }
        experience = 1
        region = $ps.Region
        workload = [ordered]@{
            type = 5; vmSize = 'Standard_B2s'
            disk = [ordered]@{ isEphemeral = $false; size = 128; type = 'Standard_LRS' }
            maxUsersPerVCpu = 1; stoppedDiskType = 'Standard_LRS'; rdpEgressGb = 10
        }
        image = [ordered]@{ type = 1; isCisHardenedImage = $false }
        autoScale = [ordered]@{ type = 0; workDays = @(1); workStartHour = 9; workStartMinutes = 0; workDurationMinutes = 60 }
        fsLogix = [ordered]@{ enabled = $true; profileSizeGb = $gbInt; storageType = $ps.StorageTypeEnum }
        administrative = [ordered]@{ tasks = $adminTasks; hourlyRate = 100; isEnabled = $false }
        savings = [ordered]@{ reservedInstances = [ordered]@{ count = 0; years = 1 } }
    })
    $provText = if ($null -ne $ps.ProvisionedGb) { "$($ps.ProvisionedGb)GB prov" } else { 'prov n/a' }
    $usedText = if ($null -ne $ps.UsedGb) { "$($ps.UsedGb)GB used" } else { 'used n/a' }
    $review.Add([pscustomobject]@{
        Pool = "FSLogix: $storeLabel"; RG = $ps.RG; Type = $ps.Kind; Exp = '-'; Region = $ps.Region
        VmSize = 'Standard_B2s (dummy)'; Limit = '-'; Density = '-'; PerHostPeak = '-'
        PeakUsers = 1; Window = '9:00+1h'; Days = '1'; Overtime = '-'
        Flags = "profile storage dummy - models $gbInt GB ($provText / $usedText); $servesNote; storage tier: $($ps.Kind) (storageType $($ps.StorageTypeEnum))$(if ($ps.TierNote) { "; $($ps.TierNote)" })"
    })
}
if ($profileStores.Count -gt 0) {
    Write-Ok "Added $(@($deployments | Where-Object { $_.name -like 'FSLogix - *' }).Count) FSLogix storage deployment(s) - compute noise ~zero (1 user, B2s, 1h/week); pools' own fsLogix stays off so storage is never double-counted."
}

$model = [ordered]@{
    schema = 4
    name = $ModelName
    description = "Generated from actuals, lookback $($LookbackDays)d, $(Get-Date -Format 'yyyy-MM-dd')"
    deployments = $deployments
    globalSettings = $globalSettings
}

# ------------------------------------------------------------------- 6. output + download
Write-Info "[7/8] Writing $OutFile..."
$model | ConvertTo-Json -Depth 30 -Compress | Out-File -FilePath $OutFile -Encoding utf8NoBOM

# ---------------------------------------- 7. actual spend (optional, skip-safe)
if (-not $SkipCosts) {
    Write-Info "[8/8] Pulling last month's ACTUAL spend for session-host VMs + disks (skips any scope without cost visibility)..."
    $costByResource = @{}
    $costCurrency = ''
    $rgScopes = @{}
    foreach ($vmId in $vmSpecs.Keys) { $parts = $vmId -split '/'; $rgScopes["/subscriptions/$($parts[2])/resourcegroups/$($parts[4])"] = $parts[4] }
    $costOk = 0; $costSkipped = @()
    foreach ($scope in $rgScopes.Keys) {
        # AmortizedCost spreads RI/Savings Plan purchases across usage (honest number for
        # reserved customers); PAYG-type offers reject it, so fall back to ActualCost.
        try { $res = Get-ActualCostRows -Scope $scope -CostType 'AmortizedCost' } catch { $res = @{ ok = $false; status = "error: $($_.Exception.Message)" } }
        if (-not $res.ok) {
            try { $res = Get-ActualCostRows -Scope $scope -CostType 'ActualCost' } catch { $res = @{ ok = $false; status = "error: $($_.Exception.Message)" } }
        }
        if (-not $res.ok) { $costSkipped += [pscustomobject]@{ RG = $rgScopes[$scope]; Reason = "$($res.status)" }; continue }
        $costOk++
        foreach ($row in $res.rows) {
            $costByResource[$row.ResourceId] = ($costByResource[$row.ResourceId] ?? 0) + $row.Cost
            if (-not $costCurrency -and $row.Currency) { $costCurrency = $row.Currency }
        }
    }
    if ($costByResource.Count -gt 0) {
        $attributed = 0.0
        for ($i = 0; $i -lt $pools.Count; $i++) {
            $key = $pools[$i].id.ToLower()
            $sum = 0.0
            if ($poolVmIds.ContainsKey($key)) {
                foreach ($vmId in $poolVmIds[$key]) {
                    $sum += ($costByResource[$vmId] ?? 0)
                    $vmSpec = $vmSpecs[$vmId]
                    if ($vmSpec -and $vmSpec.osDiskId) { $sum += ($costByResource[$vmSpec.osDiskId] ?? 0) }
                }
            }
            $attributed += $sum
            $review[$i] | Add-Member -NotePropertyName ActualMo -NotePropertyValue ([Math]::Round($sum, 2))
        }
        $pulledTotal = [Math]::Round(($costByResource.Values | Measure-Object -Sum).Sum, 2)
        Write-Ok "Actual spend (last full month, $costCurrency) pulled from $costOk resource group(s). Attributed to session hosts + disks: $([Math]::Round($attributed, 2)). Other VM/Storage spend in those RGs: $([Math]::Round($pulledTotal - $attributed, 2))."
        Write-Info "Compare the ActualMo column against the Modeler's monthly cost per deployment after import. Actuals already include their current scaling behavior; the model is the Nerdio-run future."
    } elseif ($rgScopes.Count -gt 0 -and $costOk -eq 0) {
        Write-Warn2 "No cost data was retrievable from any scope - model output unaffected."
    }
    if ($costSkipped.Count -gt 0) {
        foreach ($g in ($costSkipped | Group-Object Reason)) {
            Write-Warn2 "Cost query skipped for $(@($g.Group.RG) -join ', '): $($g.Name)"
        }
        Write-Warn2 "Common causes: subscription offer type without cost API support (sponsored/internal/MSDN - typical in demo and lab tenants), CSP without customer cost visibility, or an EA where 'view charges' is disabled. Skipped cleanly - nothing else is affected."
    }
}
Write-Host ""
Write-Host "================= REVIEW =================" -ForegroundColor Cyan
$review | Sort-Object Pool | Format-Table -AutoSize | Out-String -Width 300 | Write-Host
$reviewFile = ($OutFile -replace '\.json$', '') + '-review.csv'
# Export-Csv takes its column set from the FIRST row - make ActualMo uniform so the
# column survives even when the first pool had no cost attribution (empty = skipped).
foreach ($r in $review) { if (-not $r.PSObject.Properties['ActualMo']) { $r | Add-Member -NotePropertyName ActualMo -NotePropertyValue '' } }
$review | Sort-Object Pool | Export-Csv -Path $reviewFile
Write-Ok "Review table (including ActualMo when pulled) also written to: $reviewFile"
$withUsage = @($review | Where-Object { $_.PeakUsers -gt 0 }).Count
$flagged   = @($review | Where-Object { $_.Flags }).Count
if ($usageRows -eq 0) {
    Write-Warn2 "WORKSPACE CHECK: FAIL - no WVDConnections data found in any discovered workspace. All usage fields defaulted."
} else {
    Write-Ok "Usage found for $withUsage of $($pools.Count) pool(s)."
}
if ($flagged -gt 0) { Write-Warn2 "$flagged pool(s) carry flags - see the Flags column above." }
Write-Ok "Model written: $OutFile ($($deployments.Count) deployments)"
$vmRgGroups = @($vmSpecs.Keys | ForEach-Object { ($_ -split '/')[4] } | Group-Object | Sort-Object Count -Descending)
if ($vmRgGroups.Count -gt 0) {
    Write-Host ""
    Write-Info "Session-host VMs live in these resource groups (Cost Management: filter Resource group to this list, Service name = Virtual Machines + Storage):"
    foreach ($g in $vmRgGroups) { Write-Host ("      {0}  ({1} VM(s))" -f $g.Name, $g.Count) -ForegroundColor Gray }
}
Write-Info "After import, touch up: RDP egress GB (10), custom-image VM hours, any '(no usage data)' pools."
# ---- one-file handoff: zip = model JSON + review CSV + console log ---------------
$zipFile = ($OutFile -replace '\.json$', '') + '.zip'
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
    $zipItems = @(@($OutFile, $reviewFile, $script:TranscriptFile) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    Compress-Archive -Path $zipItems -DestinationPath $zipFile -Force
    $zipOk = $true
    Write-Ok "Packaged into one file: $zipFile (model JSON + review CSV + console log)"
    Write-Info "Send that single zip back - it carries the model, the review table, and the full run log."
} catch {
    Write-Warn2 "Could not build the zip ($($_.Exception.Message)) - files download individually."
}
if (-not $SkipDownload) {
    if ($zipOk) { Invoke-CloudShellDownload -Path $zipFile }
    else { Invoke-CloudShellDownload -Path $OutFile; Invoke-CloudShellDownload -Path $reviewFile }
} else {
    Write-Info "Downloads skipped (-SkipDownload). In the session: $(if ($zipOk) { $zipFile } else { \"$OutFile, $reviewFile\" })"
}
