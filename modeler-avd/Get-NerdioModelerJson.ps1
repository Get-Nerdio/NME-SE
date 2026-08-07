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
      5. Discovers FSLogix-candidate storage (Azure Files shares + ANF capacity
         pools) and records ALL of it in a storage ledger CSV - classification,
         sizes, SKU/billing model, log-derived pool evidence, actual cost.
         STORAGE NEVER ENTERS THE MODELER JSON: the model carries host pools
         only, and the ledger is the storage deliverable. No prompts.
      6. Prints a per-pool review table + flags, writes the schema-4 import JSON
         and the storage ledger, and packages one zip (Cloud Shell auto-download;
         local runs write it to the current folder).
      7. Pulls last month's ACTUAL spend for those VMs + disks + storage (Cost
         Management Query API, per resource group) and prints it beside the
         model inputs - skipped cleanly wherever cost visibility isn't granted.

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
    Optional subscription ID(s) to narrow the scan. Default: every enabled
    subscription this sign-in can see - enumerated and printed at the start of
    the run, and pinned onto every discovery query. One run covers ONE tenant;
    the run says so when the account can reach others.
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
    v0.17.2 (2026-08-07). DETERMINISTIC REPRESENTATIVE VM SPEC - found by
    diffing a Windows PowerShell 5.1 run against a Cloud Shell run of the SAME
    tenant minutes apart: 119 of 120 pools matched on every field; one pool
    (4 hosts: D2as x2, D4as, D8as) modeled as D2as from Cloud Shell but D8as
    from 5.1. Root cause: the representative spec grouped on
    vmSize+ephemeral+imageId in one key, so two D2as hosts running different
    images split into separate count-1 groups - a 4-way tie - and tie order
    under Sort-Object is stable in PowerShell 7 but NOT in 5.1. Now the size
    is chosen first (true mode over vmSize alone), then the image/ephemeral
    combo among hosts of that size, with every sort ordered Count desc then
    name asc - the same input picks the same spec in every shell, every run.
    v0.17.1 (2026-08-07). STALE-COPY SELF-DETECTION - a laptop ran v0.15
    three times in one day (System32 output, warning floods, 18-pool scans)
    while Cloud Shell, minutes apart, pulled current code from the same
    repo. CDN lag was ruled out (the fixes were hours old); a saved
    modeler.ps1 or a replayed SHA-pinned command keeps old code alive
    forever, and an old copy looks normal until compared against a fresh
    one. Now: the version prints as the FIRST line of every run (before
    sign-in), and the script fetches the published version marker
    (modeler/VERSION on main, cache-busting query, 5s timeout, silent on
    any failure) and prints a loud three-line warning with the exact
    re-fetch command when the running copy is old. RELEASE RULE: bump
    modeler/VERSION and $ScriptVersion together.
    v0.17 (2026-08-07). EXPLICIT SUBSCRIPTION SCOPE ON EVERY QUERY - from two
    same-day runs against the same demo estate: Cloud Shell returned 120 pools,
    local PowerShell returned 18, with ZERO overlap - disjoint subscriptions,
    disjoint workspaces. Each window was signed into a different scope, and an
    unscoped Resource Graph query silently answers for whatever the current
    sign-in happens to reach. Neither console log recorded who was signed in,
    so the gap was invisible. Now every run: (1) prints the signed-in account
    and tenant, (2) enumerates the enabled subscriptions that sign-in can see
    and prints them, (3) pins that explicit list onto every Resource Graph
    query (chunked at ARG's 1000-subscription request cap), (4) prints
    per-subscription pool counts after discovery, (5) warns when the account
    can reach OTHER tenants (a run covers one tenant - pools there need
    Connect-AzAccount -TenantId <id> and a second run), and (6) records
    account/tenant/scope in rawdata.json. Also: Az breaking-change warning
    suppression - older Az.Accounts (4.x) printed an "Upcoming breaking
    changes in Get-AzAccessToken" block around every Log Analytics query and
    flooded the 5.1 transcript.
    v0.16 (2026-08-07). CREDENTIAL CIRCUIT BREAKER - from a live Cloud Shell
    run where the shell's token service started returning garbage mid-run
    ("ManagedIdentityCredential ... invalid: ExpiresOn"). The user was signed
    in; the token provider glitched, and every later Azure call failed
    instantly and identically: 72 storage accounts mislabeled "slow or
    unreadable", ANF and the cost pull dead, ~150 identical error dumps in
    the transcript. Now: credential-shaped failures are classified apart
    from slow/unreadable; the first one triggers a pause + one cheap probe;
    if the token is still broken, ONE plain banner explains the glitch and
    the fix (restart Cloud Shell / Connect-AzAccount, run again), and every
    remaining Azure call is skipped fast under an accurate label. The census
    reports token-blocked accounts separately. Telemetry (stage 4) completes
    before storage, so pools/windows/MAU survive even a mid-run token death.
    v0.15.1 (2026-08-07). Local runs save to DOWNLOADS. The first Windows
    PowerShell 5.1 run (successful end to end - 5.1 support live-proven)
    wrote its zip to C:\Windows\System32, because that's where an elevated
    console starts and the script wrote to the current directory. Default
    output now lands in the user's Downloads folder on local runs, full path
    printed at the end. Explicit -OutFile and Cloud Shell are unchanged.
    v0.15 (2026-08-07). TWO RULINGS FROM THE FIRST LIVE v0.14 RUN:
    (1) STORAGE IS LEDGER-ONLY, ALWAYS. The v0.14 interactive triage asked the
    runner to classify stores and type pool names mid-run - unworkable at scale
    (100 stores = 100 prompts) and runners should never do data entry. Removed
    entirely: no prompts, no -NoPrompts switch, no storage deployments in the
    JSON under any circumstances. The Modeler JSON carries host pools only,
    fsLogix off everywhere. Everything discovered goes to the storage ledger
    CSV with automatic classification (name/msix/junk patterns), log-derived
    pool evidence when StorageFileLogs exist, sizes, SKU/billing model, and
    actual cost. The run flows straight through with zero stops.
    (2) WINDOWS POWERSHELL 5.1 SUPPORTED. Removed every PS7-only construct:
    ?? null-coalescing (Coalesce helper), ConvertFrom-SecureString -AsPlainText
    (BSTR marshal), -Encoding utf8NoBOM (UTF8Encoding($false) writer), and
    added TLS 1.2 enforcement plus an IANA->Windows time-zone map (.NET
    Framework doesn't know IANA ids). Export-Csv everywhere uses
    -NoTypeInformation so 5.1 doesn't prepend #TYPE lines. PowerShell 7 still
    recommended; 5.1 is the built-in fallback.
    v0.14 (2026-08-07). STORAGE OVERHAUL - nothing unconfirmed enters the model:
    (1) POLICY: a discovered store lands in the Modeler JSON only when it is
    confirmed as FSLogix profile storage AND mapped to at least one host pool
    (by log evidence accepted at the prompt, or typed by the person running).
    Everything discovered - confirmed or not, app attach, non-AVD, unknown -
    is quantified in a new storage ledger CSV that always ships in the zip.
    App attach never enters the JSON (no Modeler concept for it).
    (2) INLINE TRIAGE: one line per store with a smart default (name-matched ->
    PROFILES, msix -> APP ATTACH, pvcn-/mq/sftp patterns -> NOT AVD, else
    UNKNOWN). Enter accepts; pool assignment is search-driven - type name or
    resource-group fragments, the script resolves and echoes matches; * = all.
    Drops are bulk-confirmed at the end, never silent. -NoPrompts (or any
    non-interactive session) skips the pass: ledger only, JSON gets no storage.
    (3) EVIDENCE: mapping now correlates StorageFileLogs caller IPs with
    WVDConnections session-host IPs (works across split workspaces - joins
    happen in PowerShell), with username overlap demoted to fallback evidence;
    each storage account's own diagnostic-settings workspace is discovered and
    queried, not just the AVD workspaces. All serving pools are kept (the old
    6-pool cap was display-only in intent, stored in practice - fixed).
    (4) CLASSIFICATION BY SKU, not account kind: FileStorage no longer implies
    premium (provisioned-v2 StandardV2/PremiumV2 SKUs share the kind). Billing
    basis follows the SKU: provisioned models bill provisioned GB, v1 standard
    bills used. v2 IOPS/throughput recorded in the ledger.
    (5) SIZE RESILIENCE: share stats retry once, then fall back to the Azure
    Monitor FileCapacity metric (already computed platform-side - answers fast
    where on-demand stats on huge shares hit the 100s timeout). ANF used GB
    from the VolumeLogicalSize metric. ANF is quantified at its BILLING
    boundary - the capacity pool, priced once, member volumes listed, shared
    pools flagged. A census line ends the stage: accounts scanned/skipped,
    shares sized/unsized - gaps are named, never silent.
    v0.13 (2026-08-07). LOCAL POWERSHELL IS NOW FIRST-CLASS - from a prospect's
    local-PS run that lost every usage number:
    (1) Telemetry queries no longer use Invoke-AzOperationalInsightsQuery (the
    Az.OperationalInsights module ships in Cloud Shell but rarely on laptops -
    all 4 workspaces failed with 'not recognized' and every pool defaulted).
    Queries now go straight to the Log Analytics REST API with a token from
    Get-AzAccessToken - both live in Az.Accounts, which anyone who can run
    Connect-AzAccount already has. Handles the Az.Accounts 5.x SecureString
    token change. Commercial cloud endpoint; sovereign clouds would need edits.
    (2) Storage discovery survives slow accounts: one 100-second stats timeout
    (a 100TB share) used to abort every remaining account AND all ANF checking,
    then print 'continuing without FSLogix modeling' above a table of modeled
    shares. Now: per-account catch + per-stats catch, ANF isolated, and the log
    names exactly which accounts were skipped.
    (3) Missing/expired sign-in gets a plain message (run Connect-AzAccount,
    add -TenantId if needed) instead of a wall of red TerminatingErrors.
    v0.12 (2026-08-06). Validated against a live customer's Nerdio Mothership
    telemetry (independent hourly per-pool concurrency); three changes came out:
    (1) DAY RULE NORMALIZATION - a 30-day lookback holds 5 of some weekdays and
    4 of others; normalizing by uniform weeks penalized the 4-occurrence days
    ~20%, which cost a real call center its Saturday shift. Day and hour rules
    now normalize by each weekday's actual calendar occurrence count.
    (2) MAU column in the review table (distinct users per pool over the
    lookback) - INFORMATIONAL ONLY, never in the JSON. users.total stays peak
    concurrent: this is an Azure compute exercise, and hosts are sized per-pool
    from concurrency. MAU answers "the model says 24 users, we have 5,000" and
    feeds licensing conversations.
    (3) COUNTING BASIS, made explicit: concurrency counts CONNECTED sessions
    (WVDConnections spans). NME's console counts sessions incl. disconnected
    and reads higher (~10-25% at the validation customer). Sizing is safe
    either way - peak and per-host density share the same basis, so it cancels;
    observed density was measured on hosts that also carried the disconnected
    load. When WVDAgentHealthStatus is available and session peaks run >=15%
    above connected peaks, the pool is flagged so nobody is surprised.
    Also: rawdata meta version now comes from the same constant as this header.
    v0.11.1 (2026-08-06). Live-run polish: raw-export success message had a bad
    escape (files were written; only the message threw - now clean); usage/flag
    counters exclude storage rows; MSIX/app-attach shares are labeled
    'AppAttach - <share>' instead of FSLogix (still modeled - the storage cost
    is real - but never confused with user profiles).
    v0.11 (2026-08-06). Raw decision data rides in the zip: <name>-rawdata.json
    (inventory, VM/disk specs, workspaces, usage aggregates, storage findings,
    cost rows + skips, run parameters) and <name>-usage-buckets.csv (per-pool
    15-minute concurrency, UTC). Purpose: model adjustments re-derive offline
    from one customer run - no repeat asks. Boundaries in the file's meta.notes.
    v0.10.1 (2026-08-06). Two live-run fixes from Don's demo tenant log:
    (1) FSLogix storage discovery query used 'kind' as a projected column name -
    ARG's parser rejects it as reserved; renamed accountKind. (2) The Cost
    Management API no longer supports timeframe 'TheLastMonth' (HTTP 400
    everywhere - cost pull was silently dead on every tenant); now uses an
    explicit Custom range for last calendar month (UTC).
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
    Requires: Azure Cloud Shell (PowerShell), or local PowerShell 7 or Windows
    PowerShell 5.1 with the Az.Accounts module + Connect-AzAccount (no other
    Az modules used). Needs Reader on the subscriptions and Log Analytics
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
$ScriptVersion = 'v0.17.2'   # RELEASE RULE: bump modeler/VERSION in the same commit
# Windows PowerShell 5.1 compatibility: force TLS 1.2 (old .NET Framework
# defaults can be lower and ARM/Log Analytics require 1.2), and no PS7-only
# syntax anywhere in this file (?? / ?. / -AsPlainText / utf8NoBOM).
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
# Older Az.Accounts (4.x) prints an "Upcoming breaking changes in the cmdlet
# 'Get-AzAccessToken'" warning block on EVERY call - a live 5.1 run drowned its
# transcript in them. This env var is the Az-supported off switch; it is
# process-scoped and touches no user configuration.
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'
function Coalesce { param($a, $b) if ($null -ne $a) { $a } else { $b } }
function Write-Utf8NoBom {
    param([string]$FilePath, [string]$Content)
    $full = if ([IO.Path]::IsPathRooted($FilePath)) { $FilePath } else { Join-Path (Get-Location).Path $FilePath }
    [IO.File]::WriteAllText($full, $Content, (New-Object System.Text.UTF8Encoding($false)))
}
# Cloud Shell detection first - the output location depends on it
$script:IsCloudShell = (-not [string]::IsNullOrEmpty($env:ACC_CLOUD)) -or ($env:AZUREPS_HOST_ENVIRONMENT -like "cloud-shell*")
if ([string]::IsNullOrEmpty($OutFile)) {
    $OutFile = "modeler-import-$(Get-Date -Format 'yyyyMMdd-HHmm').json"
    # Local runs default the whole output set into the user's Downloads folder -
    # that's where people look, and an elevated console starts in
    # C:\Windows\System32, where output effectively vanishes. An explicit
    # -OutFile and Cloud Shell (which auto-downloads) are left untouched.
    if (-not $script:IsCloudShell) {
        $dl = Join-Path $HOME 'Downloads'
        if (Test-Path -LiteralPath $dl) { $OutFile = Join-Path $dl $OutFile }
    }
}

function Write-Info { param([string]$m) Write-Host "[i] $m" -ForegroundColor Gray }
function Write-Ok   { param([string]$m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2{ param([string]$m) Write-Host "[!] $m" -ForegroundColor Yellow }

# --- console transcript: captured into the output zip so one run = one file back ---
$script:TranscriptFile = ($OutFile -replace '\.json$', '') + '-console.log'
$script:TranscriptOn = $false
try { Start-Transcript -Path $script:TranscriptFile -Force | Out-Null; $script:TranscriptOn = $true }
catch { Write-Warn2 "Console transcript unavailable ($($_.Exception.Message)) - the zip will omit the run log." }

# The version is the FIRST line of every run - before sign-in, before anything.
# Three local runs in one day executed a fossilized v0.15 while Cloud Shell,
# minutes apart, pulled current code: a saved modeler.ps1 or a replayed
# SHA-pinned command keeps old code alive forever, and an old copy looks fine
# until its output is compared against a fresh one.
Write-Info "Get-NerdioModelerJson $ScriptVersion"
# Stale-copy self-check: compare against the published version marker. Any
# failure (offline, proxy, repo moved) stays silent - freshness advice must
# never break a run. The random query defeats CDN/proxy caching.
try {
    $verUrl = "https://raw.githubusercontent.com/dclawrence003/NME/main/modeler/VERSION?nocache=$(Get-Random)"
    $latestVer = ("$(Invoke-RestMethod -Uri $verUrl -TimeoutSec 5)").Trim()
    if ($latestVer -match '^v[\d.]+$' -and $latestVer -ne $ScriptVersion) {
        Write-Warn2 "THIS COPY IS STALE: it is $ScriptVersion, but the published version is $latestVer."
        Write-Warn2 "Fixes shipped since $ScriptVersion are missing from this run. Delete any saved modeler.ps1, then re-paste:"
        Write-Warn2 "    iex (irm 'https://raw.githubusercontent.com/dclawrence003/NME/main/modeler/Get-NerdioModelerJson.ps1')"
    }
} catch { }

# --- Cloud Shell auto-download (same pattern as Test-NmeDeploymentReadiness) ---
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
# EVERY query is pinned to an explicit subscription list. Two same-day runs of
# the same estate returned 120 pools (Cloud Shell) vs 18 (local PowerShell)
# with zero overlap: each window was signed into a different default scope, and
# an unscoped ARG query silently answers for whatever that happens to be.
# -SubscriptionId (if given) wins; otherwise the enabled subscriptions
# enumerated at startup. ARG caps one request at 1000 subscriptions, so the
# list is chunked and results merged. Empty list (enumeration failed) falls
# back to unscoped rather than dying - the startup warning already said so.
function Invoke-ArgQuery {
    param([string]$Query)
    $scope = @(if ($SubscriptionId.Count -gt 0) { $SubscriptionId } else { $script:ScopeSubIds })
    $chunkList = New-Object System.Collections.ArrayList
    if ($scope.Count -gt 0) {
        for ($i = 0; $i -lt $scope.Count; $i += 1000) {
            [void]$chunkList.Add(@($scope[$i..([Math]::Min($i + 999, $scope.Count - 1))]))
        }
    } else { [void]$chunkList.Add($null) }
    $all = @()
    foreach ($chunk in $chunkList) {
        $skip = $null
        do {
            $body = @{ query = $Query; options = @{ resultFormat = 'objectArray' } }
            if ($null -ne $chunk) { $body.subscriptions = @($chunk) }
            if ($skip) { $body.options.'$skipToken' = $skip }
            $resp = Invoke-AzRestMethod -Method POST -Path "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01" -Payload ($body | ConvertTo-Json -Depth 6)
            if ($resp.StatusCode -ne 200) { throw "Resource Graph query failed (HTTP $($resp.StatusCode)): $($resp.Content)" }
            $parsed = $resp.Content | ConvertFrom-Json
            $all += @($parsed.data)
            $skip = $parsed.'$skipToken'
        } while ($skip)
    }
    return $all
}

# --- Cost Management Query API, one RG scope at a time (skip-safe; see .NOTES) ---
function Get-ActualCostRows {
    param([string]$Scope, [string]$CostType = 'ActualCost')
    # The API dropped support for timeframe 'TheLastMonth' (HTTP 400: "currently not
    # supported") - use an explicit Custom range covering last calendar month (UTC).
    $utcNow = [DateTime]::UtcNow
    $firstOfThisMonth = [DateTime]::new($utcNow.Year, $utcNow.Month, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $lastMonthStart = $firstOfThisMonth.AddMonths(-1)
    $lastMonthEnd = $firstOfThisMonth.AddDays(-1)
    $body = @{
        type = $CostType
        timeframe = 'Custom'
        timePeriod = @{
            from = $lastMonthStart.ToString('yyyy-MM-ddT00:00:00+00:00')
            to   = $lastMonthEnd.ToString('yyyy-MM-ddT23:59:59+00:00')
        }
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

if (-not (Get-AzContext)) {
    Write-Warn2 "Not signed in to Azure. Run Connect-AzAccount first (add -TenantId <tenant-id> if you have several tenants), then run this command again. In Azure Cloud Shell sign-in is automatic."
    if ($script:TranscriptOn) { try { Stop-Transcript | Out-Null } catch { }; $script:TranscriptOn = $false }
    return
}

# --- identity + subscription scope: stated on every run ------------------------
# Two same-day runs against "the same demo environment" produced 120 pools from
# Cloud Shell and 18 from local PowerShell - zero overlap - because the two
# windows were signed into different scopes, and neither console log recorded
# who was signed in or what was reachable. The gap was invisible. Every run now
# states its identity, lists the subscriptions it can see, and pins discovery
# to that explicit list.
$azCtx = Get-AzContext
$script:AcctText = Coalesce $azCtx.Account.Id 'unknown account'
$script:TenText  = Coalesce $azCtx.Tenant.Id  'unknown tenant'
Write-Info "Signed in as $($script:AcctText) - tenant $($script:TenText)."
$script:ScopeSubIds = @()
$script:SubNameById = @{}
try {
    $subsRaw = @()
    $nextPath = "/subscriptions?api-version=2020-01-01"
    while ($nextPath) {
        $resp = Invoke-AzRestMethod -Method GET -Path $nextPath
        if ($resp.StatusCode -ne 200) { throw "HTTP $($resp.StatusCode): $($resp.Content)" }
        $parsed = $resp.Content | ConvertFrom-Json
        $subsRaw += @($parsed.value)
        $nextPath = if ($parsed.nextLink) { ([uri]$parsed.nextLink).PathAndQuery } else { $null }
    }
    foreach ($s in $subsRaw) {
        if ("$($s.state)" -ne 'Enabled') { continue }
        $script:ScopeSubIds += "$($s.subscriptionId)"
        $script:SubNameById["$($s.subscriptionId)".ToLower()] = "$($s.displayName)"
    }
} catch {
    Write-Warn2 "Could not enumerate subscriptions ($($_.Exception.Message)) - discovery will run unscoped against this sign-in's defaults."
}
if ($SubscriptionId.Count -gt 0) {
    $visIds = @{}
    foreach ($id in $script:ScopeSubIds) { $visIds["$id".ToLower()] = $true }
    foreach ($want in $SubscriptionId) {
        if ($script:ScopeSubIds.Count -gt 0 -and -not $visIds["$want".ToLower()]) {
            Write-Warn2 "-SubscriptionId $want is not visible to this sign-in - it will return nothing. Check the account or tenant above."
        }
    }
    Write-Info "Scope: narrowed by -SubscriptionId to $($SubscriptionId.Count) subscription(s)."
} elseif ($script:ScopeSubIds.Count -gt 0) {
    Write-Ok "Scope: $($script:ScopeSubIds.Count) enabled subscription(s) visible to this sign-in:"
    $shown = 0
    foreach ($id in $script:ScopeSubIds) {
        $shown++
        if ($shown -le 25) { Write-Info "    $($script:SubNameById["$id".ToLower()])  ($id)" }
    }
    if ($script:ScopeSubIds.Count -gt 25) { Write-Info "    ...and $($script:ScopeSubIds.Count - 25) more (full list lands in rawdata.json)." }
} else {
    Write-Warn2 "No enabled subscriptions are visible to this sign-in - discovery will find nothing. Check the account or tenant above."
}
# One run covers ONE tenant. If this sign-in can reach others, say so out loud -
# "the environment" may be bigger than what this run can see.
try {
    $tResp = Invoke-AzRestMethod -Method GET -Path "/tenants?api-version=2020-01-01"
    if ($tResp.StatusCode -eq 200) {
        $otherTenants = @((($tResp.Content | ConvertFrom-Json).value) | Where-Object { "$($_.tenantId)" -ne "$($script:TenText)" })
        if ($otherTenants.Count -gt 0) {
            Write-Warn2 "This account can also reach $($otherTenants.Count) other tenant(s). A run covers ONE tenant - host pools there are NOT in this output:"
            foreach ($t in $otherTenants) {
                $tName = Coalesce $t.displayName "$($t.tenantId)"
                Write-Warn2 "    $tName ($($t.tenantId)) - to cover it: Connect-AzAccount -TenantId $($t.tenantId), then run this command again."
            }
        }
    }
} catch { }

# --- Log Analytics query via REST (no Az.OperationalInsights dependency) ------
# Invoke-AzOperationalInsightsQuery ships in Cloud Shell but rarely on laptops -
# a prospect's local-PS run lost ALL telemetry to that missing module. This uses
# Get-AzAccessToken + Invoke-RestMethod, both in Az.Accounts, which anyone who
# can Connect-AzAccount already has. Commercial-cloud endpoint.
function Invoke-LaQuery {
    param([string]$WorkspaceCustomerId, [string]$Query)
    $tok = Get-AzAccessToken -ResourceUrl 'https://api.loganalytics.io' -WarningAction SilentlyContinue
    # Az.Accounts 5.x returns a SecureString token; older versions a plain string.
    # BSTR marshal, not ConvertFrom-SecureString -AsPlainText (that flag is PS7-only).
    $tokenText = if ($tok.Token -is [securestring]) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($tok.Token)
        try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    } else { "$($tok.Token)" }
    $resp = Invoke-RestMethod -Method Post -Uri "https://api.loganalytics.io/v1/workspaces/$WorkspaceCustomerId/query" `
        -Headers @{ Authorization = "Bearer $tokenText" } -ContentType 'application/json' `
        -Body (@{ query = $Query } | ConvertTo-Json -Depth 4 -Compress)
    $table = @($resp.tables) | Select-Object -First 1
    $rows = [System.Collections.Generic.List[object]]::new()
    if ($table) {
        $colNames = @($table.columns | ForEach-Object { "$($_.name)" })
        foreach ($r in @($table.rows)) {
            $o = [ordered]@{}
            for ($i = 0; $i -lt $colNames.Count; $i++) { $o[$colNames[$i]] = $r[$i] }
            $rows.Add([pscustomobject]$o)
        }
    }
    [pscustomobject]@{ Results = $rows }
}

# ------------------------------------------------------------------------- 1. pools
Write-Info "[1/8] Inventorying host pools via Resource Graph..."
try {
$pools = Invoke-ArgQuery -Query @"
resources
| where type =~ 'microsoft.desktopvirtualization/hostpools'
| project id, name, resourceGroup, location, subscriptionId,
          hostPoolType = tostring(properties.hostPoolType),
          maxSessionLimit = toint(properties.maxSessionLimit),
          preferredAppGroupType = tostring(properties.preferredAppGroupType),
          startVMOnConnect = tobool(properties.startVMOnConnect)
"@
} catch {
    if ("$($_.Exception.Message)" -match '(?i)Connect-AzAccount|credential|expired|authentication') {
        Write-Warn2 "Azure sign-in is missing or expired. Run Connect-AzAccount (add -TenantId <tenant-id> if it mentions tenants), then run this command again."
        if ($script:TranscriptOn) { try { Stop-Transcript | Out-Null } catch { }; $script:TranscriptOn = $false }
        return
    }
    throw
}
if ($pools.Count -eq 0) { throw "No host pools visible in the scanned scope. Check the subscription list printed above, Reader access, the signed-in tenant (Connect-AzAccount -TenantId <id>), or -SubscriptionId." }
$poolsBySub = @($pools | Group-Object subscriptionId)
Write-Ok "Found $($pools.Count) host pool(s) across $($poolsBySub.Count) subscription(s):"
foreach ($g in ($poolsBySub | Sort-Object Count -Descending)) {
    $subLabel = Coalesce $script:SubNameById["$($g.Name)".ToLower()] "$($g.Name)"
    Write-Info "    $subLabel : $($g.Count) pool(s)"
}

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
$kqlPrelude = @'
let LookbackDays = __LOOKBACK__d;
let LocalTimeZone = '__TZ__';
let WorkHourFloorPct = 0.20;
let WorkDayFloorPct = 0.25;
let WeeksObserved = todouble(LookbackDays / 7d);
let DowCal = dynamic([__DOWCAL__]);
let ConnRaw = union isfuzzy=true (datatable(TimeGenerated:datetime, State:string, CorrelationId:string, UserName:string, SessionHostName:string, _ResourceId:string)[]), (WVDConnections | project TimeGenerated, State, CorrelationId, UserName, SessionHostName, _ResourceId);
let Sessions = ConnRaw | where TimeGenerated > ago(LookbackDays) | where State == 'Connected' | project CorrelationId, UserName, SessionHostName, HostPoolId = tolower(_ResourceId), StartTime = TimeGenerated | join kind=leftouter (ConnRaw | where TimeGenerated > ago(LookbackDays) | where State == 'Completed' | project CorrelationId, EndTime = TimeGenerated) on CorrelationId | project-away CorrelationId1 | extend EndTime = coalesce(EndTime, min_of(StartTime + 12h, now())) | where EndTime > StartTime;
let Buckets = Sessions | extend Slots = range(bin(StartTime, 15m), bin(EndTime, 15m), 15m) | mv-expand Slot = Slots to typeof(datetime) | summarize ConcurrentUsers = dcount(UserName) by HostPoolId, Slot;
'@
$telemetryKql = $kqlPrelude + @'
let PeakPerHost = Sessions | extend Slots = range(bin(StartTime, 15m), bin(EndTime, 15m), 15m) | mv-expand Slot = Slots to typeof(datetime) | summarize HostConcurrent = dcount(UserName) by HostPoolId, SessionHostName, Slot | summarize HostPeak = max(HostConcurrent) by HostPoolId, SessionHostName | summarize PeakUsersPerHost = max(HostPeak) by HostPoolId;
let Peaks = Buckets | summarize PeakConcurrentUsers = max(ConcurrentUsers) by HostPoolId;
let PoolMau = Sessions | summarize Mau = dcount(UserName) by HostPoolId;
let DayLoads = Buckets | extend DowN = toint(dayofweek(datetime_utc_to_local(Slot, LocalTimeZone)) / 1d) | summarize DayUH = sum(todouble(ConcurrentUsers)) * 0.25 by HostPoolId, DowN | extend DayUH = DayUH / todouble(max_of(toint(DowCal[DowN]), 1));
let WorkDays = DayLoads | join kind=inner (DayLoads | summarize MaxDayUH = max(DayUH) by HostPoolId) on HostPoolId | where DayUH >= MaxDayUH * WorkDayFloorPct | extend ModelerDay = tolong(iff(DowN == 0, 7, DowN)) | summarize WorkDaysList = array_sort_asc(make_list(ModelerDay)) by HostPoolId;
let WorkDaySlots = WorkDays | mv-expand M = WorkDaysList to typeof(long) | extend DowX = toint(iff(M == 7, tolong(0), M)) | summarize DaySlots = sum(todouble(max_of(toint(DowCal[DowX]), 1))) * 4.0 by HostPoolId;
let WorkWindow = Buckets | extend LocalSlot = datetime_utc_to_local(Slot, LocalTimeZone) | extend LocalHour = hourofday(LocalSlot), DowN = toint(dayofweek(LocalSlot) / 1d) | extend ModelerDay = tolong(iff(DowN == 0, 7, DowN)) | join kind=inner WorkDays on HostPoolId | where set_has_element(WorkDaysList, ModelerDay) | summarize SumConcurrent = sum(todouble(ConcurrentUsers)) by HostPoolId, LocalHour | join kind=inner WorkDaySlots on HostPoolId | extend AvgConcurrent = SumConcurrent / DaySlots | join kind=inner Peaks on HostPoolId | where AvgConcurrent >= todouble(PeakConcurrentUsers) * WorkHourFloorPct | summarize StartHour = min(LocalHour), EndHour = max(LocalHour) by HostPoolId | extend WorkDurationMinutes = (EndHour - StartHour + 1) * 60;
let UsageTotals = Buckets | extend LocalSlot = datetime_utc_to_local(Slot, LocalTimeZone) | extend LocalHour = hourofday(LocalSlot), DowN = toint(dayofweek(LocalSlot) / 1d) | extend ModelerDay = tolong(iff(DowN == 0, 7, DowN)) | join kind=leftouter WorkDays on HostPoolId | join kind=leftouter WorkWindow on HostPoolId | extend InWindow = isnotnull(StartHour) and set_has_element(coalesce(WorkDaysList, dynamic([])), ModelerDay) and LocalHour >= StartHour and LocalHour <= EndHour | summarize TotalUH = sum(todouble(ConcurrentUsers)) * 0.25, InWindowUH = sumif(todouble(ConcurrentUsers), InWindow) * 0.25 by HostPoolId | extend WeeklyUH = round(TotalUH / WeeksObserved, 1), WeeklyInWindowUH = round(InWindowUH / WeeksObserved, 1) | extend WeeklyOffUH = round(WeeklyUH - WeeklyInWindowUH, 1);
Peaks
| join kind=leftouter WorkWindow on HostPoolId
| join kind=leftouter WorkDays on HostPoolId
| join kind=leftouter UsageTotals on HostPoolId
| join kind=leftouter PeakPerHost on HostPoolId
| join kind=leftouter PoolMau on HostPoolId
| project HostPoolId, PeakConcurrentUsers, StartHour, WorkDurationMinutes, WorkDaysJson = tostring(WorkDaysList), WeeklyOffUH, PeakUsersPerHost, Mau
'@
# Per-weekday calendar occurrence counts across the lookback (customer TZ).
# A 30-day window holds 5 of some weekdays and 4 of others; normalizing the day
# rule by uniform weeks penalized 4-occurrence days ~20% - a real call center's
# Saturday shift missed the cut by exactly that bias. DowCal[0]=Sunday..[6]=Saturday.
$tzInfo = $null
try { $tzInfo = [TimeZoneInfo]::FindSystemTimeZoneById($TimeZone) } catch { }
if (-not $tzInfo) {
    # Windows PowerShell 5.1 runs on .NET Framework, which doesn't know IANA ids.
    # Map the common ones to Windows ids; the KQL side keeps using IANA regardless.
    $winTz = @{ 'America/New_York' = 'Eastern Standard Time'; 'America/Chicago' = 'Central Standard Time'
                'America/Denver' = 'Mountain Standard Time'; 'America/Phoenix' = 'US Mountain Standard Time'
                'America/Los_Angeles' = 'Pacific Standard Time'; 'Europe/London' = 'GMT Standard Time'
                'Europe/Paris' = 'Romance Standard Time'; 'Europe/Berlin' = 'W. Europe Standard Time'
                'Asia/Kolkata' = 'India Standard Time'; 'Australia/Sydney' = 'AUS Eastern Standard Time' }
    if ($winTz.ContainsKey($TimeZone)) { try { $tzInfo = [TimeZoneInfo]::FindSystemTimeZoneById($winTz[$TimeZone]) } catch { } }
}
$dowCal = @(0, 0, 0, 0, 0, 0, 0)
$nowUtcForCal = [DateTime]::UtcNow
$calStart = if ($tzInfo) { [TimeZoneInfo]::ConvertTimeFromUtc($nowUtcForCal.AddDays(-$LookbackDays), $tzInfo).Date } else { $nowUtcForCal.AddDays(-$LookbackDays).Date }
$calEnd   = if ($tzInfo) { [TimeZoneInfo]::ConvertTimeFromUtc($nowUtcForCal, $tzInfo).Date } else { $nowUtcForCal.Date }
for ($cd = $calStart; $cd -le $calEnd; $cd = $cd.AddDays(1)) { $dowCal[[int]$cd.DayOfWeek]++ }
# both boundary days are partial; when they share a weekday they jointly ~= one occurrence
if ($calStart.DayOfWeek -eq $calEnd.DayOfWeek -and $calStart -ne $calEnd) { $dowCal[[int]$calStart.DayOfWeek]-- }
$dowCalCsv = ($dowCal -join ',')
$telemetryKql = $telemetryKql.Replace('__LOOKBACK__', "$LookbackDays").Replace('__TZ__', $TimeZone).Replace('__DOWCAL__', $dowCalCsv)
$bucketsKql = $kqlPrelude + @'
Buckets | project HostPoolId, SlotUtc = Slot, ConcurrentUsers
'@
$bucketsKql = $bucketsKql.Replace('__LOOKBACK__', "$LookbackDays").Replace('__TZ__', $TimeZone).Replace('__DOWCAL__', $dowCalCsv)
# Sessions incl. disconnected (WVDAgentHealthStatus) - INFORMATIONAL. Connected-basis
# sizing stays; this only feeds a review flag when NME-style counts read higher.
# Separate query + separate catch so a schema surprise can never hurt the core pull.
$sessionsKql = @'
let LookbackDays = __LOOKBACK__d;
let AgentRaw = union isfuzzy=true (datatable(TimeGenerated:datetime, SessionHostName:string, ActiveSessions:long, InactiveSessions:long, _ResourceId:string)[]), (WVDAgentHealthStatus | project TimeGenerated, SessionHostName, ActiveSessions = tolong(ActiveSessions), InactiveSessions = tolong(InactiveSessions), _ResourceId);
AgentRaw | where TimeGenerated > ago(LookbackDays) | extend HostPoolId = tolower(_ResourceId), TotalSessions = coalesce(ActiveSessions, tolong(0)) + coalesce(InactiveSessions, tolong(0)) | summarize HostSessions = max(TotalSessions) by HostPoolId, SessionHostName, Slot = bin(TimeGenerated, 15m) | summarize PoolSessions = sum(HostSessions) by HostPoolId, Slot | summarize PeakSessions = max(PoolSessions) by HostPoolId
'@
$sessionsKql = $sessionsKql.Replace('__LOOKBACK__', "$LookbackDays")
$sessionPeaks = @{}   # poolIdLower -> peak sessions incl. disconnected (max across workspaces)
$rawBuckets = [System.Collections.Generic.List[object]]::new()
$usage = @{}   # poolIdLower -> usage row (keep highest peak if seen in multiple workspaces)
$usageRows = 0
foreach ($wsId in $workspaceIds.Keys) {
    try {
        $wsResp = Invoke-AzRestMethod -Method GET -Path "$wsId`?api-version=2021-06-01"
        if ($wsResp.StatusCode -ne 200) { Write-Warn2 "Cannot read workspace $wsId (HTTP $($wsResp.StatusCode)) - skipping."; continue }
        $customerId = ($wsResp.Content | ConvertFrom-Json).properties.customerId
        $result = Invoke-LaQuery -WorkspaceCustomerId $customerId -Query $telemetryKql
        foreach ($row in $result.Results) {
            $key = $row.HostPoolId.ToLower()
            $peak = [int]$row.PeakConcurrentUsers
            if (-not $usage.ContainsKey($key) -or $peak -gt [int]$usage[$key].PeakConcurrentUsers) { $usage[$key] = $row }
            $usageRows++
        }
        Write-Ok "Workspace $($wsId.Split('/')[-1]): usage for $(@($result.Results).Count) pool(s)."
        try {
            $bres = Invoke-LaQuery -WorkspaceCustomerId $customerId -Query $bucketsKql
            $wsName = $wsId.Split('/')[-1]
            foreach ($brow in @($bres.Results)) { $rawBuckets.Add([pscustomobject]@{ Workspace = $wsName; HostPoolId = $brow.HostPoolId; SlotUtc = $brow.SlotUtc; ConcurrentUsers = $brow.ConcurrentUsers }) }
        } catch { Write-Warn2 "Raw usage buckets skipped for $($wsId.Split('/')[-1]) ($($_.Exception.Message)) - aggregates unaffected." }
        try {
            $sres = Invoke-LaQuery -WorkspaceCustomerId $customerId -Query $sessionsKql
            foreach ($srow in @($sres.Results)) {
                $skey = $srow.HostPoolId.ToLower()
                $sp = [int]$srow.PeakSessions
                if (-not $sessionPeaks.ContainsKey($skey) -or $sp -gt $sessionPeaks[$skey]) { $sessionPeaks[$skey] = $sp }
            }
        } catch { }   # informational only - missing table/columns just means no session flag
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
$storageCandidates = [System.Collections.Generic.List[object]]::new()
$profileNameRx = '(?i)prof|fslogix|upd|userdisk|usrprof|msix|app[-_]?attach'
# One slow account must never abort the rest, and a skipped size must never be
# silent: stats retry once, then fall back to the Azure Monitor FileCapacity
# metric (platform-computed - fast where on-demand stats on huge shares hit the
# fixed 100s timeout). Whatever still fails is NAMED and counted in the census.
function Get-FileShareUsedGbFromMetrics {
    param([string]$AccountId, [string]$ShareName)
    try {
        $uri = "$AccountId/fileServices/default/providers/Microsoft.Insights/metrics?api-version=2019-07-01&metricnames=FileCapacity&aggregation=Average&interval=PT1H&timespan=PT2H" + "&`$filter=FileShare eq '$ShareName'"
        $r = Invoke-AzRestMethod -Method GET -Path $uri
        if ($r.StatusCode -ne 200) { return $null }
        $m = @((($r.Content | ConvertFrom-Json).value)) | Select-Object -First 1
        $pts = @($m.timeseries | ForEach-Object { $_.data } | Where-Object { $null -ne $_.average -and $_.average -gt 0 })
        if ($pts.Count -gt 0) { return [Math]::Round(@($pts)[-1].average / 1GB, 1) }
    } catch { }
    $null
}
# --- credential circuit breaker ---------------------------------------------------
# Live failure mode (Don's Cloud Shell run 2026-08-07): mid-run, Cloud Shell's
# token service started returning garbage ("ManagedIdentityCredential ... invalid:
# ExpiresOn") when the script's ARM token needed a refresh. The user IS signed in;
# the shell's token provider glitched - and every later Azure call fails instantly
# and identically. Without a breaker that meant 72 accounts mislabeled "slow or
# unreadable" and ~150 identical error dumps. Now: first credential-shaped
# failure -> short pause -> one cheap probe -> if still broken, ONE honest banner
# and every remaining Azure call is skipped fast under an accurate label.
$script:AuthBroken = $false
function Test-CredError { param([string]$Message) [bool]($Message -match '(?i)credentials have not been set up|Connect-AzAccount|ManagedIdentityCredential') }
function Confirm-AzureAuthAlive {
    if ($script:AuthBroken) { return $false }
    Start-Sleep -Seconds 8
    try { Invoke-AzRestMethod -Method GET -Path "/subscriptions?api-version=2020-01-01" | Out-Null; return $true }
    catch {
        $script:AuthBroken = $true
        Write-Warn2 "AZURE TOKEN REFRESH IS BROKEN in this shell session - you ARE signed in, but the shell's token service returned a bad response (the Cloud Shell 'ExpiresOn' glitch) when a mid-run token refresh came due. Every remaining Azure call would fail the same way, so they are being skipped fast instead. FIX: restart Cloud Shell (or run Connect-AzAccount), then run this command again - a fresh session completes normally."
        return $false
    }
}
$storSkipped = [System.Collections.Generic.List[string]]::new()
$storAuthSkipped = [System.Collections.Generic.List[string]]::new()
$censusShares = 0; $censusSized = 0
$storAccts = @()
try {
    $storAccts = Invoke-ArgQuery -Query @'
resources
| where type =~ 'microsoft.storage/storageaccounts'
| project id, name, resourceGroup, location, accountKind = tostring(kind), skuName = tostring(sku.name)
'@
} catch {
    Write-Warn2 "Storage account inventory failed ($($_.Exception.Message)) - Azure Files profile storage not modeled."
}
foreach ($sa in $storAccts) {
    if ($script:AuthBroken) { $storAuthSkipped.Add($sa.name); continue }
    try {
        # Classification by SKU, not account kind: provisioned-v2 StandardV2/PremiumV2
        # share the FileStorage kind, and each SKU implies its billing basis.
        $sku = "$($sa.skuName)"
        $isZrs = $sku -match '(?i)zrs'
        $isPremium = $sku -match '^(?i)Premium'
        $isV2 = $sku -match '(?i)V2_'
        $provisionedModel = $isPremium -or $isV2   # premium (v1/v2) and standardV2 bill PROVISIONED; v1 standard bills USED
        $shResp = Invoke-AzRestMethod -Method GET -Path "$($sa.id)/fileServices/default/shares?api-version=2023-01-01"
        if ($shResp.StatusCode -ne 200) { continue }   # no file service or not visible
        foreach ($sh in @((($shResp.Content | ConvertFrom-Json).value))) {
            $shName = "$($sh.name)"
            $smb = ($null -eq $sh.properties.enabledProtocols) -or ("$($sh.properties.enabledProtocols)" -match '(?i)smb')
            if (-not $smb) { continue }
            if (-not ($provisionedModel -or $shName -match $profileNameRx)) { continue }
            $censusShares++
            $usedGb = $null; $usedSource = ''
            try {
                $stResp = Invoke-AzRestMethod -Method GET -Path "$($sa.id)/fileServices/default/shares/$($shName)?api-version=2023-01-01&`$expand=stats"
                if ($stResp.StatusCode -ne 200) { $stResp = Invoke-AzRestMethod -Method GET -Path "$($sa.id)/fileServices/default/shares/$($shName)?api-version=2023-01-01&`$expand=stats" }
                if ($stResp.StatusCode -eq 200) {
                    $stProps = ($stResp.Content | ConvertFrom-Json).properties
                    if ($null -ne $stProps.shareUsageBytes) { $usedGb = [Math]::Round($stProps.shareUsageBytes / 1GB, 1); $usedSource = 'stats' }
                }
            } catch { }
            if ($null -eq $usedGb) {
                $usedGb = Get-FileShareUsedGbFromMetrics -AccountId $sa.id -ShareName $shName
                if ($null -ne $usedGb) { $usedSource = 'metrics' }
            }
            if ($null -ne $usedGb) { $censusSized++ }
            $provGb = if ($null -ne $sh.properties.shareQuota) { [int]$sh.properties.shareQuota } else { $null }
            $tierLabel = if ($isPremium) { "Azure Files Premium$(if ($isV2) { ' v2' }) ($(if ($isZrs) { 'ZRS' } else { 'LRS' }))" }
                         elseif ($isV2) { 'Azure Files Standard (provisioned v2)' }
                         else { 'Azure Files Standard' }
            # Modeler storage enum (dropdown order): 1=Files Premium LRS, 2=Files Premium ZRS,
            # 3=ANF Standard, 4=ANF Premium, 5=ANF Ultra. No standard-Files option exists.
            $tierNote = if (-not $isPremium) { "the Modeler has no standard Files tier, so this models as Azure Files Premium (LRS) on $(if ($provisionedModel) { 'PROVISIONED' } else { 'USED' }) GB; conservative" } else { '' }
            $storageCandidates.Add([pscustomobject]@{
                ResourceId = $sa.id; BillingUnit = "$($sa.name)/$shName"
                Kind = $tierLabel; Sku = $sku; BillingModel = $(if ($provisionedModel) { 'Provisioned' } else { 'Used' })
                Account = $sa.name; Share = $shName; RG = $sa.resourceGroup; Region = $sa.location
                ProvisionedGb = $provGb; UsedGb = $usedGb; UsedSource = $usedSource
                ProvisionedIops = $sh.properties.provisionedIops; ThroughputMibps = $sh.properties.provisionedBandwidthMibps
                NameMatch = [bool]($shName -match $profileNameRx)
                StorageTypeEnum = if ($isPremium -and $isZrs) { 2 } else { 1 }
                TierNote = $tierNote
                Classification = ''; Evidence = 'none'; Confidence = ''
                ServesPools = @(); Notes = ''
            })
        }
    } catch {
        if (Test-CredError "$($_.Exception.Message)") {
            if (Confirm-AzureAuthAlive) { $storSkipped.Add("$($sa.name) (transient auth)") }
            else { $storAuthSkipped.Add($sa.name) }
        } else { $storSkipped.Add($sa.name) }
    }
}
if ($storSkipped.Count -gt 0) {
    Write-Warn2 "$($storSkipped.Count) storage account(s) skipped (slow or unreadable): $($storSkipped -join ', '). Their shares were NOT checked - they appear nowhere below."
}
if ($storAuthSkipped.Count -gt 0) {
    Write-Warn2 "$($storAuthSkipped.Count) storage account(s) NOT checked because the Azure token broke (see banner above) - nothing wrong with these accounts; a fresh-session re-run reads them: $($storAuthSkipped -join ', ')"
}
# ANF is quantified at its BILLING boundary: Azure bills the capacity POOL's
# provisioned size; volumes only carve quota from it. Pricing per-volume can
# badly undercount real spend, so candidates here are capacity pools - member
# SMB volumes listed, pools shared with non-SMB/non-profile volumes flagged.
if ($script:AuthBroken) { Write-Warn2 "Azure NetApp Files discovery skipped - Azure token broken (see banner above); a fresh-session re-run covers it." }
else {
try {
    $anfVols = Invoke-ArgQuery -Query @'
resources
| where type =~ 'microsoft.netapp/netappaccounts/capacitypools/volumes'
| project id, name, resourceGroup, location,
          provisionedBytes = tolong(properties.usageThreshold),
          protocols = properties.protocolTypes,
          serviceLevel = tostring(properties.serviceLevel)
'@
    $anfPools = @()
    try {
        $anfPools = Invoke-ArgQuery -Query @'
resources
| where type =~ 'microsoft.netapp/netappaccounts/capacitypools'
| project id, name, poolBytes = tolong(properties.size), serviceLevel = tostring(properties.serviceLevel)
'@
    } catch { }
    $poolInfo = @{}
    foreach ($cp in $anfPools) { $poolInfo["$($cp.id)".ToLowerInvariant()] = $cp }
    foreach ($grp in (@($anfVols) | Group-Object { ("$($_.id)" -split '(?i)/volumes/')[0].ToLowerInvariant() })) {
        $parentId = $grp.Name
        $volsAll = @($grp.Group)
        $volsSmb = @($volsAll | Where-Object { ((@($_.protocols) | ForEach-Object { "$_" }) -join ',') -match '(?i)cifs|smb' })
        if ($volsSmb.Count -eq 0) { continue }   # capacity pool with no SMB volumes - not an FSLogix candidate
        $censusShares++
        $cp = $poolInfo[$parentId]
        $poolGb = if ($cp -and $cp.poolBytes) { [int][Math]::Round($cp.poolBytes / 1GB) }
                  else { [int][Math]::Round((($volsAll | Measure-Object provisionedBytes -Sum).Sum) / 1GB) }
        $lvl = if ($cp) { "$($cp.serviceLevel)" } else { "$($volsSmb[0].serviceLevel)" }
        $anfEnum = switch -Regex ($lvl) { '^(?i)standard$' { 3; break } '^(?i)premium$' { 4; break } '^(?i)ultra$' { 5; break } default { 4 } }
        # used GB best effort from the VolumeLogicalSize metric per SMB volume
        $usedSum = $null
        foreach ($v in $volsSmb) {
            try {
                $mr = Invoke-AzRestMethod -Method GET -Path "$($v.id)/providers/Microsoft.Insights/metrics?api-version=2019-07-01&metricnames=VolumeLogicalSize&aggregation=Average&interval=PT1H&timespan=PT2H"
                if ($mr.StatusCode -eq 200) {
                    $mm = @((($mr.Content | ConvertFrom-Json).value)) | Select-Object -First 1
                    $pts = @($mm.timeseries | ForEach-Object { $_.data } | Where-Object { $null -ne $_.average -and $_.average -gt 0 })
                    if ($pts.Count -gt 0) { $usedSum = [Math]::Round((Coalesce $usedSum 0) + @($pts)[-1].average / 1GB, 1) }
                }
            } catch { }
        }
        if ($null -ne $usedSum) { $censusSized++ }
        $poolName = ($parentId -split '/')[-1]
        $anfAcct = ($parentId -split '/')[-3]
        $memberNames = @($volsSmb | ForEach-Object { ("$($_.name)" -split '/')[-1] })
        $sharedNote = if ($volsAll.Count -gt $volsSmb.Count) { "capacity pool shared with $($volsAll.Count - $volsSmb.Count) non-SMB volume(s) - pool billed as a whole" } else { '' }
        $storageCandidates.Add([pscustomobject]@{
            ResourceId = $parentId; BillingUnit = "$anfAcct/$poolName (capacity pool)"
            Kind = "Azure NetApp Files $lvl (capacity pool)"; Sku = "ANF $lvl"; BillingModel = 'Provisioned'
            Account = $anfAcct; Share = $poolName; RG = $volsSmb[0].resourceGroup; Region = $volsSmb[0].location
            ProvisionedGb = $poolGb; UsedGb = $usedSum; UsedSource = $(if ($null -ne $usedSum) { 'metrics' } else { '' })
            ProvisionedIops = $null; ThroughputMibps = $null
            NameMatch = [bool](@($memberNames | Where-Object { $_ -match $profileNameRx }).Count -gt 0)
            StorageTypeEnum = $anfEnum
            TierNote = "$(if ($lvl -notmatch '^(?i)(standard|premium|ultra)$') { "ANF service level '$lvl' unrecognized - modeled as ANF Premium; verify" })"
            Classification = ''; Evidence = 'none'; Confidence = ''
            ServesPools = @(); Notes = "$("volumes: $($memberNames -join ', ')")$(if ($sharedNote) { "; $sharedNote" })"
        })
    }
} catch {
    if (Test-CredError "$($_.Exception.Message)") { Confirm-AzureAuthAlive | Out-Null; Write-Warn2 "Azure NetApp Files discovery hit the token failure - ANF not read this run; a fresh-session re-run covers it." }
    else { Write-Warn2 "Azure NetApp Files discovery failed ($($_.Exception.Message)) - ANF profile storage not modeled; Azure Files results above are unaffected." }
}
}

# ---- share -> pool mapping evidence (best effort - the prompt pass decides) ------
# IP-first: StorageFileLogs caller IPs joined to WVDConnections session-host IPs.
# All joins happen in POWERSHELL so evidence still lands when storage logs and
# AVD logs live in different workspaces. Username overlap = fallback evidence.
$mapEvidence = [System.Collections.Generic.List[object]]::new()
if ($storageCandidates.Count -gt 0 -and $workspaceIds.Keys.Count -gt 0 -and -not $script:AuthBroken) {
    Write-Info "      Checking Log Analytics for file-access logs (share -> pool evidence)..."
    # storage accounts may ship StorageFileLogs to workspaces the AVD side never uses
    $mapWorkspaceIds = @{}
    foreach ($k in $workspaceIds.Keys) { $mapWorkspaceIds[$k] = $true }
    foreach ($acctId in (@($storageCandidates | Where-Object { $_.Kind -notmatch 'NetApp' } | ForEach-Object { $_.ResourceId }) | Select-Object -Unique)) {
        try {
            $dsResp = Invoke-AzRestMethod -Method GET -Path "$acctId/fileServices/default/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
            if ($dsResp.StatusCode -eq 200) {
                foreach ($ds in ((($dsResp.Content | ConvertFrom-Json).value))) {
                    if ($ds.properties.workspaceId) { $mapWorkspaceIds[$ds.properties.workspaceId.ToLower()] = $true }
                }
            }
        } catch { }
    }
    $mapSharesKql = @'
let LookbackDays = __LOOKBACK__d;
let FileOps = union isfuzzy=true (datatable(TimeGenerated:datetime, AccountName:string, ObjectKey:string, CallerIpAddress:string)[]), (StorageFileLogs | project TimeGenerated, AccountName, ObjectKey, CallerIpAddress);
let Ops = FileOps | where TimeGenerated > ago(LookbackDays) | extend Parts = split(ObjectKey, '/') | extend Share = tolower(tostring(Parts[2])) | where isnotempty(Share) | extend AccountName = tolower(AccountName);
let ShareIps = Ops | extend Ip = tostring(split(CallerIpAddress, ':')[0]) | where isnotempty(Ip) | summarize OpsCount = count() by RowType = 'shareip', AccountName, Share, Ip | extend UserGuess = '';
let ShareUsers = Ops | extend U1 = extract(@'(?i)Profiles?[_-]([^/\\.]+)\.vhdx?', 1, ObjectKey) | extend U2 = extract(@'(?i)/([^/]+?)_S-1-[0-9-]+', 1, ObjectKey) | extend UserGuess = tolower(coalesce(U1, U2)) | where isnotempty(UserGuess) | summarize OpsCount = count() by RowType = 'shareuser', AccountName, Share, UserGuess | extend Ip = '';
ShareIps | union ShareUsers | project RowType, AccountName, Share, Ip, UserGuess, OpsCount
'@
    $mapPoolsKql = @'
let LookbackDays = __LOOKBACK__d;
let Conn = union isfuzzy=true (datatable(TimeGenerated:datetime, State:string, UserName:string, SessionHostIPAddress:string, _ResourceId:string)[]), (WVDConnections | project TimeGenerated, State, UserName, SessionHostIPAddress, _ResourceId) | where TimeGenerated > ago(LookbackDays) | where State == 'Connected';
let HostIps = Conn | where isnotempty(SessionHostIPAddress) | summarize by RowType = 'hostip', Ip = tostring(SessionHostIPAddress), HostPoolId = tolower(_ResourceId) | extend UserGuess = '';
let PoolUsers = Conn | summarize by RowType = 'pooluser', UserGuess = tolower(tostring(split(UserName, '@')[0])), HostPoolId = tolower(_ResourceId) | extend Ip = '';
HostIps | union PoolUsers | project RowType, Ip, UserGuess, HostPoolId
'@
    $mapSharesKql = $mapSharesKql.Replace('__LOOKBACK__', "$LookbackDays")
    $mapPoolsKql = $mapPoolsKql.Replace('__LOOKBACK__', "$LookbackDays")
    $shareRows = [System.Collections.Generic.List[object]]::new()
    $poolRows = [System.Collections.Generic.List[object]]::new()
    foreach ($wsId in $mapWorkspaceIds.Keys) {
        try {
            $wsResp = Invoke-AzRestMethod -Method GET -Path "$wsId`?api-version=2021-06-01"
            if ($wsResp.StatusCode -ne 200) { continue }
            $customerId = ($wsResp.Content | ConvertFrom-Json).properties.customerId
            foreach ($row in @((Invoke-LaQuery -WorkspaceCustomerId $customerId -Query $mapSharesKql).Results)) { $shareRows.Add($row) }
            if ($workspaceIds.ContainsKey($wsId)) {
                foreach ($row in @((Invoke-LaQuery -WorkspaceCustomerId $customerId -Query $mapPoolsKql).Results)) { $poolRows.Add($row) }
            }
        } catch { }
    }
    $poolNameById = @{}
    foreach ($p in $pools) { $poolNameById["$($p.id)".ToLowerInvariant()] = $p.name }
    $ipToPools = @{}
    foreach ($r in ($poolRows | Where-Object { $_.RowType -eq 'hostip' })) { $ipToPools["$($r.Ip)"] = @(@($ipToPools["$($r.Ip)"]) + @("$($r.HostPoolId)") | Where-Object { $_ } | Select-Object -Unique) }
    $userToPools = @{}
    foreach ($r in ($poolRows | Where-Object { $_.RowType -eq 'pooluser' })) { $userToPools["$($r.UserGuess)"] = @(@($userToPools["$($r.UserGuess)"]) + @("$($r.HostPoolId)") | Where-Object { $_ } | Select-Object -Unique) }
    foreach ($cand in ($storageCandidates | Where-Object { $_.Kind -notmatch 'NetApp' })) {
        $acct = $cand.Account.ToLowerInvariant(); $shr = $cand.Share.ToLowerInvariant()
        $mine = @($shareRows | Where-Object { "$($_.AccountName)" -eq $acct -and "$($_.Share)" -eq $shr })
        # IP evidence first (strong): distinct session-host IPs seen opening this share, per pool
        $ipHits = @{}
        foreach ($r in ($mine | Where-Object { $_.RowType -eq 'shareip' })) {
            foreach ($pid_ in @($ipToPools["$($r.Ip)"])) { $ipHits[$pid_] = 1 + (Coalesce $ipHits[$pid_] 0) }
        }
        # username-overlap fallback (weak): distinct extracted usernames per pool, >= 2
        $userHits = @{}
        foreach ($r in ($mine | Where-Object { $_.RowType -eq 'shareuser' })) {
            foreach ($pid_ in @($userToPools["$($r.UserGuess)"])) { $userHits[$pid_] = 1 + (Coalesce $userHits[$pid_] 0) }
        }
        $hitIds = @()
        if ($ipHits.Keys.Count -gt 0) { $hitIds = @($ipHits.Keys); $cand.Evidence = 'logs-ip'; $cand.Confidence = 'high' }
        elseif (@($userHits.Keys | Where-Object { $userHits[$_] -ge 2 }).Count -gt 0) { $hitIds = @($userHits.Keys | Where-Object { $userHits[$_] -ge 2 }); $cand.Evidence = 'logs-user'; $cand.Confidence = 'medium' }
        if ($hitIds.Count -gt 0) {
            $cand.ServesPools = @($hitIds | ForEach-Object { $poolNameById["$_"] } | Where-Object { $_ } | Select-Object -Unique)   # ALL pools kept - no cap
            foreach ($pid_ in $hitIds) { $mapEvidence.Add([pscustomobject]@{ Account = $cand.Account; Share = $cand.Share; HostPoolId = $pid_; Evidence = $cand.Evidence; Strength = (Coalesce $ipHits[$pid_] $userHits[$pid_]) }) }
        }
    }
    $mappedCount = @($storageCandidates | Where-Object { $_.ServesPools.Count -gt 0 }).Count
    if ($mappedCount -gt 0) { Write-Ok "File-access logs found - $mappedCount store(s) carry pool evidence in the ledger's ServesPools column." }
    else { Write-Info "      No StorageFileLogs data (file-share diagnostics not enabled) - ServesPools stays empty in the ledger; the AVD admin can annotate it." }
}

# ---- automatic classification + census -------------------------------------------
$junkRx = '(?i)^pvcn?-|^mq(ha|prod|trace)|sftp|backup|tracelog'
$appAttachRx = '(?i)msix|app[-_]?attach'
foreach ($cand in $storageCandidates) {
    $cand.Classification = if ($cand.Share -match $appAttachRx) { 'AppAttach' }
                           elseif ($cand.NameMatch) { 'Profiles' }
                           elseif ($cand.Share -match $junkRx) { 'NonAVD' }
                           else { 'Unknown' }
    if ($cand.Evidence -eq 'none' -and $cand.NameMatch) { $cand.Evidence = 'name-match'; $cand.Confidence = 'low' }
}
if ($storageCandidates.Count -gt 0) {
    $storageCandidates | Sort-Object Account, Share | Select-Object Kind, Account, Share, Region, ProvisionedGb, UsedGb, Classification, @{n='ServesPools'; e={ @($_.ServesPools | Select-Object -First 6) -join ', ' }} |
        Format-Table -AutoSize | Out-String -Width 220 | Write-Host
} else {
    Write-Info "No storage candidates found - fsLogix stays off in the model (add by hand in the Modeler if profiles live outside Azure's view)."
}

# Storage is NEVER modeled in the Modeler JSON (Don's ruling, v0.15): every
# discovered store goes to the storage ledger CSV, with automatic classification
# and any log-derived pool evidence. No prompts, no runner data entry - the run
# flows straight through, and the ledger is the storage deliverable.
if ($storageCandidates.Count -gt 0) {
    Write-Info "Storage policy: all $($storageCandidates.Count) store(s) recorded in the storage ledger; the Modeler JSON carries host pools only (fsLogix off everywhere)."
}
$censusUnsized = $censusShares - $censusSized
Write-Info "Storage census: $(@($storAccts).Count) account(s) found, $($storAuthSkipped.Count) blocked by the token failure, $($storSkipped.Count) skipped (slow/unreadable), $censusShares candidate store(s), $censusSized sized, $censusUnsized without a size."
$gap = 0.0
foreach ($cand in ($storageCandidates | Where-Object { $_.Classification -in @('Profiles', 'Unknown') })) {
    if ($cand.BillingModel -eq 'Provisioned' -and $null -ne $cand.ProvisionedGb -and $null -ne $cand.UsedGb) { $gap += [Math]::Max(0, $cand.ProvisionedGb - $cand.UsedGb) }
}
if ($gap -gt 0) { Write-Info "Provisioned-over-used gap across provisioned-model profile/unknown storage: $([Math]::Round($gap)) GB - the gap Nerdio storage auto-scale reclaims." }

# --------------------------------------------------------------- 6. assemble the model
Write-Info "[6/8] Assembling deployments..."
$adminTasks = @'
{"0":[{"id":0,"isEnabled":true,"hoursWithoutNerdio":5,"hoursWithNerdio":0.5},{"id":1,"isEnabled":true,"hoursWithoutNerdio":2,"hoursWithNerdio":0.5},{"id":2,"isEnabled":true,"hoursWithoutNerdio":16,"hoursWithNerdio":4},{"id":3,"isEnabled":true,"hoursWithoutNerdio":20,"hoursWithNerdio":0.5},{"id":4,"isEnabled":false,"hoursWithoutNerdio":0,"hoursWithNerdio":2},{"id":5,"isEnabled":true,"hoursWithoutNerdio":16,"hoursWithNerdio":4}],"1":[{"id":6,"isEnabled":true,"hoursWithoutNerdio":5,"hoursWithNerdio":0.5},{"id":7,"isEnabled":true,"hoursWithoutNerdio":10,"hoursWithNerdio":2},{"id":8,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":0.5},{"id":9,"isEnabled":true,"hoursWithoutNerdio":2,"hoursWithNerdio":0.5},{"id":10,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":5}],"2":[{"id":11,"isEnabled":true,"hoursWithoutNerdio":10,"hoursWithNerdio":2.5},{"id":12,"isEnabled":true,"hoursWithoutNerdio":8,"hoursWithNerdio":0.5},{"id":13,"isEnabled":true,"hoursWithoutNerdio":10,"hoursWithNerdio":0.5},{"id":14,"isEnabled":true,"hoursWithoutNerdio":8,"hoursWithNerdio":2},{"id":15,"isEnabled":true,"hoursWithoutNerdio":5,"hoursWithNerdio":1},{"id":16,"isEnabled":true,"hoursWithoutNerdio":20,"hoursWithNerdio":2},{"id":17,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":0.5},{"id":18,"isEnabled":true,"hoursWithoutNerdio":10,"hoursWithNerdio":2},{"id":19,"isEnabled":true,"hoursWithoutNerdio":2.5,"hoursWithNerdio":0.5},{"id":20,"isEnabled":true,"hoursWithoutNerdio":8,"hoursWithNerdio":2},{"id":21,"isEnabled":true,"hoursWithoutNerdio":2,"hoursWithNerdio":0.5},{"id":22,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":0},{"id":23,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":0.5},{"id":24,"isEnabled":true,"hoursWithoutNerdio":5,"hoursWithNerdio":1},{"id":25,"isEnabled":true,"hoursWithoutNerdio":2,"hoursWithNerdio":1},{"id":26,"isEnabled":false,"hoursWithoutNerdio":0,"hoursWithNerdio":0.5}]}
'@ | ConvertFrom-Json
$globalSettings = '{"enterpriseDiscount":0,"windows365Discount":0,"azureType":1,"nerdioLicenseCost":{"type":0,"perUserCost":null,"windows365PerUserCost":null,"monthMinimumCost":null},"nerdioResourceCost":3}' | ConvertFrom-Json
$nameCounts = @{}
foreach ($p in $pools) { $nameCounts[$p.name] = 1 + (Coalesce $nameCounts[$p.name] 0) }
# Modeler disk-size tiers (from the UI dropdown); actual sizes snap UP to the nearest offered tier
$diskTiers = @(128, 256, 512, 1024, 2048, 4096)
$deployments = [System.Collections.Generic.List[object]]::new()
$review = [System.Collections.Generic.List[object]]::new()
foreach ($p in $pools) {
    $key = $p.id.ToLower()
    $u = $usage[$key]
    # representative VM spec = the pool's most common SIZE first, then the most
    # common ephemeral/image combo among hosts of that size. The old single
    # grouping keyed on vmSize+ephemeral+imageId at once, so two same-size hosts
    # running different images split into count-1 groups: a 4-host pool
    # (D2as x2 + D4as + D8as) became a 4-way tie, and tie order is not stable in
    # Windows PowerShell - the same command minutes apart returned D2as from
    # Cloud Shell (the true mode) and a one-off D8as from 5.1. Every pick now
    # sorts Count desc THEN name asc, so every shell chooses identically.
    $spec = $null
    if ($poolVmIds.ContainsKey($key)) {
        $hostSpecs = @($poolVmIds[$key] | ForEach-Object { $vmSpecs[$_] } | Where-Object { $_ })
        if ($hostSpecs.Count -gt 0) {
            $sizeGrp = @($hostSpecs | Group-Object vmSize |
                Sort-Object @{Expression='Count';Descending=$true}, @{Expression='Name';Descending=$false})[0]
            $spec = @($sizeGrp.Group | Group-Object ephemeral, imageId |
                Sort-Object @{Expression='Count';Descending=$true}, @{Expression='Name';Descending=$false})[0].Group[0]
        }
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
    $mau = if ($u -and $u.PSObject.Properties['Mau'] -and "$($u.Mau)" -ne '') { [int]$u.Mau } else { 0 }
    $sessPeak = if ($sessionPeaks.ContainsKey($key)) { [int]$sessionPeaks[$key] } else { 0 }
    $flags = @()
    if ($peak -eq 0) { $flags += 'no telemetry (users set to 1)' }
    if ($peak -gt 0 -and $sessPeak -ge [int][Math]::Ceiling(1.15 * $peak)) { $flags += "sessions incl. disconnected peaked at $sessPeak vs $peak connected - NME console counts read higher; compute is sized on connected users" }
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
        PeakUsers = $peak; MAU = $(if ($mau -gt 0) { $mau } else { '' }); Window = "$startHr`:00+$([Math]::Round($duration/60.0,2))h"; Days = ($workDays -join ',')
        Overtime = "$otPct% x $($otHours)h"; Flags = ($flags -join '; ')
    })
}
# ---- storage stays OUT of the model: ledger only (v0.15 ruling) ------------------
# No carrier deployments, no fsLogix blocks, no prompts. The storage ledger CSV
# (written with the review CSV below) is the complete storage deliverable.

$model = [ordered]@{
    schema = 4
    name = $ModelName
    description = "Generated from actuals, lookback $($LookbackDays)d, $(Get-Date -Format 'yyyy-MM-dd')"
    deployments = $deployments
    globalSettings = $globalSettings
}

# ------------------------------------------------------------------- 6. output + download
Write-Info "[7/8] Writing $OutFile..."
Write-Utf8NoBom -FilePath $OutFile -Content ($model | ConvertTo-Json -Depth 30 -Compress)

# ---------------------------------------- 7. actual spend (optional, skip-safe)
if ($script:AuthBroken -and -not $SkipCosts) {
    Write-Warn2 "[8/8] Cost pull skipped - Azure token broken (see banner above); a fresh-session re-run fills ActualMo in."
}
if (-not $SkipCosts -and -not $script:AuthBroken) {
    Write-Info "[8/8] Pulling last month's ACTUAL spend for session-host VMs + disks (skips any scope without cost visibility)..."
    $costByResource = @{}
    $costCurrency = ''
    $rgScopes = @{}
    foreach ($vmId in $vmSpecs.Keys) { $parts = $vmId -split '/'; $rgScopes["/subscriptions/$($parts[2])/resourcegroups/$($parts[4])"] = $parts[4] }
    # storage ledger gets actual spend too - add each candidate's resource group scope
    foreach ($cand in $storageCandidates) { if ($cand.ResourceId) { $parts = $cand.ResourceId -split '/'; $rgScopes["/subscriptions/$($parts[2])/resourcegroups/$($parts[4])"] = $parts[4] } }
    $costOk = 0; $costSkipped = @()
    foreach ($scope in $rgScopes.Keys) {
        # AmortizedCost spreads RI/Savings Plan purchases across usage (honest number for
        # reserved customers); PAYG-type offers reject it, so fall back to ActualCost.
        try { $res = Get-ActualCostRows -Scope $scope -CostType 'AmortizedCost' } catch { $res = @{ ok = $false; status = "error: $($_.Exception.Message)" } }
        if (-not $res.ok) {
            try { $res = Get-ActualCostRows -Scope $scope -CostType 'ActualCost' } catch { $res = @{ ok = $false; status = "error: $($_.Exception.Message)" } }
        }
        if (-not $res.ok) {
            if ((Test-CredError "$($res.status)") -and -not (Confirm-AzureAuthAlive)) {
                Write-Warn2 "Cost pull stopped at the token failure - remaining scopes untried; a fresh-session re-run fills ActualMo in."
                break
            }
            $costSkipped += [pscustomobject]@{ RG = $rgScopes[$scope]; Reason = "$($res.status)" }; continue
        }
        $costOk++
        foreach ($row in $res.rows) {
            $costByResource[$row.ResourceId] = (Coalesce $costByResource[$row.ResourceId] 0) + $row.Cost
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
                    $sum += (Coalesce $costByResource[$vmId] 0)
                    $vmSpec = $vmSpecs[$vmId]
                    if ($vmSpec -and $vmSpec.osDiskId) { $sum += (Coalesce $costByResource[$vmSpec.osDiskId] 0) }
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
$review | Sort-Object Pool | Export-Csv -Path $reviewFile -NoTypeInformation
Write-Ok "Review table (including ActualMo when pulled) also written to: $reviewFile"
# ---- the storage ledger: EVERY discovered store, whatever the model decided ------
$ledgerFile = $null
if ($storageCandidates.Count -gt 0) {
    $ledgerFile = ($OutFile -replace '\.json$', '') + '-storage-ledger.csv'
    $costLookup = @{}
    if (Get-Variable -Name costByResource -ErrorAction SilentlyContinue) {
        foreach ($k in $costByResource.Keys) { $costLookup[$k.ToLowerInvariant()] = $costByResource[$k] }
    }
    $storageCandidates | Sort-Object Classification, Account, Share | ForEach-Object {
        [pscustomobject]@{
            BillingUnit = $_.BillingUnit; Account = $_.Account; Share = $_.Share
            Kind = $_.Kind; Sku = $_.Sku; BillingModel = $_.BillingModel; Region = $_.Region; RG = $_.RG
            ProvisionedGb = $_.ProvisionedGb; UsedGb = $_.UsedGb; UsedSource = $_.UsedSource
            ProvisionedIops = $_.ProvisionedIops; ThroughputMibps = $_.ThroughputMibps
            Classification = $_.Classification; Evidence = $_.Evidence; Confidence = $_.Confidence
            ServesPools = (@($_.ServesPools) -join '; ')
            ActualMo = $(if ($costLookup.ContainsKey("$($_.ResourceId)".ToLowerInvariant())) { [Math]::Round($costLookup["$($_.ResourceId)".ToLowerInvariant()], 2) } else { '' })
            Notes = "$($_.Notes)$(if ($_.TierNote) { "; $($_.TierNote)" })".TrimStart('; ')
        }
    } | Export-Csv -Path $ledgerFile -NoTypeInformation
    Write-Ok "Storage ledger written: $ledgerFile ($($storageCandidates.Count) store(s) - classification, evidence, pools, sizes, and actual cost where visible)."
}
$poolRowsOnly = @($review | Where-Object { $_.Pool -notlike 'FSLogix:*' -and $_.Pool -notlike 'AppAttach:*' })
$withUsage = @($poolRowsOnly | Where-Object { $_.PeakUsers -gt 0 }).Count
$flagged   = @($poolRowsOnly | Where-Object { $_.Flags }).Count
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
# ---- raw decision data: everything observed, so adjustments never need a re-run ---
$rawFile = ($OutFile -replace '\.json$', '') + '-rawdata.json'
$bucketsFile = ($OutFile -replace '\.json$', '') + '-usage-buckets.csv'
try {
    $raw = [ordered]@{
        meta = [ordered]@{
            tool = 'Get-NerdioModelerJson.ps1'; version = $ScriptVersion; generatedUtc = [DateTime]::UtcNow.ToString('o')
            parameters = [ordered]@{ ModelName = $ModelName; LookbackDays = $LookbackDays; TimeZone = $TimeZone; SubscriptionId = @($SubscriptionId); SkipCosts = [bool]$SkipCosts }
            identity = [ordered]@{
                account = "$($script:AcctText)"; tenantId = "$($script:TenText)"
                scopeSubscriptions = @(foreach ($sid in $script:ScopeSubIds) { [ordered]@{ id = "$sid"; name = "$($script:SubNameById["$sid".ToLower()])" } })
            }
            notes = 'usage-buckets.csv holds per-pool 15-minute concurrency (UTC slots; convert with meta.parameters.TimeZone). Buckets include every reachable workspace - when a pool logs to several, the aggregates used the max-peak workspace, so filter buckets by Workspace to match. PeakUsersPerHost is an aggregate (per-host slot detail is not exported). Not re-derivable offline: a longer lookback, or telemetry that was not flowing during this run.'
        }
        pools = @($pools)
        poolVmIds = @($poolVmIds.Keys | ForEach-Object { [ordered]@{ poolId = $_; vmIds = @($poolVmIds[$_]) } })
        vmSpecs = @($vmSpecs.Keys | ForEach-Object { [ordered]@{ vmId = $_; spec = $vmSpecs[$_] } })
        workspaces = @($workspaceIds.Keys)
        usageAggregates = @($usage.Values)
        sessionPeaks = @($sessionPeaks.Keys | ForEach-Object { [ordered]@{ poolId = $_; peakSessionsInclDisconnected = $sessionPeaks[$_] } })
        storageCandidates = @($storageCandidates)
        mapEvidence = @($(if (Get-Variable -Name mapEvidence -ErrorAction SilentlyContinue) { $mapEvidence } else { @() }))
        costByResource = @($(if (Get-Variable -Name costByResource -ErrorAction SilentlyContinue) { $costByResource.Keys | ForEach-Object { [ordered]@{ resourceId = $_; cost = $costByResource[$_] } } } else { @() }))
        costSkipped = @($(if (Get-Variable -Name costSkipped -ErrorAction SilentlyContinue) { $costSkipped } else { @() }))
        costCurrency = $(if (Get-Variable -Name costCurrency -ErrorAction SilentlyContinue) { $costCurrency } else { $null })
    }
    Write-Utf8NoBom -FilePath $rawFile -Content ($raw | ConvertTo-Json -Depth 12)
    if ($rawBuckets.Count -gt 0) { Write-Utf8NoBom -FilePath $bucketsFile -Content ((@($rawBuckets | ConvertTo-Csv -NoTypeInformation)) -join [Environment]::NewLine) }
    $bucketsNote = if ($rawBuckets.Count -gt 0) { " + $bucketsFile ($($rawBuckets.Count) usage slots)" } else { '' }
    Write-Ok "Raw decision data written: $rawFile$bucketsNote - adjustments can be re-derived from the zip without another customer run."
} catch {
    Write-Warn2 "Raw data export failed ($($_.Exception.Message)) - zip will carry the standard outputs only."
}

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
    $zipItems = @(@($OutFile, $reviewFile, $ledgerFile, $rawFile, $bucketsFile, $script:TranscriptFile) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    Compress-Archive -Path $zipItems -DestinationPath $zipFile -Force
    $zipOk = $true
    Write-Ok "Packaged into one file: $zipFile (model JSON + review CSV + storage ledger + raw decision data + console log)"
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
