# Dev fixture: offline end-to-end test for Get-NerdioModelerJson.ps1. NOT for customers.
# Mocks every Az/REST call plus Read-Host (scripted triage answers), runs the real
# script, validates JSON + review CSV + storage ledger + zip package.
# Run on any pwsh 7+: pwsh -File Test-ModelerOffline.ps1
$poolAId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.desktopvirtualization/hostpools/PoolA'
$wsId    = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.operationalinsights/workspaces/ws1'
$wsId2   = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.operationalinsights/workspaces/ws2'   # v0.17.3: network-blocked (NSP)
$saProf  = '/subscriptions/s1/resourcegroups/rg-stor/providers/microsoft.storage/storageaccounts/stprofiles'
$saGen   = '/subscriptions/s1/resourcegroups/rg-stor/providers/microsoft.storage/storageaccounts/stgen'
# v0.19: ANF lives in subscription s2 so ONE run exercises both cost paths:
#   s1 -> one subscription-level query (429 w/ Retry-After first, then 200)
#   s2 -> subscription-level query refused (403) -> per-RG fallback -> rg-anf
#         throttled through the whole first pass -> recovered on the second pass
$anfPool = '/subscriptions/s2/resourcegroups/rg-anf/providers/microsoft.netapp/netappaccounts/anf1/capacitypools/pool1'
# v0.20: two more pools sharing rg2 (density floor + single-session rule + shared-RG cost split)
$poolTinyId   = '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.desktopvirtualization/hostpools/PoolTiny'
$poolSingleId = '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.desktopvirtualization/hostpools/PoolSingle'

# v0.15: storage is ledger-only, no prompts - nothing to mock for input.

function Get-AzContext { [pscustomobject]@{ Name = 'mock'; Account = [pscustomobject]@{ Id = 'don@mock.test' }; Tenant = [pscustomobject]@{ Id = 'ten-1' } } }
$global:ArgSubScopes = @()   # v0.17: every ARG payload's subscriptions array, for the scope-pinning check
$global:CostAnfCalls = 0     # v0.19: rg-anf answers 429 for 6 calls (one full retry budget), 200 on the 7th (second pass)
$global:CostS1SubCalls = 0   # v0.19: subscription-level s1 query: 429 + Retry-After on the first call, 200 on the second
$global:CostS2SubCalls = 0   # v0.19: subscription-level s2 query: refused (403) -> per-RG fallback
$global:CostFilterRGs = @()  # v0.19: ResourceGroupName filter values seen on the s1 subscription query
function Invoke-AzRestMethod {
    param([string]$Method, [string]$Path, [string]$Payload, [string]$Uri)
    if ($Method -eq 'GET' -and $Path.StartsWith('/subscriptions?')) {
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ value = @(
            @{ subscriptionId = 's1'; displayName = 'Sub One'; state = 'Enabled' },
            @{ subscriptionId = 's2'; displayName = 'Sub Two'; state = 'Enabled' },
            @{ subscriptionId = 's3'; displayName = 'Sub Gone'; state = 'Disabled' }
        ) } | ConvertTo-Json -Depth 10) }
    }
    if ($Method -eq 'GET' -and $Path.StartsWith('/tenants?')) {
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ value = @(
            @{ tenantId = 'ten-1'; displayName = 'Mock Tenant' },
            @{ tenantId = 'ten-2'; displayName = 'Other Tenant' }
        ) } | ConvertTo-Json -Depth 10) }
    }
    if ($Method -eq 'POST' -and $Path -like '*Microsoft.ResourceGraph*') {
        $argBody = $Payload | ConvertFrom-Json
        $global:ArgSubScopes += , @($argBody.subscriptions)
        $q = $argBody.query
        if ($q -match 'sessionhosts') {
            $data = @(
                @{ id = "$poolAId/sessionhosts/sh1"; vmId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm1' },
                @{ id = "$poolAId/sessionhosts/sh2"; vmId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm2' },
                @{ id = "$poolAId/sessionhosts/sh3"; vmId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm3' },
                # v0.20: two pools SHARE rg2 - one with a session limit that computes below the
                # Modeler's 0.1 density floor, one single-user pooled (limit 1)
                @{ id = "$poolTinyId/sessionhosts/sh4"; vmId = '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.compute/virtualmachines/vm4' },
                @{ id = "$poolSingleId/sessionhosts/sh5"; vmId = '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.compute/virtualmachines/vm5' }
            )
        } elseif ($q -match 'virtualmachines') {
            # v0.17.2 regression shape: two D8s hosts run DIFFERENT images (the old
            # vmSize+ephemeral+imageId grouping split them into count-1 groups and
            # tied with the one-off D4s; 5.1's unstable sort could then pick D4s).
            # Correct representative: size mode D8s_v5, marketplace image, disk d1.
            $data = @(
                @{ id = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm1'; vmSize = 'Standard_D8s_v5'; ephemeral = $false; imageId = ''; osDiskId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/disks/d1' },
                @{ id = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm2'; vmSize = 'Standard_D8s_v5'; ephemeral = $false; imageId = '/subscriptions/s1/resourcegroups/rg-img/providers/microsoft.compute/galleries/g1/images/win11/versions/1.0.0'; osDiskId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/disks/d2' },
                @{ id = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm3'; vmSize = 'Standard_D4s_v5'; ephemeral = $false; imageId = ''; osDiskId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/disks/d3' },
                @{ id = '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.compute/virtualmachines/vm4'; vmSize = 'Standard_D64s_v5'; ephemeral = $false; imageId = ''; osDiskId = '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.compute/disks/d4' },
                @{ id = '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.compute/virtualmachines/vm5'; vmSize = 'Standard_D16s_v5'; ephemeral = $false; imageId = ''; osDiskId = '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.compute/disks/d5' }
            )
        } elseif ($q -match 'microsoft.compute/disks') {
            $data = @(
                @{ id = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/disks/d1'; diskSizeGb = 128; diskSku = 'Premium_LRS' },
                @{ id = '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.compute/disks/d4'; diskSizeGb = 512; diskSku = 'StandardSSD_LRS' },
                @{ id = '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.compute/disks/d5'; diskSizeGb = 127; diskSku = 'Standard_LRS' }
            )
        } elseif ($q -match 'storageaccounts') {
            $data = @(
                @{ id = $saProf; name = 'stprofiles'; resourceGroup = 'rg-stor'; location = 'eastus'; accountKind = 'FileStorage'; skuName = 'Premium_ZRS' },
                @{ id = $saGen;  name = 'stgen';      resourceGroup = 'rg-stor'; location = 'eastus'; accountKind = 'StorageV2';   skuName = 'Standard_LRS' }
            )
        } elseif ($q -match 'capacitypools/volumes') {
            $data = @(@{ id = "$anfPool/volumes/anfprof"
                         name = 'anf1/pool1/anfprof'; resourceGroup = 'rg-anf'; location = 'eastus'
                         provisionedBytes = 2199023255552; protocols = @('CIFS'); serviceLevel = 'Premium' })
        } elseif ($q -match 'capacitypools') {
            $data = @(@{ id = $anfPool; name = 'anf1/pool1'; poolBytes = 4398046511104; serviceLevel = 'Premium' })
        } else {
            $data = @(
                @{ id = $poolAId; name = 'PoolA'; resourceGroup = 'rg1'; location = 'eastus'; subscriptionId = 's1'; hostPoolType = 'Pooled'; maxSessionLimit = 10; preferredAppGroupType = 'Desktop'; startVMOnConnect = $true },
                @{ id = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.desktopvirtualization/hostpools/PoolEmpty'; name = 'PoolEmpty'; resourceGroup = 'rg1'; location = 'eastus'; subscriptionId = 's1'; hostPoolType = 'Pooled'; maxSessionLimit = 5; preferredAppGroupType = 'Desktop'; startVMOnConnect = $false },
                # v0.20: limit 2 on a D64 = 0.03 users/vCPU -> must floor to the Modeler minimum 0.1
                @{ id = $poolTinyId; name = 'PoolTiny'; resourceGroup = 'rg2'; location = 'eastus'; subscriptionId = 's1'; hostPoolType = 'Pooled'; maxSessionLimit = 2; preferredAppGroupType = 'Desktop'; startVMOnConnect = $true },
                # v0.20: limit 1 = single-user pooled (experience 3) -> density 1.0, never the 1/16 the limit implies
                @{ id = $poolSingleId; name = 'PoolSingle'; resourceGroup = 'rg2'; location = 'eastus'; subscriptionId = 's1'; hostPoolType = 'Pooled'; maxSessionLimit = 1; preferredAppGroupType = 'Desktop'; startVMOnConnect = $true }
            )   # v0.18: PoolEmpty has no session hosts and no telemetry - must be excluded from the JSON
        }
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ data = $data } | ConvertTo-Json -Depth 10) }
    }
    if ($Method -eq 'GET' -and $Path -like '*fileServices/default/providers/Microsoft.Insights/diagnosticSettings*') {
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ value = @() } | ConvertTo-Json -Depth 10) }
    }
    if ($Method -eq 'GET' -and $Path -like '*Microsoft.Insights/metrics*') {
        return [pscustomobject]@{ StatusCode = 404; Content = '{}' }   # metrics fallback not exercised offline
    }
    if ($Method -eq 'GET' -and $Path -like '*diagnosticSettings*') {
        if ($Path -like "$poolAId*") {
            return [pscustomobject]@{ StatusCode = 200; Content = (@{ value = @(@{ properties = @{ workspaceId = $wsId } }, @{ properties = @{ workspaceId = $wsId2 } }) } | ConvertTo-Json -Depth 10) }
        }
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ value = @() } | ConvertTo-Json -Depth 10) }
    }
    if ($Method -eq 'GET' -and $Path -like "$wsId2*") {
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ properties = @{ customerId = '22222222-2222-4222-8222-222222222222' } } | ConvertTo-Json -Depth 10) }
    }
    if ($Method -eq 'GET' -and $Path -like "$wsId*") {
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ properties = @{ customerId = '11111111-2222-3333-4444-555555555555' } } | ConvertTo-Json -Depth 10) }
    }
    if ($Method -eq 'GET' -and $Path -like '*fileServices/default/shares/*') {
        $used = if ($Path -like '*profiles01*') { 429496729600 } else { 214748364800 }   # 400GB / 200GB
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ properties = @{ shareUsageBytes = $used } } | ConvertTo-Json -Depth 10) }
    }
    if ($Method -eq 'GET' -and $Path -like '*fileServices/default/shares*') {
        if ($Path -like "$saProf*") {
            $v = @(@{ name = 'profiles01'; properties = @{ shareQuota = 1024; enabledProtocols = 'SMB' } })
        } else {
            $v = @(
                @{ name = 'data';         properties = @{ shareQuota = 100; enabledProtocols = 'SMB' } },
                @{ name = 'userprofiles'; properties = @{ shareQuota = 500; enabledProtocols = 'SMB' } },
                @{ name = 'msixapps';     properties = @{ shareQuota = 300; enabledProtocols = 'SMB' } }
            )
        }
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ value = $v } | ConvertTo-Json -Depth 10) }
    }
    if ($Method -eq 'POST' -and $Path -like '*Microsoft.CostManagement/query*') {
        $rows = @()
        $throttled = '{"error":{"message":"Too many requests. Please retry."}}'
        if ($Path -like '/subscriptions/s1/providers/*') {
            # v0.19 fast path: one subscription-level query, filtered to the RGs that matter.
            $global:CostS1SubCalls++
            try { $global:CostFilterRGs = @((($Payload | ConvertFrom-Json).dataset.filter.and | Where-Object { $_.dimensions.name -eq 'ResourceGroupName' }).dimensions.values) } catch { }
            if ($global:CostS1SubCalls -eq 1) {
                return [pscustomobject]@{ StatusCode = 429; Content = $throttled; Headers = @{ 'Retry-After' = '7' } }
            }
            $rows += ,@(100.50, '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm1', 'USD')
            $rows += ,@(50.25,  '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm2', 'USD')
            $rows += ,@(10.00,  '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/disks/d1', 'USD')
            # v0.20: rg1 holds ONLY PoolA's hosts, and last month it also billed a VM + disk that
            # no longer exist (the pool was rebuilt) - that spend belongs to PoolA, flagged.
            $rows += ,@(30.00,  '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm-gen7-1', 'USD')
            $rows += ,@(5.00,   '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/disks/vm-gen7-1_osdisk', 'USD')
            # v0.20: rg2 is SHARED by PoolTiny (1 host) and PoolSingle (1 host): matched rows
            # go by id, the unmatched $30 splits 50/50 by host count, flagged as an estimate.
            $rows += ,@(20.00,  '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.compute/virtualmachines/vm4', 'USD')
            $rows += ,@(10.00,  '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.compute/virtualmachines/vm5', 'USD')
            $rows += ,@(30.00,  '/subscriptions/s1/resourcegroups/rg2/providers/microsoft.compute/virtualmachines/vm-old-9', 'USD')
            $rows += ,@(42.00,  $saProf.ToLower(), 'USD')
        } elseif ($Path -like '/subscriptions/s2/providers/*') {
            # v0.19 fallback trigger: subscription-level query refused -> per-RG path.
            $global:CostS2SubCalls++
            return [pscustomobject]@{ StatusCode = 403; Content = '{"error":{"message":"The client does not have authorization to perform action Microsoft.CostManagement/query/action over scope /subscriptions/s2"}}' }
        } elseif ($Path -like '*resourcegroups/rg-anf*') {
            # v0.19 second pass: a scope throttled through its whole first-pass budget
            # (6 attempts) must be recovered after the cooldown, not skipped.
            $global:CostAnfCalls++
            if ($global:CostAnfCalls -le 6) {
                return [pscustomobject]@{ StatusCode = 429; Content = $throttled; Headers = @{ 'x-ms-ratelimit-microsoft.consumption-tenant-retry-after' = '3' } }
            }
            $rows += ,@(77.00, $anfPool.ToLower(), 'USD')
        } elseif ($Path -like '*resourcegroups/rg-stor*') {
            $rows += ,@(42.00, $saProf.ToLower(), 'USD')
        } else {
            $rows += ,@(100.50, '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm1', 'USD')
            $rows += ,@(50.25,  '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm2', 'USD')
            $rows += ,@(10.00,  '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/disks/d1', 'USD')
        }
        $c = @{ properties = @{ columns = @(@{name='Cost'},@{name='ResourceId'},@{name='Currency'}); rows = $rows } }
        return [pscustomobject]@{ StatusCode = 200; Content = ($c | ConvertTo-Json -Depth 10) }
    }
    return [pscustomobject]@{ StatusCode = 404; Content = '{}' }
}
# v0.13+: Log Analytics via REST. Mock the REST layer so the tables->objects
# adapter is exercised. v0.14 adds the two map queries (share evidence + pool ips).
# v0.20: Cloud Shell's token relay fails the first two asks with the exact live error,
# then answers. The script must retry (with printed waits), then CACHE the token for
# the rest of the run - so the counter stays at 3 however many queries follow.
# LaTokenMode 'dead' (second run below) never answers: the run must finish, say
# TELEMETRY NOT COLLECTED, and give up after two full retry budgets (12 asks).
$global:LaTokenMode = 'flaky'
$global:LaTokenCalls = 0
function Get-AzAccessToken {
    param([string]$ResourceUrl)
    $global:LaTokenCalls++
    $cloudShellError = "ManagedIdentityCredential authentication failed: [Managed Identity] Error Code: invalid_request Error Message: Timeout waiting for token from portal. Audience: https://api.loganalytics.io`nSee the troubleshooting guide for more information. https://aka.ms/azsdk/net/identity/managedidentitycredential/troubleshoot"
    if ($global:LaTokenMode -eq 'dead') { throw $cloudShellError }
    if ($global:LaTokenCalls -le 2) { throw $cloudShellError }
    [pscustomobject]@{ Token = 'mock-token'; ExpiresOn = [DateTimeOffset]::Now.AddHours(1) }
}
function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $ContentType, $Body, $TimeoutSec)
    if ("$Uri" -match 'modeler/VERSION') { return 'v0.20' }   # stale-copy self-check: report current
    if ("$Uri" -notmatch 'api\.loganalytics\.io') { throw "unexpected Invoke-RestMethod uri in test: $Uri" }
    if ("$Uri" -match '22222222') { throw 'Response status code does not indicate success: 403 (Forbidden). NspValidationFailedError: Access to workspace ws2 from 1.2.3.4 is denied. To allow access from public networks, change the workspace Networking settings or add it to a Network Security Perimeter.' }
    $q = ($Body | ConvertFrom-Json).query
    $pid_ = $poolAId.ToLower()
    if ($q -match 'Buckets \| project HostPoolId, SlotUtc') {
        return ('{"tables":[{"name":"PrimaryResult","columns":[{"name":"HostPoolId"},{"name":"SlotUtc"},{"name":"ConcurrentUsers"}],"rows":[["PID","2026-08-05T13:00:00Z","5"],["PID","2026-08-05T13:15:00Z","7"],["PID","2026-08-05T13:30:00Z","6"]]}]}'.Replace('PID', $pid_) | ConvertFrom-Json)
    }
    if ($q -match 'WVDAgentHealthStatus') {
        return ('{"tables":[{"name":"PrimaryResult","columns":[{"name":"HostPoolId"},{"name":"PeakSessions"}],"rows":[["PID","60"]]}]}'.Replace('PID', $pid_) | ConvertFrom-Json)
    }
    if ($q -match 'StorageFileLogs') {
        # share evidence rows: one caller-IP row for profiles01 (strong), plus two username rows (would be fallback)
        return ('{"tables":[{"name":"PrimaryResult","columns":[{"name":"RowType"},{"name":"AccountName"},{"name":"Share"},{"name":"Ip"},{"name":"UserGuess"},{"name":"OpsCount"}],"rows":[["shareip","stprofiles","profiles01","10.0.0.4","","50"],["shareuser","stprofiles","profiles01","","user1","20"],["shareuser","stprofiles","profiles01","","user2","20"]]}]}' | ConvertFrom-Json)
    }
    if ($q -match "'hostip'") {
        return ('{"tables":[{"name":"PrimaryResult","columns":[{"name":"RowType"},{"name":"Ip"},{"name":"UserGuess"},{"name":"HostPoolId"}],"rows":[["hostip","10.0.0.4","","PID"],["pooluser","","user1","PID"],["pooluser","","user2","PID"]]}]}'.Replace('PID', $pid_) | ConvertFrom-Json)
    }
    return ('{"tables":[{"name":"PrimaryResult","columns":[{"name":"HostPoolId"},{"name":"PeakConcurrentUsers"},{"name":"StartHour"},{"name":"WorkDurationMinutes"},{"name":"WorkDaysJson"},{"name":"WeeklyOffUH"},{"name":"PeakUsersPerHost"},{"name":"Mau"}],"rows":[["PID","40","8","600","[1,2,3,4,5]","84","9","120"]]}]}'.Replace('PID', $pid_) | ConvertFrom-Json)
}

Remove-Item /tmp/test-model*.* -Force -ErrorAction SilentlyContinue
$env:MODELER_FAST_RETRY = '1'   # v0.19: skip every throttle wait and the 90s cooldown in the harness
& "$PSScriptRoot/../Get-NerdioModelerJson.ps1" -SkipDownload -OutFile /tmp/test-model.json -ModelName 'TEST'
# snapshot run 1's counters, then run again with a token relay that never answers (v0.20)
$run1 = @{ LaTokenCalls = $global:LaTokenCalls; CostS1SubCalls = $global:CostS1SubCalls; CostS2SubCalls = $global:CostS2SubCalls; CostAnfCalls = $global:CostAnfCalls; CostFilterRGs = @($global:CostFilterRGs) }
$global:LaTokenMode = 'dead'; $global:LaTokenCalls = 0
$global:CostS1SubCalls = 0; $global:CostS2SubCalls = 0; $global:CostAnfCalls = 0; $global:CostFilterRGs = @()
Write-Host "`n--- SECOND RUN: Log Analytics token never issued ---"
& "$PSScriptRoot/../Get-NerdioModelerJson.ps1" -SkipDownload -OutFile /tmp/test-model-dead.json -ModelName 'TEST-DEAD'
Remove-Item Env:MODELER_FAST_RETRY -ErrorAction SilentlyContinue

Write-Host "`n--- VALIDATION ---"
$m = Get-Content /tmp/test-model.json -Raw | ConvertFrom-Json
$csv = Import-Csv /tmp/test-model-review.csv
$ledger = if (Test-Path /tmp/test-model-storage-ledger.csv) { Import-Csv /tmp/test-model-storage-ledger.csv } else { @() }
$a = $m.deployments | Where-Object { $_.name -eq 'PoolA' }
$tiny = $m.deployments | Where-Object { $_.name -like 'PoolTiny*' }
$single = $m.deployments | Where-Object { $_.name -like 'PoolSingle*' }
$rowPoolA = $csv | Where-Object { $_.Pool -eq 'PoolA' }
$rowEmpty = $csv | Where-Object { $_.Pool -eq 'PoolEmpty' }
$rowTiny = $csv | Where-Object { $_.Pool -eq 'PoolTiny' }
$rowSingle = $csv | Where-Object { $_.Pool -eq 'PoolSingle' }
$m2 = Get-Content /tmp/test-model-dead.json -Raw | ConvertFrom-Json
$csv2 = Import-Csv /tmp/test-model-dead-review.csv
$row2PoolA = $csv2 | Where-Object { $_.Pool -eq 'PoolA' }
$raw2 = Get-Content /tmp/test-model-dead-rawdata.json -Raw | ConvertFrom-Json
$log2 = if (Test-Path /tmp/test-model-dead-console.log) { Get-Content /tmp/test-model-dead-console.log -Raw } else { '' }
$lProf = $ledger | Where-Object { $_.Share -eq 'profiles01' }
$lUser = $ledger | Where-Object { $_.Share -eq 'userprofiles' }
$lMsix = $ledger | Where-Object { $_.Share -eq 'msixapps' }
$lAnf  = $ledger | Where-Object { $_.Share -eq 'pool1' }
Remove-Item /tmp/zipcheck -Recurse -Force -ErrorAction SilentlyContinue
$zipOk = Test-Path /tmp/test-model.zip
if ($zipOk) { Expand-Archive /tmp/test-model.zip -DestinationPath /tmp/zipcheck -Force }
$logPath = '/tmp/zipcheck/test-model-console.log'
$rawJson = if (Test-Path /tmp/zipcheck/test-model-rawdata.json) { Get-Content /tmp/zipcheck/test-model-rawdata.json -Raw | ConvertFrom-Json } else { $null }
$rawBucketsCsv = if (Test-Path /tmp/zipcheck/test-model-usage-buckets.csv) { Import-Csv /tmp/zipcheck/test-model-usage-buckets.csv } else { @() }
$log = if (Test-Path $logPath) { Get-Content $logPath -Raw } else { '' }

$checks = [ordered]@{
    'schema=4'                          = ($m.schema -eq 4)
    '3 deployments (pools only)'        = (@($m.deployments).Count -eq 3)
    'PoolA users=40 abs=0'              = ($a.users.total -eq 40 -and $a.users.absentPercent -eq 0)
    'PoolA density 1.13 (obs 9/8)'      = ($a.workload.maxUsersPerVCpu -eq 1.13)
    'PoolA window 8+10h M-F'            = ($a.autoScale.workStartHour -eq 8 -and $a.autoScale.workDurationMinutes -eq 600)
    'PoolA fsLogix stays off'           = ($a.fsLogix.enabled -eq $false)
    'review: MAU column (PoolA 120)'    = ($rowPoolA.MAU -eq '120')
    'session flag fires (60 vs 40)'     = ($rowPoolA.Flags -match 'sessions incl\. disconnected peaked at 60 vs 40 connected')
    'review has NO storage rows'        = (@($csv | Where-Object { $_.Pool -like 'FSLogix*' -or $_.Pool -like 'AppAttach*' }).Count -eq 0)
    'NO storage deployments at all'     = (@($m.deployments | Where-Object { $_.name -like '*FSLogix*' -or $_.name -like '*storage*' }).Count -eq 0)
    'every deployment fsLogix off'      = (@($m.deployments | Where-Object { $_.fsLogix.enabled -eq $true }).Count -eq 0)
    'data share never a candidate'      = (@($ledger | Where-Object { $_.Share -eq 'data' }).Count -eq 0)
    'ledger: 4 rows, all classified'    = (@($ledger).Count -eq 4 -and @($ledger | Where-Object { $_.Classification }).Count -eq 4)
    'ledger: profiles01 high logs-ip'   = ($lProf.Classification -eq 'Profiles' -and $lProf.Evidence -eq 'logs-ip' -and $lProf.Confidence -eq 'high' -and $lProf.ServesPools -eq 'PoolA')
    'ledger: userprofiles used-basis'   = ($lUser.Classification -eq 'Profiles' -and $lUser.BillingModel -eq 'Used' -and $lUser.Evidence -eq 'name-match')
    'ledger: msix classified appattach' = ($lMsix.Classification -eq 'AppAttach')
    'ledger: anf capacity pool 4096'    = ($lAnf.Classification -eq 'Profiles' -and $lAnf.ProvisionedGb -eq '4096' -and $lAnf.BillingUnit -match 'capacity pool' -and $lAnf.Notes -match 'anfprof')
    'ledger: stprofiles ActualMo 42'    = ($lProf.ActualMo -eq '42')
    'census line printed'               = ($log -match 'Storage census: 2 account\(s\) found, 0 blocked by the token failure, 0 skipped')
    'ledger-only policy line printed'   = ($log -match 'Storage policy: all 4 store\(s\) recorded in the storage ledger')
    'ActualMo: PoolA 195.75 (id + rebuilt)' = ($rowPoolA.ActualMo -eq '195.75' -and $rowPoolA.ActualBasis -eq 'by id + resource group (hosts rebuilt)' -and $rowPoolA.Flags -match 'ActualMo: 35 in rg1 billed to 1 VM\(s\) that are not current hosts \(hosts rebuilt since the billing month\)')
    'ActualMo: rg2 split by host count'     = ($rowTiny.ActualMo -eq '35' -and $rowSingle.ActualMo -eq '25' -and $rowTiny.ActualBasis -match 'host-count share' -and $rowSingle.Flags -match '15 is this pool.s host-count share \(1 of 2 hosts\) of 30 unmatched VM/disk spend in rg2, which is shared by PoolSingle, PoolTiny \(estimate\)')
    'ActualMo: empty pool blank basis'      = ($rowEmpty.ActualMo -eq '0' -and $rowEmpty.ActualBasis -eq '')
    'cost: summary explains the split'      = ($log -match 'Attributed to session hosts \+ disks: 255\.75 \(190\.75 by resource id; 65 by resource group because hosts were rebuilt since the billing month, of which 30 is a host-count split' -and $log -match 'Storage accounts in those groups: 119' -and $log -match 'Hosts were rebuilt since the billing month in 1 pool\(s\)')
    'token: retried, then cached (3 asks)'  = ($run1.LaTokenCalls -eq 3 -and $log -match 'Azure did not issue a Log Analytics token \(ManagedIdentityCredential authentication failed' -and $log -match 'waiting 5s, then asking again \(attempt 1 of 6\)' -and $log -match 'waiting 10s, then asking again \(attempt 2 of 6\)' -and $log -match 'Log Analytics token issued on attempt 3')
    'PoolTiny: density floored to 0.1'      = ($tiny.workload.maxUsersPerVCpu -eq 0.1 -and $tiny.experience -eq 1 -and $rowTiny.Density -eq '0.1' -and $rowTiny.Flags -match 'density raised to the Modeler minimum 0\.1')
    'PoolSingle: exp 3, density 1.0'        = ($single.experience -eq 3 -and $single.workload.maxUsersPerVCpu -eq 1 -and $single.workload.disk.size -eq 128 -and $single.workload.disk.type -eq 'Standard_LRS' -and $rowSingle.Flags -notmatch 'density from session limit' -and $rowSingle.Flags -match 'disk 127GB snapped up to 128GB tier')
    'import pre-flight: 3/3 pass, no fixes' = ($log -match 'Import pre-flight: 3/3 deployments pass the Modeler.s import checks\.' -and $log -notmatch 'Import pre-flight corrected')
    'rawdata: costAttribution + telemetry'  = (@($rawJson.costAttribution).Count -eq 4 -and (@($rawJson.costAttribution | Where-Object { $_.poolId -eq $poolAId })[0].byResourceGroup -eq 35) -and (@($rawJson.costAttribution | Where-Object { $_.poolId -eq $poolAId })[0].rebuiltVmsBilled -eq 1) -and $rawJson.telemetry.collected -eq $true -and @($rawJson.telemetry.workspacesBlockedByNetwork).Count -eq 1)
    'dead run: TELEMETRY NOT COLLECTED'     = ($log2 -match 'TELEMETRY NOT COLLECTED - the usage queries never ran: Azure would not issue a Log Analytics token' -and $log2 -match 'RE-RUN THIS COMMAND' -and $log2 -notmatch 'no WVDConnections data found')
    'dead run: workspaces named NOT QUERIED' = (([regex]::Matches($log2, 'NOT QUERIED - Azure would not issue a Log Analytics token')).Count -eq 2 -and $log2 -match 'Share->pool evidence NOT COLLECTED')
    'dead run: gave up after 2 budgets (12)' = ($global:LaTokenCalls -eq 12 -and $log2 -match 'attempt 5 of 6' -and $log2 -notmatch 'attempt 6 of 6')
    'dead run: file says so everywhere'     = ($m2.description -match 'USAGE NOT COLLECTED \(Log Analytics token failure\)' -and $row2PoolA.Flags -match 'usage NOT collected this run \(no Log Analytics token - re-run\); users set to 1' -and $row2PoolA.PeakUsers -eq '0' -and (@($m2.deployments | Where-Object { $_.name -eq 'PoolA (no usage data)' })).Count -eq 1)
    'dead run: rawdata telemetry block'     = ($raw2.telemetry.collected -eq $false -and @($raw2.telemetry.workspacesNotQueried_tokenFailure).Count -eq 2 -and @($raw2.telemetry.poolWorkspaces).Count -eq 1)
    'dead run: rest of the run completed'   = ((Test-Path /tmp/test-model-dead.zip) -and $log2 -match 'Import pre-flight: 3/3 deployments pass' -and $log2 -match 'Storage ledger written' -and $log2 -match 'Model written')
    'admin tasks on pool deployment'    = (@($a.administrative.tasks.'2').Count -eq 16)
    'zip holds json+csv+ledger+log'     = ($zipOk -and (Test-Path /tmp/zipcheck/test-model.json) -and (Test-Path /tmp/zipcheck/test-model-review.csv) -and (Test-Path /tmp/zipcheck/test-model-storage-ledger.csv) -and (Test-Path $logPath))
    'console log captured + clean'      = ($log -match 'Assembling deployments' -and $log -notmatch [char]27)
    'no raw-export failure in log'      = ($log -notmatch 'Raw data export failed' -and $log -match 'Raw decision data written')
    'counters exclude storage rows'     = ($log -match 'Usage found for 1 of 4 pool')
    'rawdata sane + version + evidence' = ($null -ne $rawJson -and @($rawJson.pools).Count -eq 4 -and $rawJson.meta.version -eq 'v0.20' -and @($rawJson.storageCandidates).Count -eq 4 -and @($rawJson.mapEvidence).Count -ge 1)
    'version is the first output line'  = ($log -match '(?m)^\[i\] Get-NerdioModelerJson v0\.20' -and ($log.IndexOf('Get-NerdioModelerJson v0.20') -lt $log.IndexOf('Signed in as')))
    'mixed-size pool: mode wins'        = ($a.workload.vmSize -eq 'Standard_D8s_v5' -and $a.image.type -eq 1 -and $a.workload.disk.size -eq 128 -and $a.workload.disk.type -eq 'Premium_LRS')
    'no stale-copy warning (current)'   = ($log -notmatch 'THIS COPY IS STALE')
    'empty pool: out of JSON, reported' = (@($m.deployments | Where-Object { $_.name -like 'PoolEmpty*' }).Count -eq 0 -and @($m.deployments).Count -eq 3 -and $rowEmpty.Flags -match '^EMPTY - excluded' -and $rowEmpty.VmSize -eq '-' -and $rowEmpty.Window -eq '-' -and $rowEmpty.ActualMo -eq '0' -and @($rawJson.emptyPools).Count -eq 1 -and $rawJson.emptyPools[0].name -eq 'PoolEmpty' -and $log -match '1 EMPTY host pool\(s\) excluded' -and $log -match '3 deployments; 1 empty pool\(s\) excluded')
    'NSP workspace named + fix given'   = ($log -match 'BLOCKED BY ITS NETWORK SETTINGS' -and $log -match 'inside the customer network')
    'cost: ONE sub query for s1, filtered'  = ($run1.CostS1SubCalls -eq 2 -and @($run1.CostFilterRGs).Count -eq 3 -and ($run1.CostFilterRGs -contains 'rg1') -and ($run1.CostFilterRGs -contains 'rg2') -and ($run1.CostFilterRGs -contains 'rg-stor'))
    'cost: Retry-After honored (7s)'        = ($log -match 'Cost Management is throttling \(HTTP 429\) and asked for a 7s pause - honoring it')
    'cost: s2 403 -> per-RG fallback'       = ($run1.CostS2SubCalls -le 2 -and $log -match 'Subscription-level cost query for s2 was refused \(HTTP 403' -and $log -match 'falling back to one query per resource group')
    'cost: rg-anf 6 tries, then 2nd pass'   = ($run1.CostAnfCalls -eq 7 -and $log -match 'Cooling down 90s' -and $log -match 'Recovered on the second pass: resource group rg-anf' -and $log -match 'asked for a 3s pause')
    'cost: NOTHING skipped or lost'         = ($log -notmatch 'Cost query skipped' -and $log -match 'Nothing was lost to throttling' -and $log -notmatch 'Common causes')
    'ledger: anf ActualMo 77 (recovered)'   = ($lAnf.ActualMo -eq '77')
    'rawdata: throttle history recorded'    = ($rawJson.throttle.hits -eq 7 -and $rawJson.throttle.waitedSeconds -eq 22 -and $rawJson.throttle.byService.'Cost Management' -eq 7 -and @($rawJson.throttle.recoveredOnSecondPass).Count -eq 1 -and $rawJson.throttle.recoveredOnSecondPass[0] -eq 'rg-anf' -and @($rawJson.costSkipped).Count -eq 0)
    'ARG pinned to enabled subs s1+s2'  = $(
        $ok = (@($global:ArgSubScopes).Count -ge 5)
        foreach ($sc in $global:ArgSubScopes) { if (@($sc).Count -ne 2 -or @($sc)[0] -ne 's1' -or @($sc)[1] -ne 's2') { $ok = $false } }
        $ok)
    'identity banner + scope printed'   = ($log -match 'Signed in as don@mock\.test - tenant ten-1' -and $log -match 'Scope: 2 enabled subscription\(s\)' -and $log -match 'Sub One  \(s1\)' -and $log -match 'Sub Two  \(s2\)')
    'other-tenant warning printed'      = ($log -match 'can also reach 1 other tenant' -and $log -match 'Connect-AzAccount -TenantId ten-2')
    'rawdata identity block'            = ($rawJson.meta.identity.account -eq 'don@mock.test' -and $rawJson.meta.identity.tenantId -eq 'ten-1' -and @($rawJson.meta.identity.scopeSubscriptions).Count -eq 2)
    'per-sub pool counts printed'       = ($log -match 'Found 4 host pool\(s\) across 1 subscription\(s\)' -and $log -match 'Sub One : 4 pool\(s\)')
    'usage buckets csv in zip'          = (@($rawBucketsCsv).Count -eq 3 -and $rawBucketsCsv[1].ConcurrentUsers -eq '7')
    'no cmdlet-missing / skip errors'   = ($log -notmatch 'not recognized' -and $log -notmatch 'storage account\(s\) skipped \(slow')
}
$fail = 0
foreach ($k in $checks.Keys) {
    if ($checks[$k]) { Write-Host "PASS  $k" -ForegroundColor Green }
    else { Write-Host "FAIL  $k" -ForegroundColor Red; $fail++ }
}
if ($fail -eq 0) { Write-Host "`nALL CHECKS PASSED" -ForegroundColor Green } else { Write-Host "`n$fail CHECK(S) FAILED" -ForegroundColor Red; exit 1 }
