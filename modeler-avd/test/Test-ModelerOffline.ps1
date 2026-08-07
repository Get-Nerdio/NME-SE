# Dev fixture: offline end-to-end test for Get-NerdioModelerJson.ps1. NOT for customers.
# Mocks every Az/REST call plus Read-Host (scripted triage answers), runs the real
# script, validates JSON + review CSV + storage ledger + zip package.
# Run on any pwsh 7+: pwsh -File Test-ModelerOffline.ps1
$poolAId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.desktopvirtualization/hostpools/PoolA'
$wsId    = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.operationalinsights/workspaces/ws1'
$saProf  = '/subscriptions/s1/resourcegroups/rg-stor/providers/microsoft.storage/storageaccounts/stprofiles'
$saGen   = '/subscriptions/s1/resourcegroups/rg-stor/providers/microsoft.storage/storageaccounts/stgen'
$anfPool = '/subscriptions/s1/resourcegroups/rg-anf/providers/microsoft.netapp/netappaccounts/anf1/capacitypools/pool1'

# Triage answers, consumed in candidate order (Sort Account,Share):
#   anf1/pool1      -> 'y'      profiles, pools unknown  => ledger only (policy test)
#   stgen/msixapps  -> ''       default APP ATTACH       => ledger only, never JSON
#   stgen/userprofiles -> 'poola'  fragment match PoolA  => confirmed, JSON
#   stprofiles/profiles01 -> ''  default PROFILES + logs-ip pre-fill PoolA => confirmed, JSON
$global:RHQueue = [System.Collections.Generic.Queue[string]]::new()
'y', '', 'poola', '' | ForEach-Object { $global:RHQueue.Enqueue($_) }
function Read-Host { param([string]$Prompt) if ($global:RHQueue.Count -gt 0) { $global:RHQueue.Dequeue() } else { '' } }

function Get-AzContext { [pscustomobject]@{ Name = 'mock' } }
function Invoke-AzRestMethod {
    param([string]$Method, [string]$Path, [string]$Payload)
    if ($Method -eq 'POST' -and $Path -like '*Microsoft.ResourceGraph*') {
        $q = ($Payload | ConvertFrom-Json).query
        if ($q -match 'sessionhosts') {
            $data = @(
                @{ id = "$poolAId/sessionhosts/sh1"; vmId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm1' },
                @{ id = "$poolAId/sessionhosts/sh2"; vmId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm2' }
            )
        } elseif ($q -match 'virtualmachines') {
            $data = @(
                @{ id = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm1'; vmSize = 'Standard_D8s_v5'; ephemeral = $false; imageId = ''; osDiskId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/disks/d1' },
                @{ id = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm2'; vmSize = 'Standard_D8s_v5'; ephemeral = $false; imageId = ''; osDiskId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/disks/d2' }
            )
        } elseif ($q -match 'microsoft.compute/disks') {
            $data = @(@{ id = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/disks/d1'; diskSizeGb = 128; diskSku = 'Premium_LRS' })
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
            $data = @(@{ id = $poolAId; name = 'PoolA'; resourceGroup = 'rg1'; location = 'eastus'; subscriptionId = 's1'; hostPoolType = 'Pooled'; maxSessionLimit = 10; preferredAppGroupType = 'Desktop'; startVMOnConnect = $true })
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
            return [pscustomobject]@{ StatusCode = 200; Content = (@{ value = @(@{ properties = @{ workspaceId = $wsId } }) } | ConvertTo-Json -Depth 10) }
        }
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ value = @() } | ConvertTo-Json -Depth 10) }
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
        if ($Path -like '*resourcegroups/rg-stor*') {
            $rows += ,@(42.00, $saProf.ToLower(), 'USD')
        } elseif ($Path -like '*resourcegroups/rg-anf*') {
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
function Get-AzAccessToken { param([string]$ResourceUrl) [pscustomobject]@{ Token = 'mock-token' } }
function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $ContentType, $Body)
    if ("$Uri" -notmatch 'api\.loganalytics\.io') { throw "unexpected Invoke-RestMethod uri in test: $Uri" }
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
& "$PSScriptRoot/../Get-NerdioModelerJson.ps1" -SkipDownload -OutFile /tmp/test-model.json -ModelName 'TEST'

Write-Host "`n--- VALIDATION ---"
$m = Get-Content /tmp/test-model.json -Raw | ConvertFrom-Json
$csv = Import-Csv /tmp/test-model-review.csv
$ledger = if (Test-Path /tmp/test-model-storage-ledger.csv) { Import-Csv /tmp/test-model-storage-ledger.csv } else { @() }
$a = $m.deployments | Where-Object { $_.name -eq 'PoolA' }
$dProf = $m.deployments | Where-Object { $_.name -like 'FSLogix storage - profiles01*' }
$dUser = $m.deployments | Where-Object { $_.name -like 'FSLogix storage - userprofiles*' }
$rowPoolA = $csv | Where-Object { $_.Pool -eq 'PoolA' }
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
    '3 deployments (pool + 2 stores)'   = (@($m.deployments).Count -eq 3)
    'PoolA users=40 abs=0'              = ($a.users.total -eq 40 -and $a.users.absentPercent -eq 0)
    'PoolA density 1.13 (obs 9/8)'      = ($a.workload.maxUsersPerVCpu -eq 1.13)
    'PoolA window 8+10h M-F'            = ($a.autoScale.workStartHour -eq 8 -and $a.autoScale.workDurationMinutes -eq 600)
    'PoolA fsLogix stays off'           = ($a.fsLogix.enabled -eq $false)
    'review: MAU column (PoolA 120)'    = ($rowPoolA.MAU -eq '120')
    'session flag fires (60 vs 40)'     = ($rowPoolA.Flags -match 'sessions incl\. disconnected peaked at 60 vs 40 connected')
    'review has NO storage rows'        = (@($csv | Where-Object { $_.Pool -like 'FSLogix*' -or $_.Pool -like 'AppAttach*' }).Count -eq 0)
    'profiles01: logs-ip prefill -> JSON' = ($dProf.name -eq 'FSLogix storage - profiles01 (serves: PoolA)' -and $dProf.fsLogix.profileSizeGb -eq 1024 -and $dProf.fsLogix.storageType -eq 2)
    'userprofiles: typed map -> JSON'   = ($dUser.name -eq 'FSLogix storage - userprofiles (serves: PoolA)' -and $dUser.fsLogix.profileSizeGb -eq 200 -and $dUser.fsLogix.storageType -eq 1)
    'carrier shape (1 user B2s egress0)' = ($dProf.users.total -eq 1 -and $dProf.workload.vmSize -eq 'Standard_B2s' -and $dProf.workload.rdpEgressGb -eq 0 -and $dProf.autoScale.workDurationMinutes -eq 60 -and $dProf.image.type -eq 1)
    'msix/appattach NOT in JSON'        = (@($m.deployments | Where-Object { $_.name -like '*msix*' }).Count -eq 0)
    'anf unmapped NOT in JSON'          = (@($m.deployments | Where-Object { $_.name -like '*pool1*' -or $_.name -like '*anf*' }).Count -eq 0)
    'data share never a candidate'      = (@($ledger | Where-Object { $_.Share -eq 'data' }).Count -eq 0)
    'ledger: 4 rows, all classified'    = (@($ledger).Count -eq 4 -and @($ledger | Where-Object { $_.Classification }).Count -eq 4)
    'ledger: profiles01 high logs-ip'   = ($lProf.Classification -eq 'Profiles' -and $lProf.Evidence -eq 'logs-ip' -and $lProf.Confidence -eq 'high' -and $lProf.InModelJson -eq 'yes' -and $lProf.ServesPools -eq 'PoolA')
    'ledger: userprofiles admin-conf'   = ($lUser.Evidence -eq 'admin-confirmed' -and $lUser.InModelJson -eq 'yes' -and $lUser.BillingModel -eq 'Used')
    'ledger: msix appattach no-JSON'    = ($lMsix.Classification -eq 'AppAttach' -and $lMsix.InModelJson -eq 'no')
    'ledger: anf capacity pool 4096'    = ($lAnf.Classification -eq 'Profiles' -and $lAnf.InModelJson -eq 'no' -and $lAnf.ProvisionedGb -eq '4096' -and $lAnf.BillingUnit -match 'capacity pool' -and $lAnf.Notes -match 'anfprof')
    'ledger: stprofiles ActualMo 42'    = ($lProf.ActualMo -eq '42')
    'census line printed'               = ($log -match 'Storage census: 2 account\(s\) scanned, 0 skipped')
    'disposition line (2 model 2 ledger)' = ($log -match 'Storage disposition: 2 confirmed profile store\(s\) in the model JSON, 2 in the ledger only')
    'ActualMo uniform: PoolA 160.75'    = ($rowPoolA.ActualMo -eq '160.75')
    'admin tasks on carrier'            = (@($dProf.administrative.tasks.'2').Count -eq 16)
    'zip holds json+csv+ledger+log'     = ($zipOk -and (Test-Path /tmp/zipcheck/test-model.json) -and (Test-Path /tmp/zipcheck/test-model-review.csv) -and (Test-Path /tmp/zipcheck/test-model-storage-ledger.csv) -and (Test-Path $logPath))
    'console log captured + clean'      = ($log -match 'Assembling deployments' -and $log -notmatch [char]27)
    'no raw-export failure in log'      = ($log -notmatch 'Raw data export failed' -and $log -match 'Raw decision data written')
    'counters exclude storage rows'     = ($log -match 'Usage found for 1 of 1 pool')
    'rawdata sane + v0.14 + triage'     = ($null -ne $rawJson -and @($rawJson.pools).Count -eq 1 -and $rawJson.meta.version -eq 'v0.14' -and @($rawJson.storageCandidates).Count -eq 4 -and $rawJson.storageTriage.ran -eq $true -and @($rawJson.mapEvidence).Count -ge 1)
    'usage buckets csv in zip'          = (@($rawBucketsCsv).Count -eq 3 -and $rawBucketsCsv[1].ConcurrentUsers -eq '7')
    'no cmdlet-missing / skip errors'   = ($log -notmatch 'not recognized' -and $log -notmatch 'storage account\(s\) skipped \(slow')
}
$fail = 0
foreach ($k in $checks.Keys) {
    if ($checks[$k]) { Write-Host "PASS  $k" -ForegroundColor Green }
    else { Write-Host "FAIL  $k" -ForegroundColor Red; $fail++ }
}
if ($fail -eq 0) { Write-Host "`nALL CHECKS PASSED" -ForegroundColor Green } else { Write-Host "`n$fail CHECK(S) FAILED" -ForegroundColor Red; exit 1 }
