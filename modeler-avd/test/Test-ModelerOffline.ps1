# Dev fixture: offline end-to-end test for Get-NerdioModelerJson.ps1. NOT for customers.
# Mocks every Az call, runs the real script, validates JSON + CSV + zip package.
# Run on any pwsh 7+: pwsh -File Test-ModelerOffline.ps1
$poolAId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.desktopvirtualization/hostpools/PoolA'
$wsId    = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.operationalinsights/workspaces/ws1'
$saProf  = '/subscriptions/s1/resourcegroups/rg-stor/providers/microsoft.storage/storageaccounts/stprofiles'
$saGen   = '/subscriptions/s1/resourcegroups/rg-stor/providers/microsoft.storage/storageaccounts/stgen'

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
        } elseif ($q -match 'netappaccounts') {
            $data = @(@{ id = '/subscriptions/s1/resourcegroups/rg-anf/providers/microsoft.netapp/netappaccounts/anf1/capacitypools/pool1/volumes/anfprof'
                         name = 'anf1/pool1/anfprof'; resourceGroup = 'rg-anf'; location = 'eastus'
                         provisionedBytes = 2199023255552; protocols = @('CIFS'); serviceLevel = 'Premium' })
        } else {
            $data = @(@{ id = $poolAId; name = 'PoolA'; resourceGroup = 'rg1'; location = 'eastus'; subscriptionId = 's1'; hostPoolType = 'Pooled'; maxSessionLimit = 10; preferredAppGroupType = 'Desktop'; startVMOnConnect = $true })
        }
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ data = $data } | ConvertTo-Json -Depth 10) }
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
                @{ name = 'userprofiles'; properties = @{ shareQuota = 500; enabledProtocols = 'SMB' } }
            )
        }
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ value = $v } | ConvertTo-Json -Depth 10) }
    }
    if ($Method -eq 'POST' -and $Path -like '*Microsoft.CostManagement/query*') {
        $c = @{ properties = @{ columns = @(@{name='Cost'},@{name='ResourceId'},@{name='Currency'}); rows = @(
            ,@(100.50, '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm1', 'USD')
            ,@(50.25,  '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm2', 'USD')
            ,@(10.00,  '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/disks/d1', 'USD')) } }
        return [pscustomobject]@{ StatusCode = 200; Content = ($c | ConvertTo-Json -Depth 10) }
    }
    return [pscustomobject]@{ StatusCode = 404; Content = '{}' }
}
function Invoke-AzOperationalInsightsQuery {
    param([string]$WorkspaceId, [string]$Query)
    if ($Query -match 'StorageFileLogs') {
        return [pscustomobject]@{ Results = @(
            [pscustomobject]@{ AccountName = 'stprofiles'; Share = 'profiles01'; HostPoolId = $poolAId.ToLower(); Overlap = '12' }
        ) }
    }
    [pscustomobject]@{ Results = @(
        [pscustomobject]@{ HostPoolId = $poolAId.ToLower(); PeakConcurrentUsers = '40'; StartHour = '8'; WorkDurationMinutes = '600'; WorkDaysJson = '[1,2,3,4,5]'; WeeklyOffUH = '84'; PeakUsersPerHost = '9' }
    ) }
}

Remove-Item /tmp/test-model*.* -Force -ErrorAction SilentlyContinue
& "$PSScriptRoot/../Get-NerdioModelerJson.ps1" -SkipDownload -OutFile /tmp/test-model.json -ModelName 'TEST'

Write-Host "`n--- VALIDATION ---"
$m = Get-Content /tmp/test-model.json -Raw | ConvertFrom-Json
$csv = Import-Csv /tmp/test-model-review.csv
$a = $m.deployments | Where-Object { $_.name -eq 'PoolA' }
$dProf = $m.deployments | Where-Object { $_.name -like 'FSLogix - profiles01*' }
$dUser = $m.deployments | Where-Object { $_.name -eq 'FSLogix - userprofiles' }
$dAnf  = $m.deployments | Where-Object { $_.name -eq 'FSLogix - anfprof' }
$rowProf = $csv | Where-Object { $_.Pool -eq 'FSLogix: profiles01' }
$rowPoolA = $csv | Where-Object { $_.Pool -eq 'PoolA' }
Remove-Item /tmp/zipcheck -Recurse -Force -ErrorAction SilentlyContinue
$zipOk = Test-Path /tmp/test-model.zip
if ($zipOk) { Expand-Archive /tmp/test-model.zip -DestinationPath /tmp/zipcheck -Force }
$logPath = '/tmp/zipcheck/test-model-console.log'
$log = if (Test-Path $logPath) { Get-Content $logPath -Raw } else { '' }

$checks = [ordered]@{
    'schema=4'                        = ($m.schema -eq 4)
    '4 deployments (1 pool + 3 fsx)'  = (@($m.deployments).Count -eq 4)
    'PoolA users=40'                  = ($a.users.total -eq 40)
    'PoolA density 1.13 (obs 9/8)'    = ($a.workload.maxUsersPerVCpu -eq 1.13)
    'PoolA window 8+10h M-F'          = ($a.autoScale.workStartHour -eq 8 -and $a.autoScale.workDurationMinutes -eq 600)
    'PoolA fsLogix stays off'         = ($a.fsLogix.enabled -eq $false)
    'profiles01 dummy mapped name'    = ($dProf.name -eq 'FSLogix - profiles01 (PoolA)')
    'profiles01 premium->provisioned' = ($dProf.fsLogix.enabled -eq $true -and $dProf.fsLogix.profileSizeGb -eq 1024 -and $dProf.fsLogix.storageType -eq 2)
    'dummy shape (1 user B2s 1h Mon)' = ($dProf.users.total -eq 1 -and $dProf.workload.vmSize -eq 'Standard_B2s' -and (@($dProf.autoScale.workDays) -join ',') -eq '1' -and $dProf.autoScale.workDurationMinutes -eq 60 -and $dProf.image.type -eq 1)
    'userprofiles standard->used 200' = ($dUser.fsLogix.profileSizeGb -eq 200)
    'anf provisioned 2048 + enum 4'   = ($dAnf.fsLogix.profileSizeGb -eq 2048 -and $dAnf.fsLogix.storageType -eq 4)
    'no dummy for excluded data share' = (@($m.deployments | Where-Object { $_.name -like '*data*' }).Count -eq 0)
    'review: serves + tier flags'     = ($rowProf.Flags -match 'serves: PoolA' -and $rowProf.Flags -match [regex]::Escape('Azure Files Premium (ZRS) (storageType 2)'))
    'standard share tier note'        = ($dUser.fsLogix.storageType -eq 1 -and (($csv | Where-Object { $_.Pool -eq 'FSLogix: userprofiles' }).Flags -match 'standard file share'))
    'ActualMo uniform: PoolA 160.75'  = ($rowPoolA.ActualMo -eq '160.75' -and ($null -ne $rowProf.PSObject.Properties['ActualMo']))
    'admin tasks on dummy'            = (@($dProf.administrative.tasks.'2').Count -eq 16)
    'zip packaged'                    = $zipOk
    'zip holds json+csv+log'          = ((Test-Path /tmp/zipcheck/test-model.json) -and (Test-Path /tmp/zipcheck/test-model-review.csv) -and (Test-Path $logPath))
    'console log captured + clean'    = ($log -match 'Assembling deployments' -and $log -match 'FSLogix' -and $log -notmatch [char]27)
}
$fail = 0
foreach ($k in $checks.Keys) {
    if ($checks[$k]) { Write-Host "PASS  $k" -ForegroundColor Green }
    else { Write-Host "FAIL  $k" -ForegroundColor Red; $fail++ }
}
if ($fail -eq 0) { Write-Host "`nALL CHECKS PASSED" -ForegroundColor Green } else { Write-Host "`n$fail CHECK(S) FAILED" -ForegroundColor Red; exit 1 }
