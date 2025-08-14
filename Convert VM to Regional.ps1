#description: Convert a zonal VM to a regional (no-zone) VM by cloning disks/NICs; copy tags & settings; start new VM; optional cleanup of original resources. Supports running against a selected VM or from the Scripted Actions screen with runtime parameters.
#tags: Nerdio, ChatGPT, Production

<# Variables:
{
  "VmName": {
    "Description": "Name of the VM to convert to regional (no-zone). If omitted, the script will use $AzureVMName when run against a VM.",
    "IsRequired": false
  },
  "ResourceGroupName": {
    "Description": "Resource group of the VM. If omitted, the script will use $AzureResourceGroupName when run against a VM.",
    "IsRequired": false
  },
  "CleanupOldResources": {
    "Description": "If true, delete the original VM, NICs, and disks after successful creation of the new VM.",
    "IsRequired": false,
    "DefaultValue": false
  }
}
#>

<# Notes:
- Context: Azure runbook scripted action (Az modules; non-interactive).
- Auth: handled by NME; $AzureSubscriptionId is provided.
- If run against a specific VM/host in NME, $AzureVMName and $AzureResourceGroupName are predefined and will be used when VmName/ResourceGroupName are not passed at runtime.
- Private IPs are NOT preserved (new NICs get Dynamic IPs).
- Copies: NSG, NIC-level DNS servers, Accelerated Networking, identities (via REST), boot diagnostics, tags.
- Starts the new VM. Optional cleanup deletes original resources; otherwise original resources are left deallocated and fully untagged.
#>

# ===================== USER TOGGLES =====================
# Human-readable base suffix; a 4-char random string is auto-appended to ensure uniqueness
$BaseSuffix = "-nz"
# =======================================================

# -------- Generate unique suffix (4 char random alphanumeric) --------
$RandomChars = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 4 | ForEach-Object {[char]$_})
$NewSuffix = "$BaseSuffix$RandomChars"
Write-Output "[INFO]  Generated resource suffix: $NewSuffix"

$ErrorActionPreference = 'Stop'

# -------- Helpers (PS 5.1-safe) --------
function Write-Info { param($m) Write-Output ("[INFO]  " + $m) }
function Write-Warn { param($m) Write-Output ("[WARN]  " + $m) }
function Write-Err  { param($m) Write-Output ("[ERROR] " + $m) }

function Merge-Tags {
    param([Parameter(Mandatory)][string]$ResourceId,[hashtable]$Tags)
    if ($Tags -and $Tags.Count -gt 0) {
        Update-AzTag -ResourceId $ResourceId -Tag $Tags -Operation Merge | Out-Null
    }
}
function Replace-With-EmptyTags {
    param([Parameter(Mandatory)][string]$ResourceId)
    try { Update-AzTag -ResourceId $ResourceId -Tag @{} -Operation Replace | Out-Null } catch { }
}
function Test-IsDeallocated {
    param([Parameter(Mandatory)][string]$VMName,[Parameter(Mandatory)][string]$RG)
    $iv = Get-AzVM -Name $VMName -ResourceGroupName $RG -Status
    $code = ($iv.Statuses | Where-Object { $_.Code -like 'PowerState/*' } | Select-Object -Last 1).Code
    return ($code -eq 'PowerState/deallocated')
}
function Get-LocationString {
    param($val)
    $s = ($val | Select-Object -First 1) -as [string]
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    return $s.Trim()
}
function Assert-NonEmptyLocation {
    param($loc, $context)
    if ([string]::IsNullOrWhiteSpace($loc)) {
        throw "Location is null/empty for $context. Aborting to avoid 'Location property is required'."
    }
}
function StrOrNone { param($v) if ($null -eq $v) { "<none>" } else { $s=$v -as [string]; if ([string]::IsNullOrWhiteSpace($s)) { "<none>" } else { $s } } }
function JoinOrNone { param($arr) if ($null -eq $arr) { "<none>" } elseif ($arr -is [array]) { if ($arr.Count -eq 0) { "<none>" } else { ($arr -join ', ') } } else { $s=$arr -as [string]; if ([string]::IsNullOrWhiteSpace($s)) { "<none>" } else { $s } } }

# REST helper to apply VM identity post-creation (works even if Set-AzVMIdentity is unavailable)
function Set-VMIdentityViaRest {
    param(
        [Parameter(Mandatory)] [string] $SubscriptionId,
        [Parameter(Mandatory)] [string] $ResourceGroupName,
        [Parameter(Mandatory)] [string] $VMName,
        [Parameter(Mandatory)] [string] $IdentityType,            # "SystemAssigned", "UserAssigned", or "SystemAssigned,UserAssigned"
        [string[]] $UserAssignedIds = @()
    )
    $typeClean = ($IdentityType -replace '\s','')
    if ([string]::IsNullOrWhiteSpace($typeClean)) { return }

    $body = @{ identity = @{ type = $typeClean } }
    if ($UserAssignedIds -and $UserAssignedIds.Count -gt 0) {
        $uai = @{}
        foreach ($id in $UserAssignedIds) {
            if (-not [string]::IsNullOrWhiteSpace($id)) { $uai[$id] = @{} }
        }
        if ($uai.Keys.Count -gt 0) { $body.identity.userAssignedIdentities = $uai }
    }

    $json = ($body | ConvertTo-Json -Depth 10)
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachines/$VMName?api-version=2023-03-01"

    Write-Info ("Applying VM identity via REST PATCH: type={0}  UA count={1}" -f $typeClean, ($UserAssignedIds.Count))
    try {
        $resp = Invoke-AzRestMethod -Method PATCH -Path $path -Payload $json -ErrorAction Stop
        Write-Info ("Identity PATCH status: {0}" -f ($resp.StatusCode))
    } catch {
        Write-Warn ("Failed to PATCH identity on VM '{0}': {1}" -f $VMName, $_.Exception.Message)
        throw
    }
}

# -------- Resolve inputs (runtime params vs predefined variables) --------
if (-not $VmName) { $VmName = $AzureVMName }
if (-not $ResourceGroupName) { $ResourceGroupName = $AzureResourceGroupName }
if ($null -eq $CleanupOldResources) { $CleanupOldResources = $false }

if (-not $VmName) { throw "VmName not provided and `$AzureVMName is not available in this context." }
if (-not $ResourceGroupName) { throw "ResourceGroupName not provided and `$AzureResourceGroupName is not available in this context." }

$VMN = $VmName
$RG  = $ResourceGroupName

# -------- Guardrails / Context --------
if ($AzureSubscriptionId) { Set-AzContext -SubscriptionId $AzureSubscriptionId | Out-Null }

# -------- Get source VM status & ensure deallocated --------
Write-Info ("Fetching VM '{0}' in RG '{1}'..." -f $VMN, $RG)
$vmStatus = Get-AzVM -Name $VMN -ResourceGroupName $RG -Status
if (-not $vmStatus) { throw ("VM '{0}' not found in RG '{1}'." -f $VMN, $RG) }
$disp = ($vmStatus.Statuses | Where-Object Code -like 'PowerState/*' | Select-Object -Last 1).DisplayStatus
Write-Info ("Current power state: {0}" -f (StrOrNone $disp))

if (-not (Test-IsDeallocated -VMName $VMN -RG $RG)) {
    Write-Info ("Deallocating VM '{0}'..." -f $VMN)
    Stop-AzVM -Name $VMN -ResourceGroupName $RG -Force
    do { Start-Sleep -Seconds 5 } until (Test-IsDeallocated -VMName $VMN -RG $RG)
    Write-Info "VM is deallocated."
} else {
    Write-Info "VM is already deallocated; continuing."
}

# -------- Refresh VM & collect properties --------
Write-Info "Refreshing VM model and gathering properties..."
$vm = Get-AzVM -Name $VMN -ResourceGroupName $RG
$vmTags         = $vm.Tags
$vmSize         = $vm.HardwareProfile.VmSize
$osType         = $vm.StorageProfile.OsDisk.OsType
$osDiskName     = $vm.StorageProfile.OsDisk.Name
$origOsDisk     = Get-AzDisk -ResourceGroupName $RG -Name $osDiskName
$osDiskSku      = $origOsDisk.Sku.Name
$osDiskSizeGB   = $origOsDisk.DiskSizeGB
$osDiskTags     = $origOsDisk.Tags
$osDiskLocation = Get-LocationString $origOsDisk.Location
Assert-NonEmptyLocation $osDiskLocation ("OS disk '" + $origOsDisk.Name + "'")

Write-Info ("VM Size: {0}" -f $vmSize)
Write-Info ("OS Type: {0}" -f $osType)
Write-Info ("OS Disk: {0} | SKU: {1} | SizeGB: {2} | Location: {3}" -f $osDiskName, $osDiskSku, $osDiskSizeGB, $osDiskLocation)

# Identity (to re-apply post-creation via REST)
$identityType    = $null
$userAssignedIds = @()
if ($vm.Identity) {
    $identityType = ($vm.Identity.Type -as [string])
    if ($vm.Identity.UserAssignedIdentities) { $userAssignedIds = $vm.Identity.UserAssignedIdentities.Keys }
}
Write-Info ("Identity type (source): {0}" -f (StrOrNone $identityType))
if ($userAssignedIds.Count -gt 0) { Write-Info ("User-assigned identities: {0}" -f ($userAssignedIds -join ', ')) }

# Boot Diagnostics
$bootDiagEnabled = $false
$bootDiagStorage = $null
if ($vm.DiagnosticsProfile -and $vm.DiagnosticsProfile.BootDiagnostics) {
    $bootDiagEnabled = [bool]$vm.DiagnosticsProfile.BootDiagnostics.Enabled
    $bootDiagStorage = $vm.DiagnosticsProfile.BootDiagnostics.StorageUri
}
Write-Info ("Boot diagnostics enabled: {0} ; StorageUri: {1}" -f $bootDiagEnabled, (StrOrNone $bootDiagStorage))

# -------- Capture NICs from source VM --------
Write-Info "Collecting NICs from source VM..."
$nicInfos = @()
foreach ($nr in $vm.NetworkProfile.NetworkInterfaces) {
    $nic = Get-AzNetworkInterface -ResourceId $nr.Id
    $ip  = $nic.IpConfigurations[0]

    $nsgId = $null
    if ($nic.NetworkSecurityGroup) { $nsgId = $nic.NetworkSecurityGroup.Id }

    $dnsServers = @()
    if ($nic.DnsSettings -and $nic.DnsSettings.DnsServers) {
        $dnsServers = @($nic.DnsSettings.DnsServers)
    }

    $accel = $false
    try { $accel = [bool]$nic.EnableAcceleratedNetworking } catch { $accel = $false }

    $ni = [PSCustomObject]@{
        Name        = $nic.Name
        Id          = $nic.Id
        Location    = Get-LocationString $nic.Location
        SubnetId    = $ip.Subnet.Id
        NSGId       = $nsgId
        Primary     = $nic.Primary
        DnsServers  = $dnsServers
        AccelNet    = $accel
        Tags        = $nic.Tags
    }

    $logNSG  = StrOrNone $ni.NSGId
    $logLoc  = StrOrNone $ni.Location
    $logDNS  = JoinOrNone $ni.DnsServers
    Write-Info ("NIC: {0} | Primary: {1} | AccelNet: {2} | NSG: {3} | Location: {4} | SubnetId: {5} | DNS: {6}" -f `
        $ni.Name, $ni.Primary, $ni.AccelNet, $logNSG, $logLoc, $ni.SubnetId, $logDNS)

    $nicInfos += $ni
}

# -------- Snapshot disks (use each disk's own location) --------
$ts = Get-Date -Format "yyyyMMdd-HHmmss"

Write-Info "Creating OS disk snapshot..."
$osSnapName   = "$($VMN)-os-snap-$ts"
$osSnapConfig = New-AzSnapshotConfig -Location $osDiskLocation -CreateOption Copy -SourceResourceId $origOsDisk.Id
$osSnapConfig.Location = $osDiskLocation
$osSnapshot   = New-AzSnapshot -Snapshot $osSnapConfig -SnapshotName $osSnapName -ResourceGroupName $RG
Write-Info ("OS snapshot created: {0}" -f $osSnapName)

$dataDiskSnapshots = @()
foreach ($d in $vm.StorageProfile.DataDisks) {
    $dRes          = Get-AzDisk -ResourceGroupName $RG -Name $d.Name
    $dataDiskLoc   = Get-LocationString $dRes.Location
    Assert-NonEmptyLocation $dataDiskLoc ("data disk '" + $dRes.Name + "'")
    $snapNm        = "$($VMN)-data$($d.Lun)-snap-$ts"

    Write-Info ("Creating data disk snapshot for LUN {0} in {1} (disk: {2})..." -f $d.Lun, $dataDiskLoc, $dRes.Name)
    $snapCfg       = New-AzSnapshotConfig -Location $dataDiskLoc -CreateOption Copy -SourceResourceId $dRes.Id
    $snapCfg.Location = $dataDiskLoc
    $snap           = New-AzSnapshot -Snapshot $snapCfg -SnapshotName $snapNm -ResourceGroupName $RG
    Write-Info ("Data snapshot created: {0}" -f $snapNm)

    $dataDiskSnapshots += [PSCustomObject]@{ Lun = $d.Lun; Snapshot = $snap; SourceDisk = $dRes; Caching = $d.Caching }
}

# -------- Create new (no-zone) managed disks from snapshots --------
Write-Info "Creating new OS disk from snapshot..."
$newOsDiskName   = "$($VMN)-os$NewSuffix"
$newOsDiskConfig = New-AzDiskConfig -Location $osDiskLocation -CreateOption Copy -SourceResourceId $osSnapshot.Id -DiskSizeGB $osDiskSizeGB -SkuName $osDiskSku
if ($osType) { $newOsDiskConfig.OsType = $osType }
$newOsDisk       = New-AzDisk -Disk $newOsDiskConfig -ResourceGroupName $RG -DiskName $newOsDiskName
Merge-Tags -ResourceId $newOsDisk.Id -Tags $osDiskTags
Write-Info ("New OS disk created: {0}" -f $newOsDiskName)

$newDataDisks = @{}
foreach ($entry in $dataDiskSnapshots) {
    $lun     = [int]$entry.Lun
    $snap    = $entry.Snapshot
    $srcDisk = $entry.SourceDisk
    $diskLoc = Get-LocationString $srcDisk.Location
    Assert-NonEmptyLocation $diskLoc ("data disk '" + $srcDisk.Name + "'")
    $newNm   = "$($VMN)-data$lun$NewSuffix"

    Write-Info ("Creating new data disk from snapshot (LUN {0}) in {1}..." -f $lun, $diskLoc)
    $cfg     = New-AzDiskConfig -Location $diskLoc -CreateOption Copy -SourceResourceId $snap.Id -DiskSizeGB $srcDisk.DiskSizeGB -SkuName $srcDisk.Sku.Name
    $newDsk  = New-AzDisk -Disk $cfg -ResourceGroupName $RG -DiskName $newNm
    Merge-Tags -ResourceId $newDsk.Id -Tags $srcDisk.Tags
    $newDataDisks[$lun] = $newDsk
    Write-Info ("New data disk created: {0}" -f $newNm)
}

# -------- Create new NICs (explicit IP config; then set DNS/AccelNet) --------
$newNicIds = @()
$primaryNewNicId = $null

foreach ($n in $nicInfos) {
    $newNicName = ($n.Name + $NewSuffix)
    $nicLoc     = $n.Location
    if (-not $nicLoc) { $nicLoc = $osDiskLocation }  # fallback

    Write-Info ("Preparing IP config for NIC '{0}'..." -f $newNicName)
    Write-Info ("  Inputs => Location: {0} | SubnetId: {1} | NSG: {2} | AccelNet: {3} | DNSCount: {4}" -f `
        $nicLoc, $n.SubnetId, (StrOrNone $n.NSGId), $n.AccelNet, ($n.DnsServers.Count))

    try {
        # Dynamic private IP: omit -PrivateIpAddress entirely (dynamic is default)
        $ipcfg = New-AzNetworkInterfaceIpConfig -Name "ipconfig1" -SubnetId $n.SubnetId -PrivateIpAddressVersion IPv4
        Write-Info "  IP config prepared (dynamic)."
    } catch {
        Write-Err ("  FAILED: New-AzNetworkInterfaceIpConfig for NIC '{0}': {1}" -f $newNicName, $_.Exception.Message)
        throw
    }

    try {
        $nicParams = @{
            Name               = $newNicName
            ResourceGroupName  = $RG
            Location           = $nicLoc
            IpConfiguration    = $ipcfg
        }
        if ($n.NSGId) {
            $nsgObj = Get-AzNetworkSecurityGroup -Id $n.NSGId
            $nicParams.NetworkSecurityGroup = $nsgObj
        }

        Write-Info ("Creating new NIC '{0}' in {1}..." -f $newNicName, $nicLoc)
        $newNic = New-AzNetworkInterface @nicParams
        Write-Info ("  NIC created: {0}  (Id: {1})" -f $newNicName, $newNic.Id)

        # Apply DNS servers if any
        if ($n.DnsServers -and $n.DnsServers.Count -gt 0) {
            Write-Info ("  Applying DNS servers: {0}" -f (JoinOrNone $n.DnsServers))
            $newNic.DnsSettings.DnsServers = $n.DnsServers
            Set-AzNetworkInterface -NetworkInterface $newNic | Out-Null
            Write-Info "  DNS servers applied."
        }

        # Apply Accelerated Networking if original had it
        if ($n.AccelNet -eq $true) {
            Write-Info "  Enabling Accelerated Networking on NIC..."
            $newNic = Get-AzNetworkInterface -Name $newNic.Name -ResourceGroupName $RG
            $newNic.EnableAcceleratedNetworking = $true
            Set-AzNetworkInterface -NetworkInterface $newNic | Out-Null
            Write-Info ("  Accelerated Networking set = {0}" -f $newNic.EnableAcceleratedNetworking)
        }

        Merge-Tags -ResourceId $newNic.Id -Tags $n.Tags
        $newNicIds += $newNic.Id
        if ($n.Primary -and -not $primaryNewNicId) { $primaryNewNicId = $newNic.Id }
    } catch {
        Write-Err ("  FAILED: New-AzNetworkInterface for '{0}': {1}" -f $newNicName, $_.Exception.Message)
        throw
    }
}

# -------- Build new VM config (NO availability zone specified) --------
$NewVMName = ($VMN + $NewSuffix)
Write-Info ("Building new VM '{0}'..." -f $NewVMName)
# NOTE: Do NOT pass -Location here (older Az modules don't support it on New-AzVMConfig)
$newVmCfg = New-AzVMConfig -VMName $NewVMName -VMSize $vmSize

# Boot diagnostics (if enabled)
if ($bootDiagEnabled -and $bootDiagStorage) {
    $storageAcctName = ($bootDiagStorage -replace '^https://','') -replace '\.blob.*$',''
    if ($storageAcctName) {
        $newVmCfg = Set-AzVMBootDiagnostic -VM $newVmCfg -Enable -StorageAccountName $storageAcctName
        Write-Info ("Boot diagnostics enabled for storage account: {0}" -f $storageAcctName)
    }
}

# Attach NICs (primary first)
Write-Info ("Attaching {0} NIC(s) to new VM..." -f $newNicIds.Count)
foreach ($nicId in $newNicIds) {
    if (($nicId -eq $primaryNewNicId) -or (($newNicIds.Count -eq 1) -and (-not $primaryNewNicId))) {
        $newVmCfg = Add-AzVMNetworkInterface -VM $newVmCfg -Id $nicId -Primary
        Write-Info ("  NIC attached as PRIMARY: {0}" -f $nicId)
    } else {
        $newVmCfg = Add-AzVMNetworkInterface -VM $newVmCfg -Id $nicId
        Write-Info ("  NIC attached: {0}" -f $nicId)
    }
}

# Attach OS & data disks
Write-Info "Attaching OS & data disks..."
if ($osType -eq "Windows") {
    $newVmCfg = Set-AzVMOSDisk -VM $newVmCfg -ManagedDiskId $newOsDisk.Id -CreateOption Attach -Windows
} else {
    $newVmCfg = Set-AzVMOSDisk -VM $newVmCfg -ManagedDiskId $newOsDisk.Id -CreateOption Attach -Linux
}
Write-Info ("  OS disk attached: {0}" -f $newOsDisk.Id)

foreach ($d in $vm.StorageProfile.DataDisks) {
    $lun = $d.Lun
    if ($newDataDisks.ContainsKey($lun)) {
        $newVmCfg = Add-AzVMDataDisk -VM $newVmCfg -Name $newDataDisks[$lun].Name -ManagedDiskId $newDataDisks[$lun].Id -Lun $lun -Caching $d.Caching -CreateOption Attach
        Write-Info ("  Data disk attached (LUN {0}): {1}" -f $lun, $newDataDisks[$lun].Id)
    }
}

# -------- Create the new regional VM & apply original tags --------
Write-Info ("Creating new regional VM '{0}' in location '{1}'..." -f $NewVMName, $osDiskLocation)
$newVm = New-AzVM -ResourceGroupName $RG -Location $osDiskLocation -VM $newVmCfg -Tag $vmTags
Write-Info ("New VM created: {0}" -f $NewVMName)

# --- Apply identities post-creation (REST PATCH fallback) ---
if ($identityType) {
    try {
        Set-VMIdentityViaRest -SubscriptionId $AzureSubscriptionId `
                               -ResourceGroupName $RG `
                               -VMName $NewVMName `
                               -IdentityType ($identityType -replace '\s','') `
                               -UserAssignedIds $userAssignedIds
        Write-Info "Identity applied to new VM via REST."
    } catch {
        Write-Warn ("Could not apply identity to new VM via REST: {0}" -f $_.Exception.Message)
    }
}

# Start the new VM
try {
    Start-AzVM -Name $NewVMName -ResourceGroupName $RG -ErrorAction Stop | Out-Null
    Write-Info ("New VM '{0}' started." -f $NewVMName)
} catch {
    Write-Warn ("Start-AzVM reported an error (it may already be running): {0}" -f $_.Exception.Message)
}

# -------- Post-creation: cleanup or tag removal on original; remove snapshots --------
if ($CleanupOldResources) {
    Write-Info "Cleanup enabled: deleting original VM and its NICs/disks..."

    try {
        Remove-AzVM -Name $VMN -ResourceGroupName $RG -Force
        Write-Info ("Deleted original VM '{0}'." -f $VMN)
    } catch { Write-Warn ("Failed to delete original VM '{0}': {1}" -f $VMN, $_.Exception.Message) }

    foreach ($ni in $nicInfos) {
        try {
            Remove-AzNetworkInterface -Name $ni.Name -ResourceGroupName $RG -Force
            Write-Info ("Deleted original NIC '{0}'." -f $ni.Name)
        } catch { Write-Warn ("Failed to delete NIC '{0}': {1}" -f $ni.Name, $_.Exception.Message) }
    }

    try {
        Remove-AzDisk -Name $osDiskName -ResourceGroupName $RG -Force
        Write-Info ("Deleted original OS disk '{0}'." -f $osDiskName)
    } catch { Write-Warn ("Failed to delete original OS disk '{0}': {1}" -f $osDiskName, $_.Exception.Message) }

    foreach ($d in $vm.StorageProfile.DataDisks) {
        try {
            Remove-AzDisk -Name $d.Name -ResourceGroupName $RG -Force
            Write-Info ("Deleted original data disk '{0}'." -f $d.Name)
        } catch { Write-Warn ("Failed to delete data disk '{0}': {1}" -f $d.Name, $_.Exception.Message) }
    }

} else {
    Write-Info "Cleanup disabled: removing all tags from original VM and resources..."

    # --- Remove all tags from the ORIGINAL VM (explicit delete per key) ---
    $oldVm = Get-AzVM -Name $VMN -ResourceGroupName $RG
    if ($oldVm.Tags -and $oldVm.Tags.Count -gt 0) {
        Write-Info ("Original VM tags before removal: {0}" -f (($oldVm.Tags.Keys -join ', ')))
        foreach ($tagKey in $oldVm.Tags.Keys) {
            try {
                Update-AzTag -ResourceId $oldVm.Id -Tag @{ $tagKey = $null } -Operation Delete | Out-Null
                Write-Info ("Removed tag '{0}' from VM" -f $tagKey)
            } catch {
                Write-Warn ("Failed to remove tag '{0}' from VM: {1}" -f $tagKey, $_.Exception.Message)
            }
        }
    } else {
        Write-Info "Original VM has no tags."
    }

    # --- Remove tags from ORIGINAL OS disk ---
    $osDiskCurrent = Get-AzDisk -ResourceGroupName $RG -Name $osDiskName
    if ($osDiskCurrent.Tags -and $osDiskCurrent.Tags.Keys.Count -gt 0) {
        foreach ($tagKey in $osDiskCurrent.Tags.Keys) {
            try {
                Update-AzTag -ResourceId $osDiskCurrent.Id -Tag @{ $tagKey = $null } -Operation Delete | Out-Null
                Write-Info ("Removed tag '{0}' from OS disk" -f $tagKey)
            } catch {
                Write-Warn ("Failed to remove tag '{0}' from OS disk: {1}" -f $tagKey, $_.Exception.Message)
            }
        }
    }

    # --- Remove tags from ORIGINAL data disks ---
    foreach ($d in $vm.StorageProfile.DataDisks) {
        $dRes = Get-AzDisk -ResourceGroupName $RG -Name $d.Name
        if ($dRes.Tags -and $dRes.Tags.Keys.Count -gt 0) {
            foreach ($tagKey in $dRes.Tags.Keys) {
                try {
                    Update-AzTag -ResourceId $dRes.Id -Tag @{ $tagKey = $null } -Operation Delete | Out-Null
                    Write-Info ("Removed tag '{0}' from data disk '{1}'" -f $tagKey, $d.Name)
                } catch {
                    Write-Warn ("Failed to remove tag '{0}' from data disk '{1}': {2}" -f $tagKey, $d.Name, $_.Exception.Message)
                }
            }
        }
    }

    # --- Remove tags from ORIGINAL NICs ---
    foreach ($ni in $nicInfos) {
        $nicRes = Get-AzNetworkInterface -Name $ni.Name -ResourceGroupName $RG
        if ($nicRes.Tags -and $nicRes.Tags.Keys.Count -gt 0) {
            foreach ($tagKey in $nicRes.Tags.Keys) {
                try {
                    Update-AzTag -ResourceId $nicRes.Id -Tag @{ $tagKey = $null } -Operation Delete | Out-Null
                    Write-Info ("Removed tag '{0}' from NIC '{1}'" -f $tagKey, $ni.Name)
                } catch {
                    Write-Warn ("Failed to remove tag '{0}' from NIC '{1}': {2}" -f $tagKey, $ni.Name, $_.Exception.Message)
                }
            }
        }
    }

    Write-Info "Original resources untagged and left deallocated."
}

# Remove snapshots (intermediate artifacts)
Write-Info "Removing snapshots..."
try {
    Remove-AzSnapshot -ResourceGroupName $RG -SnapshotName $osSnapName -Force
    foreach ($entry in $dataDiskSnapshots) {
        Remove-AzSnapshot -ResourceGroupName $RG -SnapshotName $entry.Snapshot.Name -Force
    }
    Write-Info "All snapshots removed."
} catch {
    Write-Warn ("Snapshot removal encountered errors: {0}" -f $_.Exception.Message)
}

Write-Info ("Completed. New regional VM '{0}' is online." -f $NewVMName)
