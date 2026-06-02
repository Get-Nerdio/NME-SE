#description: Convert VM OS disk between SCSI and NVMe controllers by running Microsoft's Azure-NVMe-Conversion script. Supports single-VM and batch (by VM size) modes.
#tags: NVMe, SCSI, Disk, VM, Migration, Azure-Boost

<#variables:
{
    "VMName": {
        "Description": "Name of the specific VM to convert. Leave empty to process all VMs in RG matching SourceVMSize.",
        "DisplayName": "VM Name"
    },
    "ResourceGroupName": {
        "Description": "Name of the resource group containing the VM(s).",
        "DisplayName": "Resource Group Name"
    },
    "SourceVMSize": {
        "Description": "Source VM SKU size to filter VMs for batch processing. NOTE: changing from v6 to v3 will fail.",
        "DefaultValue": "Standard_D4s_v6",
        "DisplayName": "Source VM Size"
    },
    "DestinationVMSize": {
        "Description": "Target VM SKU size after conversion.",
        "DefaultValue": "Standard_D4s_v5",
        "DisplayName": "Destination VM Size"
    },
    "NewControllerType": {
        "Description": "Target disk controller type (SCSI or NVMe).",
        "DefaultValue": "SCSI",
        "DisplayName": "New Controller Type"
    },
    "IgnoreRunningVMs": {
        "Description": "Skip VMs that are currently running/powered on.",
        "DefaultValue": "true",
        "DisplayName": "Ignore Running VMs"
    },
    "ProcessInGroupsOf": {
        "Description": "Number of VMs to process simultaneously in parallel jobs.",
        "DefaultValue": 3,
        "DisplayName": "Process In Groups Of"
    },
    "WhatIf": {
        "Description": "Preview what changes would be made without executing them.",
        "DefaultValue": "false",
        "DisplayName": "What-If Mode"
    }
}
#>

#Requires -Modules Az.Accounts, Az.Compute, Az.Resources

$ErrorActionPreference = 'Stop'

# -------- Helpers --------
function Write-Info { param($m) Write-Output ("[INFO]  " + $m) }
function Write-Warn { param($m) Write-Output ("[WARN]  " + $m) }
function Write-Err  { param($m) Write-Output ("[ERROR] " + $m) }

function ConvertTo-Bool {
    param($v)
    if ($null -eq $v) { return $false }
    if ($v -is [bool]) { return $v }
    $s = ($v | Out-String).Trim().ToLowerInvariant()
    switch -Regex ($s) {
        '^(true|1|yes|y)$'   { return $true }
        '^(false|0|no|n|)$'  { return $false }
        default              { return $false }
    }
}

function Test-VMPowerState {
    param(
        [Parameter(Mandatory)][string]$VMName,
        [Parameter(Mandatory)][string]$ResourceGroup
    )
    try {
        $vm = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroup -Status -ErrorAction Stop
        $powerState = ($vm.Statuses | Where-Object { $_.Code -like 'PowerState/*' } | Select-Object -Last 1).Code
        return @{
            PowerState = $powerState
            IsRunning = ($powerState -eq 'PowerState/running')
            IsDeallocated = ($powerState -eq 'PowerState/deallocated')
        }
    } catch {
        Write-Err ("Failed to get power state for VM '{0}': {1}" -f $VMName, $_.Exception.Message)
        return $null
    }
}

# -------- Resolve parameters --------
$startTime = Get-Date
Write-Info ("Conversion Script started at {0}" -f $startTime.ToString("yyyy-MM-dd HH:mm:ss"))

if (-not $ResourceGroupName) {
    throw "ResourceGroupName is required."
}

# Normalize boolean parameters
$IgnoreRunningVMs = ConvertTo-Bool $IgnoreRunningVMs
$WhatIfMode = ConvertTo-Bool $WhatIf
# Normalize and validate NewControllerType

$nt = $NewControllerType.Trim()
switch ($nt.ToUpperInvariant()) {
    'SCSI' { $NewControllerType = 'SCSI' }
    'NVME' { $NewControllerType = 'NVMe' }
    default {
        throw "Invalid NewControllerType value '$NewControllerType'. Valid values are 'SCSI' or 'NVMe'."
    }
}

Write-Info ("Normalized NewControllerType: {0}" -f $NewControllerType)

Write-Info ("Parameters resolved:")
Write-Info ("  - VMName: '{0}'" -f $(if ($VMName) { $VMName } else { "<batch mode - all VMs matching source size>" }))
Write-Info ("  - ResourceGroupName: '{0}'" -f $ResourceGroupName)
Write-Info ("  - SourceVMSize: '{0}'" -f $SourceVMSize)
Write-Info ("  - DestinationVMSize: '{0}'" -f $DestinationVMSize)
Write-Info ("  - NewControllerType: '{0}'" -f $NewControllerType)
Write-Info ("  - IgnoreRunningVMs: {0}" -f $IgnoreRunningVMs)
Write-Info ("  - ProcessInGroupsOf: {0}" -f $ProcessInGroupsOf)
Write-Info ("  - WhatIfMode: {0}" -f $WhatIfMode)

# -------- Download Microsoft's conversion script --------
$downloadStartTime = Get-Date
Write-Info ("Downloading Microsoft's NVMe conversion script... (started at {0})" -f $downloadStartTime.ToString("HH:mm:ss"))

$scriptUrl = "https://raw.githubusercontent.com/Azure/SAP-on-Azure-Scripts-and-Utilities/refs/heads/main/Azure-NVMe-Utils/Azure-NVMe-Conversion.ps1"
$localScriptPath = Join-Path $env:TEMP "Azure-NVMe-Conversion.ps1"

try {
    Invoke-WebRequest -Uri $scriptUrl -OutFile $localScriptPath -ErrorAction Stop
    Write-Info ("Successfully downloaded script to: {0}" -f $localScriptPath)
} catch {
    Write-Err ("Failed to download Microsoft's conversion script: {0}" -f $_.Exception.Message)
    if (Test-Path $localScriptPath) {
        Remove-Item $localScriptPath -Force -ErrorAction SilentlyContinue
    }
    throw
}


# -------- Identify VMs to process --------

Write-Info ("Identifying VMs to process...")

$vmsToProcess = @()

if ($VMName -and -not [string]::IsNullOrWhiteSpace($VMName)) {
    # Single VM mode
    Write-Info ("Single VM mode: processing specific VM '{0}'" -f $VMName)
    try {
        $vm = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        $vmsToProcess += $vm
        Write-Info ("Found target VM: {0} (Size: {1})" -f $vm.Name, $vm.HardwareProfile.VmSize)
    } catch {
        Write-Err ("Failed to find VM '{0}' in resource group '{1}': {2}" -f $VMName, $ResourceGroupName, $_.Exception.Message)
        throw
    }
} else {
    # Batch mode - find all VMs matching source size
    Write-Info ("Batch mode: finding all VMs with size '{0}' in resource group '{1}'" -f $SourceVMSize, $ResourceGroupName)
    try {
        $allVMs = Get-AzVM -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        $vmsToProcess = $allVMs | Where-Object { $_.HardwareProfile.VmSize -eq $SourceVMSize }
        
        Write-Info ("Found {0} total VMs in resource group" -f $allVMs.Count)
        Write-Info ("Found {0} VMs matching source size '{1}'" -f $vmsToProcess.Count, $SourceVMSize)
        
        if ($vmsToProcess.Count -eq 0) {
            Write-Warn ("No VMs found matching source size '{0}' in resource group '{1}'" -f $SourceVMSize, $ResourceGroupName)
            return
        }
        
        foreach ($vm in $vmsToProcess) {
            Write-Info ("  - {0} (Size: {1})" -f $vm.Name, $vm.HardwareProfile.VmSize)
        }
    } catch {
        Write-Err ("Failed to retrieve VMs from resource group '{0}': {1}" -f $ResourceGroupName, $_.Exception.Message)
        throw
    }
}


# -------- Filter/warn by power state --------
$powerStateFilterStartTime = Get-Date
$filterAction = if ($IgnoreRunningVMs) { "Filtering out running VMs" } else { "Checking power states (IgnoreRunningVMs=false — running VMs will be included and may fail conversion)" }
Write-Info ("{0}... (started at {1})" -f $filterAction, $powerStateFilterStartTime.ToString("HH:mm:ss"))

$filteredVMs = @()
$skippedVMs = @()

foreach ($vm in $vmsToProcess) {
    $powerInfo = Test-VMPowerState -VMName $vm.Name -ResourceGroup $ResourceGroupName
    if ($powerInfo) {
        if ($powerInfo.IsRunning -and $IgnoreRunningVMs) {
            $skippedVMs += $vm
            Write-Info ("  - SKIPPED: {0} (PowerState: {1})" -f $vm.Name, $powerInfo.PowerState)
        } elseif ($powerInfo.IsRunning -and -not $IgnoreRunningVMs) {
            $filteredVMs += $vm
            Write-Warn ("  - INCLUDED (RUNNING): {0} — VM is running; conversion will likely fail unless the Microsoft script stops it" -f $vm.Name)
        } else {
            $filteredVMs += $vm
            Write-Info ("  - ELIGIBLE: {0} (PowerState: {1})" -f $vm.Name, $powerInfo.PowerState)
        }
    } else {
        Write-Warn ("  - ERROR: Could not determine power state for {0}, skipping" -f $vm.Name)
        $skippedVMs += $vm
    }
}

$vmsToProcess = $filteredVMs

Write-Info ("Power state check results:")
Write-Info ("  - Eligible VMs: {0}" -f $vmsToProcess.Count)
Write-Info ("  - Skipped VMs: {0}" -f $skippedVMs.Count)

if ($vmsToProcess.Count -eq 0) {
    Write-Warn "No VMs are eligible for processing after power state filtering"
    return
}

$powerStateFilterDuration = ((Get-Date) - $powerStateFilterStartTime).TotalSeconds
Write-Info ("Power state check completed in {0:F1}s" -f $powerStateFilterDuration)

# -------- What-If mode --------
if ($WhatIfMode) {
    $whatIfStartTime = Get-Date
    Write-Info ("=== WHAT-IF MODE: Changes that would be made === (started at {0})" -f $whatIfStartTime.ToString("HH:mm:ss"))

    $eligibleVMs = @()
    $ineligibleVMs = @()

    foreach ($vm in $vmsToProcess) {
        Write-Info ("Checking VM '{0}':" -f $vm.Name)
        Write-Info ("  - Current Size: {0}" -f $vm.HardwareProfile.VmSize)
        Write-Info ("  - Target Size: {0}" -f $DestinationVMSize)
        Write-Info ("  - Controller: Current -> {0}" -f $NewControllerType)
        Write-Info ("  - Resource Group: {0}" -f $ResourceGroupName)

        $reasons = @()
        try {
            $vmFull = Get-AzVM -Name $vm.Name -ResourceGroupName $ResourceGroupName -Status -ErrorAction Stop

            # Check SecurityType - Trusted Launch blocks NVMe conversion
            $securityType = if ($vmFull.SecurityProfile) { $vmFull.SecurityProfile.SecurityType } else { $null }
            if ($NewControllerType -eq 'NVMe' -and $securityType -eq 'TrustedLaunch') {
                $reasons += "Trusted Launch VM — NVMe conversion is not supported"
            }

            if ($reasons.Count -eq 0) {
                $eligibleVMs += $vm
                Write-Info ("  - ELIGIBLE for conversion")
                Write-Info ("  - Process: Stop VM -> Update OS settings -> Convert controller -> Resize -> Start")
            } else {
                $ineligibleVMs += $vm
                foreach ($reason in $reasons) {
                    Write-Warn ("  - INELIGIBLE: {0}" -f $reason)
                }
            }
        } catch {
            $ineligibleVMs += $vm
            Write-Warn ("  - INELIGIBLE: Could not fetch VM details — {0}" -f $_.Exception.Message)
        }
    }

    Write-Info ("")
    Write-Info ("What-If eligibility summary:")
    Write-Info ("  - Eligible: {0}" -f $eligibleVMs.Count)
    Write-Info ("  - Ineligible: {0}" -f $ineligibleVMs.Count)

    if ($ineligibleVMs.Count -gt 0) {
        Write-Warn ("The following VMs would be skipped during actual execution:")
        foreach ($vm in $ineligibleVMs) {
            Write-Warn ("  - {0}" -f $vm.Name)
        }
    }

    Write-Info ("")
    Write-Info ("Batch processing configuration:")
    Write-Info ("  - Total eligible VMs: {0}" -f $eligibleVMs.Count)
    Write-Info ("  - Process in groups of: {0}" -f $ProcessInGroupsOf)
    Write-Info ("  - Estimated groups: {0}" -f [Math]::Ceiling($eligibleVMs.Count / $ProcessInGroupsOf))

    $whatIfDuration = ((Get-Date) - $whatIfStartTime).TotalSeconds
    Write-Info ("=== END WHAT-IF MODE === (took {0:F1}s)" -f $whatIfDuration)
    return
}

# -------- Process VMs --------
try {
    $conversionStartTime = Get-Date
    Write-Info ("Starting VM conversions... (started at {0})" -f $conversionStartTime.ToString("HH:mm:ss"))

# Create script block for parallel execution
$ConversionScriptBlock = {
    param(
        $VM,
        $ResourceGroupName,
        $DestinationVMSize,
        $NewControllerType,
        $LocalScriptPath
    )
    
    function Write-JobInfo { param($m) Write-Output ("[JOB-$($VM.Name)] " + $m) }
    function Write-JobWarn { param($m) Write-Output ("[WARN-$($VM.Name)] " + $m) }
    function Write-JobErr  { param($m) Write-Output ("[ERROR-$($VM.Name)] " + $m) }
    
    $jobStartTime = Get-Date
    Write-JobInfo ("Starting conversion process (started at {0})" -f $jobStartTime.ToString("HH:mm:ss"))
    
    try {
        # Verify the script file exists in the job context
        if (-not (Test-Path $LocalScriptPath)) {
            throw "Microsoft's conversion script not found at: $LocalScriptPath"
        }
        
        Write-JobInfo ("Converting VM '{0}' from size '{1}' to '{2}'" -f $VM.Name, $VM.HardwareProfile.VmSize, $DestinationVMSize)
        Write-JobInfo ("Using Microsoft's script: {0}" -f $LocalScriptPath)
        
        # Get initial VM state for validation
        $initialVM = Get-AzVM -Name $VM.Name -ResourceGroupName $ResourceGroupName -Status -ErrorAction Stop
        $initialPowerState = ($initialVM.Statuses | Where-Object { $_.Code -like 'PowerState/*' } | Select-Object -Last 1).Code
        $initialSize = $initialVM.HardwareProfile.VmSize
        $initialControllerType = $initialVM.StorageProfile.DiskControllerType
        
        Write-JobInfo ("Initial VM state - Size: {0}, PowerState: {1}" -f $initialSize, $initialPowerState)
        
        # Run the conversion script and capture its output
        Write-JobInfo ("Calling Microsoft's NVMe conversion script...")

        $scriptArgs = @{
            ResourceGroupName      = $ResourceGroupName
            VMName                 = $VM.Name
            NewControllerType      = $NewControllerType
            VMSize                 = $DestinationVMSize
            StartVM                = $true
            IgnoreAzureModuleCheck = $true
        }

        Write-JobInfo ("Script arguments: ResourceGroupName={0}, VMName={1}, NewControllerType={2}, VMSize={3}, StartVM={4}, IgnoreAzureModuleCheck={5}" -f $scriptArgs.ResourceGroupName, $scriptArgs.VMName, $scriptArgs.NewControllerType, $scriptArgs.VMSize, $scriptArgs.StartVM, $scriptArgs.IgnoreAzureModuleCheck)

        try {
            # Capture all streams including Write-Host (stream 6) which the Microsoft script uses heavily
            $conversionOutput = & $LocalScriptPath @scriptArgs *>&1

            Write-JobInfo ("Microsoft script execution completed")

            # Display the conversion script output (only if we captured something)
            if ($conversionOutput -and $conversionOutput.Count -gt 0) {
                Write-JobInfo ("Microsoft script output:")
                foreach ($line in $conversionOutput) {
                    if ($line -and $line.ToString().Trim()) {
                        Write-JobInfo ("  $($line.ToString())")
                    }
                }
            }

        } catch {
            Write-JobErr ("Error executing Microsoft script: {0}" -f $_.Exception.Message)
            Write-Error $_.Exception.Message
            throw
        }
        
        # Validate the conversion actually happened
        Write-JobInfo ("Validating conversion results...")
        Start-Sleep -Seconds 15  # Give Azure more time to update after script execution

        $finalVM = Get-AzVM -Name $VM.Name -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        $finalSize = $finalVM.HardwareProfile.VmSize
        $finalControllerType = $finalVM.StorageProfile.DiskControllerType

        Write-JobInfo ("Final VM state - Size: {0}, Controller: {1}" -f $finalSize, $finalControllerType)

        # Primary check: controller type must have changed to the target
        $controllerChanged = ($finalControllerType -eq $NewControllerType)

        if ($controllerChanged) {
            Write-JobInfo ("Controller type changed: {0} -> {1} (SUCCESS)" -f $initialControllerType, $NewControllerType)
        } else {
            Write-JobWarn ("Controller type did not change: still {0} (expected {1})" -f $finalControllerType, $NewControllerType)
        }

        # Secondary check: VM size should match destination (informational)
        if ($finalSize -ne $DestinationVMSize) {
            Write-JobWarn ("VM size is '{0}', expected '{1}' (may not match if conversion succeeded with same SKU family)" -f $finalSize, $DestinationVMSize)
        }

        # Additional storage profile information
        $storageProfile = $finalVM.StorageProfile
        if ($storageProfile) {
            Write-JobInfo ("Storage profile:")
            Write-JobInfo ("  - OS Disk: {0}" -f $storageProfile.OsDisk.Name)
            Write-JobInfo ("  - Controller: {0}" -f $storageProfile.DiskControllerType)
            if ($storageProfile.DataDisks) {
                Write-JobInfo ("  - Data Disks: {0}" -f $storageProfile.DataDisks.Count)
            }
        }

        $conversionSuccessful = $controllerChanged
        
        if ($conversionSuccessful) {
            $jobDuration = ((Get-Date) - $jobStartTime).TotalSeconds
            Write-JobInfo ("Conversion completed successfully in {0:F1}s" -f $jobDuration)
            
            return @{
                Success = $true
                VMName = $VM.Name
                OriginalSize = $initialSize
                NewSize = $finalSize
                Duration = $jobDuration
                Message = "Conversion completed successfully"
                InitialPowerState = $initialPowerState
            }
        } else {
            $jobDuration = ((Get-Date) - $jobStartTime).TotalSeconds
            $errorMessage = "Conversion validation failed: controller type is '{0}', expected '{1}'" -f $finalControllerType, $NewControllerType
            Write-JobErr ("Conversion failed after {0:F1}s: {1}" -f $jobDuration, $errorMessage)
            
            return @{
                Success = $false
                VMName = $VM.Name
                OriginalSize = $initialSize
                NewSize = $finalSize
                Duration = $jobDuration
                Message = $errorMessage
                InitialPowerState = $initialPowerState
            }
        }
        
    } catch {
        $jobDuration = ((Get-Date) - $jobStartTime).TotalSeconds
        $errorMessage = $_.Exception.Message

        Write-JobErr ("Conversion failed after {0:F1}s: {1}" -f $jobDuration, $errorMessage)
        Write-Error $_.Exception.Message

        return @{
            Success = $false
            VMName = $VM.Name
            OriginalSize = if ($VM.HardwareProfile.VmSize) { $VM.HardwareProfile.VmSize } else { "Unknown" }
            NewSize = $DestinationVMSize
            Duration = $jobDuration
            Message = "Conversion failed: $errorMessage"
            Error = $errorMessage
        }
    }
}

# Process VMs in groups
$allResults = @()
$totalVMs = $vmsToProcess.Count
$processedVMs = 0

for ($i = 0; $i -lt $totalVMs; $i += $ProcessInGroupsOf) {
    $groupStartTime = Get-Date
    
    # Calculate the actual number of VMs in this group
    $remainingVMs = $totalVMs - $i
    $vmsInThisGroup = [Math]::Min($ProcessInGroupsOf, $remainingVMs)
    $groupEndIndex = $i + $vmsInThisGroup - 1
    
    $currentGroup = @($vmsToProcess)[$i..$groupEndIndex]
    $groupNumber = [Math]::Floor($i / $ProcessInGroupsOf) + 1
    $totalGroups = [Math]::Ceiling($totalVMs / $ProcessInGroupsOf)
    
    Write-Info ("Processing group {0}/{1} ({2} VMs)... (started at {3})" -f $groupNumber, $totalGroups, $currentGroup.Count, $groupStartTime.ToString("HH:mm:ss"))
    
    # Start jobs for current group
    $jobs = @()
    foreach ($vm in $currentGroup) {
        Write-Info ("  Starting job for VM: {0}" -f $vm.Name)
        $job = Start-Job -ScriptBlock $ConversionScriptBlock -ArgumentList $vm, $ResourceGroupName, $DestinationVMSize, $NewControllerType, $localScriptPath
        $jobs += @{ Job = $job; VM = $vm }
    }
    
    # Wait for all jobs in the group to complete
    Write-Info ("Waiting for {0} jobs to complete..." -f $jobs.Count)
    
    foreach ($jobInfo in $jobs) {
        $job = $jobInfo.Job
        $vm = $jobInfo.VM
        
        Write-Info ("Waiting for job completion: {0}" -f $vm.Name)
        
        # Wait for job to complete and get all output
        $jobOutput = Receive-Job -Job $job -Wait
        
        # Display job output (this includes both logging and the return hashtable)
        $jobResult = $null
        if ($jobOutput) {
            foreach ($output in $jobOutput) {
                if ($output -is [hashtable] -and $output.ContainsKey('VMName')) {
                    # This is our return result
                    $jobResult = $output
                } else {
                    # This is logging output
                    Write-Output $output
                }
            }
        }
        
        # Store the result
        if ($jobResult) {
            $allResults += $jobResult
        } else {
            # Fallback result if job didn't return expected format
            Write-Warn ("Job for VM '{0}' did not return expected result format. Job state: {1}" -f $vm.Name, $job.State)
            $allResults += @{
                Success = $job.State -eq 'Completed'
                VMName = $vm.Name
                OriginalSize = $vm.HardwareProfile.VmSize
                NewSize = $DestinationVMSize
                Message = "Job completed with state: $($job.State) but did not return expected result"
                Duration = 0
            }
        }
        
        Remove-Job -Job $job
        $processedVMs++
        
        Write-Info ("Progress: {0}/{1} VMs completed" -f $processedVMs, $totalVMs)
    }
    
    $groupDuration = ((Get-Date) - $groupStartTime).TotalSeconds
    Write-Info ("Group {0}/{1} completed in {2:F1}s" -f $groupNumber, $totalGroups, $groupDuration)
}

# -------- Summary --------
$totalDuration = ((Get-Date) - $startTime).TotalSeconds
Write-Info ("=== CONVERSION SUMMARY ===")
Write-Info ("Total execution time: {0:F1}s" -f $totalDuration)
Write-Info ("Total VMs processed: {0}" -f $allResults.Count)

$successfulConversions = @($allResults | Where-Object { $_.Success -eq $true })
$failedConversions = @($allResults | Where-Object { $_.Success -eq $false })

Write-Info ("Successful conversions: {0}" -f $successfulConversions.Count)
Write-Info ("Failed conversions: {0}" -f $failedConversions.Count)

if ($successfulConversions.Count -gt 0) {
    Write-Info ("Successful conversions:")
    foreach ($result in $successfulConversions) {
        $durationText = if ($result.Duration) { "{0:F1}s" -f $result.Duration } else { "unknown duration" }
        Write-Info ("  ✓ {0}: {1} -> {2} (took {3})" -f $result.VMName, $result.OriginalSize, $result.NewSize, $durationText)
    }
}

if ($failedConversions.Count -gt 0) {
    Write-Warn ("Failed conversions:")
    foreach ($result in $failedConversions) {
        Write-Warn ("  ✗ {0}: {1}" -f $result.VMName, $result.Message)
    }
}

Write-Info ("Disk controller conversion process completed at {0}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))

} catch {
    Write-Error $_.Exception.Message
    throw
} finally {
    try {
        if (Test-Path $localScriptPath) {
            Remove-Item $localScriptPath -Force
            Write-Info ("Cleaned up downloaded script file: {0}" -f $localScriptPath)
        }
    } catch {
        Write-Warn ("Failed to clean up script file: {0}" -f $_.Exception.Message)
    }
}
