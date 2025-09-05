<#
.SYNOPSIS
  Adds autoscale restriction tags to VMs and deallocates running VMs that don't have protection tags.

.DESCRIPTION
  This script finds all VMs across all subscriptions available to the automation account's managed identity
  that do not have a 'DoNotRestrictAutoscale' tag. For each qualifying VM:
  - Adds 'NMW_AUTOSCALE_RESTRICTION' tag if not already present
  - Deallocates the VM if it is currently running
  
  Designed for Azure Automation (PowerShell) using the account's Managed Identity.

.PARAMETER SubscriptionIds
  Optional: limit processing to these subscription IDs. If omitted, all accessible subscriptions are processed.

.PARAMETER PreviewOnly
  If true, shows what would be done without making any changes.

.PARAMETER SkipDeallocation
  If true, only adds tags but does not deallocate VMs.

.PREREQS
  • Automation account has Az.Accounts and Az.Compute modules (recent versions).
  • Managed Identity has at least "Contributor" on the target subscriptions to modify VMs and tags.

.EXAMPLE
  .\DisableAutoscaleAndShutdownVms.ps1
  .\DisableAutoscaleAndShutdownVms.ps1 -PreviewOnly $true
  .\DisableAutoscaleAndShutdownVms.ps1 -SkipDeallocation $true

.TAGS
  Azure Automation, VM Management, Autoscale
#>

[CmdletBinding()]
param(
  # Optional: limit processing to these subscription IDs. If omitted, all accessible subscriptions are processed.
  [Parameter(Mandatory = $false)]
  [string[]] $SubscriptionIds = @(),

  # Dry run (no changes). Shows what would be done.
  [bool] $PreviewOnly = $false,

  # Only add tags, do not deallocate VMs.
  [bool] $SkipDeallocation = $false
)

#------------- Helpers -------------#

function Write-Log {
  param(
    [string] $Message,
    [ValidateSet('INFO','WARN','ERROR','DEBUG')]
    [string] $Level = 'INFO'
  )
  $stamp = (Get-Date).ToString('u')
  switch ($Level) {
    'INFO'  { Write-Output    "[$stamp] [INFO]  $Message" }
    'WARN'  { Write-Warning   "[$stamp] [WARN]  $Message" }
    'ERROR' { Write-Error     "[$stamp] [ERROR] $Message" }
    'DEBUG' { Write-Verbose   "[$stamp] [DEBUG] $Message" }
  }
}

function Add-TagToVM {
  param(
    [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine] $VM,
    [string] $TagName,
    [string] $TagValue = "true"
  )

  try {
    # Get current tags or create new hashtable
    $tags = @{}
    if ($VM.Tags) {
      # Copy existing tags to new hashtable
      foreach ($key in $VM.Tags.Keys) {
        $tags[$key] = $VM.Tags[$key]
      }
    }

    # Check if tag already exists
    if ($tags.ContainsKey($TagName)) {
      if ($PreviewOnly) {
        Write-Log "[PREVIEW] VM '$($VM.Name)' already has tag '$TagName' - no change needed" 'INFO'
      } else {
        Write-Log "VM '$($VM.Name)' already has tag '$TagName'" 'DEBUG'
      }
      return $true
    }

    # Add the new tag
    $tags[$TagName] = $TagValue

    if ($PreviewOnly) {
      Write-Log "[PREVIEW] Would add tag '$TagName'='$TagValue' to VM '$($VM.Name)'" 'INFO'
      return $true
    }

    # Update the VM tags
    Update-AzVM -ResourceGroupName $VM.ResourceGroupName -VM $VM -Tag $tags | Out-Null
    Write-Log "Added tag '$TagName'='$TagValue' to VM '$($VM.Name)'" 'INFO'
    return $true

  } catch {
    Write-Log "Failed to add tag to VM '$($VM.Name)': $($_.Exception.Message)" 'ERROR'
    return $false
  }
}

function Stop-VMIfRunning {
  param(
    [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine] $VM
  )

  try {
    # Get current VM status
    $vmStatus = Get-AzVM -ResourceGroupName $VM.ResourceGroupName -Name $VM.Name -Status
    $powerState = ($vmStatus.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus

    if ($powerState -eq "VM running") {
      if ($PreviewOnly) {
        Write-Log "[PREVIEW] Would deallocate running VM '$($VM.Name)'" 'INFO'
        return $true
      }

      Write-Log "Deallocating running VM '$($VM.Name)'" 'INFO'
      Stop-AzVM -ResourceGroupName $VM.ResourceGroupName -Name $VM.Name -Force | Out-Null
      Write-Log "Successfully deallocated VM '$($VM.Name)'" 'INFO'
      return $true
    } else {
      Write-Log "VM '$($VM.Name)' is not running (Status: $powerState)" 'DEBUG'
      return $true
    }

  } catch {
    Write-Log "Failed to deallocate VM '$($VM.Name)': $($_.Exception.Message)" 'ERROR'
    return $false
  }
}

#------------- Connect (Managed Identity) -------------#

try {
  Disable-AzContextAutosave -Scope Process | Out-Null
  Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
  Write-Log "Authenticated with managed identity." 'INFO'
} catch {
  throw "Failed to authenticate with managed identity: $($_.Exception.Message)"
}

# Determine subscriptions to process
$subs = @()
try {
  if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
    foreach ($sid in $SubscriptionIds) {
      $subs += Get-AzSubscription -SubscriptionId $sid -ErrorAction Stop
    }
  } else {
    $subs = Get-AzSubscription -ErrorAction Stop
  }
} catch {
  throw "Failed to enumerate subscriptions: $($_.Exception.Message)"
}

if (-not $subs -or $subs.Count -eq 0) {
  throw "No subscriptions available to the managed identity."
}

Write-Log "Processing $($subs.Count) subscription(s)" 'INFO'

# Counters for summary
$totalVMs = 0
$processedVMs = 0
$skippedVMs = 0
$taggedVMs = 0
$deallocatedVMs = 0
$errorVMs = 0

#------------- Main -------------#

foreach ($sub in $subs) {
  Write-Log "Processing subscription $($sub.Name) ($($sub.Id))" 'INFO'
  
  try {
    Set-AzContext -SubscriptionId $sub.Id -Tenant $sub.TenantId -ErrorAction Stop | Out-Null
  } catch {
    Write-Log "Failed to set context for subscription $($sub.Id): $($_.Exception.Message)" 'ERROR'
    continue
  }

  # Get all VMs in the subscription
  try {
    $vms = Get-AzVM -ErrorAction Stop
  } catch {
    Write-Log "Failed to get VMs in subscription $($sub.Id): $($_.Exception.Message)" 'ERROR'
    continue
  }

  if (-not $vms -or $vms.Count -eq 0) {
    Write-Log "No VMs found in subscription $($sub.Id)" 'INFO'
    continue
  }

  Write-Log "Found $($vms.Count) VM(s) in subscription $($sub.Id)" 'INFO'
  $totalVMs += $vms.Count

  foreach ($vm in $vms) {
    if ($PreviewOnly) {
      Write-Log "[PREVIEW] Evaluating VM '$($vm.Name)' in resource group '$($vm.ResourceGroupName)'" 'INFO'
    } else {
      Write-Log "Evaluating VM '$($vm.Name)' in resource group '$($vm.ResourceGroupName)'" 'DEBUG'
    }

    # Check if VM has the protection tag
    if ($vm.Tags -and $vm.Tags.ContainsKey('DoNotRestrictAutoscale')) {
      Write-Log "Skipping VM '$($vm.Name)' - has 'DoNotRestrictAutoscale' tag" 'INFO'
      $skippedVMs++
      continue
    }

    $processedVMs++
    $vmSuccess = $true

    # Add the autoscale restriction tag
    if (-not ($vm.Tags -and $vm.Tags.ContainsKey('NMW_AUTOSCALE_RESTRICTION'))) {
      if (Add-TagToVM -VM $vm -TagName 'NMW_AUTOSCALE_RESTRICTION' -TagValue 'true') {
        $taggedVMs++
      } else {
        $vmSuccess = $false
      }
    } else {
      Write-Log "VM '$($vm.Name)' already has 'NMW_AUTOSCALE_RESTRICTION' tag - no action needed" 'INFO'
      # Still count as "tagged" since it has the desired state
      $taggedVMs++
    }

    # Deallocate VM if running (unless skipping deallocation)
    if (-not $SkipDeallocation) {
      if (Stop-VMIfRunning -VM $vm) {
        # Check if we actually would deallocate or did deallocate it
        try {
          $vmStatus = Get-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name -Status
          $powerState = ($vmStatus.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus
          if ($powerState -eq "VM running") {
            # VM was running and we attempted to stop it (or would stop it in preview)
            $deallocatedVMs++
          }
        } catch {
          # Don't fail the whole operation if we can't check status
          Write-Log "Could not verify final status of VM '$($vm.Name)'" 'WARN'
        }
      } else {
        $vmSuccess = $false
      }
    }

    if (-not $vmSuccess) {
      $errorVMs++
    }
  }
}

#------------- Summary -------------#

Write-Log "" 'INFO'
Write-Log "=== OPERATION COMPLETED ===" 'INFO'
Write-Log "Total VMs found: $totalVMs" 'INFO'
Write-Log "VMs processed: $processedVMs" 'INFO'
Write-Log "VMs skipped (protected): $skippedVMs" 'INFO'
Write-Log "VMs tagged: $taggedVMs" 'INFO'
if (-not $SkipDeallocation) {
  Write-Log "VMs deallocated: $deallocatedVMs" 'INFO'
}
Write-Log "VMs with errors: $errorVMs" 'INFO'
Write-Log "Preview mode: $PreviewOnly" 'INFO'
Write-Log "Skip deallocation: $SkipDeallocation" 'INFO'
