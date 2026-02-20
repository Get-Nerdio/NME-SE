<#
.SYNOPSIS
  Disables autoscale for all host pools in Nerdio Manager, powers off all running session hosts,
  and deallocates all desktop image VMs.

.DESCRIPTION
  This runbook uses the NerdioManagerPowerShell module to:
  1. Disable autoscale for every AVD host pool managed by NME
  2. Power off all session hosts that are currently powered on
  3. Deallocate all desktop image VMs

  Intended for scheduled use in lab and demo environments to reduce Azure spend.

.PARAMETER PreviewOnly
  If true, logs what would be done without making changes.

.PREREQS
  - Automation account has the NerdioManagerPowerShell module installed
  - Automation account has Az.Accounts, Az.Compute, Az.Resources, Az.DesktopVirtualization modules
  - Automation account variables: NmeTenantId, NmeClientId, NmeClientSecret, NmeScope, NmeUri
  - Managed Identity has at least Contributor on target subscriptions

.EXAMPLE
  .\DisableAutoscaleAndPowerOffVMs.ps1
  .\DisableAutoscaleAndPowerOffVMs.ps1 -PreviewOnly $true
#>

[CmdletBinding()]
param(
  [bool] $PreviewOnly = $false,
  [string]$NmeVariablePrefix  # Prefix for NME API credentials in Automation Account variables
)

$ErrorActionPreference = 'Stop'

#region Helpers

function Write-Log {
  param(
    [string] $Message,
    [ValidateSet('INFO','WARN','ERROR')]
    [string] $Level = 'INFO'
  )
  $stamp = (Get-Date).ToString('u')
  switch ($Level) {
    'INFO'  { Write-Output  "[$stamp] [INFO]  $Message" }
    'WARN'  { Write-Warning "[$stamp] [WARN]  $Message" }
    'ERROR' { Write-Error   "[$stamp] [ERROR] $Message" }
  }
}

#endregion

#region Authentication

# Retrieve NME API credentials from automation account variables
$NmeTenantId     = Get-AutomationVariable -Name "${NmeVariablePrefix}TenantId"
$NmeClientId     = Get-AutomationVariable -Name "${NmeVariablePrefix}ClientId"
$NmeClientSecret = Get-AutomationVariable -Name "${NmeVariablePrefix}ClientSecret"
$NmeScope        = Get-AutomationVariable -Name "${NmeVariablePrefix}Scope"
$NmeUri          = Get-AutomationVariable -Name "${NmeVariablePrefix}Uri"

# Connect to Azure using automation account managed identity
Disable-AzContextAutosave -Scope Process | Out-Null
Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
Write-Log "Authenticated with Azure managed identity."

# Import NME module and connect to NME API
Import-Module NerdioManagerPowerShell -Force
Connect-Nme -ClientId $NmeClientId -ClientSecret $NmeClientSecret -TenantId $NmeTenantId -ApiScope $NmeScope -NmeUri $NmeUri | Out-Null
Write-Log "Connected to NME API at $NmeUri."

#endregion

# Counters for summary
$hostPoolsProcessed   = 0
$autoscaleDisabled    = 0
$hostsStopRequested   = 0
$hostsSkipped         = 0
$imagesStopRequested  = 0
$errors               = 0

#region 1. Enumerate host pools in NME-linked resource groups

$linkedRGs = Get-NmeLinkedResourceGroup -ErrorAction Stop
Write-Log "Found $($linkedRGs.Count) NME-linked resource group(s)."

$allHostPools = @()
foreach ($rg in $linkedRGs) {
  Set-AzContext -SubscriptionId $rg.SubscriptionId -ErrorAction Stop | Out-Null
  $hps = Get-AzResource -ResourceType 'Microsoft.DesktopVirtualization/hostpools' -ResourceGroupName $rg.Name -ErrorAction SilentlyContinue
  if ($hps) {
    foreach ($hp in $hps) {
      $allHostPools += [PSCustomObject]@{
        SubscriptionId = $rg.SubscriptionId
        ResourceGroup  = $rg.Name
        HostPoolName   = $hp.Name
      }
    }
  }
}

Write-Log "Found $($allHostPools.Count) host pool(s) across NME-linked resource groups."

#endregion

#region 2. Disable autoscale and power off session hosts for each host pool

foreach ($hp in $allHostPools) {
  $hpLabel = "$($hp.HostPoolName) ($($hp.ResourceGroup))"
  $hostPoolsProcessed++

  # --- Disable autoscale ---
  try {
    $asConfig = Get-NmeHostPoolAutoScaleConfig `
      -SubscriptionId $hp.SubscriptionId `
      -ResourceGroup  $hp.ResourceGroup `
      -HostPoolName   $hp.HostPoolName -ErrorAction Stop

    if ($asConfig.IsEnabled -eq $true) {
      if ($PreviewOnly) {
        Write-Log "[PREVIEW] [$hpLabel] Would disable autoscale."
      } else {
        $disableRequest = New-NmeUpdateAutoScaleRequest -IsEnabled $false
        Update-NmeHostPoolAutoScaleConfig `
          -SubscriptionId          $hp.SubscriptionId `
          -ResourceGroup           $hp.ResourceGroup `
          -HostPoolName            $hp.HostPoolName `
          -NmeUpdateAutoScaleRequest $disableRequest -ErrorAction Stop | Out-Null
        Write-Log "[$hpLabel] Autoscale disabled."
      }
      $autoscaleDisabled++
    } else {
      Write-Log "[$hpLabel] Autoscale already disabled."
    }
  } catch {
    # Host pool may not be managed by NME or may not be dynamic
    Write-Log "[$hpLabel] Could not update autoscale: $($_.Exception.Message)" 'WARN'
    $errors++
  }

  # --- Power off session hosts ---
  try {
    $sessionHosts = Get-NmeHostPoolSessionHosts `
      -SubscriptionId $hp.SubscriptionId `
      -ResourceGroup  $hp.ResourceGroup `
      -HostPoolName   $hp.HostPoolName -ErrorAction Stop

    if (-not $sessionHosts) {
      Write-Log "[$hpLabel] No session hosts found."
      continue
    }

    # Set Azure context for VM status checks
    Set-AzContext -SubscriptionId $hp.SubscriptionId -ErrorAction Stop | Out-Null

    foreach ($sh in $sessionHosts) {
      $hostName = $sh.HostName
      if (-not $hostName) { continue }

      # Derive VM name (hostName may be FQDN like "vm-0.domain.local" or just "vm-0")
      $vmName = ($hostName -split '\.')[0]

      try {
        # Check VM power state via Azure to avoid unnecessary stop calls
        $vmStatus = Get-AzVM -ResourceGroupName $hp.ResourceGroup -Name $vmName -Status -ErrorAction SilentlyContinue
        if (-not $vmStatus) {
          # VM might be in a different resource group; search by name
          $vmStatus = Get-AzVM -Name $vmName -Status -ErrorAction SilentlyContinue
        }

        $powerState = ($vmStatus.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus

        if ($powerState -eq 'VM running') {
          if ($PreviewOnly) {
            Write-Log "[PREVIEW] [$hpLabel] Would power off session host '$vmName'."
          } else {
            Write-Log "[$hpLabel] Powering off session host '$vmName'..."
            $stopCmd     = New-NmePowerStateCommandPayload -Command "Stop"
            $stopRequest = New-NmePowerStateCommandRequest -JobPayload $stopCmd
            Set-NmeSessionHostPowerState `
              -SubscriptionId              $hp.SubscriptionId `
              -ResourceGroup               $hp.ResourceGroup `
              -HostPoolName                $hp.HostPoolName `
              -Hostname                    $hostName `
              -NmePowerStateCommandRequest $stopRequest -ErrorAction Stop | Out-Null
            Write-Log "[$hpLabel] Stop requested for session host '$vmName'."
          }
          $hostsStopRequested++
        } else {
          Write-Log "[$hpLabel] Session host '$vmName' is not running (Status: $powerState)."
          $hostsSkipped++
        }
      } catch {
        Write-Log "[$hpLabel] Failed to stop session host '$vmName': $($_.Exception.Message)" 'WARN'
        $errors++
      }
    }
  } catch {
    Write-Log "[$hpLabel] Failed to enumerate session hosts: $($_.Exception.Message)" 'WARN'
    $errors++
  }
}

#endregion

#region 3. Power off desktop image VMs

try {
  $desktopImages = Get-NmeDesktopImage -ErrorAction Stop

  if (-not $desktopImages) {
    Write-Log "No desktop images found in NME."
  } else {
    Write-Log "Found $($desktopImages.Count) desktop image(s)."

    foreach ($image in $desktopImages) {
      $imageName = $image.Name
      if (-not $imageName) { continue }

      try {
        # Desktop images are Azure VMs; find and deallocate if running
        $vm = $null

        # Search for the VM across NME-linked resource groups
        foreach ($rg in $linkedRGs) {
          Set-AzContext -SubscriptionId $rg.SubscriptionId -ErrorAction Stop | Out-Null
          $vm = Get-AzVM -ResourceGroupName $rg.Name -Name $imageName -Status -ErrorAction SilentlyContinue
          if ($vm) { break }
        }

        if (-not $vm) {
          Write-Log "[Desktop Image] VM '$imageName' not found in Azure." 'WARN'
          $errors++
          continue
        }

        $powerState = ($vm.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus

        if ($powerState -eq 'VM running') {
          if ($PreviewOnly) {
            Write-Log "[PREVIEW] [Desktop Image] Would deallocate VM '$imageName'."
          } else {
            Write-Log "[Desktop Image] Deallocating VM '$imageName'..."
            Stop-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $imageName -Force -ErrorAction Stop | Out-Null
            Write-Log "[Desktop Image] VM '$imageName' deallocated."
          }
          $imagesStopRequested++
        } else {
          Write-Log "[Desktop Image] VM '$imageName' is not running (Status: $powerState)."
        }
      } catch {
        Write-Log "[Desktop Image] Failed to deallocate VM '$imageName': $($_.Exception.Message)" 'WARN'
        $errors++
      }
    }
  }
} catch {
  Write-Log "Failed to retrieve desktop images from NME: $($_.Exception.Message)" 'WARN'
  $errors++
}

#endregion

#region Summary

Write-Log ""
Write-Log "=== OPERATION COMPLETED ==="
Write-Log "Host pools processed:       $hostPoolsProcessed"
Write-Log "Autoscale disabled:         $autoscaleDisabled"
Write-Log "Session hosts stop requested: $hostsStopRequested"
Write-Log "Session hosts skipped:      $hostsSkipped"
Write-Log "Desktop images deallocated: $imagesStopRequested"
Write-Log "Errors:                     $errors"
Write-Log "Preview mode:               $PreviewOnly"

#endregion
