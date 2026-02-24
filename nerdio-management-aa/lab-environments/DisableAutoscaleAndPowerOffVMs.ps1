<#
.SYNOPSIS
  Disables autoscale for all host pools in Nerdio Manager, powers off all running session hosts,
  and deallocates all desktop image VMs.

.DESCRIPTION
  This runbook uses the NerdioManagerPowerShell module to:
  1. Enumerate all host pools across NME-linked resource groups
  2. Disable autoscale for every dynamic AVD host pool managed by NME
  3. Power off all session hosts that are not already deallocated
  4. Deallocate all desktop image VMs that are not already deallocated

  Intended for scheduled use in lab and demo environments to reduce Azure spend.

.PARAMETER PreviewOnly
  If true, logs what would be done without making changes.

.PARAMETER NmeVariablePrefix
  Prefix for NME API credentials in Automation Account variables.

.PREREQS
  - Automation account has the NerdioManagerPowerShell module installed
  - Automation account has Az.Accounts, Az.Compute, Az.Resources modules
  - Automation account variables: {Prefix}TenantId, {Prefix}ClientId, {Prefix}ClientSecret, {Prefix}Scope, {Prefix}Uri
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
$hostsAlreadyStopped  = 0
$imagesStopRequested  = 0
$imagesAlreadyStopped = 0
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
    # Host pool may not be dynamic (static pools have no autoscale config)
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

    foreach ($sh in $sessionHosts) {
      $hostName = $sh.HostName
      if (-not $hostName) { continue }

      # Derive VM name for logging (hostName may be FQDN like "vm-0.domain.local")
      $vmName = ($hostName -split '\.')[0]

      try {
        # Use the PowerState from the NME API response
        $powerState = $sh.PowerState

        if ($powerState -eq 'deallocated') {
          Write-Log "[$hpLabel] Session host '$vmName' already deallocated."
          $hostsAlreadyStopped++
        } elseif ($powerState -eq 'running' -or $powerState -eq 'stopped') {
          # 'running' = powered on; 'stopped' = OS shut down but not deallocated (still costs money)
          if ($PreviewOnly) {
            Write-Log "[PREVIEW] [$hpLabel] Would stop session host '$vmName' (current state: $powerState)."
          } else {
            Write-Log "[$hpLabel] Stopping session host '$vmName' (current state: $powerState)..."
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
          Write-Log "[$hpLabel] Session host '$vmName' in state '$powerState', skipping."
          $hostsAlreadyStopped++
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
        # Parse subscription and resource group from the desktop image's resource ID
        $imageId = $image.Id
        $imageSub = $null
        $imageRg  = $null

        if ($imageId -match '/subscriptions/([^/]+)/resourceGroups/([^/]+)') {
          $imageSub = $Matches[1]
          $imageRg  = $Matches[2]
        }

        if ($imageSub -and $imageRg) {
          Set-AzContext -SubscriptionId $imageSub -ErrorAction Stop | Out-Null
          $vm = Get-AzVM -ResourceGroupName $imageRg -Name $imageName -Status -ErrorAction SilentlyContinue
        } else {
          # Fallback: search across NME-linked resource groups
          $vm = $null
          foreach ($rg in $linkedRGs) {
            Set-AzContext -SubscriptionId $rg.SubscriptionId -ErrorAction Stop | Out-Null
            $vm = Get-AzVM -ResourceGroupName $rg.Name -Name $imageName -Status -ErrorAction SilentlyContinue
            if ($vm) { break }
          }
        }

        if (-not $vm) {
          Write-Log "[Desktop Image] VM '$imageName' not found in Azure." 'WARN'
          $errors++
          continue
        }

        $powerState = ($vm.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus

        if ($powerState -eq 'VM deallocated') {
          Write-Log "[Desktop Image] VM '$imageName' already deallocated."
          $imagesAlreadyStopped++
        } elseif ($powerState -eq 'VM running' -or $powerState -eq 'VM stopped') {
          # 'VM stopped' = OS shut down but not deallocated (still costs money)
          if ($PreviewOnly) {
            Write-Log "[PREVIEW] [Desktop Image] Would deallocate VM '$imageName' (current state: $powerState)."
          } else {
            Write-Log "[Desktop Image] Deallocating VM '$imageName' (current state: $powerState)..."
            Stop-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $imageName -Force -ErrorAction Stop | Out-Null
            Write-Log "[Desktop Image] VM '$imageName' deallocated."
          }
          $imagesStopRequested++
        } else {
          Write-Log "[Desktop Image] VM '$imageName' in state '$powerState', skipping."
          $imagesAlreadyStopped++
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
Write-Log "Host pools processed:         $hostPoolsProcessed"
Write-Log "Autoscale disabled:           $autoscaleDisabled"
Write-Log "Session hosts stop requested: $hostsStopRequested"
Write-Log "Session hosts already off:    $hostsAlreadyStopped"
Write-Log "Desktop images deallocated:   $imagesStopRequested"
Write-Log "Desktop images already off:   $imagesAlreadyStopped"
Write-Log "Errors:                       $errors"
Write-Log "Preview mode:                 $PreviewOnly"

#endregion
