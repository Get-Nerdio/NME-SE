<#  Remove resources in resource groups that have an "AutoClean" tag when tag DestroyAfter (datetime) is in the past.
  Designed for Azure Automation (PowerShell) using the account's Managed Identity.

.prereqs
  • Automation account has Az.Accounts and Az.Resources modules (recent versions).
  • Managed Identity has at least "Contributor" on the target subscriptions/resource groups.
  • If resources have locks and you want them removed, pass -RemoveLocks.

.notes
  • The script finds all resource groups with an "AutoClean" tag
  • For resources within those RGs, it checks the "DestroyAfter" tag
  • Tag value examples (parsed robustly):
      2025-08-14T16:30:00Z
      2025-08-14T16:30:00-05:00
      2025-08-14
      08/14/2025 16:30
      08/14/2025
  • You can pass -PreviewOnly to see what would be deleted.
  • Optionally supply -SubscriptionIds to constrain processing.emove resources in specified resource groups when tag DestroyAfter (datetime) is in the past.
  Designed for Azure Automation (PowerShell) using the account’s Managed Identity.

.prereqs
  • Automation account has Az.Accounts and Az.Resources modules (recent versions).
  • Managed Identity has at least "Contributor" on the target subscriptions/resource groups.
  • If resources have locks and you want them removed, pass -RemoveLocks.

.notes
  • Tag key: DestroyAfter
  • Tag value examples (parsed robustly):
      2025-08-14T16:30:00Z
      2025-08-14T16:30:00-05:00
      2025-08-14
      08/14/2025 16:30
      08/14/2025
  • You can pass -PreviewOnly to see what would be deleted.
  • Optionally supply -SubscriptionIds to constrain processing.
  • If -ResourceGroups is omitted, the script will try an Automation Variable named "CleanResourceGroup".
    This can be a JSON array ["rg1","rg2"] or a comma-separated string.

.tags
  ChatGPT
#>

[CmdletBinding()]
param(
  # Optional: limit processing to these subscription IDs. If omitted, all accessible subscriptions are processed.
  [Parameter(Mandatory = $false)]
  [string[]] $SubscriptionIds = @(),

  # Dry run (no deletes). Also surfaces parse errors and ordering.
  [bool] $PreviewOnly = $false,

  # Remove any resource locks found on deletable resources before deletion.
  [bool] $RemoveLocks = $false
)

#------------- Helpers -------------#

function Write-Log {
  param(
    [string] $Message,
    [ValidateSet('INFO','WARN','ERROR','DEBUG')]
    [string] $Level = 'INFO'
  )
  switch ($Level) {
    'INFO'  { Write-Output    "[INFO]  $Message" }
    'WARN'  { Write-Warning   "[WARN]  $Message" }
    'ERROR' { Write-Error     "[ERROR] $Message" }
    'DEBUG' { Write-Verbose   "[DEBUG] $Message" }
  }
}

function Parse-DestroyAfter {
  [OutputType([Nullable[datetimeoffset]])]
  param([string] $Value)

  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

  # Try common exact formats first (assume UTC when zone absent)
  $styles   = [System.Globalization.DateTimeStyles]::AssumeUniversal
  $culture  = [System.Globalization.CultureInfo]::InvariantCulture
  $formats  = @(
    'yyyy-MM-ddTHH:mm:ssK',
    'yyyy-MM-ddTHH:mmK',
    'yyyy-MM-ddTHH:mm:ss.fffK',
    'yyyy-MM-dd',
    'MM/dd/yyyy HH:mm',
    'MM/dd/yyyy'
  )

  $dto = [datetimeoffset]::MinValue
  foreach ($fmt in $formats) {
    if ([datetimeoffset]::TryParseExact($Value, $fmt, $culture, $styles, [ref]$dto)) { return $dto }
  }

  # Fallback to flexible parse
  if ([datetimeoffset]::TryParse($Value, [ref]$dto)) { return $dto }
  return $null
}

function Get-DeletionPriority {
  <#
    Return an integer where lower = delete earlier.
    We delete VMs before NICs, NICs before PIPs, etc.
    Unknown types get a reasonable default based on type depth.
  #>
  param([string] $ResourceType)

  $map = @{
    'microsoft.compute/virtualmachines/extensions' = 10
    'microsoft.compute/virtualmachines'            = 20
    'microsoft.network/networkinterfaces'          = 30
    'microsoft.network/publicipaddresses'          = 40
    'microsoft.compute/disks'                      = 50
    'microsoft.network/networksecuritygroups'      = 60
    'microsoft.web/sites/slots'                    = 70
    'microsoft.web/sites'                          = 75
    'microsoft.storage/storageaccounts'            = 80
    'microsoft.keyvault/vaults'                    = 80
  }

  $t = $ResourceType.ToLowerInvariant()
  if ($map.ContainsKey($t)) { return $map[$t] }
  # Default: child-first by resource type depth, then name length as a mild tie-breaker
  $depth = ($t -split '/').Count
  return 90 + $depth
}

function Remove-ResourceLocksIfRequested {
  param([string] $ResourceId, [string] $ResourceGroupName, [switch] $DoIt)

  if (-not $DoIt) { return }

  try {
    $locks = Get-AzResourceLock -Scope $ResourceId -ErrorAction Stop
  } catch {
    $locks = @()
  }

  foreach ($l in $locks) {
    Write-Log "[$ResourceGroupName] Removing lock '$($l.Name)' from $ResourceId" 'INFO'
    if ($PreviewOnly) {
      Write-Log "[$ResourceGroupName] PreviewOnly: would remove lockId $($l.LockId)" 'DEBUG'
    } else {
      try {
        Remove-AzResourceLock -LockId $l.LockId -Force -ErrorAction Stop
      } catch {
        Write-Log "[$ResourceGroupName] Failed to remove lock on $ResourceId`: $($_.Exception.Message)" 'WARN'
      }
    }
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

$nowUtc = (Get-Date).ToUniversalTime()

#------------- Main -------------#

foreach ($sub in $subs) {
  Write-Log "Processing subscription $($sub.Name) ($($sub.Id))" 'INFO'
  Set-AzContext -SubscriptionId $sub.Id -Tenant $sub.TenantId -ErrorAction Stop | Out-Null

  # Find all resource groups with "AutoClean" tag
  try {
    $autoCleanRgs = Get-AzResourceGroup | Where-Object { $_.Tags -and $_.Tags.ContainsKey("AutoClean") }
  } catch {
    Write-Log "Failed to get resource groups in subscription $($sub.Id): $($_.Exception.Message)" 'ERROR'
    continue
  }

  if (-not $autoCleanRgs -or $autoCleanRgs.Count -eq 0) {
    Write-Log "No resource groups with 'AutoClean' tag found in subscription $($sub.Id)" 'INFO'
    continue
  }

  $rgNames = $autoCleanRgs | ForEach-Object { $_.ResourceGroupName }
  Write-Log "Found $($rgNames.Count) resource groups with 'AutoClean' tag: $(($rgNames -join ', '))" 'INFO'

  foreach ($rgName in $rgNames) {
    Write-Log "[$rgName] Scanning for resources tagged DestroyAfter < $($nowUtc.ToString('u'))" 'INFO'

    # Fetch all resources in RG
    try {
      $resources = Get-AzResource -ResourceGroupName $rgName -ErrorAction Stop
    } catch {
      Write-Log "[$rgName] Failed to list resources: $($_.Exception.Message)" 'WARN'
      continue
    }

    # Filter to those with DestroyAfter tag in the past
    $candidates = @()
    foreach ($r in $resources) {
      if (-not $r.Tags) { continue }
      
      # Skip resources with DoNotDestroy tag
      if ($r.Tags.ContainsKey('DoNotDestroy')) {
        Write-Log "[$rgName] Skipping $($r.ResourceType) '$($r.Name)' - has DoNotDestroy tag" 'DEBUG'
        continue
      }
      
      if (-not $r.Tags.ContainsKey('DestroyAfter')) { continue }

      $raw = $r.Tags['DestroyAfter']
      $dto = Parse-DestroyAfter -Value $raw
      if (-not $dto) {
        Write-Log "[$rgName] Could not parse DestroyAfter='$raw' on $($r.ResourceType) '$($r.Name)'. Skipping." 'WARN'
        continue
      }

      if ($dto.UtcDateTime -lt $nowUtc) {
        $candidates += [pscustomobject]@{
          Resource     = $r
          DestroyAfter = $dto
          Priority     = (Get-DeletionPriority -ResourceType $r.ResourceType)
        }
      }
    }

    if (-not $candidates -or $candidates.Count -eq 0) {
      Write-Log "[$rgName] No deletable resources found." 'INFO'
      continue
    }

    # Order for safer deletion (VMs first, then NICs, then PIPs, then disks, etc.)
    $ordered = $candidates | Sort-Object Priority, @{Expression = { $_.Resource.Name.Length }; Descending = $true }

    foreach ($item in $ordered) {
      $res = $item.Resource
      $msg = "[$rgName] Remove $($res.ResourceType) '$($res.Name)' (DestroyAfter=$($item.DestroyAfter.UtcDateTime.ToString('u')), Priority=$($item.Priority))"
      Write-Log $msg 'INFO'

      # Optional: remove locks
      Remove-ResourceLocksIfRequested -ResourceId $res.ResourceId -ResourceGroupName $rgName -DoIt:$RemoveLocks

      if ($PreviewOnly) {
        Write-Log "[$rgName] PreviewOnly: would run Remove-AzResource -ResourceId $($res.ResourceId) -Force" 'DEBUG'
        continue
      }

      # Attempt deletion
      try {
        Remove-AzResource -ResourceId $res.ResourceId -Force -ErrorAction Stop
        Write-Log "[$rgName] Deleted $($res.ResourceType) '$($res.Name)'" 'INFO'
      } catch {
        # Common dependency errors happen if ordering wasn't sufficient for some exotic types.
        Write-Log "[$rgName] Failed to delete $($res.ResourceType) '$($res.Name)': $($_.Exception.Message)" 'ERROR'
      }
    }
  }
}

Write-Log "Completed. PreviewOnly=$PreviewOnly, RemoveLocks=$RemoveLocks" 'INFO'
