<# 
.SYNOPSIS
  Delete resource groups by DestroyAfter tag, skipping RGs with the DoNotDestroy tag or with a lock on the RG itself.
.DESCRIPTION
  - Looks for RGs where DoNotDestroy tag is NOT present.
  - If DestroyAfter (datetime) < now (UTC), attempts deletion.
  - Before deletion, removes resource-level locks ONLY for:
      * Microsoft.KeyVault/vaults
      * Microsoft.Sql/servers and Microsoft.Sql/servers/databases
      * Microsoft.Storage/storageAccounts
    If the RG itself has a lock, the RG is skipped (RG-level locks are NOT removed).
.NOTES
  Requires Az.Accounts, Az.Resources modules in the Automation account.
  Runbook authenticates via Managed Identity.
.TAGS
  ChatGPT
#>

param(
  [Parameter(Mandatory=$false)]
  [string[]] $SubscriptionIds,               # Optional: limit scope; otherwise uses current context

  [Parameter(Mandatory=$false)]
  [string] $DestroyAfterTagName = 'DestroyAfter',

  [Parameter(Mandatory=$false)]
  [string] $SkipTagName = 'DoNotDestroy',

  [Parameter(Mandatory=$false)]
  [bool] $WhatIf                           # Dry-run support
)

#---------- Helper: robust datetime parse (UTC) ----------
function Convert-ToUtcDateTime {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

  try {
    # Parse the specific format: "2025-09-05T19:57:27.5084110Z"
    $parsedDate = [DateTime]::Parse($Value)
    return $parsedDate.ToUniversalTime()
  } catch {
    Write-Output "[WARNING] Failed to parse date '$Value': $_"
    return $null
  }
}

#---------- Auth ----------
Write-Output "[INFO] Signing in with Managed Identity..."
Connect-AzAccount -Identity | Out-Null   # Azure Automation best practice for MI auth. :contentReference[oaicite:1]{index=1}

if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
  Write-Output "[INFO] Target subscriptions: $($SubscriptionIds -join ', ')"
} else {
  $ctx = Get-AzContext
  if (-not $ctx) { throw "No Azure context. Ensure the Automation account identity has Reader at subscription scope at minimum." }
  $SubscriptionIds = @($ctx.Subscription.Id)
  Write-Output "[INFO] Using current context subscription: $($SubscriptionIds -join ', ')"
}

$utcNow = [DateTime]::UtcNow
Write-Output "[INFO] Current UTC time: $utcNow"

# Resource types where we are allowed to remove resource-level locks
$unlockTypes = @(
  "Microsoft.KeyVault/vaults",
  "Microsoft.Sql/servers",
  "Microsoft.Sql/servers/databases",
  "Microsoft.Storage/storageAccounts"
)

#---------- Main ----------
foreach ($subId in $SubscriptionIds) {
  Write-Output "===== Subscription: $subId ====="
  Set-AzContext -SubscriptionId $subId | Out-Null

  # Get all RGs; filter ones that DO NOT have the Skip tag
  $rgs = Get-AzResourceGroup
  foreach ($rg in $rgs) {
    $rgName = $rg.ResourceGroupName
    $tags = $rg.Tags

    $hasSkip = $false
    if ($tags -and $tags.ContainsKey($SkipTagName)) { $hasSkip = $true }

    if ($hasSkip) {
      Write-Output "[SKIP] RG '$rgName' has tag '$SkipTagName' — skipping."
      continue
    }

    # Parse DestroyAfter
    $destroyAfter = $null
    if ($tags -and $tags.ContainsKey($DestroyAfterTagName)) {
      $destroyAfter = Convert-ToUtcDateTime -Value $tags[$DestroyAfterTagName]
    }

    if (-not $destroyAfter) {
      Write-Output "[SKIP] RG '$rgName' has no parsable '$DestroyAfterTagName' tag — skipping."
      continue
    }

    if ($destroyAfter -gt $utcNow) {
      Write-Output "[SKIP] RG '$rgName' DestroyAfter=$destroyAfter (UTC) is in the future — skipping."
      continue
    }

    # Check for RG-level locks (do not remove; skip RG if present)
    # -AtScope returns locks at the RG scope (not child resources). :contentReference[oaicite:2]{index=2}
    $rgLocks = @( Get-AzResourceLock -ResourceGroupName $rgName -AtScope -ErrorAction SilentlyContinue )
    if ($rgLocks.Count -gt 0) {
      Write-Output "[SKIP] RG '$rgName' has $($rgLocks.Count) lock(s) at the RG scope — not removing, per policy."
      continue
    }

    # Remove resource-level locks for specific types inside the RG (KeyVault, SQL, Storage)
    # Query all locks within the RG scope (children). Then filter by resource type. :contentReference[oaicite:3]{index=3}
    $childLocks = @( Get-AzResourceLock -ResourceGroupName $rgName -ErrorAction SilentlyContinue )
    if ($childLocks.Count -gt 0) {
      # Build a fast lookup for allowed types
      $allowed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      $unlockTypes | ForEach-Object { [void]$allowed.Add($_) }

      foreach ($lock in $childLocks) {
        # Each lock includes ResourceId, ResourceType (may be null for subscription/RG-level).
        $rid = $lock.ResourceId
        $rtype = $lock.ResourceType

        # Normalize type from ResourceId if needed
        if (-not $rtype -and $rid) {
          # ResourceId like /subscriptions/.../providers/Microsoft.KeyVault/vaults/kv1
          $providerIndex = $rid.ToLower().IndexOf("/providers/")
          if ($providerIndex -ge 0) {
            $typeSegment = $rid.Substring($providerIndex + 11) # after "/providers/"
            # e.g. microsoft.keyvault/vaults/kv1  -> take first two segments as type
            $parts = $typeSegment.Trim("/").Split("/")
            if ($parts.Length -ge 2) {
              $rtype = "$($parts[0])/$($parts[1])"
            }
          }
        }

        if ($rtype -and $allowed.Contains($rtype)) {
          Write-Output "[INFO] Removing resource-level lock '$($lock.Name)' on type '$rtype' (ResourceId: $rid)"
          if ($WhatIf) {
            Remove-AzResourceLock -LockId $lock.LockId -WhatIf -Confirm:$false -Force
          } else {
            Remove-AzResourceLock -LockId $lock.LockId -Confirm:$false -Force
          }
        }
      }
    }

    # Finally, delete the RG (Azure handles child dependency ordering; locks must be gone). :contentReference[oaicite:4]{index=4}
    Write-Output "[ACTION] Deleting RG '$rgName' (DestroyAfter=$destroyAfter UTC)"
    if ($WhatIf) {
      Remove-AzResourceGroup -Name $rgName -Force -WhatIf
    } else {
      # AsJob lets ARM handle long-running deletes without blocking runbook thread
      Remove-AzResourceGroup -Name $rgName -Force -AsJob | Out-Null
    }
  }
}

Write-Output "[DONE] Evaluation complete."
