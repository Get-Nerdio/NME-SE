<#
.SYNOPSIS
  Snapshots the current live NME sales demo environment into desired-state.json.

.DESCRIPTION
  Reads the live state of the scoped resource group from NME and Azure, then writes
  a desired-state.json capturing all host pools, FSLogix configs, auto-scale profiles,
  and the workspace. Use this to:

  - Seed the desired state file initially from a correctly-configured environment
  - Create a backup after intentional changes
  - Bootstrap from an existing environment before enabling Maintain-NmeDemoEnvironment

  Host pools tagged NME-SE-Manage=ignore are excluded from the snapshot.

  OUTPUT:
  - -LocalOutputFile  : Write JSON to this local path (no git commit)
  - (default)         : Commit updated desired-state.json to GitHub

.PARAMETER VariablePrefix
  Prefix for Automation Account variables. Defaults to 'SalesDemo'.

.PARAMETER CommitMessage
  Commit message for the git commit. Defaults to a timestamped message.

.PARAMETER LocalOutputFile
  Write output to this local file path instead of committing to git.

.EXAMPLE
  .\Export-NmeDemoDesiredState.ps1
  .\Export-NmeDemoDesiredState.ps1 -LocalOutputFile ./desired-state-snapshot.json
  .\Export-NmeDemoDesiredState.ps1 -CommitMessage "Manual update after adding demo-pooled-desktop"
#>

[CmdletBinding()]
param(
    [string]$VariablePrefix  = 'SalesDemo',
    [string]$CommitMessage   = '',
    [string]$LocalOutputFile = ''
)

$ErrorActionPreference = 'Stop'

#region Helpers

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )
    $stamp = (Get-Date).ToString('u')
    switch ($Level) {
        'INFO'  { Write-Output  "[$stamp] [INFO]  $Message" }
        'WARN'  { Write-Output  "[$stamp] [WARN]  $Message"; Write-Warning "[$stamp] [WARN]  $Message" }
        'ERROR' { Write-Error   "[$stamp] [ERROR] $Message" }
    }
}

function Get-NmeHeaders {
    $tokenResponse = Invoke-RestMethod `
        -Uri "https://login.microsoftonline.com/$NmeTenantId/oauth2/v2.0/token" `
        -Method Post `
        -Body @{
            grant_type    = 'client_credentials'
            client_id     = $NmeClientId
            client_secret = $NmeClientSecret
            scope         = $NmeScope
        }
    return @{
        'Authorization' = "Bearer $($tokenResponse.access_token)"
        'Content-Type'  = 'application/json'
    }
}

function Invoke-NmeApi {
    param(
        [string]$Method,
        [string]$Uri,
        [string]$Body = $null
    )
    $params = @{
        Uri     = $Uri
        Method  = $Method
        Headers = $NmeHeaders
    }
    if ($Body) { $params['Body'] = $Body }
    return Invoke-RestMethod @params
}

function Get-GitDesiredState {
    param(
        [string]$Owner,
        [string]$Repo,
        [string]$Branch,
        [string]$FilePath,
        [string]$Pat
    )
    $uri = "https://api.github.com/repos/$Owner/$Repo/contents/$FilePath`?ref=$Branch"
    $headers = @{
        Authorization = "token $Pat"
        Accept        = 'application/vnd.github.v3+json'
        'User-Agent'  = 'NME-SalesDemo-Runbook/1.0'
    }
    try {
        $response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers -ErrorAction Stop
        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(($response.content -replace "`n",'')))
        return @{ Content = $decoded; Sha = $response.sha }
    } catch {
        # File may not exist yet — return null sha
        if ($_.Exception.Response.StatusCode.value__ -eq 404) {
            return @{ Content = $null; Sha = $null }
        }
        throw
    }
}

function Set-GitDesiredState {
    param(
        [string]$Owner,
        [string]$Repo,
        [string]$Branch,
        [string]$FilePath,
        [string]$Pat,
        [string]$JsonContent,
        [string]$Sha,
        [string]$CommitMessage
    )
    $uri = "https://api.github.com/repos/$Owner/$Repo/contents/$FilePath"
    $headers = @{
        Authorization  = "token $Pat"
        Accept         = 'application/vnd.github.v3+json'
        'User-Agent'   = 'NME-SalesDemo-Runbook/1.0'
        'Content-Type' = 'application/json'
    }
    $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($JsonContent))
    $body = @{
        message = $CommitMessage
        content = $encoded
        branch  = $Branch
    }
    if ($Sha) { $body['sha'] = $Sha }  # omit sha to create new file
    $response = Invoke-RestMethod -Uri $uri -Method PUT -Headers $headers -Body ($body | ConvertTo-Json) -ErrorAction Stop
    return $response.content.sha
}

function Get-ArmTagValue {
    param([string]$ResourceId, [string]$TagName)
    $resource = Get-AzResource -ResourceId $ResourceId -ErrorAction SilentlyContinue
    if ($resource -and $resource.Tags -and $resource.Tags.ContainsKey($TagName)) {
        return $resource.Tags[$TagName]
    }
    return $null
}

#endregion

#region Variables

$NmeTenantId     = Get-AutomationVariable -Name "${VariablePrefix}TenantId"
$NmeClientId     = Get-AutomationVariable -Name "${VariablePrefix}ClientId"
$NmeClientSecret = Get-AutomationVariable -Name "${VariablePrefix}ClientSecret"
$NmeScope        = Get-AutomationVariable -Name "${VariablePrefix}Scope"
$NmeUri          = Get-AutomationVariable -Name "${VariablePrefix}Uri"
$SubscriptionId  = Get-AutomationVariable -Name "${VariablePrefix}SubscriptionId"
$ScopedResourceGroup = Get-AutomationVariable -Name "${VariablePrefix}ScopedResourceGroup"

if (-not $LocalOutputFile) {
    $GitRepoOwner  = Get-AutomationVariable -Name "${VariablePrefix}GitRepoOwner"
    $GitRepoName   = Get-AutomationVariable -Name "${VariablePrefix}GitRepoName"
    $GitRepoBranch = Get-AutomationVariable -Name "${VariablePrefix}GitRepoBranch"
    $GitFilePath   = Get-AutomationVariable -Name "${VariablePrefix}GitFilePath"
    $GitPat        = Get-AutomationVariable -Name "${VariablePrefix}GitPat"
}

if (-not $CommitMessage) {
    $CommitMessage = "Export desired state snapshot $(Get-Date -Format 'yyyy-MM-dd HH:mm UTC') [automation]"
}

Write-Log "=== Export-NmeDemoDesiredState starting ==="

#endregion

#region Authentication

Disable-AzContextAutosave -Scope Process | Out-Null
Connect-AzAccount -Identity -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
Write-Log "Connected to Azure subscription $SubscriptionId."

$NmeHeaders = Get-NmeHeaders
Write-Log "Connected to NME API at $NmeUri."

#endregion

#region Gather live state

Write-Log "Gathering live state..."

$liveWorkspaces = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/workspace"
$liveFslogix    = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/fslogix"
$liveAutoScale  = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/auto-scale-profile"
$liveHostPools  = @(Get-AzWvdHostPool -ResourceGroupName $ScopedResourceGroup -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue)

if (-not $liveWorkspaces) { $liveWorkspaces = @() }
if (-not $liveFslogix)    { $liveFslogix    = @() }
if (-not $liveAutoScale)  { $liveAutoScale  = @() }

Write-Log "Found $($liveHostPools.Count) host pool(s), $(@($liveFslogix).Count) FSLogix config(s), $(@($liveAutoScale).Count) auto-scale profile(s)."

#endregion

#region Build desired-state.json

# Use first workspace in scoped RG as the canonical workspace, or placeholder if none exists
$wsEntry = $null
$wsInRg = $liveWorkspaces | Where-Object {
    $_.id.resourceGroup -ieq $ScopedResourceGroup -and $_.id.subscriptionId -ieq $SubscriptionId
}
if ($wsInRg) {
    $wsObj  = @($wsInRg)[0]
    $wsEntry = [ordered]@{
        subscriptionId = $wsObj.id.subscriptionId
        resourceGroup  = $wsObj.id.resourceGroup
        name           = $wsObj.id.name
        location       = $wsObj.location
        friendlyName   = $wsObj.friendlyName
    }
} else {
    Write-Log "No workspace found in '$ScopedResourceGroup'. Using placeholder in output." 'WARN'
    $wsEntry = [ordered]@{
        subscriptionId = $SubscriptionId
        resourceGroup  = $ScopedResourceGroup
        name           = 'sales-demo-workspace'
        location       = 'centralus'
        friendlyName   = 'Nerdio SE Sales Demo'
    }
}

# Build FSLogix configs section
$fslEntries = @()
foreach ($fsl in $liveFslogix) {
    $fslEntries += [ordered]@{
        name      = $fsl.name
        isDefault = $fsl.isDefault
        properties = [ordered]@{
            profileContainer = [ordered]@{
                locations = @($fsl.properties.profileContainer.locations)
            }
            entraIdKerberos = $fsl.properties.entraIdKerberos
            cloudCache      = $fsl.properties.cloudCache
            pageBlobs       = $fsl.properties.pageBlobs
        }
    }
}

# Build auto-scale profiles section
$asEntries = @()
foreach ($as in $liveAutoScale) {
    $asEntries += [ordered]@{
        name        = $as.name
        mode        = $as.mode
        description = $as.description
    }
}

# Build host pools section
$hpEntries = @()
foreach ($hp in $liveHostPools) {
    $hpName = $hp.Name
    $hpRg   = $ScopedResourceGroup
    $hpSub  = $SubscriptionId
    $hpUrl  = "$NmeUri/api/v1/arm/hostpool/$hpSub/$hpRg/$hpName"

    # Skip ignored host pools
    $tag = Get-ArmTagValue -ResourceId $hp.Id -TagName 'NME-SE-Manage'
    if ($tag -eq 'ignore') {
        Write-Log "Skipping host pool '$hpName' (NME-SE-Manage=ignore)."
        continue
    }

    Write-Log "Exporting host pool '$hpName'..."

    try {
        $wvd       = Invoke-NmeApi -Method GET -Uri "$hpUrl/wvd"
        $fslAssign = Invoke-NmeApi -Method GET -Uri "$hpUrl/fslogix"
        $asConfig  = Invoke-NmeApi -Method GET -Uri "$hpUrl/auto-scale"

        # Resolve FSLogix config name from assigned ID
        $fslConfigName = $null
        if ($fslAssign.enable -and $fslAssign.predefinedConfigId) {
            $fslMatch = $liveFslogix | Where-Object { $_.id -eq $fslAssign.predefinedConfigId }
            if ($fslMatch) { $fslConfigName = $fslMatch.name }
        }

        # Resolve auto-scale profile name from HP assignments
        $assignedProfileName = $null
        $assignedProfileId   = $null
        foreach ($profile in $liveAutoScale) {
            try {
                $assignments = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/auto-scale-profile/$($profile.id)/assignments"
                if (-not $assignments) { continue }
                $hpArmIdSuffix = "/hostpools/$hpName"
                $match = $assignments | Where-Object { $_.hostPoolId -like "*$hpArmIdSuffix" }
                if ($match) {
                    $assignedProfileName = $profile.name
                    $assignedProfileId   = $profile.id
                    break
                }
            } catch { }
        }

        $poolType = if ($hp.HostPoolType -eq 'Personal') { 'Personal' } else { 'Pooled' }

        $hpEntry = [ordered]@{
            id             = [ordered]@{
                subscriptionId = $hpSub
                resourceGroup  = $hpRg
                hostpoolName   = $hpName
            }
            friendlyName           = $hp.FriendlyName
            description            = $hp.Description
            poolType               = $poolType
            isDesktop              = ($hp.PreferredAppGroupType -ne 'RailApplications')
            isSingleUser           = ($hp.MaxSessionLimit -eq 1)
            loadBalancingAlgorithm = $wvd.loadBalancerType
            maxSessionLimit        = $wvd.maxSessionLimit
            fslogixConfigName      = $fslConfigName
            autoScale              = [ordered]@{
                profileName         = $assignedProfileName
                isEnabled           = $asConfig.isEnabled
                vmSize              = $asConfig.vmTemplate.vmSize
                hostPoolCapacity    = $asConfig.hostPoolCapacity
                minActiveHostsCount = $asConfig.minActiveHostsCount
            }
        }

        if ($poolType -eq 'Personal') {
            $hpEntry['personalAssignmentType'] = 'Automatic'
        }

        $hpEntries += $hpEntry
        Write-Log "Exported '$hpName' (poolType=$poolType, isDesktop=$($hpEntry.isDesktop), vmSize=$($asConfig.vmTemplate.vmSize))."
    } catch {
        Write-Log "Failed to export host pool '$hpName': $($_.Exception.Message)" 'WARN'
    }
}

# Assemble final document
$desiredState = [ordered]@{
    schemaVersion    = '1.0'
    lastUpdated      = (Get-Date -Format 'o')
    workspace        = $wsEntry
    fslogixConfigs   = $fslEntries
    autoScaleProfiles = $asEntries
    hostPools        = $hpEntries
}

$outputJson = $desiredState | ConvertTo-Json -Depth 20

#endregion

#region Write output

if ($LocalOutputFile) {
    $outputJson | Set-Content -Path $LocalOutputFile -Encoding UTF8 -Force
    Write-Log "Desired state written to local file: $LocalOutputFile"
} else {
    Write-Log "Committing desired state to GitHub ($GitRepoOwner/$GitRepoName/$GitFilePath@$GitRepoBranch)..."
    # Read current sha (file may not exist yet on first run)
    $existing = Get-GitDesiredState -Owner $GitRepoOwner -Repo $GitRepoName `
                    -Branch $GitRepoBranch -FilePath $GitFilePath -Pat $GitPat
    $newSha = Set-GitDesiredState `
        -Owner $GitRepoOwner -Repo $GitRepoName -Branch $GitRepoBranch `
        -FilePath $GitFilePath -Pat $GitPat -JsonContent $outputJson `
        -Sha $existing.Sha -CommitMessage $CommitMessage
    Write-Log "Committed desired state to git (new sha: $newSha)."
}

Write-Log "=== Export-NmeDemoDesiredState completed. Exported $($hpEntries.Count) host pool(s). ==="

#endregion
