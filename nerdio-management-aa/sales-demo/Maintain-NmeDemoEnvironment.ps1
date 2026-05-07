<#
.SYNOPSIS
  Reconciles the live NME sales demo environment against a desired state stored in Git.

.DESCRIPTION
  This runbook reads a desired-state.json from a GitHub repository and ensures the live
  NME environment matches it. On every run it will:

  1. Load desired state from GitHub (or a local file for testing)
  2. Import any host pools tagged NME-SE-Manage=import into desired state and commit to git
  3. Reconcile the AVD workspace (create if missing)
  4. Reconcile FSLogix configurations (create or update)
  5. Reconcile auto-scale profiles (create or update)
  6. Reconcile host pools scoped to the demo resource group:
       - Create missing host pools and apply full desired configuration
       - Correct drifted settings (WVD props, FSLogix assignment, auto-scale config)
       - Remove stray host pools not in desired state (unless tagged ignore)
  7. Advise on session host availability and re-enable auto-scale if disabled

  TAG BEHAVIOR (ARM tag 'NME-SE-Manage' on Azure host pool resources):
    import   — Ingest current live config into desired-state.json and commit to git.
               Tag is updated to 'managed' after import.
    ignore   — Skip entirely. Config is never reset; resource is never removed.
    managed  — Same as no tag for reconciliation purposes.
    (no tag) — Normal managed resource: reconcile config, remove if not in desired state.

  PREREQUISITES
  =============

  Automation Account Modules:
    - Az.Accounts
    - Az.Compute         (tag reads)
    - Az.DesktopVirtualization (Get-AzWvdHostPool, host reads)
    - Az.Resources       (Update-AzTag)
    - Az.Storage         (New-AzStorageAccount, New-AzRmStorageShare)
    - Az.Websites        (Get-AzWebApp — for NME App Service restart after SQL cleanup)

  Automation Account Variables (prefixed with VariablePrefix, default 'SalesDemo'):
    - {Prefix}TenantId              NME API app registration tenant ID
    - {Prefix}ClientId              NME API app registration client ID
    - {Prefix}ClientSecret          NME API app registration client secret (encrypted)
    - {Prefix}Scope                 NME API scope (e.g. api://<app-id>/.default)
    - {Prefix}Uri                   NME API base URI
    - {Prefix}SubscriptionId        Azure subscription containing demo resources
    - {Prefix}ScopedResourceGroup   Resource group scoping host pool discovery
    - {Prefix}GitRepoOwner          GitHub org/user owning the repo
    - {Prefix}GitRepoName           GitHub repository name
    - {Prefix}GitRepoBranch         Branch containing desired-state.json
    - {Prefix}GitFilePath           Repo-relative path to desired-state.json
    - {Prefix}GitPat                GitHub PAT with contents:read+write (encrypted)
    - {Prefix}NmeAppResourceGroup   (Optional) Resource group containing the NME App Service.
                                    If not set, app is discovered via Get-AzWebApp by name.
                                    Required for profile-cache flush after SQL cleanup.

  Managed Identity Permissions:
    - Azure RBAC Reader on ScopedResourceGroup (read ARM tags on host pools)
    - Azure RBAC Tag Contributor on ScopedResourceGroup (write NME-SE-Manage tag after import)

.PARAMETER VariablePrefix
  Prefix for Automation Account variables. Defaults to 'SalesDemo'.

.PARAMETER LocalDesiredStateFile
  If set, bypass the GitHub API and read desired state from this local file path.
  No git write-back occurs in local mode (useful for testing).

.PARAMETER WhatIf
  Log what would be changed without applying any changes.

.PARAMETER RemoveUndefinedResources
  Actively remove resources not present in desired state: stray host pools (after disabling
  auto-scale and removing session hosts), desktop images, unlinked storage shares, and VNets.
  Without this switch, stray resources are only logged as warnings.

.PARAMETER SkipSessionHostCheck
  Skip the session host availability advisory at the end.

.EXAMPLE
  .\Maintain-NmeDemoEnvironment.ps1
  .\Maintain-NmeDemoEnvironment.ps1 -LocalDesiredStateFile ./desired-state.json -WhatIf
  .\Maintain-NmeDemoEnvironment.ps1 -RemoveUndefinedResources
  .\Maintain-NmeDemoEnvironment.ps1 -RemoveUndefinedResources -WhatIf
#>

param(
    [string]$VariablePrefix           = 'SalesDemo',
    [string]$LocalDesiredStateFile    = '',
    [bool]$WhatIf                     = $false,
    [bool]$RemoveUndefinedResources   = $false,
    [bool]$SkipSessionHostCheck       = $false
)

$ErrorActionPreference = 'Stop'

#region 1 — Helpers

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

function Wait-NmeJob {
    param([string]$JobId, [string]$Description)
    $timeoutSeconds = 600
    $elapsed = 0
    $job = Invoke-RestMethod "$NmeUri/api/v1/job/$JobId" -Headers $NmeHeaders -SkipCertificateCheck
    while ($job.jobStatus -in @('Pending', 'InProgress', 'Running')) {
        if ($elapsed -ge $timeoutSeconds) {
            throw "Timeout waiting for $Description (job $JobId) after ${timeoutSeconds}s"
        }
        Write-Log "Waiting for $Description to complete (${elapsed}s elapsed)..."
        Start-Sleep -Seconds 10
        $elapsed += 10
        $job = Invoke-RestMethod "$NmeUri/api/v1/job/$JobId" -Headers $NmeHeaders -SkipCertificateCheck
    }
    if ($job.jobStatus -eq 'Failed') {
        throw "NME job failed: $Description. Error: $($job.error.message)"
    }
    return $job
}

function Invoke-NmeApi {
    param(
        [string]$Method,
        [string]$Uri,
        [string]$Body = $null
    )
    $params = @{
        Uri                  = $Uri
        Method               = $Method
        Headers              = $NmeHeaders
        SkipCertificateCheck = $true
    }
    if ($Body) { $params['Body'] = $Body }
    try {
        return Invoke-RestMethod @params
    } catch {
        # Attach the response body to the exception so callers can log detail
        $detail = $_.ErrorDetails.Message
        if ($detail) {
            throw [System.Exception]::new("$($_.Exception.Message) — $detail", $_.Exception)
        }
        throw
    }
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
    $response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers -ErrorAction Stop
    # response.content is base64-encoded with newlines; decode it
    $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(($response.content -replace "`n",'')))
    return @{
        Content = $decoded
        Sha     = $response.sha
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
        Authorization = "token $Pat"
        Accept        = 'application/vnd.github.v3+json'
        'User-Agent'  = 'NME-SalesDemo-Runbook/1.0'
        'Content-Type' = 'application/json'
    }
    $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($JsonContent))
    $body = @{
        message = $CommitMessage
        content = $encoded
        sha     = $Sha
        branch  = $Branch
    } | ConvertTo-Json
    $response = Invoke-RestMethod -Uri $uri -Method PUT -Headers $headers -Body $body -ErrorAction Stop
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

function Resolve-FslogixIdByName {
    param([string]$Name, [array]$LiveConfigs)
    $match = $LiveConfigs | Where-Object { $_.name -eq $Name }
    if (-not $match) { return $null }
    return $match.id
}

function Compare-HostPoolWvdProps {
    param([PSCustomObject]$Live, [PSCustomObject]$Desired)
    # Only compare fields that are explicitly set in desired state (null = don't care)
    if ($null -ne $Desired.loadBalancingAlgorithm -and $Live.loadBalancerType -ne $Desired.loadBalancingAlgorithm) { return $true }
    # Personal pools: NME always overrides maxSessionLimit to 999999 internally — skip comparison
    if ($null -ne $Desired.maxSessionLimit -and $Desired.poolType -ne 'Personal' -and $Live.maxSessionLimit -ne $Desired.maxSessionLimit) { return $true }
    return $false
}

function Compare-FslogixConfig {
    param([PSCustomObject]$Live, [PSCustomObject]$Desired)
    # Only compare fields that are explicitly set in desired state (null = don't care)
    if ($null -ne $Desired.isDefault -and $Live.isDefault -ne $Desired.isDefault) { return $true }
    $dp = $Desired.properties
    if ($null -ne $dp) {
        if ($null -ne $dp.entraIdKerberos -and $Live.properties.entraIdKerberos -ne $dp.entraIdKerberos) { return $true }
        if ($null -ne $dp.cloudCache      -and $Live.properties.cloudCache      -ne $dp.cloudCache)      { return $true }
        if ($null -ne $dp.pageBlobs       -and $Live.properties.pageBlobs       -ne $dp.pageBlobs)       { return $true }
        if ($null -ne $dp.profileContainer -and $null -ne $dp.profileContainer.locations) {
            # Compare profile container locations (order-insensitive)
            $liveLocations    = @($Live.properties.profileContainer.locations | Sort-Object)
            $desiredLocations = @($dp.profileContainer.locations              | Sort-Object)
            if ($liveLocations.Count -ne $desiredLocations.Count) { return $true }
            for ($i = 0; $i -lt $liveLocations.Count; $i++) {
                if ($liveLocations[$i] -ne $desiredLocations[$i]) { return $true }
            }
        }
    }
    return $false
}

function Compare-HpFslogixAssignment {
    param([PSCustomObject]$Live, [int]$DesiredConfigId)
    if (-not $Live.enable) { return $true }
    if ($Live.type -ne 'Predefined') { return $true }
    if ($Live.predefinedConfigId -ne $DesiredConfigId) { return $true }
    return $false
}

function Compare-HpAutoScale {
    # $DesiredPrefix: pre-computed "{prefix}-{????}" string, or $null if vmNamePrefix not in desired state
    param([PSCustomObject]$Live, [PSCustomObject]$Desired, [string]$DesiredPrefix = $null, [string]$PoolType = 'Pooled')
    # Only compare fields that are explicitly set in desired state (null = don't care)
    if ($null -ne $Desired.isEnabled -and $Live.isEnabled -ne $Desired.isEnabled) { return $true }
    # Personal pools: NME does not surface hostPoolCapacity/minActiveHostsCount — skip comparison
    if ($PoolType -ne 'Personal') {
        if ($null -ne $Desired.hostPoolCapacity    -and $Live.hostPoolCapacity    -ne $Desired.hostPoolCapacity)    { return $true }
        if ($null -ne $Desired.minActiveHostsCount -and $Live.minActiveHostsCount -ne $Desired.minActiveHostsCount) { return $true }
    }
    if ($null -ne $Desired.vmSize    -and $Live.vmTemplate.size   -ne $Desired.vmSize)    { return $true }
    if ($DesiredPrefix               -and $Live.vmTemplate.prefix -ne $DesiredPrefix)     { return $true }
    if ($null -ne $Desired.scalingMode       -and $Live.scalingMode       -ne $Desired.scalingMode)       { return $true }
    if ($null -ne $Desired.autoScaleCriteria -and $Live.autoScaleCriteria -ne $Desired.autoScaleCriteria) { return $true }
    return $false
}

function Add-NonFatalError {
    param([string]$Message)
    $script:NonFatalErrors += $Message
    Write-Log $Message 'WARN'
}

function Get-NmeSqlConnection {
    <#
    .SYNOPSIS
      Opens an authenticated connection to the NME SQL database using managed identity.
      Returns $null (with a WARN log) if connection fails — callers must guard on $null.
    #>
    param([string]$ServerFqdn, [string]$DatabaseName)
    try {
        $token = (Get-AzAccessToken -ResourceUrl 'https://database.windows.net/').Token
        $conn  = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$ServerFqdn;Database=$DatabaseName;Encrypt=True;TrustServerCertificate=False;"
        $conn.AccessToken      = $token
        $conn.Open()
        return $conn
    } catch {
        Write-Log "Unable to connect to NME SQL ($ServerFqdn / $DatabaseName): $($_.Exception.Message). SQL-based profile cleanup will be skipped." 'WARN'
        return $null
    }
}

function Invoke-NmeSql {
    param(
        [System.Data.SqlClient.SqlConnection]$Connection,
        [string]$Query,
        [hashtable]$Parameters = @{},
        [switch]$AsDataTable
    )
    $cmd = $Connection.CreateCommand()
    $cmd.CommandText  = $Query
    $cmd.CommandTimeout = 30
    foreach ($k in $Parameters.Keys) {
        $cmd.Parameters.AddWithValue($k, $Parameters[$k]) | Out-Null
    }
    if ($AsDataTable) {
        $reader  = $cmd.ExecuteReader()
        $results = [System.Collections.Generic.List[PSObject]]::new()
        while ($reader.Read()) {
            $obj = [ordered]@{}
            for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                $obj[$reader.GetName($i)] = if ($reader.IsDBNull($i)) { $null } else { $reader.GetValue($i) }
            }
            $results.Add([PSCustomObject]$obj)
        }
        $reader.Close()
        return $results
    } else {
        return $cmd.ExecuteNonQuery()
    }
}

#endregion

#region 2 — Variables

$NmeTenantId     = Get-AutomationVariable -Name "${VariablePrefix}TenantId"
$NmeClientId     = Get-AutomationVariable -Name "${VariablePrefix}ClientId"
$NmeClientSecret = Get-AutomationVariable -Name "${VariablePrefix}ClientSecret"
$NmeScope        = Get-AutomationVariable -Name "${VariablePrefix}Scope"
$NmeUri          = Get-AutomationVariable -Name "${VariablePrefix}Uri"
$SubscriptionId  = Get-AutomationVariable -Name "${VariablePrefix}SubscriptionId"
$ScopedResourceGroup = Get-AutomationVariable -Name "${VariablePrefix}ScopedResourceGroup"

if (-not $LocalDesiredStateFile) {
    $GitRepoOwner  = Get-AutomationVariable -Name "${VariablePrefix}GitRepoOwner"
    $GitRepoName   = Get-AutomationVariable -Name "${VariablePrefix}GitRepoName"
    $GitRepoBranch = Get-AutomationVariable -Name "${VariablePrefix}GitRepoBranch"
    $GitFilePath   = Get-AutomationVariable -Name "${VariablePrefix}GitFilePath"
    $GitPat        = Get-AutomationVariable -Name "${VariablePrefix}GitPat"
}

$script:NonFatalErrors = @()
$script:DesiredStateSha = $null

# SQL variables — optional; SQL-based profile cleanup is skipped if not set.
# Set {Prefix}SqlServer (FQDN) and {Prefix}SqlDatabase in the Automation Account.
$SqlServerFqdn   = $null
$SqlDatabaseName = $null
try { $SqlServerFqdn   = Get-AutomationVariable -Name "${VariablePrefix}SqlServer"   -ErrorAction Stop } catch {}
try { $SqlDatabaseName = Get-AutomationVariable -Name "${VariablePrefix}SqlDatabase" -ErrorAction Stop } catch {}

# NME App Service resource group — used to restart the app after SQL profile cleanup,
# which is required to flush the NME in-memory profile cache.
# If not set, a restart is attempted by discovering the app from the NME URI.
$NmeAppResourceGroup = $null
try { $NmeAppResourceGroup = Get-AutomationVariable -Name "${VariablePrefix}NmeAppResourceGroup" -ErrorAction Stop } catch {}

# Counters
$hpCreated              = 0
$hpUpdated              = 0
$hpRemoved              = 0
$hpImported             = 0
$fslCreated             = 0
$fslUpdated             = 0
$fslRemoved             = 0
$asCreated              = 0
$asRemoved              = 0
$scriptedActionsRemoved = 0
$sqlProfilesRemoved     = 0
$imagesRemoved          = 0
$storageUnlinked        = 0
$vnetsUnlinked          = 0

Write-Log "=== Maintain-NmeDemoEnvironment starting (WhatIf=$WhatIf, RemoveUndefinedResources=$RemoveUndefinedResources) ==="

#endregion

#region 3 — Authentication

$ErrorActionPreference = 'Stop'

Disable-AzContextAutosave -Scope Process | Out-Null
Connect-AzAccount -Identity -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
Write-Log "Connected to Azure subscription $SubscriptionId."

$NmeHeaders = Get-NmeHeaders
Write-Log "Connected to NME API at $NmeUri."

# Connectivity diagnostic — logs full exception chain if SSL fails
try {
    $null = Invoke-RestMethod -Uri "$NmeUri/api/v1/workspace" -Method GET -Headers $NmeHeaders -SkipCertificateCheck -ErrorAction Stop
    Write-Log "NME API connectivity: OK"
} catch {
    $ex = $_.Exception
    $chain = @()
    while ($ex) { $chain += $ex.GetType().Name + ': ' + $ex.Message; $ex = $ex.InnerException }
    Write-Log "NME API connectivity FAILED — $($chain -join ' --> ')" 'WARN'
}

$ErrorActionPreference = 'Continue'

# SQL connection (optional — only needed for SQL-based profile cleanup)
$SqlConnection = $null
if ($RemoveUndefinedResources) {
    if ($SqlServerFqdn -and $SqlDatabaseName) {
        $SqlConnection = Get-NmeSqlConnection -ServerFqdn $SqlServerFqdn -DatabaseName $SqlDatabaseName
        if ($SqlConnection) { Write-Log "Connected to NME SQL ($SqlServerFqdn / $SqlDatabaseName)." }
    } else {
        Write-Log "SQL variables ${VariablePrefix}SqlServer / ${VariablePrefix}SqlDatabase not set — SQL-based profile cleanup will be skipped." 'WARN'
    }
}

#endregion


#region 4 — Load Desired State

$ErrorActionPreference = 'Stop'

if ($LocalDesiredStateFile) {
    Write-Log "Loading desired state from local file: $LocalDesiredStateFile"
    $rawJson = Get-Content $LocalDesiredStateFile -Raw -ErrorAction Stop
    $script:DesiredStateSha = $null  # no git write-back in local mode
} else {
    Write-Log "Loading desired state from GitHub: $GitRepoOwner/$GitRepoName/$GitFilePath@$GitRepoBranch"
    $gitResult = Get-GitDesiredState -Owner $GitRepoOwner -Repo $GitRepoName `
                     -Branch $GitRepoBranch -FilePath $GitFilePath -Pat $GitPat
    $rawJson = $gitResult.Content
    $script:DesiredStateSha = $gitResult.Sha
    Write-Log "Loaded desired state (sha: $($script:DesiredStateSha))."
}

$DesiredState = $rawJson | ConvertFrom-Json
if (-not $DesiredState.workspace -or -not $DesiredState.hostPools) {
    throw "desired-state.json is missing required 'workspace' or 'hostPools' keys."
}
Write-Log "Desired state loaded: $($DesiredState.hostPools.Count) host pool(s), $($DesiredState.profiles.fslogix.Count) FSLogix config(s), $($DesiredState.profiles.autoScale.Count) auto-scale profile(s)."

$ErrorActionPreference = 'Continue'

#endregion

#region 5 — Gather Live State

Write-Log "Gathering live state from NME and Azure..."

$liveWorkspaces = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/workspace"
$liveFslogix    = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/fslogix"
$liveAutoScale  = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/auto-scale-profile"
$liveHostPools  = @(Get-AzWvdHostPool -ResourceGroupName $ScopedResourceGroup -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue)

if (-not $liveWorkspaces) { $liveWorkspaces = @() }
if (-not $liveFslogix)    { $liveFslogix    = @() }
if (-not $liveAutoScale)  { $liveAutoScale  = @() }

Write-Log "Live state: $($liveHostPools.Count) host pool(s) in '$ScopedResourceGroup', $(@($liveFslogix).Count) FSLogix config(s), $(@($liveAutoScale).Count) auto-scale profile(s)."
Write-Log "(VNets, storage accounts, and images gathered per-region.)"

#endregion

#region 6 — Import Pass (tag NME-SE-Manage=import)

Write-Log "--- Import Pass ---"

foreach ($hp in $liveHostPools) {
    $tag = Get-ArmTagValue -ResourceId $hp.Id -TagName 'NME-SE-Manage'
    if ($tag -ne 'import') { continue }

    $hpName = $hp.Name
    $hpRg   = $ScopedResourceGroup
    $hpSub  = $SubscriptionId

    # Check if already in desired state
    $alreadyInDs = $DesiredState.hostPools | Where-Object { $_.id.hostpoolName -eq $hpName }
    if ($alreadyInDs) {
        Write-Log "Host pool '$hpName' is tagged 'import' but is already in desired state. Updating tag to 'managed'." 'WARN'
        if (-not $WhatIf) {
            Update-AzTag -Tag @{'NME-SE-Manage' = 'managed'} -Operation Merge -ResourceId $hp.Id | Out-Null
        }
        continue
    }

    Write-Log "Importing host pool '$hpName' into desired state..."

    try {
        # Read WVD props
        $wvd = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/arm/hostpool/$hpSub/$hpRg/$hpName/wvd"

        # Read FSLogix assignment
        $fslAssign = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/arm/hostpool/$hpSub/$hpRg/$hpName/fslogix"
        $fslConfigName = $null
        if ($fslAssign.enable -and $fslAssign.predefinedConfigId) {
            $fslMatch = $liveFslogix | Where-Object { $_.id -eq $fslAssign.predefinedConfigId }
            if ($fslMatch) { $fslConfigName = $fslMatch.name }
        }

        # Read auto-scale config (local HP rules — no profile assignment)
        $asConfig = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/arm/hostpool/$hpSub/$hpRg/$hpName/auto-scale"

        $poolType = if ($hp.HostPoolType -eq 'Personal') { 'Personal' } else { 'Pooled' }
        $entry = [ordered]@{
            id              = [ordered]@{
                subscriptionId = $hpSub
                resourceGroup  = $hpRg
                hostpoolName   = $hpName
            }
            friendlyName            = $hp.FriendlyName
            description             = $hp.Description
            poolType                = $poolType
            isDesktop               = ($hp.PreferredAppGroupType -ne 'RailApplications')
            isSingleUser            = ($hp.MaxSessionLimit -eq 1)
            loadBalancingAlgorithm  = $wvd.loadBalancerType
            maxSessionLimit         = $wvd.maxSessionLimit
            fslogixConfigName       = $fslConfigName
            autoScale               = [ordered]@{
                isEnabled           = $asConfig.isEnabled
                vmSize              = $asConfig.vmTemplate.size
                hostPoolCapacity    = $asConfig.hostPoolCapacity
                minActiveHostsCount = $asConfig.minActiveHostsCount
            }
        }
        if ($poolType -eq 'Personal') {
            $entry['personalAssignmentType'] = 'Automatic'
        }

        # Append to desired state
        $DesiredState.hostPools += [PSCustomObject]$entry
        $DesiredState.lastUpdated = (Get-Date -Format 'o')

        if (-not $WhatIf -and $script:DesiredStateSha) {
            $newJson = $DesiredState | ConvertTo-Json -Depth 20
            $script:DesiredStateSha = Set-GitDesiredState `
                -Owner $GitRepoOwner -Repo $GitRepoName -Branch $GitRepoBranch `
                -FilePath $GitFilePath -Pat $GitPat -JsonContent $newJson `
                -Sha $script:DesiredStateSha `
                -CommitMessage "Import host pool '$hpName' into desired state [automation]"
            Write-Log "Committed updated desired state to git (new sha: $($script:DesiredStateSha))."
        }

        if (-not $WhatIf) {
            Update-AzTag -Tag @{'NME-SE-Manage' = 'managed'} -Operation Merge -ResourceId $hp.Id | Out-Null
        }

        $hpImported++
        Write-Log "[IMPORT] '$hpName' imported and tag updated to 'managed'."
    } catch {
        Add-NonFatalError "Failed to import host pool '$hpName': $($_.Exception.Message)"
    }
}

# Refresh live FSLogix and auto-scale in case we committed new data
if ($hpImported -gt 0) {
    $liveFslogix   = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/fslogix"
    $liveAutoScale = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/auto-scale-profile"
    if (-not $liveFslogix)   { $liveFslogix   = @() }
    if (-not $liveAutoScale) { $liveAutoScale  = @() }
}

#endregion

#region 7 — Reconcile Workspace

Write-Log "--- Reconcile Workspace ---"

$ws = $DesiredState.workspace
$wsMatch = $liveWorkspaces | Where-Object { $_.id.name -eq $ws.name }

if (-not $wsMatch) {
    Write-Log "Workspace '$($ws.name)' not found. Creating..."
    if (-not $WhatIf) {
        $wsBody = @{
            id = @{
                subscriptionId = $ws.subscriptionId
                resourceGroup  = $ws.resourceGroup
                name           = $ws.name
            }
            location     = $ws.location
            friendlyName = $ws.friendlyName
            description  = 'Nerdio SE Sales Demo workspace'
            tags         = @{
                'NME-SE-Manage' = 'managed'
                Environment     = 'SalesDemo'
            }
        } | ConvertTo-Json -Depth 5
        try {
            $wsResult = Invoke-NmeApi -Method POST -Uri "$NmeUri/api/v1/workspace" -Body $wsBody
            Wait-NmeJob -JobId $wsResult.job.id -Description "create workspace '$($ws.name)'"
            Write-Log "Workspace '$($ws.name)' created."
            # Refresh
            $liveWorkspaces = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/workspace"
            $wsMatch = $liveWorkspaces | Where-Object { $_.id.name -eq $ws.name }
        } catch {
            Add-NonFatalError "Failed to create workspace '$($ws.name)': $($_.Exception.Message)"
        }
    } else {
        Write-Log "[WHATIF] Would create workspace '$($ws.name)'."
    }
} else {
    Write-Log "Workspace '$($ws.name)' exists."
}

#endregion

#region 8 — Reconcile FSLogix Configs

Write-Log "--- Reconcile FSLogix Configs ---"

foreach ($entry in $DesiredState.profiles.fslogix) {
    $live = $liveFslogix | Where-Object { $_.name -eq $entry.name }

    if (-not $live) {
        Write-Log "FSLogix config '$($entry.name)' not found. Creating..."
        if (-not $WhatIf) {
            # Unspecified boolean/array fields default to $false / @() for create
            $fslBody = @{
                name      = $entry.name
                isDefault = $entry.isDefault ?? $false
                properties = @{
                    installer        = @{ version = ''; forceUpdate = $false }
                    profileContainer = @{
                        locations = @($entry.properties.profileContainer.locations ?? @())
                        options   = ''
                    }
                    officeContainer  = @{ locations = @(); options = '' }
                    cloudCache       = $entry.properties.cloudCache      ?? $false
                    pageBlobs        = $entry.properties.pageBlobs        ?? $false
                    entraIdKerberos  = $entry.properties.entraIdKerberos  ?? $false
                    redirectionsXml  = ''
                    exclusions       = @{ exclusionMode = 'None' }
                    appServiceRegistryOptions = @{ registryOptionsMode = 'None'; registryOptions = '' }
                    logRegistryOptions        = @{ registryOptionsMode = 'None'; registryOptions = '' }
                }
            } | ConvertTo-Json -Depth 10
            try {
                Invoke-NmeApi -Method POST -Uri "$NmeUri/api/v1/fslogix" -Body $fslBody | Out-Null
                $fslCreated++
                Write-Log "FSLogix config '$($entry.name)' created."
                $liveFslogix = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/fslogix"
                if (-not $liveFslogix) { $liveFslogix = @() }
            } catch {
                Add-NonFatalError "Failed to create FSLogix config '$($entry.name)': $($_.Exception.Message)"
            }
        } else {
            Write-Log "[WHATIF] Would create FSLogix config '$($entry.name)'."
        }
    } elseif (Compare-FslogixConfig -Live $live -Desired $entry) {
        Write-Log "FSLogix config '$($entry.name)' has drifted. Updating..."
        if (-not $WhatIf) {
            # Read-modify-write: fetch live state and only overwrite specified fields
            $liveFull = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/fslogix"
            $liveFull = @($liveFull) | Where-Object { $_.id -eq $live.id }
            if (-not $liveFull) { $liveFull = $live }
            if ($null -ne $entry.isDefault) { $liveFull.isDefault = $entry.isDefault }
            $dp = $entry.properties
            if ($null -ne $dp) {
                if ($null -ne $dp.entraIdKerberos) { $liveFull.properties.entraIdKerberos = $dp.entraIdKerberos }
                if ($null -ne $dp.cloudCache)      { $liveFull.properties.cloudCache      = $dp.cloudCache }
                if ($null -ne $dp.pageBlobs)       { $liveFull.properties.pageBlobs       = $dp.pageBlobs }
                if ($null -ne $dp.profileContainer -and $null -ne $dp.profileContainer.locations) {
                    $liveFull.properties.profileContainer.locations = @($dp.profileContainer.locations)
                }
            }
            $patchBody = $liveFull | ConvertTo-Json -Depth 10
            try {
                Invoke-NmeApi -Method PATCH -Uri "$NmeUri/api/v1/fslogix/$($live.id)" -Body $patchBody | Out-Null
                $fslUpdated++
                Write-Log "FSLogix config '$($entry.name)' updated."
                $liveFslogix = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/fslogix"
                if (-not $liveFslogix) { $liveFslogix = @() }
            } catch {
                Add-NonFatalError "Failed to update FSLogix config '$($entry.name)': $($_.Exception.Message)"
            }
        } else {
            Write-Log "[WHATIF] Would update FSLogix config '$($entry.name)'."
        }
    } else {
        Write-Log "FSLogix config '$($entry.name)' is correct."
    }
}

# Stray FSLogix configs
foreach ($live in $liveFslogix) {
    $inDs = $DesiredState.profiles.fslogix | Where-Object { $_.name -eq $live.name }
    if (-not $inDs) {
        if ($live.isDefault) {
            Write-Log "FSLogix config '$($live.name)' is the NME default — cannot remove. Consider reassigning the default in NME first." 'WARN'
            continue
        }
        if ($RemoveUndefinedResources) {
            Write-Log "FSLogix config '$($live.name)' not in desired state. Removing..."
            if (-not $WhatIf) {
                try {
                    Invoke-NmeApi -Method DELETE -Uri "$NmeUri/api/v1/fslogix/$($live.id)" | Out-Null
                    $fslRemoved++
                    Write-Log "FSLogix config '$($live.name)' removed."
                } catch {
                    Add-NonFatalError "Failed to remove FSLogix config '$($live.name)': $($_.Exception.Message)"
                }
            } else {
                Write-Log "[WHATIF] Would remove FSLogix config '$($live.name)'."
            }
        } else {
            Write-Log "FSLogix config '$($live.name)' is not in desired state (stray). Run with -RemoveUndefinedResources to remove." 'WARN'
        }
    }
}

#endregion

#region 9 — Reconcile Auto-Scale Profiles

Write-Log "--- Reconcile Auto-Scale Profiles ---"
# Note: host pools use local auto-scale rules, not profile assignments.
# This section only verifies expected profiles exist (for use by demo users who
# may want to assign them manually). Missing profiles are logged as warnings —
# they must be created manually in NME since the full schedule configuration
# cannot be derived from the desired-state schema.

foreach ($entry in $DesiredState.profiles.autoScale) {
    $live = $liveAutoScale | Where-Object { $_.name -eq $entry.name }

    if (-not $live) {
        Write-Log "Auto-scale profile '$($entry.name)' not found. Create it manually in NME (mode=$($entry.mode))." 'WARN'
    } elseif ($null -ne $entry.mode -and $live.mode -ne $entry.mode) {
        Write-Log "Auto-scale profile '$($entry.name)' mode drifted ('$($live.mode)' → '$($entry.mode)'). Updating..."
        if (-not $WhatIf) {
            # Only include fields that are explicitly set in desired state
            $asPatch = @{ name = $entry.name }
            if ($null -ne $entry.mode)        { $asPatch['mode']        = $entry.mode }
            if ($null -ne $entry.description) { $asPatch['description'] = $entry.description }
            $asPatchBody = $asPatch | ConvertTo-Json -Depth 5
            try {
                Invoke-NmeApi -Method PATCH -Uri "$NmeUri/api/v1/auto-scale-profile/$($live.id)" -Body $asPatchBody | Out-Null
                Write-Log "Auto-scale profile '$($entry.name)' updated."
                $liveAutoScale = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/auto-scale-profile"
                if (-not $liveAutoScale) { $liveAutoScale = @() }
            } catch {
                Add-NonFatalError "Failed to update auto-scale profile '$($entry.name)': $($_.Exception.Message)"
            }
        } else {
            Write-Log "[WHATIF] Would update auto-scale profile '$($entry.name)' mode to '$($entry.mode)'."
        }
    } else {
        Write-Log "Auto-scale profile '$($entry.name)' is correct (mode=$($live.mode))."
    }
}

# Stray auto-scale profiles
foreach ($live in $liveAutoScale) {
    $inDs = $DesiredState.profiles.autoScale | Where-Object { $_.name -eq $live.name }
    if (-not $inDs) {
        if ($RemoveUndefinedResources) {
            Write-Log "Auto-scale profile '$($live.name)' not in desired state. Removing..."
            if (-not $WhatIf) {
                try {
                    Invoke-NmeApi -Method DELETE -Uri "$NmeUri/api/v1/auto-scale-profile/$($live.id)" | Out-Null
                    $asRemoved++
                    Write-Log "Auto-scale profile '$($live.name)' removed."
                } catch {
                    Add-NonFatalError "Failed to remove auto-scale profile '$($live.name)': $($_.Exception.Message)"
                }
            } else {
                Write-Log "[WHATIF] Would remove auto-scale profile '$($live.name)'."
            }
        } else {
            Write-Log "Auto-scale profile '$($live.name)' is not in desired state (stray). Run with -RemoveUndefinedResources to remove." 'WARN'
        }
    }
}

#endregion

#region 9b — Reconcile Scripted Actions

Write-Log "--- Reconcile Scripted Actions ---"

# Only enforced when scriptedActions section is explicitly defined in desired state.
# Local (non-repository) scripted actions not in the list are logged as stray,
# and removed when -RemoveUndefinedResources is set.
if ($null -ne $DesiredState.profiles.scriptedActions) {
    $liveScriptedActions = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/scripted-actions"
    if (-not $liveScriptedActions) { $liveScriptedActions = @() }

    $repoLinkedSkipped = 0
    foreach ($live in $liveScriptedActions) {
        $inDs = $DesiredState.profiles.scriptedActions | Where-Object { $_.name -ieq $live.name }
        if (-not $inDs) {
            if ($RemoveUndefinedResources) {
                if (-not $WhatIf) {
                    try {
                        $deleteBody = @{ force = $true } | ConvertTo-Json
                        Invoke-NmeApi -Method DELETE -Uri "$NmeUri/api/v1/scripted-actions/$($live.id)" -Body $deleteBody | Out-Null
                        $scriptedActionsRemoved++
                        Write-Log "Scripted action '$($live.name)' removed."
                    } catch {
                        $errMsg = $_.Exception.Message
                        if ($errMsg -match 'repository-linked') {
                            $repoLinkedSkipped++
                        } else {
                            Add-NonFatalError "Failed to remove scripted action '$($live.name)': $errMsg"
                        }
                    }
                } else {
                    Write-Log "[WHATIF] Would remove scripted action '$($live.name)'."
                }
            } else {
                Write-Log "Scripted action '$($live.name)' is not in desired state (stray). Run with -RemoveUndefinedResources to remove." 'WARN'
            }
        }
    }
    if ($repoLinkedSkipped -gt 0) {
        Write-Log "Skipped $repoLinkedSkipped repository-linked scripted action(s) — cannot be deleted via API."
    }
} else {
    Write-Log "No 'profiles.scriptedActions' section in desired state — skipping scripted action enforcement."
}

#endregion

#region 10 — Reconcile VNets

Write-Log "--- Reconcile VNets ---"

if ($DesiredState.vnets) {
    $liveNets = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/networks"
    if (-not $liveNets) { $liveNets = @() }

    foreach ($entry in $DesiredState.vnets) {
        $match = $liveNets | Where-Object {
            $_.name -ieq $entry.networkName -and $_.subnet -ieq $entry.subnetName
        }
        if (-not $match) {
            Write-Log "VNet '$($entry.networkName)/$($entry.subnetName)' not linked. Linking..."
            if (-not $WhatIf) {
                try {
                    $netBody = @{
                        subscriptionId    = $entry.subscriptionId
                        resourceGroupName = $entry.resourceGroupName
                        networkName       = $entry.networkName
                        subnetName        = $entry.subnetName
                    } | ConvertTo-Json
                    Invoke-NmeApi -Method POST -Uri "$NmeUri/api/v1/networks" -Body $netBody | Out-Null
                    Write-Log "VNet '$($entry.networkName)/$($entry.subnetName)' linked."
                } catch {
                    Add-NonFatalError "Failed to link VNet '$($entry.networkName)': $($_.Exception.Message)"
                }
            } else {
                Write-Log "[WHATIF] Would link VNet '$($entry.networkName)/$($entry.subnetName)'."
            }
        } else {
            Write-Log "VNet '$($entry.networkName)/$($entry.subnetName)' is linked."
        }
    }

    # Stray VNets
    foreach ($live in $liveNets) {
        $inDs = $DesiredState.vnets | Where-Object {
            $_.networkName -ieq $live.name -and $_.subnetName -ieq $live.subnet
        }
        if (-not $inDs) {
            if ($RemoveUndefinedResources) {
                Write-Log "VNet '$($live.name)/$($live.subnet)' not in desired state. Unlinking..."
                if (-not $WhatIf) {
                    try {
                        Invoke-NmeApi -Method DELETE -Uri "$NmeUri/api/v1/networks/$($live.id)" | Out-Null
                        $vnetsUnlinked++
                        Write-Log "VNet '$($live.name)/$($live.subnet)' unlinked."
                    } catch {
                        Add-NonFatalError "Failed to unlink VNet '$($live.name)/$($live.subnet)': $($_.Exception.Message)"
                    }
                } else {
                    Write-Log "[WHATIF] Would unlink VNet '$($live.name)/$($live.subnet)'."
                }
            } else {
                Write-Log "VNet '$($live.name)/$($live.subnet)' is not in desired state (stray). Run with -RemoveUndefinedResources to unlink." 'WARN'
            }
        }
    }
} else {
    Write-Log "No vnets defined in desired state. Skipping."
}

#endregion

#region 11 — Reconcile Storage Accounts

Write-Log "--- Reconcile Storage Accounts ---"

if ($DesiredState.storageAccounts) {
    $liveStorage = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/storage/azure-files"
    if (-not $liveStorage) { $liveStorage = @() }

    foreach ($entry in $DesiredState.storageAccounts) {
        # NME storage IDs are ARM resource IDs — construct expected ID for comparison
        $expectedId = "/subscriptions/$($entry.subscriptionId)/resourceGroups/$($entry.resourceGroup)/providers/Microsoft.Storage/storageAccounts/$($entry.accountName)/fileServices/default/shares/$($entry.shareName)"
        $match = $liveStorage | Where-Object { $_.id -ieq $expectedId }

        if (-not $match) {
            Write-Log "Storage account '$($entry.accountName)/$($entry.shareName)' not linked to NME."
            if ($WhatIf) {
                Write-Log "[WHATIF] Would create (if missing) and link storage '$($entry.accountName)/$($entry.shareName)'."
            } else {
                try {
                    # Ensure the Azure Storage account exists — create it if not
                    $azSa = Get-AzStorageAccount -ResourceGroupName $entry.resourceGroup `
                        -Name $entry.accountName -ErrorAction SilentlyContinue
                    if (-not $azSa) {
                        Write-Log "Storage account '$($entry.accountName)' not found in Azure. Creating in '$($entry.resourceGroup)'..."
                        $rgObj = Get-AzResourceGroup -Name $entry.resourceGroup -ErrorAction Stop
                        $azSa  = New-AzStorageAccount `
                            -ResourceGroupName $entry.resourceGroup `
                            -Name             $entry.accountName `
                            -Location         $rgObj.Location `
                            -SkuName          'Standard_LRS' `
                            -Kind             'StorageV2' `
                            -AllowBlobPublicAccess $false `
                            -MinimumTlsVersion 'TLS1_2' `
                            -ErrorAction Stop
                        Write-Log "Storage account '$($entry.accountName)' created (Standard_LRS, $($rgObj.Location))."
                    }

                    # Ensure the file share exists — create it if not
                    $azShare = Get-AzRmStorageShare -ResourceGroupName $entry.resourceGroup `
                        -StorageAccountName $entry.accountName -Name $entry.shareName `
                        -ErrorAction SilentlyContinue
                    if (-not $azShare) {
                        Write-Log "File share '$($entry.shareName)' not found. Creating..."
                        New-AzRmStorageShare `
                            -ResourceGroupName  $entry.resourceGroup `
                            -StorageAccountName $entry.accountName `
                            -Name               $entry.shareName `
                            -QuotaGiB           100 `
                            -ErrorAction Stop | Out-Null
                        Write-Log "File share '$($entry.shareName)' created (100 GiB)."
                    }

                    # Link the share to NME
                    $linkUrl = "$NmeUri/api/v1/storage/azure-files/$($entry.subscriptionId)/$($entry.resourceGroup)/$($entry.accountName)/$($entry.shareName)/link"
                    Invoke-NmeApi -Method POST -Uri $linkUrl | Out-Null
                    Write-Log "Storage '$($entry.accountName)/$($entry.shareName)' linked to NME."
                } catch {
                    Add-NonFatalError "Failed to provision/link storage '$($entry.accountName)/$($entry.shareName)': $($_.Exception.Message)"
                }
            }
        } else {
            Write-Log "Storage account '$($entry.accountName)/$($entry.shareName)' is linked."
        }
    }

    # Stray storage — unlink any share not in desired state.
    # NME unlink is non-destructive: the Azure storage account and file share are NOT deleted.
    # Note: NME enforces ownership on linked storage — accounts linked by other users/credentials
    # will return 500 and must be unlinked manually via the NME portal.
    foreach ($live in $liveStorage) {
        $inDs = $DesiredState.storageAccounts | Where-Object {
            $expectedId = "/subscriptions/$($_.subscriptionId)/resourceGroups/$($_.resourceGroup)/providers/Microsoft.Storage/storageAccounts/$($_.accountName)/fileServices/default/shares/$($_.shareName)"
            $expectedId -ieq $live.id
        }
        if (-not $inDs) {
            if ($RemoveUndefinedResources) {
                # Parse ARM resource ID: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{acct}/fileServices/default/shares/{share}
                $idParts   = $live.id -split '/'
                $liveSub   = $idParts[2]
                $liveRg    = $idParts[4]
                $liveAcct  = $idParts[8]
                $liveShare = $idParts[12]
                Write-Log "Unlinking stray storage '$liveAcct/$liveShare' from NME (Azure resource NOT deleted — remove manually to avoid ongoing costs)..." 'WARN'
                if (-not $WhatIf) {
                    try {
                        $unlinkUrl = "$NmeUri/api/v1/storage/azure-files/$liveSub/$liveRg/$liveAcct/$liveShare/link"
                        Invoke-NmeApi -Method DELETE -Uri $unlinkUrl | Out-Null
                        $storageUnlinked++
                        Write-Log "Storage '$liveAcct/$liveShare' unlinked. NOTE: '$liveAcct' in '$liveRg' still exists in Azure — delete manually to stop billing." 'WARN'
                    } catch {
                        if ($_.Exception.Message -match '404') {
                            Write-Log "Storage '$liveAcct/$liveShare' already removed from NME (404). Skipping."
                        } elseif ($_.Exception.Message -match '500') {
                            # NME enforces ownership on linked storage — accounts linked by other users
                            # can only be unlinked by those users or via the NME portal.
                            Write-Log "Cannot unlink '$liveAcct/$liveShare' — NME returned 500 (likely linked by a different user/credential). Unlink manually via the NME portal." 'WARN'
                        } else {
                            Add-NonFatalError "Failed to unlink storage '$liveAcct/$liveShare': $($_.Exception.Message)"
                        }
                    }
                } else {
                    Write-Log "[WHATIF] Would unlink storage '$liveAcct/$liveShare'."
                }
            } else {
                Write-Log "Storage '$($live.id)' is not in desired state (stray). Run with -RemoveUndefinedResources to unlink." 'WARN'
            }
        }
    }
} else {
    Write-Log "No storageAccounts defined in desired state. Skipping."
}

#endregion

#region 12 — Check Desktop Images

Write-Log "--- Check Desktop Images ---"

$liveImages = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/desktop-image"
if (-not $liveImages) { $liveImages = @() }

if ($DesiredState.images) {
    # Derive network info from the first vnet in desired state (used as the build VM's network)
    $imgVnet   = $null
    $imgSubnet = $null
    $imgNetId  = $null
    if ($DesiredState.vnets -and @($DesiredState.vnets).Count -gt 0) {
        $imgVnet   = @($DesiredState.vnets)[0]
        $imgSubnet = $imgVnet.subnetName
        $imgNetId  = "/subscriptions/$($imgVnet.subscriptionId)/resourceGroups/$($imgVnet.resourceGroupName)/providers/Microsoft.Network/virtualNetworks/$($imgVnet.networkName)"
    }

    foreach ($entry in $DesiredState.images) {
        # Derive a valid Azure VM name (max 15 chars, alphanumeric + hyphens).
        # NME image list returns "vmname (timestamp)" — match by VM name as last segment of ARM id.
        if ($entry.vmName) {
            $imgVmName = ($entry.vmName -replace '[^a-zA-Z0-9-]', '-').ToLower()
        } else {
            $imgVmName = ($entry.name -replace '[^a-zA-Z0-9]', '-').ToLower()
        }
        if ($imgVmName.Length -gt 15) { $imgVmName = $imgVmName.Substring(0, 15).TrimEnd('-') }

        $match = $liveImages | Where-Object { ($_.id -split '/')[-1] -ieq $imgVmName }
        if (-not $match) {
            if ($entry.sourceImageId) {
                # Required fields present — create the image via create-from-library
                $imgRg  = if ($entry.resourceGroup) { $entry.resourceGroup } else { $DesiredState.workspace.resourceGroup }
                $imgSub = $DesiredState.workspace.subscriptionId
                $imgVmSize      = if ($entry.vmSize)      { $entry.vmSize }      else { 'Standard_D2s_v5' }
                $imgStorageType = if ($entry.storageType) { $entry.storageType } else { 'StandardSSD_LRS' }

                if (-not $imgNetId) {
                    Write-Log "Cannot create image '$($entry.name)' — no vnets defined in desired state to use as build network." 'WARN'
                    continue
                }

                Write-Log "Desktop image '$($entry.name)' (vm: $imgVmName) not found in NME. Creating from source '$($entry.sourceImageId)'..."
                if (-not $WhatIf) {
                    try {
                        $imgPayload = [ordered]@{
                            imageId        = [ordered]@{ subscriptionId = $imgSub; resourceGroup = $imgRg; name = $imgVmName }
                            sourceImageId  = $entry.sourceImageId
                            vmSize         = $imgVmSize
                            storageType    = $imgStorageType
                            diskSize       = if ($entry.diskSize) { [int]$entry.diskSize } else { 128 }
                            networkId      = $imgNetId
                            subnet         = $imgSubnet
                            scriptedActions       = @()
                            applicationsTarget    = 'Clone'
                            scriptedActionTarget  = 'Clone'
                            description    = if ($entry.description) { $entry.description } else { '' }
                        }
                        $imgBody = @{ jobPayload = $imgPayload } | ConvertTo-Json -Depth 10
                        $imgResult = Invoke-NmeApi -Method POST -Uri "$NmeUri/api/v1/desktop-image/create-from-library" -Body $imgBody
                        # Image builds take 20-45 minutes — don't block the runbook waiting.
                        # The image will appear in NME on the next reconcile run.
                        $imgJobId = if ($imgResult.job.id) { $imgResult.job.id } else { $imgResult.id }
                        Write-Log "Desktop image '$($entry.name)' build queued (job: $imgJobId). Will be available after build completes."
                    } catch {
                        Add-NonFatalError "Failed to create desktop image '$($entry.name)': $($_.Exception.Message)"
                    }
                } else {
                    Write-Log "[WHATIF] Would create desktop image '$($entry.name)' (vm: $imgVmName) from '$($entry.sourceImageId)' using $imgVmSize in '$imgRg'."
                }
            } else {
                Write-Log "Desktop image '$($entry.name)' not found in NME. Add 'sourceImageId' to the desired state entry to enable automatic creation." 'WARN'
            }
        } else {
            Write-Log "Desktop image '$($entry.name)' exists (vm: $imgVmName, id=$($match.id))."
        }
    }
} else {
    Write-Log "No images defined in desired state. Skipping."
}

# Stray images — match live image VM name (last segment of ARM id) against desired vm names
foreach ($live in $liveImages) {
    $liveVmName = ($live.id -split '/')[-1]
    $inDs = $DesiredState.images | Where-Object {
        $dsVmName = if ($_.vmName) { ($_.vmName -replace '[^a-zA-Z0-9-]', '-').ToLower() } else { ($_.name -replace '[^a-zA-Z0-9]', '-').ToLower() }
        if ($dsVmName.Length -gt 15) { $dsVmName = $dsVmName.Substring(0, 15).TrimEnd('-') }
        $dsVmName -ieq $liveVmName
    }
    if (-not $inDs) {
        if ($RemoveUndefinedResources) {
            Write-Log "Desktop image '$($live.name)' not in desired state. Removing..."
            if (-not $WhatIf) {
                try {
                    Invoke-NmeApi -Method DELETE -Uri "$NmeUri/api/v1/desktop-image/$($live.id)" | Out-Null
                    $imagesRemoved++
                    Write-Log "Desktop image '$($live.name)' removed."
                } catch {
                    Add-NonFatalError "Failed to remove desktop image '$($live.name)': $($_.Exception.Message)"
                }
            } else {
                Write-Log "[WHATIF] Would remove desktop image '$($live.name)'."
            }
        } else {
            Write-Log "Desktop image '$($live.name)' is not in desired state (stray). Run with -RemoveUndefinedResources to remove." 'WARN'
        }
    }
}

#endregion

#region 13 — Reconcile Host Pools

Write-Log "--- Reconcile Host Pools ---"

# Pre-resolve all FSLogix and auto-scale IDs from desired state names
# (ensures freshest live data after region 8/9 potentially created new resources)
$liveFslogix   = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/fslogix"
$liveAutoScale = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/auto-scale-profile"
if (-not $liveFslogix)   { $liveFslogix   = @() }
if (-not $liveAutoScale) { $liveAutoScale  = @() }

# Refresh workspace match (needed for create body)
$liveWorkspaces = Invoke-NmeApi -Method GET -Uri "$NmeUri/api/v1/workspace"
if (-not $liveWorkspaces) { $liveWorkspaces = @() }
$wsMatch = $liveWorkspaces | Where-Object { $_.id.name -eq $DesiredState.workspace.name }

# Refresh live host pools
$liveHostPools = @(Get-AzWvdHostPool -ResourceGroupName $ScopedResourceGroup -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue)

foreach ($entry in $DesiredState.hostPools) {
    $hpName = $entry.id.hostpoolName
    $hpRg   = $entry.id.resourceGroup
    $hpSub  = $entry.id.subscriptionId
    $hpUrl  = "$NmeUri/api/v1/arm/hostpool/$hpSub/$hpRg/$([uri]::EscapeDataString($hpName))"
    # VM name prefix used in the create payload (always has a value — falls back to pool name).
    # $hpVmPrefixEnforce is non-null only when vmNamePrefix is explicitly in desired state,
    # so Compare-HpAutoScale skips the prefix drift check when it wasn't specified.
    if ($entry.autoScale.vmNamePrefix) {
        $raw = ($entry.autoScale.vmNamePrefix -replace '[^a-zA-Z0-9]', '').ToLower()
        if ($raw.Length -gt 9) { $raw = $raw.Substring(0, 9) }
        $hpVmPrefixTemplate = "$raw-{????}"
        $hpVmPrefixEnforce  = $hpVmPrefixTemplate
    } else {
        $raw = ($hpName -replace '[^a-zA-Z0-9]', '').ToLower()
        if ($raw.Length -gt 9) { $raw = $raw.Substring(0, 9) }
        $hpVmPrefixTemplate = "$raw-{????}"   # create only
        $hpVmPrefixEnforce  = $null           # not specified — skip drift check
    }

    Write-Log "Processing host pool '$hpName'..."

    # Resolve FSLogix config ID
    $resolvedFslId = $null
    if ($entry.fslogixConfigName) {
        $resolvedFslId = Resolve-FslogixIdByName -Name $entry.fslogixConfigName -LiveConfigs $liveFslogix
        if (-not $resolvedFslId) {
            Add-NonFatalError "Cannot resolve FSLogix config '$($entry.fslogixConfigName)' for host pool '$hpName'. Skipping FSLogix operations."
        }
    }

    $liveHp = $liveHostPools | Where-Object { $_.Name -eq $hpName }
    $tag    = if ($liveHp) { Get-ArmTagValue -ResourceId $liveHp.Id -TagName 'NME-SE-Manage' } else { $null }

    if ($tag -eq 'ignore') {
        Write-Log "Skipping '$hpName' (NME-SE-Manage=ignore)."
        continue
    }

    if (-not $liveHp) {
        # ── CREATE ──────────────────────────────────────────────────────────
        Write-Log "Host pool '$hpName' does not exist. Creating..."

        if (-not $wsMatch) {
            Add-NonFatalError "Cannot create host pool '$hpName': workspace '$($DesiredState.workspace.name)' not found."
            continue
        }

        if ($WhatIf) {
            Write-Log "[WHATIF] Would create host pool '$hpName' (poolType=$($entry.poolType), isDesktop=$($entry.isDesktop))."
            continue
        }

        try {
            # Build create body
            if ($entry.poolType -eq 'Personal') {
                $poolParams = @{ personalParams = @{ assignmentType = if ($entry.personalAssignmentType) { $entry.personalAssignmentType } else { 'Automatic' } } }
            } else {
                $poolParams = @{ pooledParams = @{ isDesktop = $entry.isDesktop; isSingleUser = $entry.isSingleUser } }
            }

            $createBody = @{
                workspaceId  = @{
                    subscriptionId = $wsMatch.id.subscriptionId
                    resourceGroup  = $wsMatch.id.resourceGroup
                    name           = $wsMatch.id.name
                }
                friendlyName = $entry.friendlyName
                description  = $entry.description
                tags         = @{ 'NME-SE-Manage' = 'managed'; Environment = 'SalesDemo' }
            }
            # Merge pool type params
            foreach ($k in $poolParams.Keys) { $createBody[$k] = $poolParams[$k] }

            # Add FSLogix at create time if we have a config
            if ($resolvedFslId) {
                $createBody['fsLogix'] = @{ enable = $true; type = 'Predefined'; predefinedConfigId = $resolvedFslId }
            }

            $createJson = $createBody | ConvertTo-Json -Depth 10
            $createResult = Invoke-NmeApi -Method POST -Uri $hpUrl -Body $createJson
            Wait-NmeJob -JobId $createResult.job.id -Description "create host pool '$hpName'"
            Write-Log "Host pool '$hpName' created."

            # Set loadBalancerType + maxSessionLimit (not part of create body)
            $wvdBody = @{
                loadBalancerType = $entry.loadBalancingAlgorithm
                maxSessionLimit  = $entry.maxSessionLimit
            } | ConvertTo-Json
            $wvdResult = Invoke-NmeApi -Method PATCH -Uri "$hpUrl/wvd" -Body $wvdBody
            if ($wvdResult.job.id) {
                Wait-NmeJob -JobId $wvdResult.job.id -Description "set WVD props on '$hpName'"
            }
            Write-Log "WVD props set on '$hpName'."

            # Set auto-scale config directly on HP (local rules, no profile assignment)
            if ($entry.autoScale) {
                try {
                    # Try GET; if 404 (HP is static) convert to dynamic first
                    $asConfig = $null
                    try { $asConfig = Invoke-NmeApi -Method GET -Uri "$hpUrl/auto-scale" } catch {}
                    if (-not $asConfig) {
                        Write-Log "Converting '$hpName' from static to dynamic (auto-scale)..."
                        Invoke-NmeApi -Method POST -Uri "$hpUrl/auto-scale" | Out-Null
                        $asConfig = Invoke-NmeApi -Method GET -Uri "$hpUrl/auto-scale"
                    }

                    # Step 1 — PUT all desired settings with auto-scale DISABLED.
                    # This prevents the default post-conversion config (e.g. capacity=5, random vmName)
                    # from triggering VM provisioning before our settings are in place.
                    $asConfig.isEnabled = $false
                    if ($entry.poolType -ne 'Personal') {
                        $asConfig.hostPoolCapacity    = $entry.autoScale.hostPoolCapacity
                        $asConfig.minActiveHostsCount = $entry.autoScale.minActiveHostsCount
                    }
                    if ($asConfig.vmTemplate) {
                        $asConfig.vmTemplate.size   = $entry.autoScale.vmSize
                        $asConfig.vmTemplate.prefix = $hpVmPrefixTemplate
                    }
                    if ($entry.autoScale.scalingMode)       { $asConfig.scalingMode       = $entry.autoScale.scalingMode }
                    if ($entry.autoScale.autoScaleCriteria) { $asConfig.autoScaleCriteria = $entry.autoScale.autoScaleCriteria }
                    $asResult = Invoke-NmeApi -Method PUT -Uri "$hpUrl/auto-scale" -Body ($asConfig | ConvertTo-Json -Depth 20)
                    if ($asResult.job.id) {
                        Wait-NmeJob -JobId $asResult.job.id -Description "configure auto-scale on '$hpName'"
                    }

                    # Step 2 — Enable auto-scale now that the correct config is locked in.
                    if ($entry.autoScale.isEnabled) {
                        $enableResult = Invoke-NmeApi -Method PATCH -Uri "$hpUrl/auto-scale" -Body (@{ isEnabled = $true } | ConvertTo-Json)
                        if ($enableResult.job.id) {
                            Wait-NmeJob -JobId $enableResult.job.id -Description "enable auto-scale on '$hpName'"
                        }
                        Write-Log "Auto-scale configured (vmPrefix='$hpVmPrefixTemplate', capacity=$($entry.autoScale.hostPoolCapacity)) and enabled on '$hpName'."
                    } else {
                        Write-Log "Auto-scale configured (vmPrefix='$hpVmPrefixTemplate') and left disabled on '$hpName'."
                    }
                } catch {
                    Add-NonFatalError "Failed to set auto-scale config on '$hpName': $($_.Exception.Message)"
                }
            }

            $hpCreated++
        } catch {
            Add-NonFatalError "Failed to create host pool '$hpName': $($_.Exception.Message)"
        }

    } else {
        # ── CHECK & UPDATE ───────────────────────────────────────────────────
        Write-Log "Host pool '$hpName' exists. Checking for drift..."
        $driftFound = $false

        try {
            # WVD props
            $liveWvd = Invoke-NmeApi -Method GET -Uri "$hpUrl/wvd"
            if (Compare-HostPoolWvdProps -Live $liveWvd -Desired $entry) {
                Write-Log "WVD props drifted on '$hpName' (loadBalancer='$($liveWvd.loadBalancerType)'→'$($entry.loadBalancingAlgorithm)', maxSession=$($liveWvd.maxSessionLimit)→$($entry.maxSessionLimit))."
                if (-not $WhatIf) {
                    # Only include fields that are explicitly set in desired state
                    $wvdPatch = @{}
                    if ($null -ne $entry.loadBalancingAlgorithm)                               { $wvdPatch['loadBalancerType'] = $entry.loadBalancingAlgorithm }
                    if ($null -ne $entry.maxSessionLimit -and $entry.poolType -ne 'Personal')  { $wvdPatch['maxSessionLimit']  = [int]$entry.maxSessionLimit }
                    $wvdBody   = $wvdPatch | ConvertTo-Json
                    $wvdResult = Invoke-NmeApi -Method PATCH -Uri "$hpUrl/wvd" -Body $wvdBody
                    if ($wvdResult.job.id) {
                        Wait-NmeJob -JobId $wvdResult.job.id -Description "update WVD props on '$hpName'"
                    }
                    Write-Log "WVD props corrected on '$hpName'."
                } else {
                    Write-Log "[WHATIF] Would update WVD props on '$hpName'."
                }
                $driftFound = $true
            }
        } catch {
            Add-NonFatalError "Failed to check/update WVD props on '$hpName': $($_.Exception.Message)"
        }

        # FSLogix assignment
        if ($resolvedFslId) {
            try {
                $liveFslAssign = Invoke-NmeApi -Method GET -Uri "$hpUrl/fslogix"
                if (Compare-HpFslogixAssignment -Live $liveFslAssign -DesiredConfigId $resolvedFslId) {
                    Write-Log "FSLogix assignment drifted on '$hpName'."
                    if (-not $WhatIf) {
                        $fslAssignBody = @{ enable = $true; type = 'Predefined'; predefinedConfigId = $resolvedFslId } | ConvertTo-Json
                        Invoke-NmeApi -Method PUT -Uri "$hpUrl/fslogix" -Body $fslAssignBody | Out-Null
                        Write-Log "FSLogix assignment corrected on '$hpName'."
                    } else {
                        Write-Log "[WHATIF] Would correct FSLogix assignment on '$hpName'."
                    }
                    $driftFound = $true
                }
            } catch {
                Add-NonFatalError "Failed to check/update FSLogix assignment on '$hpName': $($_.Exception.Message)"
            }
        }

        # Auto-scale config (local rules directly on HP — no profile assignment)
        if ($entry.autoScale) {
            try {
                $liveAs = $null
                try { $liveAs = Invoke-NmeApi -Method GET -Uri "$hpUrl/auto-scale" } catch {}
                if (-not $liveAs) {
                    # HP is static — convert to dynamic first
                    Write-Log "Converting '$hpName' from static to dynamic (auto-scale)..."
                    Invoke-NmeApi -Method POST -Uri "$hpUrl/auto-scale" | Out-Null
                    $liveAs = Invoke-NmeApi -Method GET -Uri "$hpUrl/auto-scale"
                }
                if (Compare-HpAutoScale -Live $liveAs -Desired $entry.autoScale -DesiredPrefix $hpVmPrefixEnforce -PoolType $entry.poolType) {
                    Write-Log "Auto-scale config drifted on '$hpName' (isEnabled=$($liveAs.isEnabled), vmSize=$($liveAs.vmTemplate.size), prefix='$($liveAs.vmTemplate.prefix)', capacity=$($liveAs.hostPoolCapacity), minActive=$($liveAs.minActiveHostsCount))."
                    if (-not $WhatIf) {
                        # Read-modify-write: only overwrite fields that are explicitly set in desired state
                        # Personal pools don't support hostPoolCapacity/minActiveHostsCount
                        if ($null -ne $entry.autoScale.isEnabled) { $liveAs.isEnabled = $entry.autoScale.isEnabled }
                        if ($entry.poolType -ne 'Personal') {
                            if ($null -ne $entry.autoScale.hostPoolCapacity)    { $liveAs.hostPoolCapacity    = $entry.autoScale.hostPoolCapacity }
                            if ($null -ne $entry.autoScale.minActiveHostsCount) { $liveAs.minActiveHostsCount = $entry.autoScale.minActiveHostsCount }
                        }
                        if ($liveAs.vmTemplate) {
                            if ($null -ne $entry.autoScale.vmSize)      { $liveAs.vmTemplate.size   = $entry.autoScale.vmSize }
                            if ($entry.autoScale.vmNamePrefix)          { $liveAs.vmTemplate.prefix = $hpVmPrefixTemplate }
                        }
                        if ($null -ne $entry.autoScale.scalingMode)       { $liveAs.scalingMode       = $entry.autoScale.scalingMode }
                        if ($null -ne $entry.autoScale.autoScaleCriteria) { $liveAs.autoScaleCriteria = $entry.autoScale.autoScaleCriteria }
                        $asResult = Invoke-NmeApi -Method PUT -Uri "$hpUrl/auto-scale" -Body ($liveAs | ConvertTo-Json -Depth 20)
                        if ($asResult.job.id) {
                            Wait-NmeJob -JobId $asResult.job.id -Description "update auto-scale config on '$hpName'"
                        }
                        Write-Log "Auto-scale config corrected on '$hpName'."
                    } else {
                        Write-Log "[WHATIF] Would correct auto-scale config on '$hpName'."
                    }
                    $driftFound = $true
                }
            } catch {
                Add-NonFatalError "Failed to check/update auto-scale config on '$hpName': $($_.Exception.Message)"
            }
        }

        if ($driftFound) { $hpUpdated++ } else { Write-Log "Host pool '$hpName' is correctly configured." }
    }

    # ── User assignment ──────────────────────────────────────────────────────────
    # Ensure every user listed in desired-state users[] is assigned to this pool.
    # Runs after both create and update paths. Extra users already on the pool are
    # never removed — assignment enforcement is strictly additive.
    if ($entry.users -and @($entry.users).Count -gt 0) {
        if ($WhatIf) {
            Write-Log "[WHATIF] Would assign users on '$hpName': $(@($entry.users) -join ', ')."
        } else {
            try {
                $assignBody = @{ users = @($entry.users) } | ConvertTo-Json
                $assignResult = Invoke-NmeApi -Method POST -Uri "$hpUrl/assign" -Body $assignBody
                if ($assignResult.job.id) {
                    Wait-NmeJob -JobId $assignResult.job.id -Description "assign users on '$hpName'"
                }
                Write-Log "User assignment confirmed on '$hpName': $(@($entry.users) -join ', ')."
            } catch {
                Add-NonFatalError "Failed to assign users on '$hpName': $($_.Exception.Message)"
            }
        }
    }
}

# ── REMOVAL PASS ─────────────────────────────────────────────────────────────

if ($RemoveUndefinedResources) {
    Write-Log "--- Removal Pass (RemoveUndefinedResources) ---"
    $desiredNames = @($DesiredState.hostPools | ForEach-Object { $_.id.hostpoolName })

    foreach ($liveHp in $liveHostPools) {
        if ($desiredNames -contains $liveHp.Name) { continue }

        $tag = Get-ArmTagValue -ResourceId $liveHp.Id -TagName 'NME-SE-Manage'
        if ($tag -eq 'ignore') {
            Write-Log "Skipping stray host pool '$($liveHp.Name)' (NME-SE-Manage=ignore)."
            continue
        }

        Write-Log "Stray host pool '$($liveHp.Name)' found (not in desired state). Removing..."

        if ($WhatIf) {
            Write-Log "[WHATIF] Would disable auto-scale, remove session hosts, and delete host pool '$($liveHp.Name)'."
            continue
        }

        $strayUrl = "$NmeUri/api/v1/arm/hostpool/$SubscriptionId/$ScopedResourceGroup/$([uri]::EscapeDataString($liveHp.Name))"

        # Step 1 — Disable auto-scale so it won't provision new hosts during teardown
        try {
            $strayAs = $null
            try { $strayAs = Invoke-NmeApi -Method GET -Uri "$strayUrl/auto-scale" } catch {}
            if ($strayAs -and $strayAs.isEnabled) {
                Write-Log "Disabling auto-scale on '$($liveHp.Name)'..."
                Invoke-NmeApi -Method PATCH -Uri "$strayUrl/auto-scale" -Body (@{ isEnabled = $false } | ConvertTo-Json) | Out-Null
            }
        } catch {
            Add-NonFatalError "Failed to disable auto-scale on '$($liveHp.Name)' (continuing removal): $($_.Exception.Message)"
        }

        # Step 2 — Remove all session hosts via NME API; wait up to 60s for records to clear;
        #           fall back to Az cmdlets only if orphaned records remain after the wait.
        try {
            $strayHosts = Invoke-NmeApi -Method GET -Uri "$strayUrl/host"
            if (-not $strayHosts) { $strayHosts = @() }

            # Remove hosts with known names via NME DropVM jobs
            foreach ($sh in $strayHosts) {
                $shVmName = $sh.hostName
                if ([string]::IsNullOrWhiteSpace($shVmName)) { continue }
                Write-Log "Removing session host '$shVmName' from '$($liveHp.Name)'..."
                try {
                    # jobPayload wrapper required by SessionHostRemove schema
                    $shBody = @{ jobPayload = @{ forceRemoveWVDRecord = $true; skipAdRemoval = $false; removeUsedVmName = $false } } | ConvertTo-Json -Depth 5
                    $shResult = Invoke-NmeApi -Method DELETE -Uri "$strayUrl/host/$([uri]::EscapeDataString($shVmName))" -Body $shBody
                    if ($shResult.job.id) {
                        Wait-NmeJob -JobId $shResult.job.id -Description "remove session host '$shVmName' from '$($liveHp.Name)'"
                    }
                } catch {
                    Add-NonFatalError "Failed to remove session host '$shVmName' from '$($liveHp.Name)': $($_.Exception.Message)"
                }
            }

            # Wait up to 60s for NME to finish clearing session host records before resorting to Az cmdlets.
            # After DropVM jobs complete there can be a brief delay before WVD deregisters the hosts.
            $waitSecs   = 0
            $maxWaitSecs = 60
            do {
                $remaining = Invoke-NmeApi -Method GET -Uri "$strayUrl/host"
                if (-not $remaining) { $remaining = @() }
                $nullHosts = @($remaining | Where-Object { [string]::IsNullOrWhiteSpace($_.hostName) })
                if ($nullHosts.Count -eq 0) { break }
                if ($waitSecs -ge $maxWaitSecs) { break }
                Write-Log "Waiting for NME to clear $($nullHosts.Count) orphaned session host record(s) ($waitSecs/$maxWaitSecs s)..."
                Start-Sleep -Seconds 15
                $waitSecs += 15
            } while ($true)

            # Fall back to Az cmdlets for any orphaned records that remain after the wait
            $remaining = Invoke-NmeApi -Method GET -Uri "$strayUrl/host"
            if (-not $remaining) { $remaining = @() }
            $nullHosts = @($remaining | Where-Object { [string]::IsNullOrWhiteSpace($_.hostName) })
            if ($nullHosts.Count -gt 0) {
                Write-Log "$($nullHosts.Count) orphaned session host record(s) remain after ${maxWaitSecs}s — removing via Az WVD cmdlets..."
                try {
                    $azHosts = Get-AzWvdSessionHost -ResourceGroupName $liveHp.ResourceGroupName `
                        -HostPoolName $liveHp.Name -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
                    if (-not $azHosts) { $azHosts = @() }
                    foreach ($azSh in $azHosts) {
                        $azShName = ($azSh.Name -split '/')[1]  # "poolname/hostname" → "hostname"
                        Write-Log "Removing orphaned WVD session host '$azShName' via Az cmdlet..."
                        Remove-AzWvdSessionHost -ResourceGroupName $liveHp.ResourceGroupName `
                            -HostPoolName $liveHp.Name -Name $azShName -Force -ErrorAction Stop | Out-Null
                        Write-Log "Orphaned session host '$azShName' removed."
                    }
                } catch {
                    Add-NonFatalError "Failed to remove orphaned session hosts on '$($liveHp.Name)' via Az cmdlet: $($_.Exception.Message)"
                }
            }
        } catch {
            Add-NonFatalError "Failed to enumerate/remove session hosts on '$($liveHp.Name)' (continuing removal): $($_.Exception.Message)"
        }

        # Step 3 — Delete the host pool
        try {
            $delResult = Invoke-NmeApi -Method DELETE -Uri $strayUrl
            if ($delResult.job.id) {
                Wait-NmeJob -JobId $delResult.job.id -Description "remove stray host pool '$($liveHp.Name)'"
            }
            $hpRemoved++
            Write-Log "Stray host pool '$($liveHp.Name)' removed."
        } catch {
            Add-NonFatalError "Failed to remove stray host pool '$($liveHp.Name)': $($_.Exception.Message)"
        }
    }
} else {
    Write-Log "RemoveUndefinedResources not set — stray host pools logged above as warnings only."
}

#endregion

#region 13b — Remove Stray NME Profiles via SQL

# Removes profile types that have no NME REST API endpoint for deletion.
# Each type is only enforced if the corresponding section is defined in desired-state.json.
# Requires {Prefix}SqlServer and {Prefix}SqlDatabase AA variables and appropriate SQL
# permissions on the NME database (db_datareader + db_datawriter). If the SQL connection
# could not be established, this region is skipped and a WARN is logged in region 3.
#
# Supported profile types:
#   rdpConfigs  → RdpPropertiesConfigurations table
#   adConfigs   → ADConfigurations table  (domain join configs)
#
# To enforce a type, add the section under "profiles" in desired-state.json:
#   "profiles": {
#     "rdpConfigs":             [{"name": "Default RDP"}],
#     "adConfigs":              [{"name": "MyDomain-Config"}],
#     "vmProfiles":             [{"name": "MyVmProfile"}],
#     "capacityProfiles":       [{"name": "MyCapacityProfile"}],
#     "scriptedActionProfiles": [{"name": "MyScriptedActionProfile"}]
#   }
# An empty array means "remove all profiles of this type".

if ($RemoveUndefinedResources -and $SqlConnection) {

    # Definition table: desired-state key → SQL table, name column, FK null-outs before delete
    $sqlProfileTypes = @(
        @{
            DsKey      = 'rdpConfigs'
            Table      = 'RdpPropertiesConfigurations'
            NameCol    = 'Name'
            PreCleanup = @(
                "UPDATE HostPoolProperties SET RdpPropertiesConfig = NULL WHERE RdpPropertiesConfig IN (SELECT Id FROM RdpPropertiesConfigurations WHERE Name = @Name)"
            )
        },
        @{
            DsKey      = 'adConfigs'
            Table      = 'ADConfigurations'
            NameCol    = 'FriendlyName'
            PreCleanup = @(
                "UPDATE HostPoolADConfigurations SET ADConfigId = NULL WHERE ADConfigId IN (SELECT Id FROM ADConfigurations WHERE FriendlyName = @Name)"
                "UPDATE HostPoolScriptedActionConfigurations SET ActiveDirectoryId = NULL WHERE ActiveDirectoryId IN (SELECT Id FROM ADConfigurations WHERE FriendlyName = @Name)"
            )
        },
        @{
            DsKey      = 'vmProfiles'
            Table      = 'VmDeploymentProfiles'
            NameCol    = 'Name'
            PreCleanup = @(
                "UPDATE HostPoolProperties SET VmDeploymentProfileId = NULL WHERE VmDeploymentProfileId IN (SELECT Id FROM VmDeploymentProfiles WHERE Name = @Name)"
            )
        },
        @{
            DsKey      = 'capacityProfiles'
            Table      = 'CapacityExtenderProfiles'
            NameCol    = 'Name'
            PreCleanup = @(
                "UPDATE HostPoolProperties SET CapacityExtenderProfileId = NULL WHERE CapacityExtenderProfileId IN (SELECT Id FROM CapacityExtenderProfiles WHERE Name = @Name)"
            )
        },
        @{
            DsKey      = 'scriptedActionProfiles'
            Table      = 'HostPoolScriptedActionProfiles'
            NameCol    = 'Name'
            PreCleanup = @(
                "DELETE FROM HostPoolScriptedActionConfigurations WHERE ProfileId IN (SELECT Id FROM HostPoolScriptedActionProfiles WHERE Name = @Name)"
                "UPDATE HostPoolProperties SET ScriptedActionsProfileId = NULL WHERE ScriptedActionsProfileId IN (SELECT Id FROM HostPoolScriptedActionProfiles WHERE Name = @Name)"
            )
        }
    )

    foreach ($pt in $sqlProfileTypes) {
        $dsKey = $pt.DsKey
        # Skip if section not defined in desired state
        $dsSection = $DesiredState.profiles.$dsKey
        if ($null -eq $dsSection) {
            continue
        }

        Write-Log "--- Enforce $dsKey via SQL (keep: $(@($dsSection | ForEach-Object { $_.name }) -join ', ')) ---"
        $desiredNames = @($dsSection | ForEach-Object { $_.name })

        try {
            $liveRows = Invoke-NmeSql -Connection $SqlConnection `
                -Query "SELECT Id, [$($pt.NameCol)] AS ProfileName FROM [$($pt.Table)]" `
                -AsDataTable
        } catch {
            Add-NonFatalError "Failed to query $($pt.Table): $($_.Exception.Message)"
            continue
        }

        Write-Log "$($pt.Table): $($liveRows.Count) row(s) found."
        foreach ($row in $liveRows) {
            $liveName = $row.ProfileName
            if ([string]::IsNullOrWhiteSpace($liveName)) { continue }
            if ($liveName -iin $desiredNames) { continue }

            Write-Log "$($pt.Table) '$liveName' not in desired state. Removing..."
            if (-not $WhatIf) {
                try {
                    foreach ($preQ in $pt.PreCleanup) {
                        Invoke-NmeSql -Connection $SqlConnection -Query $preQ `
                            -Parameters @{ '@Name' = $liveName } | Out-Null
                    }
                    $deleted = Invoke-NmeSql -Connection $SqlConnection `
                        -Query "DELETE FROM [$($pt.Table)] WHERE [$($pt.NameCol)] = @Name" `
                        -Parameters @{ '@Name' = $liveName }
                    if ($deleted -gt 0) {
                        $sqlProfilesRemoved++
                        Write-Log "$($pt.Table) '$liveName' removed."
                    }
                } catch {
                    Add-NonFatalError "Failed to remove $($pt.Table) '$liveName': $($_.Exception.Message)"
                }
            } else {
                Write-Log "[WHATIF] Would remove $($pt.Table) '$liveName'."
            }
        }
    }

} elseif ($RemoveUndefinedResources -and -not $SqlConnection) {
    Write-Log "SQL connection unavailable — skipping SQL-based profile cleanup." 'WARN'
}

# Close SQL connection if open
if ($SqlConnection -and $SqlConnection.State -eq 'Open') {
    $SqlConnection.Close()
}

# If SQL profiles were removed, restart the NME App Service to flush its in-memory cache.
# NME loads profiles (VM deployment, RDP, AD configs, capacity, scripted action profiles)
# at startup — direct SQL deletions are invisible to the running app until it restarts.
if ($sqlProfilesRemoved -gt 0 -and -not $WhatIf) {
    try {
        # Derive app service name from the NME URI subdomain (e.g. "nw-demo-xyz.azurewebsites.net" → "nw-demo-xyz")
        $nmeAppName = ([System.Uri]$NmeUri).Host.Split('.')[0]

        # Find the resource group if not configured
        if (-not $NmeAppResourceGroup) {
            $app = Get-AzWebApp -Name $nmeAppName -ErrorAction SilentlyContinue
            if ($app) { $NmeAppResourceGroup = $app.ResourceGroup }
        }

        if ($NmeAppResourceGroup) {
            Write-Log "Restarting NME App Service '$nmeAppName' (rg: $NmeAppResourceGroup) to flush profile cache..."
            $restartUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$NmeAppResourceGroup/providers/Microsoft.Web/sites/$nmeAppName/restart?api-version=2022-03-01&softRestart=false"
            Invoke-AzRestMethod -Uri $restartUri -Method POST -ErrorAction Stop | Out-Null
            Write-Log "App Service restart triggered. Waiting 90s for NME to come back online..."
            Start-Sleep -Seconds 90

            # Verify NME API is reachable again
            $retries = 0
            while ($retries -lt 10) {
                try {
                    Invoke-RestMethod -Uri "$NmeUri/api/v1/test" -Headers (Get-NmeHeaders) -TimeoutSec 15 -ErrorAction Stop | Out-Null
                    Write-Log "NME API is back online."
                    break
                } catch {
                    $retries++
                    Write-Log "NME not yet ready (attempt $retries/10)..."
                    Start-Sleep -Seconds 15
                }
            }
            if ($retries -ge 10) {
                Add-NonFatalError "NME App Service was restarted but API did not become reachable within expected time."
            }
        } else {
            Write-Log "Could not determine NME App Service resource group — skipping restart. Set '${VariablePrefix}NmeAppResourceGroup' AA variable to enable." 'WARN'
        }
    } catch {
        Add-NonFatalError "Failed to restart NME App Service: $($_.Exception.Message)"
    }
}

#endregion

#region 14 — Session Host Count Advisory

if (-not $SkipSessionHostCheck) {
    Write-Log "--- Session Host Count Advisory ---"

    foreach ($entry in $DesiredState.hostPools) {
        $hpName = $entry.id.hostpoolName
        $hpRg   = $entry.id.resourceGroup
        $hpSub  = $entry.id.subscriptionId
        $hpUrl  = "$NmeUri/api/v1/arm/hostpool/$hpSub/$hpRg/$([uri]::EscapeDataString($hpName))"

        try {
            $hosts     = Invoke-NmeApi -Method GET -Uri "$hpUrl/host"
            if (-not $hosts) { $hosts = @() }
            $available = @($hosts | Where-Object { $_.status -eq 'Available' }).Count
            $minimum   = $entry.autoScale.minActiveHostsCount

            if ($available -lt $minimum) {
                Write-Log "HP '$hpName': $available available session host(s), minimum desired is $minimum." 'WARN'

                # Re-enable auto-scale if it got disabled during demo
                if (-not $WhatIf -and $entry.autoScale.isEnabled) {
                    try {
                        $liveAs = $null
                        try { $liveAs = Invoke-NmeApi -Method GET -Uri "$hpUrl/auto-scale" } catch {}
                        if (-not $liveAs) {
                            Invoke-NmeApi -Method POST -Uri "$hpUrl/auto-scale" | Out-Null
                            $liveAs = Invoke-NmeApi -Method GET -Uri "$hpUrl/auto-scale"
                        }
                        if (-not $liveAs.isEnabled) {
                            Write-Log "Auto-scale is disabled on '$hpName'. Re-enabling..."
                            $liveAs.isEnabled = $true
                            Invoke-NmeApi -Method PUT -Uri "$hpUrl/auto-scale" -Body ($liveAs | ConvertTo-Json -Depth 20) | Out-Null
                            Write-Log "Auto-scale re-enabled on '$hpName'."
                        }
                    } catch {
                        Add-NonFatalError "Failed to re-enable auto-scale on '$hpName': $($_.Exception.Message)"
                    }
                }
            } else {
                Write-Log "HP '$hpName': $available available session host(s) (minimum: $minimum). OK."
            }
        } catch {
            Add-NonFatalError "Failed to check session hosts on '$hpName': $($_.Exception.Message)"
        }
    }
}

#endregion

#region 15 — Summary

Write-Log "=== Summary ==="
Write-Log "Host pools       — imported: $hpImported, created: $hpCreated, updated: $hpUpdated, removed: $hpRemoved"
Write-Log "FSLogix configs  — created: $fslCreated, updated: $fslUpdated, removed: $fslRemoved"
Write-Log "Auto-scale       — created: $asCreated, removed: $asRemoved"
Write-Log "Scripted actions — removed: $scriptedActionsRemoved (stray)"
Write-Log "SQL profiles     — removed: $sqlProfilesRemoved (stray)"
Write-Log "Images           — removed: $imagesRemoved (stray)"
Write-Log "Storage          — unlinked: $storageUnlinked (stray)"
Write-Log "VNets            — unlinked: $vnetsUnlinked (stray)"

if ($script:NonFatalErrors.Count -gt 0) {
    Write-Log "$($script:NonFatalErrors.Count) non-fatal error(s) occurred:" 'WARN'
    $script:NonFatalErrors | ForEach-Object { Write-Log "  - $_" 'WARN' }
    Write-Error "Maintain-NmeDemoEnvironment completed with $($script:NonFatalErrors.Count) error(s). See warnings above."
} else {
    Write-Log "Maintain-NmeDemoEnvironment completed successfully."
}

#endregion
