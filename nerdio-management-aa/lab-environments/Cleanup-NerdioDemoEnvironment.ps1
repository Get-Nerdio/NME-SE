<#
.SYNOPSIS
  Cleans up a Nerdio demo environment by removing resources created by demo users,
  the workspace, and the Entra ID users.

.DESCRIPTION
  This runbook removes resources created by New-NerdioDemoEnvironment.ps1 and by demo users:
  1. Queries NME analytics LAW to discover resources created by demo users
  2. Clears RBAC workspace assignments via the NME API (must happen before user deletion),
     then revokes sign-in sessions and deletes demo users from Entra ID
  3. Cleans up any orphaned RBAC data from the NME SQL database
  4. Removes host pools created by demo users (via NME API)
  5. Removes FSLogix profiles created by demo users
  5b. Removes FSLogix profile VHDs from the file share for demo users
  6. Removes auto-scale profiles created by demo users
  7. Removes app management policies created by demo users
  8. Removes scripted actions created by demo users (via NME API) - both Windows and Azure Automation types
  9. Removes desktop image VMs created by demo users (Azure VM, NIC, OS disk, captured images)
  10. Removes storage accounts and temp VMs created by demo users (Azure)
  10b. Removes VNets created by demo users (Azure VNet + Networks SQL table)
  11. Removes the NME workspace and any additional workspaces created by demo users
  12. Removes resources without API removal functions directly from the NME database:
      AD configs, RDP properties configs, scripted actions profiles,
      capacity extender profiles, deployment models, shell apps, custom views,
      VM deployment profiles
  13. Removes the scheduled cleanup runbook if it exists (prevents duplicate runs)

  PREREQUISITES
  =============

  Automation Account Modules (PowerShell 5.1):
    - Az.Accounts
    - Az.Sql                         (SQL server/database discovery)
    - Az.Compute                     (VM, disk removal)
    - Az.Network                     (NIC removal)
    - Az.Storage                     (storage account removal)
    - Az.DesktopVirtualization       (workspace and host pool queries/removal)
    - Az.OperationalInsights         (Log Analytics Workspace queries)
    - Microsoft.Graph.Authentication (Connect-MgGraph with managed identity)
    - Microsoft.Graph.Users          (Get-MgUser, Remove-MgUser)
    - Microsoft.Graph.Users.Actions  (Revoke-MgUserSignInSession)

  Automation Account Variables (prefixed with VariablePrefix, default 'CustomerDemo'):
    - {Prefix}TenantId          NME API app registration tenant ID
    - {Prefix}ClientId          NME API app registration client ID
    - {Prefix}ClientSecret      NME API app registration client secret (encrypt)
    - {Prefix}Scope             NME API scope (e.g. api://<app-id>/.default)
    - {Prefix}Uri               NME API base URI (e.g. https://app.nerdio.net)
    - {Prefix}SubscriptionId    Azure subscription containing the demo resources
    - {Prefix}TenantDomain      Entra ID tenant domain (e.g. contoso.onmicrosoft.com)
    - {Prefix}LawWorkspaceId    Log Analytics Workspace ID for NME analytics
    - {Prefix}NmeResourceGroup  Resource group containing the NME deployment (SQL server, etc.)
    - {Prefix}-SAKey            Storage account key for the FSLogix profile share
    - {Prefix}-FslStorageAccount Storage account name for FSLogix profiles
    - {Prefix}-FslShareName      File share name for FSLogix profiles

  Managed Identity Permissions:
    - Azure RBAC: Contributor on the subscription (or scoped to the demo resource groups) for
      removing VMs, NICs, disks, storage accounts, workspaces, and host pools.
    - Azure RBAC: Reader on the NME resource group for SQL server discovery.
    - Microsoft Graph: User.ReadWrite.All (to read CompanyName and delete demo users).
    - SQL: The automation account managed identity must be added as a user on the NME SQL
      database with db_datareader and db_datawriter roles for direct SQL cleanup operations.

  SQL Connectivity:
    The runbook discovers the NME SQL server by looking for the tag 'NMW_OBJECT_TYPE' =
    'PRIMARY_SQL_SERVER' on SQL servers in the NME resource group. It authenticates using a
    managed identity access token for https://database.windows.net/. The NME SQL server
    firewall must allow connections from the automation account (e.g. Allow Azure services).

  Naming Conventions:
    Demo users are identified by their CompanyName attribute matching '{CustomerAbbreviation}-Demo'.
    The workspace created by the setup script is named '{CustomerAbbreviation}-Demo-workspace'.
    Demo resources are expected in the 'autoclean-rg' resource group.

.PARAMETER CustomerAbbreviation
  Short customer abbreviation used when the demo environment was created.

.PARAMETER VariablePrefix
  Prefix for automation account variables. Defaults to 'CustomerDemo'.

.EXAMPLE
  .\Cleanup-NerdioDemoEnvironment.ps1 -CustomerAbbreviation 'ACME'
  .\Cleanup-NerdioDemoEnvironment.ps1 -CustomerAbbreviation 'CNTO' -VariablePrefix 'Prod'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CustomerAbbreviation,
    [string]$VariablePrefix = 'CustomerDemo'
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
        'WARN'  { Write-Output  "[$stamp] [WARN]  $Message"; Write-Warning "[$stamp] [WARN]  $Message" }
        'ERROR' { Write-Error   "[$stamp] [ERROR] $Message" }
    }
}

function Invoke-LawQuery {
    <#
    .SYNOPSIS
      Executes a KQL query against the Log Analytics workspace via the Azure management REST API.
      Returns a PSCustomObject with a .Results array of PSCustomObjects (one per row).
      Uses the management.azure.com token — same auth path as the Azure CLI.
    #>
    param(
        [string]$Query,
        [string]$Timespan = 'P30D'
    )
    try {
        $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com/').Token
        $body  = (@{ query = $Query; timespan = $Timespan } | ConvertTo-Json -Depth 3)
        $uri   = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$LawResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$LawWorkspaceName/api/query?api-version=2020-08-01"
        $raw   = Invoke-RestMethod -Uri $uri -Method POST -Body $body `
                     -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } `
                     -ErrorAction Stop
        # Management API response uses Pascal-case: Tables, Columns, ColumnName, Rows
        if ($raw.Tables -and $raw.Tables.Count -gt 0) {
            $t    = $raw.Tables[0]
            $cols = @($t.Columns | Select-Object -ExpandProperty ColumnName -ErrorAction SilentlyContinue)
            if (-not $cols -or $cols.Count -eq 0) {
                Write-Log "LAW query succeeded but returned no column metadata" 'WARN'
                return [PSCustomObject]@{ Results = @() }
            }
            $rows = @(foreach ($row in $t.Rows) {
                $obj = [ordered]@{}
                for ($i = 0; $i -lt $cols.Count; $i++) { $obj[$cols[$i]] = $row[$i] }
                [PSCustomObject]$obj
            })
            Write-Log "LAW query returned $($rows.Count) row(s)."
            return [PSCustomObject]@{ Results = $rows }
        }
        Write-Log "LAW query returned no tables."
        return [PSCustomObject]@{ Results = @() }
    } catch {
        Write-Log "LAW REST query failed: $($_.Exception.Message)" 'WARN'
        return [PSCustomObject]@{ Results = @() }
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
    $job = Invoke-RestMethod "$NmeUri/api/v1/job/$JobId" -Headers $NmeHeaders
    while ($job.jobStatus -in @('Pending', 'InProgress')) {
        Write-Log "Waiting for $Description to complete..."
        Start-Sleep -Seconds 10
        $job = Invoke-RestMethod "$NmeUri/api/v1/job/$JobId" -Headers $NmeHeaders
    }
    return $job
}

function Get-NmeSqlConnection {
    <#
    .SYNOPSIS
      Discovers the NME SQL server and database, returns an open SqlConnection
      authenticated via the automation account managed identity.
    #>
    param([string]$ResourceGroupName)

    # Find primary SQL server by tag
    $NmeResourceTagName = 'NMW_OBJECT_TYPE'
    $SqlServer = Get-AzSqlServer -ResourceGroupName $ResourceGroupName |
        Where-Object { $_.Tags[$NmeResourceTagName] -eq 'PRIMARY_SQL_SERVER' }

    if (-not $SqlServer) {
        # Fallback: exclude secondary and non-NME servers
        $SqlServer = Get-AzSqlServer -ResourceGroupName $ResourceGroupName |
            Where-Object { $_.ServerName -notmatch '-secondary' } |
            Where-Object {
                $_.Tags[$NmeResourceTagName] -ne 'INTUNE_INSIGHTS_DEPLOYMENT_RESOURCE' -and
                $_.Tags[$NmeResourceTagName] -ne 'EIDO_DEPLOYMENT_RESOURCE' -and
                $_.Tags[$NmeResourceTagName] -ne 'REAL_TIME_INSIGHTS_DEPLOYMENT_RESOURCE' -and
                $_.Tags[$NmeResourceTagName] -ne 'NERDIO_COPILOT_DEPLOYMENT_RESOURCE'
            }
    }

    if (-not $SqlServer -or $SqlServer.Count -ne 1) {
        throw "Unable to find NME SQL server in resource group '$ResourceGroupName'. Ensure the tag '$NmeResourceTagName' = 'PRIMARY_SQL_SERVER' is set."
    }

    $DbName = (Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $SqlServer.ServerName |
        Where-Object { $_.DatabaseName -ne 'master' }).DatabaseName

    # Log via Write-Warning to avoid polluting the output pipeline (Write-Output would become part of the return value)
    Write-Warning "Found NME SQL server: $($SqlServer.ServerName), database: $DbName"

    # Get access token for Azure SQL using managed identity
    $token = (Get-AzAccessToken -ResourceUrl 'https://database.windows.net/').Token

    $conn = New-Object System.Data.SqlClient.SqlConnection
    $conn.ConnectionString = "Server=$($SqlServer.FullyQualifiedDomainName);Database=$DbName;Encrypt=True;TrustServerCertificate=False;"
    $conn.AccessToken = $token
    $conn.Open()
    return $conn
}

function Invoke-NmeSql {
    <#
    .SYNOPSIS
      Executes a parameterised SQL command against the NME database.
      Returns the number of rows affected for non-query statements, or a
      DataTable for SELECT statements.
    #>
    param(
        [System.Data.SqlClient.SqlConnection]$Connection,
        [string]$Query,
        [hashtable]$Parameters = @{},
        [switch]$AsDataTable
    )

    $cmd = $Connection.CreateCommand()
    $cmd.CommandText = $Query
    $cmd.CommandTimeout = 30
    foreach ($key in $Parameters.Keys) {
        $cmd.Parameters.AddWithValue($key, $Parameters[$key]) | Out-Null
    }

    if ($AsDataTable) {
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
        $dt = New-Object System.Data.DataTable
        $adapter.Fill($dt) | Out-Null
        return $dt
    } else {
        return $cmd.ExecuteNonQuery()
    }
}

#endregion

#region Variables

# NME API credentials from automation account variables
$NmeTenantId     = Get-AutomationVariable -Name "${VariablePrefix}TenantId"
$NmeClientId     = Get-AutomationVariable -Name "${VariablePrefix}ClientId"
$NmeClientSecret = Get-AutomationVariable -Name "${VariablePrefix}ClientSecret"
$NmeScope        = Get-AutomationVariable -Name "${VariablePrefix}Scope"
$NmeUri          = Get-AutomationVariable -Name "${VariablePrefix}Uri"
$SubscriptionId  = Get-AutomationVariable -Name "${VariablePrefix}SubscriptionId"
$TenantDomain    = Get-AutomationVariable -Name "${VariablePrefix}TenantDomain"
$LawWorkspaceId   = Get-AutomationVariable -Name "${VariablePrefix}LawWorkspaceId"
# LAW resource path constants — used by Invoke-LawQuery (management.azure.com endpoint)
$LawResourceGroup = 'nme-standard-1'
$LawWorkspaceName = 'nme-st1-law-insights-vhsxofas5fpmu'

# FSLogix profile share variables are optional — skip VHD cleanup if not configured
try { $FslStorageAccountName = Get-AutomationVariable -Name "${VariablePrefix}-FslStorageAccount" } catch { $FslStorageAccountName = $null }
try { $FslShareName          = Get-AutomationVariable -Name "${VariablePrefix}-FslShareName"      } catch { $FslShareName = $null }
try { $FslStorageAccountKey  = Get-AutomationVariable -Name "${VariablePrefix}-SAKey"             } catch { $FslStorageAccountKey = $null }

try { $ResourceGroupName = Get-AutomationVariable -Name "${VariablePrefix}DefaultRG" } catch { $ResourceGroupName = 'autoclean-rg' }
$NmeResourceGroupName = Get-AutomationVariable -Name "${VariablePrefix}NmeResourceGroup"

# Automation account constants (must match New-NerdioDemoEnvironment.ps1)
$automationAccountName = 'nerdio-management-aa'
$AutomationRg          = 'nerdio-management-rg'

# Naming conventions (must match New-NerdioDemoEnvironment.ps1)
$EnvironmentName = "$CustomerAbbreviation-Demo"
$NewWorkspaceName = "$EnvironmentName-workspace"
$BaseUserName = "$CustomerAbbreviation-User"

Write-Log "Cleaning up demo environment: $EnvironmentName"

#endregion

#region Authentication

# Connect to Azure using automation account managed identity
Disable-AzContextAutosave -Scope Process | Out-Null
Connect-AzAccount -Identity -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
Write-Log "Connected to Azure subscription $SubscriptionId."

# Connect to Microsoft Graph API using managed identity
Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop | Out-Null
Write-Log "Connected to Microsoft Graph."

# Connect to NME API
$NmeHeaders = Get-NmeHeaders
Write-Log "Connected to NME API at $NmeUri."

# Connect to NME SQL database using managed identity
$SqlConnection = Get-NmeSqlConnection -ResourceGroupName $NmeResourceGroupName

#endregion

# Counters for summary
$hostPoolsRemoved = 0
$fslProfilesRemoved = 0
$fslVhdsRemoved = 0
$asProfilesRemoved = 0
$appPoliciesRemoved = 0
$scriptedActionsRemoved = 0
$desktopImagesRemoved = 0
$storageAccountsRemoved = 0
$dbResourcesRemoved = 0
$usersRemoved = 0
$workspacesRemoved = 0
$errors = 0

#region 1. Query LAW for resources created by demo users

Write-Log "Querying Log Analytics for resources created by demo users..."

# Get demo user UPNs from Entra ID
$Users = Get-MgUser -Property DisplayName,UserPrincipalName,CompanyName,Id -All | Where-Object { $_.CompanyName -eq $EnvironmentName }
$userUpns = @($Users | ForEach-Object { $_.UserPrincipalName })

$discoveredHostPools = @()
$discoveredJobTypes = @()

$upnFilter = $null
if ($userUpns.Count -gt 0) {
    Write-Log "Found $($userUpns.Count) demo user(s) in Entra ID."
    $upnFilter = ($userUpns | ForEach-Object { "`"$_`"" }) -join ', '
} else {
    # Users already deleted from Entra — recover their UPNs from LAW using the naming pattern
    Write-Log "No demo users found in Entra ID. Trying to recover UPNs from LAW..." 'WARN'
    $patternDiscoveryQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) startswith "$CustomerAbbreviation-User"
| where tostring(Props.Username) endswith "@$TenantDomain"
| distinct UserPrincipalName = tostring(Props.Username)
"@
    $patternResult = Invoke-LawQuery -Query $patternDiscoveryQuery
    if ($patternResult.Results) {
        $userUpns = @($patternResult.Results | ForEach-Object { $_.UserPrincipalName })
        $upnFilter = ($userUpns | ForEach-Object { "`"$_`"" }) -join ', '
        Write-Log "Recovered $($userUpns.Count) UPN(s) from LAW: $($userUpns -join ', ')"
    } else {
        Write-Log "No activity found in LAW for $CustomerAbbreviation users either. LAW-dependent cleanup steps will be skipped." 'WARN'
    }
}

if ($upnFilter) {
    Write-Log "Querying LAW for resource types created by demo users..."
    $upnFilter = $upnFilter  # keep in scope for nested here-strings

    # Summary: what resource types did demo users create?
    $summaryQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) in ($upnFilter)
| where Props.TaskStatus == "Success"
| where isnotempty(Props.JobType)
| summarize TaskCount = count() by JobType = tostring(Props.JobType)
| order by TaskCount desc
"@

    $summaryResult = Invoke-LawQuery -Query $summaryQuery
    if ($summaryResult.Results) {
        $discoveredJobTypes = $summaryResult.Results
        Write-Log "Resource types created by demo users:"
        foreach ($row in $discoveredJobTypes) {
            Write-Log "  $($row.JobType): $($row.TaskCount) task(s)"
        }
    } else {
        Write-Log "No activity found in LAW for demo users."
    }

    # Find host pools from CreateHostPool and UpdateDynamicScaleSettings request paths
    # CreateHostPool path: /api/arm/workspace/{sub}/{rg}/{ws}/hostpool/dynamic
    #   -> host pool name is in the "Create host pool" task result
    # UpdateDynamicScaleSettings path: /api/arm/hostpool/dynamic/{sub}/{rg}/{hostPoolName}
    $hpQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) in ($upnFilter)
| where Props.TaskStatus == "Success"
| where tostring(Props.JobType) in ("CreateHostPool", "UpdateDynamicScaleSettings")
| extend RequestPath = tostring(Props.RequestPath)
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskName = tostring(Props.TaskName)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| extend PayloadStr = tostring(TaskResultArray.payload)
| where PayloadStr contains "/hostPools/" or RequestPath contains "/hostpool/dynamic/"
| extend HpFromPayload = extract("/hostPools/([a-zA-Z0-9_-]+)", 1, PayloadStr)
| extend RgFromPayload = extract("/resourceGroups/([a-zA-Z0-9._-]+)", 1, PayloadStr)
| extend SubFromPayload = extract("/subscriptions/([a-fA-F0-9-]+)", 1, PayloadStr)
| parse RequestPath with "/api/arm/hostpool/dynamic/" HpSubFromPath "/" HpRgFromPath "/" HpNameFromPath
| extend HostPoolName = coalesce(HpFromPayload, HpNameFromPath)
| extend HostPoolRg = coalesce(RgFromPayload, HpRgFromPath)
| extend HostPoolSub = coalesce(SubFromPayload, HpSubFromPath)
| where isnotempty(HostPoolName)
| where HostPoolSub =~ "$SubscriptionId"
| where HostPoolRg =~ "$ResourceGroupName"
| distinct HostPoolSub, HostPoolRg, HostPoolName
"@

    $hpResult = Invoke-LawQuery -Query $hpQuery
    if ($hpResult.Results) {
        $discoveredHostPools = @($hpResult.Results)
        Write-Log "Discovered $($discoveredHostPools.Count) host pool(s) from LAW."
    }

    # Verify discovered host pools still exist in Azure (filter out already-deleted ones)
    $verifiedHostPools = @()
    foreach ($hp in $discoveredHostPools) {
        $azHp = Get-AzWvdHostPool -ResourceGroupName $hp.HostPoolRg -Name $hp.HostPoolName -SubscriptionId $hp.HostPoolSub -ErrorAction SilentlyContinue
        if ($azHp) {
            $verifiedHostPools += $hp
        } else {
            Write-Log "Host pool '$($hp.HostPoolName)' discovered in LAW but no longer exists in Azure, skipping."
        }
    }
    $discoveredHostPools = $verifiedHostPools
}

# Fallback: scan the demo resource group for host pools not captured by LAW queries
# (e.g. personal host pools created via a job type not covered above, or pools whose logs
# have aged out of the 30-day LAW retention window)
if ($ResourceGroupName) {
    Write-Log "Scanning '$ResourceGroupName' for host pools not yet in discovery list..."
    $azScanHps = @(Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue)
    foreach ($azHp in $azScanHps) {
        $alreadyDiscovered = $discoveredHostPools | Where-Object {
            $_.HostPoolName -eq $azHp.Name -and $_.HostPoolRg -ieq $ResourceGroupName
        }
        if (-not $alreadyDiscovered) {
            Write-Log "Adding undiscovered host pool '$($azHp.Name)' (found via Azure RG scan)."
            $discoveredHostPools += [PSCustomObject]@{
                HostPoolSub  = $SubscriptionId
                HostPoolRg   = $ResourceGroupName
                HostPoolName = $azHp.Name
            }
        }
    }
    Write-Log "Total host pools to remove after RG scan: $($discoveredHostPools.Count)."
}

#endregion

#region 2. Clear RBAC workspace assignments and remove Entra ID users

# Clear RBAC workspace assignments via the NME API BEFORE deleting users from Entra ID.
# Set-NmeRbacRolesAssignment uses PUT to overwrite (not append), so sending an empty
# AvdWorkspaces array removes all workspace-scoped access for the user.
# This must happen while the user still exists in Entra ID.
$rbacAssignmentsCleared = 0
if ($Users) {
    Write-Log "Clearing RBAC workspace assignments for $($Users.Count) demo user(s)..."

    # Build an empty assignment body to overwrite each user's workspace access
    $EmptyRbacBody = @{ avdWorkspaces = @() } | ConvertTo-Json -Depth 3

    foreach ($user in $Users) {
        try {
            Invoke-RestMethod "$NmeUri/api/v1/users-and-roles/assignment/$($user.Id)" -Method Put -Headers $NmeHeaders -Body $EmptyRbacBody | Out-Null
            Write-Log "Cleared RBAC workspace assignments for $($user.UserPrincipalName)."
            $rbacAssignmentsCleared++
        } catch {
            Write-Log "Failed to clear RBAC assignments for $($user.UserPrincipalName): $($_.Exception.Message)" 'WARN'
            $errors++
        }
    }
    Write-Log "Cleared RBAC workspace assignments for $rbacAssignmentsCleared of $($Users.Count) user(s)."
}

# Delete demo users from Entra ID to invalidate their sessions and prevent them
# from creating new resources while cleanup is in progress. Revoking sign-in sessions
# before deletion ensures refresh tokens are immediately invalidated.
if ($Users) {
    Write-Log "Removing $($Users.Count) demo user(s) from Entra ID to revoke access..."
    foreach ($user in $Users) {
        try {
            Write-Log "Revoking sign-in sessions for $($user.UserPrincipalName)..."
            Revoke-MgUserSignInSession -UserId $user.Id -ErrorAction Stop | Out-Null
        } catch {
            Write-Log "Failed to revoke sessions for $($user.UserPrincipalName): $($_.Exception.Message)" 'WARN'
        }
        try {
            Write-Log "Removing user $($user.UserPrincipalName)..."
            Remove-MgUser -UserId $user.Id -ErrorAction Stop
            $usersRemoved++
        } catch {
            Write-Log "Failed to remove user $($user.UserPrincipalName): $($_.Exception.Message)" 'WARN'
            $errors++
        }
    }
} else {
    Write-Log "No users found with CompanyName '$EnvironmentName'."
}

#endregion

#region 3. Clean up orphaned RBAC data from SQL

# Safety net: remove any residual RBAC data from the NME database.
# The API call in region 2 handles workspace-scoped assignments, but custom role
# definitions or SQL-backed assignments may also need cleanup.
if ($Users) {
    # Collect RoleIds assigned to demo users
    $demoRoleIds = @()
    foreach ($user in $Users) {
        try {
            $roleIdResult = Invoke-NmeSql -Connection $SqlConnection `
                -Query "SELECT RoleId FROM RoleAssignments WHERE PrincipalId = @PrincipalId" `
                -Parameters @{ '@PrincipalId' = $user.Id } -AsDataTable
            foreach ($row in $roleIdResult.Rows) {
                $demoRoleIds += $row.RoleId
            }
        } catch {
            # Table may be empty or not contain entries for these users - that's expected
        }
    }
    $demoRoleIds = $demoRoleIds | Sort-Object -Unique

    # Delete any SQL-backed RBAC assignments for demo users
    foreach ($user in $Users) {
        try {
            $rowsDeleted = Invoke-NmeSql -Connection $SqlConnection `
                -Query "DELETE FROM RoleAssignments WHERE PrincipalId = @PrincipalId" `
                -Parameters @{ '@PrincipalId' = $user.Id }
            if ($rowsDeleted -gt 0) {
                Write-Log "Removed $rowsDeleted SQL RBAC assignment(s) for $($user.UserPrincipalName)."
                $dbResourcesRemoved += $rowsDeleted
            }
        } catch {
            Write-Log "Failed to remove SQL RBAC assignments for $($user.UserPrincipalName): $($_.Exception.Message)" 'WARN'
        }
    }

    # Delete orphaned custom role definitions
    foreach ($roleId in $demoRoleIds) {
        try {
            $refCheck = Invoke-NmeSql -Connection $SqlConnection `
                -Query "SELECT COUNT(*) AS Cnt FROM RoleAssignments WHERE RoleId = @RoleId" `
                -Parameters @{ '@RoleId' = $roleId } -AsDataTable
            if ($refCheck.Rows[0].Cnt -eq 0) {
                $rowsDeleted = Invoke-NmeSql -Connection $SqlConnection `
                    -Query "DELETE FROM RoleDefinitions WHERE Id = @RoleId" `
                    -Parameters @{ '@RoleId' = $roleId }
                if ($rowsDeleted -gt 0) {
                    Write-Log "Removed orphaned RBAC role definition (Id: $roleId)."
                    $dbResourcesRemoved++
                }
            }
        } catch {
            Write-Log "Failed to remove RBAC role definition (Id: $roleId): $($_.Exception.Message)" 'WARN'
        }
    }
}

#endregion

#region 4. Remove host pools

if ($discoveredHostPools.Count -gt 0) {
    Write-Log "Removing $($discoveredHostPools.Count) host pool(s)..."
    foreach ($hp in $discoveredHostPools) {
        try {
            Write-Log "Removing host pool $($hp.HostPoolName) in $($hp.HostPoolRg)..."
            $Result = Invoke-RestMethod "$NmeUri/api/v1/arm/hostpool/$($hp.HostPoolSub)/$($hp.HostPoolRg)/$($hp.HostPoolName)" -Method Delete -Headers $NmeHeaders
            $job = Wait-NmeJob -JobId $Result.job.id -Description "host pool removal ($($hp.HostPoolName))"
            if ($job.jobStatus -eq 'Failed') {
                Write-Log "Host pool removal failed for $($hp.HostPoolName): $($job.error.message)" 'WARN'
                $errors++
            } else {
                Write-Log "Host pool $($hp.HostPoolName) removed."
                $hostPoolsRemoved++
            }
        } catch {
            Write-Log "NME API failed for host pool '$($hp.HostPoolName)': $($_.Exception.Message). Trying Azure ARM fallback..." 'WARN'
            # Fallback: remove session host VMs via Azure ARM, then remove the AVD host pool resource
            $armFallbackSucceeded = $false
            try {
                $sessionHosts = @(Get-AzWvdSessionHost `
                    -ResourceGroupName $hp.HostPoolRg `
                    -HostPoolName      $hp.HostPoolName `
                    -SubscriptionId    $hp.HostPoolSub `
                    -ErrorAction SilentlyContinue)
                Write-Log "Removing $($sessionHosts.Count) session host VM(s) from '$($hp.HostPoolName)' via Azure ARM..."
                foreach ($sh in $sessionHosts) {
                    # .Name is "HostPoolName/vmhostname" — take only the host part
                    $shVmName = ($sh.Name -split '/')[-1]
                    try {
                        $vm = Get-AzVM -ResourceGroupName $hp.HostPoolRg -Name $shVmName -ErrorAction SilentlyContinue
                        if ($vm) {
                            $shNicIds    = @($vm.NetworkProfile.NetworkInterfaces | Select-Object -ExpandProperty Id)
                            $shOsDiskName = $vm.StorageProfile.OsDisk.Name
                            Write-Log "Removing session host VM '$shVmName'..."
                            Remove-AzVM -ResourceGroupName $hp.HostPoolRg -Name $shVmName -ForceDeletion $true -Force -ErrorAction Stop | Out-Null
                            Write-Log "Session host VM '$shVmName' removed."
                            foreach ($nicId in $shNicIds) {
                                $shNicName = ($nicId -split '/')[-1]
                                $shNicRg   = ($nicId -replace '^.*/resourceGroups/([^/]+)/.*$', '$1')
                                Write-Log "Removing NIC '$shNicName'..."
                                Remove-AzNetworkInterface -ResourceGroupName $shNicRg -Name $shNicName -Force -ErrorAction SilentlyContinue | Out-Null
                            }
                            if ($shOsDiskName) {
                                Write-Log "Removing OS disk '$shOsDiskName'..."
                                Remove-AzDisk -ResourceGroupName $hp.HostPoolRg -DiskName $shOsDiskName -Force -ErrorAction SilentlyContinue | Out-Null
                            }
                        }
                    } catch {
                        Write-Log "Failed to remove session host VM '$shVmName': $($_.Exception.Message)" 'WARN'
                    }
                    # Remove the session host registration from AVD
                    Remove-AzWvdSessionHost -ResourceGroupName $hp.HostPoolRg -HostPoolName $hp.HostPoolName `
                        -Name $shVmName -Force -ErrorAction SilentlyContinue | Out-Null
                }
                # Remove associated ApplicationGroups first — host pool deletion fails (400) if any remain
                $appGroups = @(Get-AzWvdApplicationGroup -ResourceGroupName $hp.HostPoolRg `
                    -ErrorAction SilentlyContinue |
                    Where-Object { $_.HostPoolArmPath -like "*/hostPools/$($hp.HostPoolName)" })
                foreach ($ag in $appGroups) {
                    Write-Log "Removing ApplicationGroup '$($ag.Name)' from '$($hp.HostPoolName)'..."
                    Remove-AzWvdApplicationGroup -ResourceGroupName $hp.HostPoolRg -Name $ag.Name `
                        -ErrorAction SilentlyContinue | Out-Null
                    Write-Log "ApplicationGroup '$($ag.Name)' removed."
                }
                Write-Log "Removing host pool '$($hp.HostPoolName)' via Azure ARM..."
                Remove-AzWvdHostPool -ResourceGroupName $hp.HostPoolRg -Name $hp.HostPoolName `
                    -SubscriptionId $hp.HostPoolSub -Force -ErrorAction Stop
                Write-Log "Host pool '$($hp.HostPoolName)' removed via Azure ARM fallback."
                $hostPoolsRemoved++
                $armFallbackSucceeded = $true
            } catch {
                Write-Log "Azure ARM fallback also failed for '$($hp.HostPoolName)': $($_.Exception.Message)" 'WARN'
            }
            if (-not $armFallbackSucceeded) { $errors++ }
        }
    }
} else {
    Write-Log "No host pools found to remove."
}

#endregion

#region 5. Remove FSLogix profiles created by demo users

if ($discoveredJobTypes | Where-Object { $_.JobType -eq 'CreateFSLogixConfiguration' }) {
    Write-Log "Checking for FSLogix profiles created by demo users..."
    $fslQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateFSLogixConfiguration"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 5
| extend Payload = parse_json(tostring(TaskResultArray.payload))
| extend ConfigJson = parse_json(tostring(Payload.message))
| extend FslProfileName = tostring(ConfigJson.name)
| where isnotempty(FslProfileName)
| distinct FslProfileName
"@

    $fslResult = Invoke-LawQuery -Query $fslQuery
    if ($fslResult.Results) {
        $allFslProfiles = Invoke-RestMethod "$NmeUri/api/v1/fslogix" -Headers $NmeHeaders
        foreach ($fslRow in $fslResult.Results) {
            $profileName = $fslRow.FslProfileName
            $matchingProfile = $allFslProfiles | Where-Object { $_.Name -eq $profileName }
            if ($matchingProfile) {
                try {
                    Write-Log "Removing FSLogix profile '$profileName'..."
                    Invoke-RestMethod "$NmeUri/api/v1/fslogix/$($matchingProfile.id)" -Method Delete -Headers $NmeHeaders | Out-Null
                    Write-Log "FSLogix profile '$profileName' removed."
                    $fslProfilesRemoved++
                } catch {
                    Write-Log "Failed to remove FSLogix profile '$profileName': $($_.Exception.Message)" 'WARN'
                    $errors++
                }
            }
        }
    }
}

#endregion

#region 5b. Remove FSLogix profile VHDs from the file share

if ($Users.Count -gt 0 -and $FslStorageAccountName -and $FslShareName -and $FslStorageAccountKey) {
    Write-Log "Checking for FSLogix profile VHDs on file share..."

    try {
        # Use the Azure Storage SDK to list and delete profile directories.
        # This avoids SMB mount issues and lets us force-close open file handles
        # (e.g. VHDs still mounted by session hosts).
        $storageContext = New-AzStorageContext -StorageAccountName $FslStorageAccountName -StorageAccountKey $FslStorageAccountKey
        $share = Get-AzStorageShare -Name $FslShareName -Context $storageContext -ErrorAction Stop

        # List top-level directories in the share
        $profileDirs = Get-AzStorageFile -ShareName $FslShareName -Context $storageContext -ErrorAction Stop |
            Where-Object { $_.GetType().Name -eq 'AzureStorageFileDirectory' }

        # Match profile directories for demo users
        # Directory naming: S-1-12-1-*_<DisplayName> (e.g. S-1-12-1-3441947837-1330913454-3785854094-1796405929_NJW-User2)
        $userDisplayNames = @($Users | ForEach-Object { $_.DisplayName })

        foreach ($dir in $profileDirs) {
            if ($dir.Name -match '^S-1-\d+-\d+-.+_(.+)$') {
                $dirUserName = $Matches[1]
                if ($dirUserName -in $userDisplayNames) {
                    try {
                        Write-Log "Removing FSLogix profile directory '$($dir.Name)'..."

                        # Close any open SMB file handles (e.g. mounted VHDs) before deleting
                        $openHandles = Get-AzStorageFileHandle -ShareName $FslShareName -Path $dir.Name -Recursive -Context $storageContext -ErrorAction SilentlyContinue
                        if ($openHandles) {
                            Write-Log "Closing $($openHandles.Count) open file handle(s) in '$($dir.Name)'..."
                            Close-AzStorageFileHandle -ShareName $FslShareName -Path $dir.Name -Recursive -CloseAll -Context $storageContext -ErrorAction SilentlyContinue
                            # Brief pause for handle closure to propagate
                            Start-Sleep -Seconds 2
                        }

                        # Remove the directory and all contents
                        Remove-AzStorageDirectory -ShareName $FslShareName -Path $dir.Name -Context $storageContext -ErrorAction Stop
                        Write-Log "FSLogix profile directory '$($dir.Name)' removed."
                        $fslVhdsRemoved++
                    } catch {
                        Write-Log "Failed to remove FSLogix profile directory '$($dir.Name)': $($_.Exception.Message)" 'WARN'
                        $errors++
                    }
                }
            }
        }
    } catch {
        Write-Log "Failed to access FSLogix profile share '$FslShareName' on '$FslStorageAccountName': $($_.Exception.Message)" 'WARN'
        $errors++
    }
} elseif (-not ($FslStorageAccountName -and $FslShareName -and $FslStorageAccountKey)) {
    Write-Log "FSLogix share variables not configured (${VariablePrefix}-FslStorageAccount / -FslShareName / -SAKey), skipping VHD cleanup."
} else {
    Write-Log "No demo users found, skipping FSLogix profile VHD cleanup."
}

#endregion

#region 6. Remove auto-scale profiles created by demo users

if ($discoveredJobTypes | Where-Object { $_.JobType -eq 'CreateAutoScaleTemplate' }) {
    Write-Log "Checking for auto-scale profiles created by demo users..."
    $asQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateAutoScaleTemplate"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 5
| extend Payload = parse_json(tostring(TaskResultArray.payload))
| extend PayloadMessage = tostring(Payload.message)
| parse PayloadMessage with "Template name: none -> " AsProfileName "\r\n" *
| where isnotempty(AsProfileName)
| distinct AsProfileName
"@

    $asResult = Invoke-LawQuery -Query $asQuery
    if ($asResult.Results) {
        $allAsProfiles = Invoke-RestMethod "$NmeUri/api/v1/auto-scale-profile" -Headers $NmeHeaders
        foreach ($asRow in $asResult.Results) {
            $profileName = $asRow.AsProfileName
            $matchingProfile = $allAsProfiles | Where-Object { $_.Name -eq $profileName }
            if ($matchingProfile) {
                try {
                    Write-Log "Removing auto-scale profile '$profileName' (Id: $($matchingProfile.Id))..."
                    Invoke-RestMethod "$NmeUri/api/v1/auto-scale-profile/$($matchingProfile.id)" -Method Delete -Headers $NmeHeaders | Out-Null
                    Write-Log "Auto-scale profile '$profileName' removed."
                    $asProfilesRemoved++
                } catch {
                    if ($_.Exception.Message -match 'not found') {
                        Write-Log "Auto-scale profile '$profileName' already removed."
                        $asProfilesRemoved++
                    } else {
                        Write-Log "Failed to remove auto-scale profile '$profileName': $($_.Exception.Message)" 'WARN'
                        $errors++
                    }
                }
            }
        }
    }
}

#endregion

#region 7. Remove app management policies created by demo users

if ($discoveredJobTypes | Where-Object { $_.JobType -eq 'CreateAppPolicy' }) {
    Write-Log "Checking for app management policies created by demo users..."
    $appQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateAppPolicy"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| extend Payload = parse_json(tostring(TaskResultArray.payload))
| where isnotempty(Payload)
| extend PolicyName = tostring(Payload)
| where PolicyName startswith "Name:"
| parse PolicyName with "Name: " AppPolicyName
| where isnotempty(AppPolicyName)
| distinct AppPolicyName
"@

    $appResult = Invoke-LawQuery -Query $appQuery
    if ($appResult.Results) {
        # Check both one-time and recurrent policies
        $oneTimePolicies = Invoke-RestMethod "$NmeUri/api/v1/app-management/policy/onetime?createdSince=2020-01-01" -Headers $NmeHeaders
        $recurrentPolicies = Invoke-RestMethod "$NmeUri/api/v1/app-management/policy/recurrent" -Headers $NmeHeaders
        foreach ($appRow in $appResult.Results) {
            $policyName = $appRow.AppPolicyName
            $matchingOneTime = $oneTimePolicies | Where-Object { $_.Name -eq $policyName }
            $matchingRecurrent = $recurrentPolicies | Where-Object { $_.Name -eq $policyName }

            if ($matchingOneTime) {
                try {
                    Write-Log "Removing one-time app policy '$policyName'..."
                    Invoke-RestMethod "$NmeUri/api/v1/app-management/policy/onetime/$($matchingOneTime.id)" -Method Delete -Headers $NmeHeaders | Out-Null
                    Write-Log "One-time app policy '$policyName' removed."
                    $appPoliciesRemoved++
                } catch {
                    Write-Log "Failed to remove one-time app policy '$policyName': $($_.Exception.Message)" 'WARN'
                    $errors++
                }
            }
            if ($matchingRecurrent) {
                try {
                    Write-Log "Removing recurrent app policy '$policyName'..."
                    Invoke-RestMethod "$NmeUri/api/v1/app-management/policy/recurrent/$($matchingRecurrent.id)" -Method Delete -Headers $NmeHeaders | Out-Null
                    Write-Log "Recurrent app policy '$policyName' removed."
                    $appPoliciesRemoved++
                } catch {
                    Write-Log "Failed to remove recurrent app policy '$policyName': $($_.Exception.Message)" 'WARN'
                    $errors++
                }
            }
        }
    }
}

#endregion

#region 8. Remove scripted actions created by demo users

if ($discoveredJobTypes | Where-Object { $_.JobType -in @('CreateWindowsScriptedAction', 'CreateAutomationScriptedAction') }) {
    Write-Log "Checking for scripted actions created by demo users..."
    $saQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) in ($upnFilter)
| where Props.TaskStatus == "Success"
| where tostring(Props.JobType) in ("CreateWindowsScriptedAction", "CreateAutomationScriptedAction")
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 5
| extend Payload = parse_json(tostring(TaskResultArray.payload))
| extend ConfigJson = parse_json(tostring(Payload.message))
| extend ScriptedActionName = tostring(ConfigJson.name)
| where isnotempty(ScriptedActionName)
| distinct ScriptedActionName
"@

    $saResult = Invoke-LawQuery -Query $saQuery
    if ($saResult.Results) {
        $allScriptedActions = Invoke-RestMethod "$NmeUri/api/v1/scripted-actions" -Headers $NmeHeaders
        $deleteRequestBody = @{ force = $true } | ConvertTo-Json
        foreach ($saRow in $saResult.Results) {
            $actionName = $saRow.ScriptedActionName
            $matchingAction = $allScriptedActions | Where-Object { $_.Name -eq $actionName }
            if ($matchingAction) {
                try {
                    Write-Log "Removing scripted action '$actionName' (Id: $($matchingAction.id))..."
                    Invoke-RestMethod "$NmeUri/api/v1/scripted-actions/$($matchingAction.id)" -Method Delete -Headers $NmeHeaders -Body $deleteRequestBody | Out-Null
                    Write-Log "Scripted action '$actionName' removed."
                    $scriptedActionsRemoved++
                } catch {
                    Write-Log "Failed to remove scripted action '$actionName': $($_.Exception.Message)" 'WARN'
                    $errors++
                }
            }
        }
    }
}

#endregion

#region 9. Remove desktop images created by demo users

if ($discoveredJobTypes | Where-Object { $_.JobType -eq 'CreateDesktopImage' }) {
    Write-Log "Checking for desktop image VMs created by demo users..."
    $diQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateDesktopImage"
| where Props.TaskName == "Create network interface"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 0
| extend NicResourceId = tostring(TaskResultArray.payload)
| where NicResourceId contains "/networkInterfaces/"
| parse NicResourceId with "/subscriptions/" DiSub "/resourceGroups/" DiRg "/providers/Microsoft.Network/networkInterfaces/" NicName
| extend ImageName = replace_string(NicName, "-nic", "")
| where isnotempty(ImageName)
| distinct DiSub, DiRg, ImageName, NicResourceId
"@

    $diResult = Invoke-LawQuery -Query $diQuery
    if ($diResult.Results) {
        foreach ($diRow in $diResult.Results) {
            $imageName = $diRow.ImageName
            $diSub = $diRow.DiSub
            $diRg = $diRow.DiRg

            # Remove the VM
            try {
                Write-Log "Removing desktop image VM '$imageName' in $diRg..."
                Remove-AzVM -ResourceGroupName $diRg -Name $imageName -ForceDeletion $true -Force -ErrorAction Stop | Out-Null
                Write-Log "Desktop image VM '$imageName' removed."
                $desktopImagesRemoved++
            } catch {
                Write-Log "Failed to remove desktop image VM '$imageName': $($_.Exception.Message)" 'WARN'
                $errors++
            }

            # Remove the NIC
            try {
                $nicName = "$imageName-nic"
                Write-Log "Removing NIC '$nicName' in $diRg..."
                Remove-AzNetworkInterface -ResourceGroupName $diRg -Name $nicName -Force -ErrorAction Stop | Out-Null
                Write-Log "NIC '$nicName' removed."
            } catch {
                Write-Log "Failed to remove NIC '$nicName': $($_.Exception.Message)" 'WARN'
                $errors++
            }

            # Remove the OS disk (named after the VM by Azure convention)
            try {
                $osDisk = Get-AzDisk -ResourceGroupName $diRg -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$imageName*" }
                foreach ($disk in $osDisk) {
                    Write-Log "Removing OS disk '$($disk.Name)' in $diRg..."
                    Remove-AzDisk -ResourceGroupName $diRg -DiskName $disk.Name -Force -ErrorAction Stop | Out-Null
                    Write-Log "OS disk '$($disk.Name)' removed."
                }
            } catch {
                Write-Log "Failed to remove OS disk for '$imageName': $($_.Exception.Message)" 'WARN'
                $errors++
            }

            # Remove captured compute images (VM may have been sysprepped/captured before deletion)
            try {
                $capturedImages = Get-AzImage -ResourceGroupName $diRg -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$imageName*" }
                foreach ($image in $capturedImages) {
                    Write-Log "Removing captured image '$($image.Name)' in $diRg..."
                    Remove-AzImage -ResourceGroupName $diRg -ImageName $image.Name -Force -ErrorAction Stop | Out-Null
                    Write-Log "Captured image '$($image.Name)' removed."
                }
            } catch {
                Write-Log "Failed to remove captured image(s) for '$imageName': $($_.Exception.Message)" 'WARN'
                $errors++
            }
        }
    }
}

# Fallback: scan demo RG for any captured images not discovered via LAW
# (e.g. SysprepVM → SysprepVM-image captured after 'Smurfs' VM was logged)
if ($ResourceGroupName) {
    $remainingImages = @(Get-AzImage -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)
    if ($remainingImages.Count -gt 0) {
        Write-Log "Scanning '$ResourceGroupName' for orphaned captured images..."
        foreach ($img in $remainingImages) {
            try {
                Write-Log "Removing captured image '$($img.Name)' from $ResourceGroupName (RG scan fallback)..."
                Remove-AzImage -ResourceGroupName $ResourceGroupName -ImageName $img.Name -Force -ErrorAction Stop | Out-Null
                Write-Log "Captured image '$($img.Name)' removed."
                $desktopImagesRemoved++
            } catch {
                Write-Log "Failed to remove captured image '$($img.Name)': $($_.Exception.Message)" 'WARN'
                $errors++
            }
        }
    }
}

#endregion

#region 10. Remove storage accounts created by demo users

if ($discoveredJobTypes | Where-Object { $_.JobType -eq 'AddFileShare' }) {
    Write-Log "Checking for storage accounts created by demo users..."
    $storQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "AddFileShare"
| where Props.TaskName startswith "Create Storage Account:"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 0
| extend PayloadStr = tostring(TaskResultArray.payload)
| extend StorageAccountName = extract("^StorageAccountName: ([^\",]+)", 1, PayloadStr)
| extend StorageRg = extract("^ResourceGroupName: ([^\",]+)", 1, PayloadStr)
| summarize StorageAccountName = max(StorageAccountName), StorageRg = max(StorageRg) by TaskId = tostring(Props.TaskId)
| where isnotempty(StorageAccountName) and isnotempty(StorageRg)
| distinct StorageAccountName, StorageRg
"@

    $storResult = Invoke-LawQuery -Query $storQuery
    if ($storResult.Results) {
        foreach ($storRow in $storResult.Results) {
            $saName = $storRow.StorageAccountName
            $saRg = $storRow.StorageRg

            try {
                Write-Log "Removing storage account '$saName' in $saRg..."
                Remove-AzStorageAccount -ResourceGroupName $saRg -Name $saName -Force -ErrorAction Stop
                Write-Log "Storage account '$saName' removed."
                $storageAccountsRemoved++
            } catch {
                Write-Log "Failed to remove storage account '$saName': $($_.Exception.Message)" 'WARN'
                $errors++
            }
        }
    }

    # Also remove temp VMs and NICs created during AddFileShare jobs
    $storNicQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "AddFileShare"
| where Props.TaskName == "Create network interface"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 0
| extend NicResourceId = tostring(TaskResultArray.payload)
| where NicResourceId contains "/networkInterfaces/"
| parse NicResourceId with "/subscriptions/" NicSub "/resourceGroups/" NicRg "/providers/Microsoft.Network/networkInterfaces/" NicName
| extend VmName = replace_string(NicName, "-nic", "")
| where isnotempty(VmName)
| distinct NicSub, NicRg, VmName, NicName
"@

    $storNicResult = Invoke-LawQuery -Query $storNicQuery
    if ($storNicResult.Results) {
        foreach ($nicRow in $storNicResult.Results) {
            $vmName = $nicRow.VmName
            $nicName = $nicRow.NicName
            $nicRg = $nicRow.NicRg

            # Remove the temp VM
            try {
                Write-Log "Removing temp VM '$vmName' in $nicRg (from AddFileShare)..."
                Remove-AzVM -ResourceGroupName $nicRg -Name $vmName -ForceDeletion $true -Force -ErrorAction Stop | Out-Null
                Write-Log "Temp VM '$vmName' removed."
            } catch {
                if ($_.Exception.Message -notmatch 'not found|could not be found') {
                    Write-Log "Failed to remove temp VM '$vmName': $($_.Exception.Message)" 'WARN'
                    $errors++
                }
            }

            # Remove the NIC
            try {
                Write-Log "Removing NIC '$nicName' in $nicRg..."
                Remove-AzNetworkInterface -ResourceGroupName $nicRg -Name $nicName -Force -ErrorAction Stop | Out-Null
                Write-Log "NIC '$nicName' removed."
            } catch {
                if ($_.Exception.Message -notmatch 'not found|could not be found') {
                    Write-Log "Failed to remove NIC '$nicName': $($_.Exception.Message)" 'WARN'
                    $errors++
                }
            }

            # Remove the OS disk
            try {
                $osDisk = Get-AzDisk -ResourceGroupName $nicRg -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$vmName*" }
                foreach ($disk in $osDisk) {
                    Write-Log "Removing OS disk '$($disk.Name)' in $nicRg..."
                    Remove-AzDisk -ResourceGroupName $nicRg -DiskName $disk.Name -Force -ErrorAction Stop | Out-Null
                    Write-Log "OS disk '$($disk.Name)' removed."
                }
            } catch {
                Write-Log "Failed to remove OS disk for '$vmName': $($_.Exception.Message)" 'WARN'
                $errors++
            }
        }
    }
}

#endregion

#region 10b. Remove VNets created by demo users

# Always scan the Networks SQL table for VNets in the demo subscription — do not gate on LAW
# because CreateNetwork jobs may not appear if activity predates the LAW retention window.
Write-Log "Checking for VNets in the demo subscription (Networks SQL table)..."
if ($true) {

    # Query the Networks SQL table for VNets in the demo resource group.
    # NetworkId format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{name}
    # Use the resource group name as the filter (simpler and unambiguous vs subscription GUID LIKE patterns).
    $networkRgPattern = "%/resourceGroups/$ResourceGroupName/%"
    try {
        $networkRows = Invoke-NmeSql -Connection $SqlConnection `
            -Query "SELECT NetworkId FROM Networks WHERE NetworkId LIKE @Pattern" `
            -Parameters @{ '@Pattern' = $networkRgPattern } -AsDataTable
        Write-Log "Networks SQL query returned $($networkRows.Rows.Count) row(s) for RG '$ResourceGroupName'."
    } catch {
        Write-Log "Failed to query Networks SQL table: $($_.Exception.Message)" 'WARN'
        $networkRows = $null
        $errors++
    }

    if ($networkRows -and $networkRows.Rows.Count -gt 0) {
        foreach ($row in $networkRows.Rows) {
            $networkArmId = $row.NetworkId
            if ($networkArmId -match '/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.Network/virtualNetworks/([^/]+)') {
                $vnetSub = $Matches[1]
                $vnetRg  = $Matches[2]
                $vnetName = $Matches[3]

                # Null FK references in DynamicPoolConfigurations and VmTemplates before deleting
                foreach ($fkQuery in @(
                    "UPDATE DynamicPoolConfigurations SET SecondaryNetworkDbId = NULL WHERE SecondaryNetworkDbId IN (SELECT Id FROM Networks WHERE NetworkId = @NetworkId)",
                    "UPDATE VmTemplates SET NetworkDbId = NULL WHERE NetworkDbId IN (SELECT Id FROM Networks WHERE NetworkId = @NetworkId)"
                )) {
                    try {
                        Invoke-NmeSql -Connection $SqlConnection -Query $fkQuery -Parameters @{ '@NetworkId' = $networkArmId } | Out-Null
                    } catch {
                        Write-Log "Failed to null FK for VNet '$vnetName': $($_.Exception.Message)" 'WARN'
                    }
                }

                # Remove the Azure VNet
                try {
                    Write-Log "Removing VNet '$vnetName' in $vnetRg..."
                    Remove-AzVirtualNetwork -ResourceGroupName $vnetRg -Name $vnetName -Force -ErrorAction Stop | Out-Null
                    Write-Log "VNet '$vnetName' removed from Azure."
                } catch {
                    if ($_.Exception.Message -notmatch 'not found|could not be found') {
                        Write-Log "Failed to remove VNet '$vnetName': $($_.Exception.Message)" 'WARN'
                        $errors++
                    } else {
                        Write-Log "VNet '$vnetName' already gone from Azure."
                    }
                }

                # Delete from Networks SQL table
                try {
                    $rowsDeleted = Invoke-NmeSql -Connection $SqlConnection `
                        -Query "DELETE FROM Networks WHERE NetworkId = @NetworkId" `
                        -Parameters @{ '@NetworkId' = $networkArmId }
                    if ($rowsDeleted -gt 0) {
                        Write-Log "Removed VNet '$vnetName' from Networks SQL table."
                        $dbResourcesRemoved++
                    }
                } catch {
                    Write-Log "Failed to delete VNet '$vnetName' from Networks SQL table: $($_.Exception.Message)" 'WARN'
                    $errors++
                }
            }
        }
    } else {
        Write-Log "No VNets found in Networks SQL table for this subscription."
    }
}

#endregion

#region 10c. Remove orphaned VMs in the demo resource group

# After host-pool session-host removal, scan the demo RG for any VMs that are not
# currently registered as a session host in any remaining host pool. These are typically
# desktop-image VMs (e.g. SysprepVM) or VMs whose session host registration was already
# deleted but the underlying Azure VM, NIC, and disk were never removed.
if ($ResourceGroupName) {
    Write-Log "Scanning '$ResourceGroupName' for orphaned VMs (not registered as session hosts)..."

    # Build a set of VM names still registered as session hosts in this subscription/RG
    $registeredShVmNames = @{}
    $remainingHpList = @(Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName `
        -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue)
    foreach ($rhp in $remainingHpList) {
        $shList = @(Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName `
            -HostPoolName $rhp.Name -ErrorAction SilentlyContinue)
        foreach ($sh in $shList) {
            $registeredShVmNames[($sh.Name -split '/')[-1]] = $true
        }
    }

    $allVmsInRg = @(Get-AzVM -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)
    foreach ($vm in $allVmsInRg) {
        if ($registeredShVmNames.ContainsKey($vm.Name)) { continue }  # still a session host
        Write-Log "Removing orphaned VM '$($vm.Name)' from $ResourceGroupName..."
        try {
            $vmNicIds    = @($vm.NetworkProfile.NetworkInterfaces | Select-Object -ExpandProperty Id)
            $vmOsDiskName = $vm.StorageProfile.OsDisk.Name
            Remove-AzVM -ResourceGroupName $ResourceGroupName -Name $vm.Name -ForceDeletion $true -Force -ErrorAction Stop | Out-Null
            Write-Log "Orphaned VM '$($vm.Name)' removed."
            foreach ($nicId in $vmNicIds) {
                $nicName = ($nicId -split '/')[-1]
                $nicRg   = ($nicId -replace '^.*/resourceGroups/([^/]+)/.*$', '$1')
                Remove-AzNetworkInterface -ResourceGroupName $nicRg -Name $nicName -Force -ErrorAction SilentlyContinue | Out-Null
                Write-Log "NIC '$nicName' removed."
            }
            if ($vmOsDiskName) {
                Remove-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $vmOsDiskName -Force -ErrorAction SilentlyContinue | Out-Null
                Write-Log "OS disk '$vmOsDiskName' removed."
            }
        } catch {
            Write-Log "Failed to remove orphaned VM '$($vm.Name)': $($_.Exception.Message)" 'WARN'
            $errors++
        }
    }
}

#endregion

#region 11. Remove workspaces

# Remove the workspace we created for the demo environment
$Workspace = (Invoke-RestMethod "$NmeUri/api/v1/workspace" -Headers $NmeHeaders -ErrorAction SilentlyContinue) | Where-Object { $_.id.name -eq $NewWorkspaceName }
if ($null -ne $Workspace) {
    try {
        Write-Log "Removing workspace $NewWorkspaceName..."
        Remove-AzWvdWorkspace -ResourceGroupName $Workspace.id.resourceGroup -Name $Workspace.id.name -SubscriptionId $Workspace.id.subscriptionId -ErrorAction Stop
        Write-Log "Workspace $NewWorkspaceName removed."
        $workspacesRemoved++
    } catch {
        Write-Log "Failed to remove workspace $NewWorkspaceName`: $($_.Exception.Message)" 'WARN'
        $errors++
    }
} else {
    Write-Log "Workspace $NewWorkspaceName not found."
}

# Also remove any additional workspaces created by demo users
if ($discoveredJobTypes | Where-Object { $_.JobType -eq 'CreateWorkspace' }) {
    Write-Log "Checking for additional workspaces created by demo users..."
    $wsQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateWorkspace"
| where Props.TaskName == "Create workspace"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 0
| extend PayloadStr = tostring(TaskResultArray.payload)
| where PayloadStr startswith "Name: "
| extend WsName = substring(PayloadStr, 6)
| where isnotempty(WsName)
| distinct WsName
"@

    $wsResult = Invoke-LawQuery -Query $wsQuery
    if ($wsResult.Results) {
        $allWorkspaces = Invoke-RestMethod "$NmeUri/api/v1/workspace" -Headers $NmeHeaders
        foreach ($wsRow in $wsResult.Results) {
            $wsName = $wsRow.WsName
            if ($wsName -eq $NewWorkspaceName) { continue } # Already handled above
            $matchingWs = $allWorkspaces | Where-Object { $_.id.name -eq $wsName }
            if ($matchingWs) {
                try {
                    Write-Log "Removing workspace '$wsName' created by demo user..."
                    Remove-AzWvdWorkspace -ResourceGroupName $matchingWs.id.resourceGroup -Name $matchingWs.id.name -SubscriptionId $matchingWs.id.subscriptionId -ErrorAction Stop
                    Write-Log "Workspace '$wsName' removed."
                    $workspacesRemoved++
                } catch {
                    Write-Log "Failed to remove workspace '$wsName': $($_.Exception.Message)" 'WARN'
                    $errors++
                }
            } else {
                Write-Log "Workspace '$wsName' not found (may have been removed already)."
            }
        }
    }
}

#endregion

#region 12. Remove resources via direct SQL (no API removal function)

# Map of JobType to the LAW query that extracts the resource name and the SQL cleanup logic
# Helper: builds a LAW query to extract a resource name from changelog-format TaskResult messages.
# The message format is "FieldName: none -> value\r\n..." and we extract the value after " -> ".
# $jobType: the JobType to filter on
# $nameField: the field label in the changelog (e.g. "Name", "FriendlyName", "Template name")
function Build-ChangelogNameQuery {
    param([string]$jobType, [string]$nameField)
    return @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "$jobType"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 5
| extend Payload = parse_json(tostring(TaskResultArray.payload))
| extend Message = tostring(Payload.message)
| extend ResourceName = extract("(?:^|\\r\\n)${nameField}: (?:none -> )?(.+?)(?:\\r\\n|`$)", 1, Message)
| where isnotempty(ResourceName)
| distinct ResourceName
"@
}

$sqlCleanupTypes = @(
    @{ JobType = 'CreateActiveDirectoryConfig';            NameField = 'FriendlyName'
       ParseQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where tostring(Props.Username) in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateActiveDirectoryConfig"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 5
| extend Payload = parse_json(tostring(TaskResultArray.payload))
| extend ConfigJson = parse_json(tostring(Payload.message))
| extend ResourceName = tostring(ConfigJson.friendlyName)
| where isnotempty(ResourceName)
| distinct ResourceName
"@ }
    @{ JobType = 'CreateRdpPropertiesConfig';              NameField = 'Name'
       ParseQuery = Build-ChangelogNameQuery 'CreateRdpPropertiesConfig' 'Name'
       SqlFallback = $true
       SqlFallbackDirect = $true }
    @{ JobType = 'CreateHostPoolScriptedActionsProfile';   NameField = 'Name'
       ParseQuery = Build-ChangelogNameQuery 'CreateHostPoolScriptedActionsProfile' 'Name' }
    @{ JobType = 'CreateHostPoolCapacityExtenderProfile';  NameField = 'Name'
       ParseQuery = Build-ChangelogNameQuery 'CreateHostPoolCapacityExtenderProfile' 'Name' }
    @{ JobType = 'CreateOrUpdateDeploymentModel';          NameField = 'Name'
       ParseQuery = Build-ChangelogNameQuery 'CreateOrUpdateDeploymentModel' 'Name' }
    @{ JobType = 'CreateShellApp';                         NameField = 'Name'
       ParseQuery = Build-ChangelogNameQuery 'CreateShellApp' 'Name' }
    @{ JobType = 'CreateCustomView';                       NameField = 'Name'
       ParseQuery = Build-ChangelogNameQuery 'CreateCustomView' 'Name' }
    @{ JobType = 'CreateHostPoolVmDeploymentProfile';      NameField = 'Name'
       ParseQuery = Build-ChangelogNameQuery 'CreateHostPoolVmDeploymentProfile' 'Name' }
)

# SQL cleanup definitions: table name, name column, and any child tables that must be deleted first
$sqlCleanupMap = @{
    'CreateActiveDirectoryConfig' = @{
        Table = 'ADConfigurations'; NameColumn = 'FriendlyName'
        # Null out FK references before deleting
        PreCleanup = @(
            "UPDATE HostPoolADConfigurations SET ADConfigId = NULL WHERE ADConfigId IN (SELECT Id FROM ADConfigurations WHERE FriendlyName = @Name)"
            "UPDATE HostPoolScriptedActionConfigurations SET ActiveDirectoryId = NULL WHERE ActiveDirectoryId IN (SELECT Id FROM ADConfigurations WHERE FriendlyName = @Name)"
        )
    }
    'CreateRdpPropertiesConfig' = @{
        Table = 'RdpPropertiesConfigurations'; NameColumn = 'Name'
        PreCleanup = @(
            "UPDATE HostPoolProperties SET RdpPropertiesConfig = NULL WHERE RdpPropertiesConfig IN (SELECT Id FROM RdpPropertiesConfigurations WHERE Name = @Name)"
        )
    }
    'CreateHostPoolScriptedActionsProfile' = @{
        Table = 'HostPoolScriptedActionProfiles'; NameColumn = 'Name'
        PreCleanup = @(
            "DELETE FROM HostPoolScriptedActionConfigurations WHERE ProfileId IN (SELECT Id FROM HostPoolScriptedActionProfiles WHERE Name = @Name)"
            "UPDATE HostPoolProperties SET ScriptedActionsProfileId = NULL WHERE ScriptedActionsProfileId IN (SELECT Id FROM HostPoolScriptedActionProfiles WHERE Name = @Name)"
        )
    }
    'CreateHostPoolCapacityExtenderProfile' = @{
        Table = 'CapacityExtenderProfiles'; NameColumn = 'Name'
        PreCleanup = @(
            "UPDATE HostPoolProperties SET CapacityExtenderProfileId = NULL WHERE CapacityExtenderProfileId IN (SELECT Id FROM CapacityExtenderProfiles WHERE Name = @Name)"
        )
    }
    'CreateOrUpdateDeploymentModel' = @{
        Table = 'AvdModels'; NameColumn = 'Name'
        PreCleanup = @()
    }
    'CreateShellApp' = @{
        Table = 'ManagedApp'; NameColumn = 'Name'
        PreCleanup = @(
            "DELETE FROM ManagedAppVersion WHERE AppId IN (SELECT Id FROM ManagedApp WHERE Name = @Name)"
        )
    }
    'CreateCustomView' = @{
        Table = 'CustomViews'; NameColumn = 'Name'
        PreCleanup = @()
    }
    'CreateHostPoolVmDeploymentProfile' = @{
        Table = 'VmDeploymentProfiles'; NameColumn = 'Name'
        PreCleanup = @(
            "UPDATE HostPoolProperties SET VmDeploymentProfileId = NULL WHERE VmDeploymentProfileId IN (SELECT Id FROM VmDeploymentProfiles WHERE Name = @Name)"
        )
    }
}

foreach ($cleanupType in $sqlCleanupTypes) {
    $jobType = $cleanupType.JobType
    if (-not ($discoveredJobTypes | Where-Object { $_.JobType -eq $jobType })) { continue }

    Write-Log "Checking for $jobType resources created by demo users..."

    $mapEntry = $sqlCleanupMap[$jobType]
    $resourceNames = @()

    # Try LAW query first if available
    if ($cleanupType.ParseQuery) {
        $lawResult = Invoke-LawQuery -Query $cleanupType.ParseQuery
        if ($lawResult.Results) {
            foreach ($row in $lawResult.Results) {
                if (-not [string]::IsNullOrWhiteSpace($row.ResourceName)) {
                    $resourceNames += $row.ResourceName
                }
            }
        }
    }

    # Fall back to SQL ProvisionJob table if LAW returned nothing and SqlFallback is enabled
    if ($resourceNames.Count -eq 0 -and $cleanupType.SqlFallback) {
        $upnParams = @{}
        $upnPlaceholders = @()
        for ($u = 0; $u -lt $userUpns.Count; $u++) {
            $upnParams["@upn$u"] = $userUpns[$u]
            $upnPlaceholders += "@upn$u"
        }
        $upnParams['@JobType'] = switch ($jobType) {
            'CreateRdpPropertiesConfig' { 2800 }
        }

        # First try: ProvisionJob.Resources column
        $jobQuery = "SELECT DISTINCT Resources FROM ProvisionJob WHERE UserId IN (SELECT Id FROM JobUser WHERE Username IN ({0})) AND JobType = @JobType AND Resources IS NOT NULL AND Resources <> ''"
        $jobQuery = $jobQuery -f ($upnPlaceholders -join ', ')
        $jobResult = Invoke-NmeSql -Connection $SqlConnection -Query $jobQuery -Parameters $upnParams -AsDataTable
        foreach ($row in $jobResult.Rows) {
            if (-not [string]::IsNullOrWhiteSpace($row.Resources)) {
                $resourceNames += $row.Resources
            }
        }

        # Second try: query the target table directly
        # The CreateRdpPropertiesConfig changelog doesn't include the config name in
        # the TaskResult payload, so LAW extraction always fails. Fall back to querying
        # the RdpPropertiesConfigurations table for non-default configs when we know
        # the demo users created RDP configs (ProvisionJob records exist).
        if ($resourceNames.Count -eq 0 -and $cleanupType.SqlFallbackDirect) {
            Write-Log "ProvisionJob.Resources empty for $jobType; querying $($mapEntry.Table) directly..."
            $checkQuery = "SELECT COUNT(*) AS Cnt FROM ProvisionJob WHERE UserId IN (SELECT Id FROM JobUser WHERE Username IN ({0})) AND JobType = @JobType"
            $checkQuery = $checkQuery -f ($upnPlaceholders -join ', ')
            $checkResult = Invoke-NmeSql -Connection $SqlConnection -Query $checkQuery -Parameters $upnParams -AsDataTable
            if ($checkResult -and $checkResult.Rows.Count -gt 0 -and $checkResult.Rows[0].Cnt -gt 0) {
                # Get all non-default configs — in a demo environment these are demo-user-created
                $directQuery = "SELECT [$($mapEntry.NameColumn)] AS ResourceName FROM [$($mapEntry.Table)] WHERE Id > 1"
                $directResult = Invoke-NmeSql -Connection $SqlConnection -Query $directQuery -Parameters @{} -AsDataTable
                foreach ($row in $directResult.Rows) {
                    if (-not [string]::IsNullOrWhiteSpace($row.ResourceName)) {
                        $resourceNames += $row.ResourceName
                    }
                }
                if ($resourceNames.Count -gt 0) {
                    Write-Log "Found $($resourceNames.Count) $jobType resource(s) via direct table query: $($resourceNames -join ', ')"
                }
            }
        }
    }

    if ($resourceNames.Count -eq 0) {
        Write-Log "No $jobType resources found."
        continue
    }

    foreach ($resourceName in $resourceNames) {
        if ([string]::IsNullOrWhiteSpace($resourceName)) { continue }
        try {
            # Run pre-cleanup to remove FK references
            foreach ($preQuery in $mapEntry.PreCleanup) {
                Invoke-NmeSql -Connection $SqlConnection -Query $preQuery -Parameters @{ '@Name' = $resourceName } | Out-Null
            }

            # Delete the record
            $deleteQuery = "DELETE FROM [$($mapEntry.Table)] WHERE [$($mapEntry.NameColumn)] = @Name"
            $rowsDeleted = Invoke-NmeSql -Connection $SqlConnection -Query $deleteQuery -Parameters @{ '@Name' = $resourceName }

            if ($rowsDeleted -gt 0) {
                Write-Log "Removed $jobType '$resourceName' from $($mapEntry.Table) ($rowsDeleted row(s))."
                $dbResourcesRemoved++
            } else {
                Write-Log "$jobType '$resourceName' not found in $($mapEntry.Table) (may have been removed already)."
            }
        } catch {
            Write-Log "Failed to remove $jobType '$resourceName': $($_.Exception.Message)" 'WARN'
            $errors++
        }
    }
}


#endregion

#region 13. Remove cleanup schedule

$ScheduleName = "$EnvironmentName-destroy-schedule"
$Schedule = Get-AzAutomationSchedule -Name $ScheduleName -ResourceGroupName $AutomationRg -AutomationAccountName $automationAccountName -ErrorAction SilentlyContinue
    if ($null -ne $Schedule) {
    try {
        Write-Log "Removing cleanup schedule '$ScheduleName'..."
        Remove-AzAutomationSchedule -Name $ScheduleName -ResourceGroupName $AutomationRg -AutomationAccountName $automationAccountName -Force -ErrorAction Stop
        Write-Log "Cleanup schedule '$ScheduleName' removed."
    } catch {
        Write-Log "Failed to remove cleanup schedule '$ScheduleName': $($_.Exception.Message)" 'WARN'
        $errors++
    }
} else {
    Write-Log "No cleanup schedule '$ScheduleName' found."
}

#endregion

#region Summary

# Close SQL connection
if ($SqlConnection -and $SqlConnection.State -eq 'Open') {
    $SqlConnection.Close()
    Write-Log "SQL connection closed."
}

Write-Log ""
Write-Log "=== CLEANUP COMPLETED ==="
Write-Log "Environment:          $EnvironmentName"
Write-Log "RBAC assignments:     $rbacAssignmentsCleared cleared"
Write-Log "Host pools removed:   $hostPoolsRemoved"
Write-Log "FSLogix profiles:     $fslProfilesRemoved"
Write-Log "FSLogix profile VHDs: $fslVhdsRemoved"
Write-Log "Auto-scale profiles:  $asProfilesRemoved"
Write-Log "App policies:         $appPoliciesRemoved"
Write-Log "Scripted actions:     $scriptedActionsRemoved"
Write-Log "Desktop images:       $desktopImagesRemoved"
Write-Log "Storage accounts:     $storageAccountsRemoved"
Write-Log "DB resources removed: $dbResourcesRemoved  (includes VNet SQL rows)"
Write-Log "Workspaces removed:   $workspacesRemoved"
Write-Log "Users removed:
        $usersRemoved"
Write-Log "Errors:               $errors"

#endregion
