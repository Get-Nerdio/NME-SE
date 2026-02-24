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
  6. Removes auto-scale profiles created by demo users
  7. Removes app management policies created by demo users
  8. Removes scripted actions created by demo users (via NME API)
  9. Removes desktop image VMs created by demo users (Azure VM, NIC, OS disk)
  10. Removes storage accounts and temp VMs created by demo users (Azure)
  11. Removes the NME workspace and any additional workspaces created by demo users
  12. Removes resources without API removal functions directly from the NME database:
      AD configs, RDP properties configs, scripted actions profiles,
      capacity extender profiles, deployment models, shell apps, custom views
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
    - NerdioManagerPowerShell        (NME API: host pools, FSLogix, auto-scale, app policies,
                                      scripted actions, workspaces)

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
        'WARN'  { Write-Warning "[$stamp] [WARN]  $Message" }
        'ERROR' { Write-Error   "[$stamp] [ERROR] $Message" }
    }
}

function Wait-NmeJob {
    param([string]$JobId, [string]$Description)
    $job = Get-NmeJob -jobid $JobId
    while ($job.status -eq 'InProgress') {
        Write-Log "Waiting for $Description to complete..."
        Start-Sleep -Seconds 10
        $job = Get-NmeJob -jobid $JobId
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
$LawWorkspaceId  = Get-AutomationVariable -Name "${VariablePrefix}LawWorkspaceId"

$ResourceGroupName = 'autoclean-rg'
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
Import-Module NerdioManagerPowerShell -Force
Connect-Nme -ClientId $NmeClientId -ClientSecret $NmeClientSecret -TenantId $NmeTenantId -ApiScope $NmeScope -NmeUri $NmeUri | Out-Null
Write-Log "Connected to NME API at $NmeUri."

# Connect to NME SQL database using managed identity
$SqlConnection = Get-NmeSqlConnection -ResourceGroupName $NmeResourceGroupName

#endregion

# Counters for summary
$hostPoolsRemoved = 0
$fslProfilesRemoved = 0
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

if ($userUpns.Count -eq 0) {
    Write-Log "No demo users found in Entra ID. Skipping LAW query." 'WARN'
} else {
    Write-Log "Found $($userUpns.Count) demo user(s). Querying LAW for their activity..."
    $upnFilter = ($userUpns | ForEach-Object { "`"$_`"" }) -join ', '

    # Summary: what resource types did demo users create?
    $summaryQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where Props.Username in ($upnFilter)
| where Props.TaskStatus == "Success"
| where isnotempty(Props.JobType)
| summarize TaskCount = count() by JobType = tostring(Props.JobType)
| order by TaskCount desc
"@

    $summaryResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $summaryQuery -ErrorAction SilentlyContinue
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
| where Props.Username in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType in ("CreateHostPool", "UpdateDynamicScaleSettings")
| extend RequestPath = tostring(Props.RequestPath)
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskName = tostring(Props.TaskName)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| extend PayloadStr = tostring(TaskResultArray.payload)
| where PayloadStr contains "/hostPools/" or RequestPath contains "/hostpool/dynamic/"
| extend HpFromPayload = extract("/hostPools/([^/\"]+)", 1, PayloadStr)
| extend RgFromPayload = extract("/resourceGroups/([^/\"]+)", 1, PayloadStr)
| extend SubFromPayload = extract("/subscriptions/([^/\"]+)", 1, PayloadStr)
| parse RequestPath with "/api/arm/hostpool/dynamic/" HpSubFromPath "/" HpRgFromPath "/" HpNameFromPath
| extend HostPoolName = coalesce(HpFromPayload, HpNameFromPath)
| extend HostPoolRg = coalesce(RgFromPayload, HpRgFromPath)
| extend HostPoolSub = coalesce(SubFromPayload, HpSubFromPath)
| where isnotempty(HostPoolName)
| distinct HostPoolSub, HostPoolRg, HostPoolName
"@

    $hpResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $hpQuery -ErrorAction SilentlyContinue
    if ($hpResult.Results) {
        $discoveredHostPools = @($hpResult.Results)
        Write-Log "Discovered $($discoveredHostPools.Count) host pool(s) from LAW."
    }

    # Fallback: also find host pools in the resource group via Azure
    $azHostPools = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
    if ($azHostPools) {
        foreach ($azHp in $azHostPools) {
            $hpName = $azHp.Name
            $alreadyDiscovered = $discoveredHostPools | Where-Object { $_.HostPoolName -eq $hpName }
            if (-not $alreadyDiscovered) {
                Write-Log "Found additional host pool '$hpName' in resource group $ResourceGroupName."
                $discoveredHostPools += [PSCustomObject]@{
                    HostPoolSub  = $SubscriptionId
                    HostPoolRg   = $ResourceGroupName
                    HostPoolName = $hpName
                }
            }
        }
    }
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

    # Build an empty assignment model to overwrite each user's workspace access
    $EmptyRbacAssignment = New-Object -TypeName psobject -Property @{ AvdWorkspaces = @() }
    $EmptyRbacAssignment.PSObject.TypeNames.Insert(0, 'NmeRbacAssignmentUpdateRestModel')

    foreach ($user in $Users) {
        try {
            Set-NmeRbacRolesAssignment -ObjectId $user.Id -NmeRbacAssignmentUpdateRestModel $EmptyRbacAssignment -ErrorAction Stop | Out-Null
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
            $Result = Remove-NmeHostPool -SubscriptionId $hp.HostPoolSub -ResourceGroup $hp.HostPoolRg -HostPoolName $hp.HostPoolName -ErrorAction Stop
            $job = Wait-NmeJob -JobId $Result.job.Id -Description "host pool removal ($($hp.HostPoolName))"
            if ($job.status -eq 'Failed') {
                Write-Log "Host pool removal failed for $($hp.HostPoolName): $($job.error.message)" 'WARN'
                $errors++
            } else {
                Write-Log "Host pool $($hp.HostPoolName) removed."
                $hostPoolsRemoved++
            }
        } catch {
            Write-Log "Failed to remove host pool $($hp.HostPoolName): $($_.Exception.Message)" 'WARN'
            $errors++
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
| where Props.Username in ($upnFilter)
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

    $fslResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $fslQuery -ErrorAction SilentlyContinue
    if ($fslResult.Results) {
        $allFslProfiles = Get-NmeFslogixProfile -ErrorAction SilentlyContinue
        foreach ($fslRow in $fslResult.Results) {
            $profileName = $fslRow.FslProfileName
            $matchingProfile = $allFslProfiles | Where-Object { $_.Name -eq $profileName }
            if ($matchingProfile) {
                try {
                    Write-Log "Removing FSLogix profile '$profileName'..."
                    Remove-NmeFslogixProfileById -Id $matchingProfile.Id -ErrorAction Stop | Out-Null
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

#region 6. Remove auto-scale profiles created by demo users

if ($discoveredJobTypes | Where-Object { $_.JobType -eq 'CreateAutoScaleTemplate' }) {
    Write-Log "Checking for auto-scale profiles created by demo users..."
    $asQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where Props.Username in ($upnFilter)
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

    $asResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $asQuery -ErrorAction SilentlyContinue
    if ($asResult.Results) {
        $allAsProfiles = Get-NmeAutoScaleProfile -ErrorAction SilentlyContinue
        foreach ($asRow in $asResult.Results) {
            $profileName = $asRow.AsProfileName
            $matchingProfile = $allAsProfiles | Where-Object { $_.Name -eq $profileName }
            if ($matchingProfile) {
                try {
                    Write-Log "Removing auto-scale profile '$profileName' (Id: $($matchingProfile.Id))..."
                    Remove-NmeAutoScaleProfileId -ProfileId $matchingProfile.Id -ErrorAction Stop | Out-Null
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
| where Props.Username in ($upnFilter)
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

    $appResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $appQuery -ErrorAction SilentlyContinue
    if ($appResult.Results) {
        # Check both one-time and recurrent policies
        $oneTimePolicies = Get-NmeAppManagementOneTimePolicy -CreatedSince '2020-01-01' -ErrorAction SilentlyContinue
        $recurrentPolicies = Get-NmeAppManagementRecurrentPolicy -ErrorAction SilentlyContinue

        foreach ($appRow in $appResult.Results) {
            $policyName = $appRow.AppPolicyName
            $matchingOneTime = $oneTimePolicies | Where-Object { $_.Name -eq $policyName }
            $matchingRecurrent = $recurrentPolicies | Where-Object { $_.Name -eq $policyName }

            if ($matchingOneTime) {
                try {
                    Write-Log "Removing one-time app policy '$policyName'..."
                    Remove-NmeAppManagementOneTimePolicyId -PolicyId $matchingOneTime.Id -ErrorAction Stop | Out-Null
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
                    Remove-NmeAppManagementRecurrentPolicyId -PolicyId $matchingRecurrent.Id -ErrorAction Stop | Out-Null
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

if ($discoveredJobTypes | Where-Object { $_.JobType -eq 'CreateWindowsScriptedAction' }) {
    Write-Log "Checking for scripted actions created by demo users..."
    $saQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where Props.Username in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateWindowsScriptedAction"
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

    $saResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $saQuery -ErrorAction SilentlyContinue
    if ($saResult.Results) {
        $allScriptedActions = Get-NmeScriptedActions -ErrorAction SilentlyContinue
        $deleteRequest = New-NmeDeleteScriptedActionRequest -Force $true
        foreach ($saRow in $saResult.Results) {
            $actionName = $saRow.ScriptedActionName
            $matchingAction = $allScriptedActions | Where-Object { $_.Name -eq $actionName }
            if ($matchingAction) {
                try {
                    Write-Log "Removing scripted action '$actionName' (Id: $($matchingAction.Id))..."
                    Remove-NmeScriptedAction -Id $matchingAction.Id -NmeDeleteScriptedActionRequest $deleteRequest -ErrorAction Stop | Out-Null
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
| where Props.Username in ($upnFilter)
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

    $diResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $diQuery -ErrorAction SilentlyContinue
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
| where Props.Username in ($upnFilter)
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

    $storResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $storQuery -ErrorAction SilentlyContinue
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
| where Props.Username in ($upnFilter)
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

    $storNicResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $storNicQuery -ErrorAction SilentlyContinue
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

#region 11. Remove workspaces

# Remove the workspace we created for the demo environment
$Workspace = Get-NmeWorkspace -ErrorAction SilentlyContinue | Where-Object { $_.id.name -eq $NewWorkspaceName }
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
| where Props.Username in ($upnFilter)
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

    $wsResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $wsQuery -ErrorAction SilentlyContinue
    if ($wsResult.Results) {
        $allWorkspaces = Get-NmeWorkspace -ErrorAction SilentlyContinue
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
| where Props.Username in ($upnFilter)
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
| where Props.Username in ($upnFilter)
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
       SqlFallback = $true }
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
}

foreach ($cleanupType in $sqlCleanupTypes) {
    $jobType = $cleanupType.JobType
    if (-not ($discoveredJobTypes | Where-Object { $_.JobType -eq $jobType })) { continue }

    Write-Log "Checking for $jobType resources created by demo users..."

    $mapEntry = $sqlCleanupMap[$jobType]
    $resourceNames = @()

    if ($cleanupType.SqlFallback) {
        # Some job types don't include the resource name in LAW logs.
        # Fall back to querying the NME ProvisionJob table by demo user ID and job description.
        $jobQuery = "SELECT DISTINCT Resources FROM ProvisionJob WHERE UserId IN (SELECT Id FROM JobUser WHERE Username IN ({0})) AND JobType = @JobType AND Resources IS NOT NULL AND Resources <> ''"
        $upnParams = @{}
        $upnPlaceholders = @()
        for ($u = 0; $u -lt $userUpns.Count; $u++) {
            $upnParams["@upn$u"] = $userUpns[$u]
            $upnPlaceholders += "@upn$u"
        }
        $jobQuery = $jobQuery -f ($upnPlaceholders -join ', ')
        $upnParams['@JobType'] = switch ($jobType) {
            'CreateRdpPropertiesConfig' { 2800 }
        }
        $jobResult = Invoke-NmeSql -Connection $SqlConnection -Query $jobQuery -Parameters $upnParams -AsDataTable
        foreach ($row in $jobResult.Rows) {
            $resourceNames += $row.Resources
        }
    } else {
        $lawResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $cleanupType.ParseQuery -ErrorAction SilentlyContinue
        if ($lawResult.Results) {
            foreach ($row in $lawResult.Results) {
                $resourceNames += $row.ResourceName
            }
        }
    }

    if ($resourceNames.Count -eq 0) {
        Write-Log "No $jobType resources found."
        continue
    }

    foreach ($resourceName in $resourceNames) {
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
Write-Log "Auto-scale profiles:  $asProfilesRemoved"
Write-Log "App policies:         $appPoliciesRemoved"
Write-Log "Scripted actions:     $scriptedActionsRemoved"
Write-Log "Desktop images:       $desktopImagesRemoved"
Write-Log "Storage accounts:     $storageAccountsRemoved"
Write-Log "DB resources removed: $dbResourcesRemoved"
Write-Log "Workspaces removed:   $workspacesRemoved"
Write-Log "Users removed:        $usersRemoved"
Write-Log "Errors:               $errors"

#endregion
