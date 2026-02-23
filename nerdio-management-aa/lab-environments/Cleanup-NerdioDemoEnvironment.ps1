<#
.SYNOPSIS
  Cleans up a Nerdio demo environment by removing resources created by demo users,
  the workspace, and the Entra ID users.

.DESCRIPTION
  This runbook removes resources created by New-NerdioDemoEnvironment.ps1 and by demo users:
  1. Queries NME analytics LAW to discover resources created by demo users
  2. Removes host pools created by demo users (via NME API)
  3. Removes FSLogix profiles created by demo users
  4. Removes auto-scale profiles created by demo users
  5. Removes app management policies created by demo users
  6. Removes the NME workspace
  7. Removes the Entra ID users (identified by CompanyName matching the environment name)
  8. Removes resources without API removal functions directly from the NME database:
     AD configs, RDP properties configs, scripted actions profiles,
     capacity extender profiles, deployment models, shell apps, custom views

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
$dbResourcesRemoved = 0
$usersRemoved = 0
$workspaceRemoved = $false
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

    # Find host pools from UpdateDynamicScaleSettings request paths
    # Path format: /api/arm/hostpool/dynamic/{subscriptionId}/{resourceGroup}/{hostPoolName}
    $hpQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where Props.Username in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "UpdateDynamicScaleSettings"
| extend RequestPath = tostring(Props.RequestPath)
| parse RequestPath with "/api/arm/hostpool/dynamic/" HostPoolSub "/" HostPoolRg "/" HostPoolName
| where isnotempty(HostPoolName)
| distinct HostPoolSub, HostPoolRg, HostPoolName
"@

    $hpResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $hpQuery -ErrorAction SilentlyContinue
    if ($hpResult.Results) {
        $discoveredHostPools = $hpResult.Results
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

#region 2. Remove host pools

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

#region 3. Remove FSLogix profiles created by demo users

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

#region 4. Remove auto-scale profiles created by demo users

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
                    Write-Log "Removing auto-scale profile '$profileName'..."
                    Remove-NmeAutoScaleProfileId -ProfileId $matchingProfile.Id -ErrorAction Stop | Out-Null
                    Write-Log "Auto-scale profile '$profileName' removed."
                    $asProfilesRemoved++
                } catch {
                    Write-Log "Failed to remove auto-scale profile '$profileName': $($_.Exception.Message)" 'WARN'
                    $errors++
                }
            }
        }
    }
}

#endregion

#region 5. Remove app management policies created by demo users

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

#region 6. Remove workspace

$Workspace = Get-NmeWorkspace -ErrorAction SilentlyContinue | Where-Object { $_.id.name -eq $NewWorkspaceName }
if ($null -ne $Workspace) {
    try {
        Write-Log "Removing workspace $NewWorkspaceName..."
        Remove-AzWvdWorkspace -ResourceGroupName $Workspace.id.resourceGroup -Name $Workspace.id.name -SubscriptionId $Workspace.id.subscriptionId -ErrorAction Stop
        Write-Log "Workspace $NewWorkspaceName removed."
        $workspaceRemoved = $true
    } catch {
        Write-Log "Failed to remove workspace $NewWorkspaceName`: $($_.Exception.Message)" 'WARN'
        $errors++
    }
} else {
    Write-Log "Workspace $NewWorkspaceName not found."
}

#endregion

#region 7. Remove users from Entra ID

if ($Users) {
    Write-Log "Found $($Users.Count) user(s) with CompanyName '$EnvironmentName'."
    foreach ($user in $Users) {
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

#region 8. Remove resources via direct SQL (no API removal function)

# Map of JobType to the LAW query that extracts the resource name and the SQL cleanup logic
$sqlCleanupTypes = @(
    @{ JobType = 'CreateActiveDirectoryConfig';            NameField = 'FriendlyName'; ParseQuery = @"
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
    @{ JobType = 'CreateRdpPropertiesConfig';              NameField = 'Name'; ParseQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where Props.Username in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateRdpPropertiesConfig"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 5
| extend Payload = parse_json(tostring(TaskResultArray.payload))
| extend ConfigJson = parse_json(tostring(Payload.message))
| extend ResourceName = tostring(ConfigJson.name)
| where isnotempty(ResourceName)
| distinct ResourceName
"@ }
    @{ JobType = 'CreateHostPoolScriptedActionsProfile';   NameField = 'Name'; ParseQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where Props.Username in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateHostPoolScriptedActionsProfile"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 5
| extend Payload = parse_json(tostring(TaskResultArray.payload))
| extend ConfigJson = parse_json(tostring(Payload.message))
| extend ResourceName = tostring(ConfigJson.name)
| where isnotempty(ResourceName)
| distinct ResourceName
"@ }
    @{ JobType = 'CreateHostPoolCapacityExtenderProfile';  NameField = 'Name'; ParseQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where Props.Username in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateHostPoolCapacityExtenderProfile"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 5
| extend Payload = parse_json(tostring(TaskResultArray.payload))
| extend ConfigJson = parse_json(tostring(Payload.message))
| extend ResourceName = tostring(ConfigJson.name)
| where isnotempty(ResourceName)
| distinct ResourceName
"@ }
    @{ JobType = 'CreateOrUpdateDeploymentModel';          NameField = 'Name'; ParseQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where Props.Username in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateOrUpdateDeploymentModel"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 5
| extend Payload = parse_json(tostring(TaskResultArray.payload))
| extend ConfigJson = parse_json(tostring(Payload.message))
| extend ResourceName = tostring(ConfigJson.name)
| where isnotempty(ResourceName)
| distinct ResourceName
"@ }
    @{ JobType = 'CreateShellApp';                         NameField = 'Name'; ParseQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where Props.Username in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateShellApp"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 5
| extend Payload = parse_json(tostring(TaskResultArray.payload))
| extend ConfigJson = parse_json(tostring(Payload.message))
| extend ResourceName = tostring(ConfigJson.name)
| where isnotempty(ResourceName)
| distinct ResourceName
"@ }
    @{ JobType = 'CreateCustomView';                       NameField = 'Name'; ParseQuery = @"
AppTraces
| extend Props = parse_json(Properties)
| where Props.Username in ($upnFilter)
| where Props.TaskStatus == "Success"
| where Props.JobType == "CreateCustomView"
| extend TaskResultRaw = tostring(Props.TaskResult)
| extend TaskResultArray = parse_json(TaskResultRaw)
| mv-expand TaskResultArray
| where TaskResultArray.type == 5
| extend Payload = parse_json(tostring(TaskResultArray.payload))
| extend ConfigJson = parse_json(tostring(Payload.message))
| extend ResourceName = tostring(ConfigJson.name)
| where isnotempty(ResourceName)
| distinct ResourceName
"@ }
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

    $lawResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $LawWorkspaceId -Query $cleanupType.ParseQuery -ErrorAction SilentlyContinue
    if (-not $lawResult.Results) {
        Write-Log "No $jobType resources found in LAW."
        continue
    }

    $mapEntry = $sqlCleanupMap[$jobType]

    foreach ($row in $lawResult.Results) {
        $resourceName = $row.ResourceName
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

#region Summary

# Close SQL connection
if ($SqlConnection -and $SqlConnection.State -eq 'Open') {
    $SqlConnection.Close()
    Write-Log "SQL connection closed."
}

Write-Log ""
Write-Log "=== CLEANUP COMPLETED ==="
Write-Log "Environment:          $EnvironmentName"
Write-Log "Host pools removed:   $hostPoolsRemoved"
Write-Log "FSLogix profiles:     $fslProfilesRemoved"
Write-Log "Auto-scale profiles:  $asProfilesRemoved"
Write-Log "App policies:         $appPoliciesRemoved"
Write-Log "DB resources removed: $dbResourcesRemoved"
Write-Log "Workspace removed:    $workspaceRemoved"
Write-Log "Users removed:        $usersRemoved"
Write-Log "Errors:               $errors"

#endregion
