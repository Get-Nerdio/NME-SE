<#
.SYNOPSIS
  Creates a Nerdio demo environment with Entra ID users and an NME workspace.

.DESCRIPTION
  This runbook creates a simplified Nerdio demo environment:
  1. Creates Entra ID users with a default password
  2. Creates an NME workspace in the specified resource group
  3. Assigns users to the workspace with the WVD Admin role

  Intended for quick demo/POC setups. A corresponding Cleanup-NerdioDemoEnvironment.ps1
  will be created to remove the resources created here.

.PARAMETER DemoAbbreviation
  Short abbreviation (2-4 alphanumeric characters) used to name resources and users.

.PARAMETER UserCount
  Number of demo users to create.

.PARAMETER UserDefaultPassword
  Default password for created users.

.PARAMETER ResourceGroupName
  Name of an existing NME-linked resource group where the workspace will be created.

.PARAMETER AzureRegion
  Azure region for the workspace.

.PARAMETER DestroyOnUTC
  UTC datetime when the demo environment should be cleaned up.

.PARAMETER NmeVariablePrefix
  Prefix for NME API credentials in Automation Account variables.

.EXAMPLE
  .\New-NerdioDemoEnvironment.ps1 -DemoAbbreviation 'D01' -UserCount 5 -ResourceGroupName 'demo-rg'
  .\New-NerdioDemoEnvironment.ps1 -DemoAbbreviation 'POC1' -UserCount 3 -ResourceGroupName 'demo-rg' -NmeVariablePrefix 'Prod'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-zA-Z0-9]{2,4}$')][string]$DemoAbbreviation,
    [Parameter(Mandatory=$true)][int]$UserCount,
    [string]$UserDefaultPassword = 'Nerdio123!',
    [Parameter(Mandatory=$true)][string]$ResourceGroupName,
    [string]$AzureRegion = 'centralus',
    [Parameter(Mandatory=$true)][datetime]$DestroyOnUTC,
    [string]$NmeVariablePrefix
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

#region Variables

# NME API credentials from automation account variables
$NmeTenantId     = Get-AutomationVariable -Name "${NmeVariablePrefix}TenantId"
$NmeClientId     = Get-AutomationVariable -Name "${NmeVariablePrefix}ClientId"
$NmeClientSecret = Get-AutomationVariable -Name "${NmeVariablePrefix}ClientSecret"
$NmeScope        = Get-AutomationVariable -Name "${NmeVariablePrefix}Scope"
$NmeUri          = Get-AutomationVariable -Name "${NmeVariablePrefix}Uri"
$NmeAppObjectId  = Get-AutomationVariable -Name "${NmeVariablePrefix}AppObjectId"
$SubscriptionId  = Get-AutomationVariable -Name "${NmeVariablePrefix}SubscriptionId"
$TenantDomain    = Get-AutomationVariable -Name "${NmeVariablePrefix}TenantDomain"
$automationAccountName = 'nerdio-management-aa'
$AutomationRg          = 'nerdio-management-rg'

# Naming conventions
$Year = (Get-Date).Year.ToString().Substring(2, 2)
$EnvironmentName = "Demo-$DemoAbbreviation$Year"
$NewWorkspaceName = "$EnvironmentName-workspace"
$BaseUserName = "$DemoAbbreviation-User"

Write-Log "Environment name: $EnvironmentName"

#endregion

#region Authentication

# Connect to Azure using automation account managed identity
Disable-AzContextAutosave -Scope Process | Out-Null
Connect-AzAccount -Identity -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
Write-Log "Connected to Azure subscription $SubscriptionId."

# Connect to Microsoft Graph API using managed identity
Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop | Out-Null
Write-Log "Connected to Microsoft Graph."

# Get NME app registration details
$Application = Get-MgApplicationById -Ids $NmeAppObjectId -ErrorAction Stop

# Connect to NME API
Import-Module NerdioManagerPowerShell -Force
Connect-Nme -ClientId $NmeClientId -ClientSecret $NmeClientSecret -TenantId $NmeTenantId -ApiScope $NmeScope -NmeUri $NmeUri | Out-Null
Write-Log "Connected to NME API at $NmeUri."

#endregion

#region 1. Create workspace

$Workspace = Get-NmeWorkspace -ErrorAction SilentlyContinue | Where-Object { $_.id.name -eq $NewWorkspaceName }
if ($null -eq $Workspace) {
    Write-Log "Creating workspace $NewWorkspaceName..."
    $WorkspaceRequest = New-NmeCreateWorkspaceRequest `
        -id (New-NmeWvdObjectId -subscriptionId $SubscriptionId -resourceGroup $ResourceGroupName -name $NewWorkspaceName) `
        -location $AzureRegion `
        -friendlyName "Demo Workspace" `
        -description "Workspace for demo $EnvironmentName"
    $WorkspaceResult = New-NmeWorkspace -NmeCreateWorkspaceRequest $WorkspaceRequest

    # Wait for workspace creation job to complete
    $job = Get-NmeJob -jobid $WorkspaceResult.job.Id
    while ($job.status -eq 'InProgress') {
        Write-Log "Waiting for workspace creation to complete..."
        Start-Sleep -Seconds 10
        $job = Get-NmeJob -jobid $WorkspaceResult.job.Id
    }
    if ($job.status -eq 'Failed') {
        Write-Log "Workspace creation failed: $($job.error.message)" 'ERROR'
        exit
    }

    Write-Log "Workspace $NewWorkspaceName created successfully."
    $Workspace = Get-NmeWorkspace -ErrorAction Stop | Where-Object { $_.id.name -eq $NewWorkspaceName }
} else {
    Write-Log "Workspace $NewWorkspaceName already exists."
}

#endregion

#region 2. Prepare role assignment objects

$WorkspaceScopeUpdateRestModel = New-NmeWorkspaceScopeUpdateRestModel `
    -workspaceId "/subscriptions/$($Workspace.id.subscriptionid)/resourceGroups/$($Workspace.id.resourceGroup)/providers/Microsoft.DesktopVirtualization/workspaces/$($Workspace.id.name)"
$RbacAssignmentUpdateRestModel = New-NmeRbacAssignmentUpdateRestModel -avdWorkspaces $WorkspaceScopeUpdateRestModel

# Get WVD Admin role ID from the NME app registration
$AdminRoleName = 'WVD Admin'
$AdminRoleId = ($Application.AdditionalProperties.appRoles | Where-Object { $_.displayName -eq $AdminRoleName }).id

# Get service principal for the NME app
$ServicePrincipal = Get-MgServicePrincipal -Filter "Id eq '$NmeAppObjectId'" -ErrorAction Stop

#endregion

#region 3. Create users and assign to workspace

Write-Log "Creating $UserCount user(s) with base name '$BaseUserName'..."
$UserUpns = @()

for ($i = 1; $i -le $UserCount; $i++) {
    $UserName = "$BaseUserName$i"
    $UserUpn = "$UserName@$TenantDomain"

    # Create user in Entra ID
    Write-Log "Creating user $UserUpn..."
    $passwordProfile = @{ ForceChangePasswordNextSignIn = $false; Password = $UserDefaultPassword }
    $User = New-MgUser `
        -DisplayName $UserName `
        -MailNickname $UserName `
        -PasswordProfile $passwordProfile `
        -UserPrincipalName $UserUpn `
        -CompanyName $EnvironmentName `
        -AccountEnabled `
        -ErrorAction Stop

    # Assign WVD Admin role on the NME app registration
    New-MgUserAppRoleAssignment `
        -UserId $User.Id `
        -AppRoleId $AdminRoleId `
        -ResourceId $ServicePrincipal.Id `
        -PrincipalId $User.Id `
        -PrincipalType "User" `
        -ErrorAction Stop | Out-Null

    $UserUpns += $UserUpn

    # Assign user to workspace with retry (Entra ID replication delay)
    $retryCount = 0
    $maxRetries = 12
    $retryInterval = 5

    while ($retryCount -lt $maxRetries) {
        try {
            Set-NmeRbacRolesAssignment -objectId $User.Id -NmeRbacAssignmentUpdateRestModel $RbacAssignmentUpdateRestModel | Out-Null
            Write-Log "Assigned user $UserName to workspace $NewWorkspaceName."
            break
        } catch {
            $retryCount++
            if ($retryCount -ge $maxRetries) {
                Write-Log "Failed to assign user $UserName to workspace after $maxRetries retries: $($_.Exception.Message)" 'WARN'
            }
            Start-Sleep -Seconds $retryInterval
        }
    }
}

#endregion

#region 4. Schedule cleanup runbook

Write-Log "Scheduling cleanup runbook..."
$ScheduleName = "$EnvironmentName-destroy-schedule"
$RunbookName = 'Cleanup-NerdioDemoEnvironment'

# Remove existing schedule if it exists
$Schedule = Get-AzAutomationSchedule -Name $ScheduleName -ResourceGroupName $AutomationRg -AutomationAccountName $automationAccountName -ErrorAction SilentlyContinue
if ($null -ne $Schedule) {
    Write-Log "Removing existing schedule $ScheduleName..."
    Remove-AzAutomationSchedule -Name $ScheduleName -ResourceGroupName $AutomationRg -AutomationAccountName $automationAccountName -Force -ErrorAction Stop
}

$Schedule = New-AzAutomationSchedule -Name $ScheduleName -StartTime $DestroyOnUTC -OneTime -ResourceGroupName $AutomationRg -AutomationAccountName $automationAccountName -ErrorAction Stop
$RunbookParams = @{
    DemoAbbreviation = $DemoAbbreviation
    NmeVariablePrefix = $NmeVariablePrefix
}
Register-AzAutomationScheduledRunbook -ResourceGroupName $AutomationRg -AutomationAccountName $automationAccountName -RunbookName $RunbookName -ScheduleName $ScheduleName -Parameters $RunbookParams -ErrorAction Stop | Out-Null
Write-Log "Cleanup scheduled for $DestroyOnUTC (UTC)."

#endregion

#region Summary

Write-Log ""
Write-Log "=== DEMO ENVIRONMENT CREATED ==="
Write-Log "Environment:  $EnvironmentName"
Write-Log "Workspace:    $NewWorkspaceName"
Write-Log "Resource group: $ResourceGroupName"
Write-Log "Users created: $UserCount"
Write-Log ""
Write-Log "Users:"
foreach ($upn in $UserUpns) {
    Write-Log "  $upn"
}
Write-Log ""
Write-Log "Users can login at $NmeUri using the default password: $UserDefaultPassword"
Write-Log "They will be prompted to register for MFA."
Write-Log ""
Write-Log "WARNING: This demo environment will be cleaned up on $DestroyOnUTC (UTC)."

#endregion
