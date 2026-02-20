<#
.SYNOPSIS
  Cleans up a Nerdio demo environment by removing users and the workspace.

.DESCRIPTION
  This runbook removes resources created by New-NerdioDemoEnvironment.ps1:
  1. Removes the NME workspace
  2. Removes the Entra ID users (identified by CompanyName matching the environment name)

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
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-zA-Z0-9]{2,4}$')][string]$CustomerAbbreviation,
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

#endregion

#region Variables

# NME API credentials from automation account variables
$NmeTenantId     = Get-AutomationVariable -Name "${VariablePrefix}TenantId"
$NmeClientId     = Get-AutomationVariable -Name "${VariablePrefix}ClientId"
$NmeClientSecret = Get-AutomationVariable -Name "${VariablePrefix}ClientSecret"
$NmeScope        = Get-AutomationVariable -Name "${VariablePrefix}Scope"
$NmeUri          = Get-AutomationVariable -Name "${VariablePrefix}Uri"
$SubscriptionId  = Get-AutomationVariable -Name "${VariablePrefix}SubscriptionId"

# Naming conventions (must match New-NerdioDemoEnvironment.ps1)
$EnvironmentName = "$CustomerAbbreviation-Demo"
$NewWorkspaceName = "$EnvironmentName-workspace"

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

#endregion

# Counters for summary
$usersRemoved = 0
$workspaceRemoved = $false
$errors = 0

#region 1. Remove workspace

$Workspace = Get-NmeWorkspace -ErrorAction SilentlyContinue | Where-Object { $_.id.name -eq $NewWorkspaceName }
if ($null -ne $Workspace) {
    try {
        Write-Log "Removing workspace $NewWorkspaceName..."
        $Result = Remove-NmeWorkspace -SubscriptionId $Workspace.id.subscriptionId -ResourceGroup $Workspace.id.resourceGroup -WorkspaceName $Workspace.id.name -ErrorAction Stop

        # Wait for removal job to complete
        $job = Get-NmeJob -jobid $Result.job.Id
        while ($job.status -eq 'InProgress') {
            Write-Log "Waiting for workspace removal to complete..."
            Start-Sleep -Seconds 10
            $job = Get-NmeJob -jobid $Result.job.Id
        }
        if ($job.status -eq 'Failed') {
            Write-Log "Workspace removal failed: $($job.error.message)" 'WARN'
            $errors++
        } else {
            Write-Log "Workspace $NewWorkspaceName removed."
            $workspaceRemoved = $true
        }
    } catch {
        Write-Log "Failed to remove workspace $NewWorkspaceName`: $($_.Exception.Message)" 'WARN'
        $errors++
    }
} else {
    Write-Log "Workspace $NewWorkspaceName not found."
}

#endregion

#region 2. Remove users from Entra ID

$Users = Get-MgUser -Property DisplayName,UserPrincipalName,CompanyName,Id -All | Where-Object { $_.CompanyName -eq $EnvironmentName }

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

#region Summary

Write-Log ""
Write-Log "=== CLEANUP COMPLETED ==="
Write-Log "Environment:      $EnvironmentName"
Write-Log "Workspace removed: $workspaceRemoved"
Write-Log "Users removed:    $usersRemoved"
Write-Log "Errors:           $errors"

#endregion
