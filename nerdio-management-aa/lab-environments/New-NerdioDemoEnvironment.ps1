<#
.SYNOPSIS
  Creates a Nerdio demo environment with Entra ID users and an NME workspace.

.DESCRIPTION
  This runbook creates a simplified Nerdio demo environment:
  1. Creates an NME workspace (skips if it already exists)
  2. Creates Entra ID users with a default password (skips existing users)
  3. Assigns users to the workspace with the WVD Admin role (skips if already assigned)
  4. Schedules the Cleanup-NerdioDemoEnvironment runbook
  5. Sends a welcome email with login credentials via SendGrid (if DestEmailAddress is provided)

  This script is idempotent. Running it again with the same parameters will
  skip already-completed steps and finish any remaining work. If UserCount is
  increased, only the additional users are created.

.PARAMETER CustomerAbbreviation
  Short customer abbreviation (2-4 alphanumeric characters) used to name resources and users.

.PARAMETER UserCount
  Number of demo users to create.

.PARAMETER UserDefaultPassword
  Default password for created users.

.PARAMETER AzureRegion
  Azure region for the workspace.

.PARAMETER DestroyOnUTC
  UTC datetime when the demo environment should be cleaned up.

.PARAMETER UpdateExistingDemoEnv
  If specified, allows updating an existing demo environment instead of
  blocking when one already exists. Existing resources are skipped and
  only missing items (users, role assignments, etc.) are created.

.PARAMETER VariablePrefix
  Prefix for automation account variables. Defaults to 'CustomerDemo'.

.PARAMETER DestEmailAddress
  Email address to send the welcome email with login credentials. If not specified, no email is sent.

.EXAMPLE
  .\New-NerdioDemoEnvironment.ps1 -CustomerAbbreviation 'ACME' -UserCount 5
  .\New-NerdioDemoEnvironment.ps1 -CustomerAbbreviation 'CNTO' -UserCount 3 -VariablePrefix 'Prod'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-zA-Z0-9]{2,8}$')][string]$CustomerAbbreviation,
    [Parameter(Mandatory=$true)][int]$UserCount,
    [string]$UserDefaultPassword = 'Nerdio123!',
    [string]$AzureRegion = 'centralus',
    [Parameter(Mandatory=$true)][datetime]$DestroyOnUTC,
    [bool]$UpdateExistingDemoEnv = $false,
    [string]$VariablePrefix = 'CustomerDemo',
    [string]$DestEmailAddress
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

#endregion

#region Variables

# NME API credentials from automation account variables
$NmeTenantId     = Get-AutomationVariable -Name "${VariablePrefix}TenantId"
$NmeClientId     = Get-AutomationVariable -Name "${VariablePrefix}ClientId"
$NmeClientSecret = Get-AutomationVariable -Name "${VariablePrefix}ClientSecret"
$NmeScope        = Get-AutomationVariable -Name "${VariablePrefix}Scope"
$NmeUri          = Get-AutomationVariable -Name "${VariablePrefix}Uri"
$NmeAppObjectId  = Get-AutomationVariable -Name "${VariablePrefix}AppObjectId"
$SubscriptionId  = Get-AutomationVariable -Name "${VariablePrefix}SubscriptionId"
$TenantDomain    = Get-AutomationVariable -Name "${VariablePrefix}TenantDomain"
$ResourceGroupName     = Get-AutomationVariable -Name "${VariablePrefix}DefaultRG"
$automationAccountName = 'nerdio-management-aa'
$AutomationRg          = 'nerdio-management-rg'

# Naming conventions
$EnvironmentName = "$CustomerAbbreviation-Demo"
$NewWorkspaceName = "$EnvironmentName-workspace"
$BaseUserName = "$CustomerAbbreviation-User"

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

#region Validate environment does not already exist

$existingUsers = Get-MgUser -Property DisplayName,CompanyName -All | Where-Object { $_.CompanyName -eq $EnvironmentName }
$existingWorkspace = Get-NmeWorkspace -ErrorAction SilentlyContinue | Where-Object { $_.id.name -eq $NewWorkspaceName }

if (($existingUsers -or $existingWorkspace) -and -not $UpdateExistingDemoEnv) {
    $conflicts = @()
    if ($existingUsers) { $conflicts += "$($existingUsers.Count) user(s) with CompanyName '$EnvironmentName'" }
    if ($existingWorkspace) { $conflicts += "workspace '$NewWorkspaceName'" }
    Write-Log "Customer abbreviation '$CustomerAbbreviation' is already in use: $($conflicts -join '; '). Use -UpdateExistingDemoEnv to update the existing environment." 'ERROR'
    exit 1
}

if ($UpdateExistingDemoEnv) {
    Write-Log "UpdateExistingDemoEnv specified. Will skip existing resources and complete any remaining work."
}

#endregion

#region 1. Create workspace

$Workspace = Get-NmeWorkspace -ErrorAction SilentlyContinue | Where-Object { $_.id.name -eq $NewWorkspaceName }
if ($null -eq $Workspace) {
    Write-Log "Creating workspace $NewWorkspaceName..."
    $WorkspaceRequest = New-NmeCreateWorkspaceRequest `
        -id (New-NmeWvdObjectId -subscriptionId $SubscriptionId -resourceGroup $ResourceGroupName -name $NewWorkspaceName) `
        -location $AzureRegion `
        -friendlyName "$NewWorkspaceName" `
        -description "Workspace for demo $EnvironmentName" `
        -tags @{ DestroyAfter = $DestroyOnUTC.ToString('o'); DoNotDestroy = 'true' }
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

    # Update DestroyAfter tag if re-running with a potentially different date
    $workspaceResourceId = "/subscriptions/$($Workspace.id.subscriptionid)/resourceGroups/$($Workspace.id.resourceGroup)/providers/Microsoft.DesktopVirtualization/workspaces/$($Workspace.id.name)"
    Update-AzTag -Tag @{ DestroyAfter = $DestroyOnUTC.ToString('o') } -Operation Merge -ResourceId $workspaceResourceId -ErrorAction Stop | Out-Null
    Write-Log "Updated DestroyAfter tag on workspace to $($DestroyOnUTC.ToString('o'))."
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

Write-Log "Ensuring $UserCount user(s) with base name '$BaseUserName'..."
$UserUpns = @()
$usersCreated = 0
$usersExisting = 0

for ($i = 1; $i -le $UserCount; $i++) {
    $UserName = "$BaseUserName$i"
    $UserUpn = "$UserName@$TenantDomain"

    # Check if user already exists
    $User = Get-MgUser -Filter "userPrincipalName eq '$UserUpn'" -ErrorAction SilentlyContinue

    if ($User) {
        Write-Log "User $UserUpn already exists, skipping creation."
        $usersExisting++
    } else {
        Write-Log "Creating user $UserUpn..."
        $passwordProfile = @{ ForceChangePasswordNextSignIn = $true; ForceChangePasswordNextSignInWithMfa = $true; Password = $UserDefaultPassword }
        $User = New-MgUser `
            -DisplayName $UserName `
            -MailNickname $UserName `
            -PasswordProfile $passwordProfile `
            -UserPrincipalName $UserUpn `
            -CompanyName $EnvironmentName `
            -AccountEnabled `
            -ErrorAction Stop
        $usersCreated++
    }

    $UserUpns += $UserUpn

    # Ensure WVD Admin role assignment (skip if already assigned)
    $existingAppRole = Get-MgUserAppRoleAssignment -UserId $User.Id -ErrorAction SilentlyContinue |
        Where-Object { $_.AppRoleId -eq $AdminRoleId -and $_.ResourceId -eq $ServicePrincipal.Id }

    if (-not $existingAppRole) {
        New-MgUserAppRoleAssignment `
            -UserId $User.Id `
            -AppRoleId $AdminRoleId `
            -ResourceId $ServicePrincipal.Id `
            -PrincipalId $User.Id `
            -PrincipalType "User" `
            -ErrorAction Stop | Out-Null
        Write-Log "Assigned WVD Admin role to $UserName."
    } else {
        Write-Log "User $UserName already has WVD Admin role."
    }

    # Ensure workspace assignment with retry (Entra ID replication delay)
    $retryCount = 0
    $maxRetries = 12
    $retryInterval = 5

    while ($retryCount -lt $maxRetries) {
        try {
            Set-NmeRbacRolesAssignment -objectId $User.Id -NmeRbacAssignmentUpdateRestModel $RbacAssignmentUpdateRestModel | Out-Null
            Write-Log "Ensured user $UserName is assigned to workspace $NewWorkspaceName."
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

Write-Log "Users: $usersCreated created, $usersExisting already existed."

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
    CustomerAbbreviation = $CustomerAbbreviation
    VariablePrefix = $VariablePrefix
}
Register-AzAutomationScheduledRunbook -ResourceGroupName $AutomationRg -AutomationAccountName $automationAccountName -RunbookName $RunbookName -ScheduleName $ScheduleName -Parameters $RunbookParams -ErrorAction Stop | Out-Null
Write-Log "Cleanup scheduled for $DestroyOnUTC (UTC)."

#endregion

#region Summary

Write-Log ""
Write-Log "=== DEMO ENVIRONMENT READY ==="
Write-Log "Environment:    $EnvironmentName"
Write-Log "Workspace:      $NewWorkspaceName"
Write-Log "Resource group: $ResourceGroupName"
Write-Log "Users created:  $usersCreated"
Write-Log "Users existing: $usersExisting"
Write-Log "Total users:    $UserCount"
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

#region 5. Send welcome email via SendGrid

if ($DestEmailAddress) {
    Write-Log "Sending welcome email to $DestEmailAddress..."

    $SendGridApiKey = Get-AutomationVariable -Name 'SendGridKey'
    $fromEmailAddress = 'team@nerdio.net'

    # Build user credentials table rows
    $userRows = ""
    foreach ($upn in $UserUpns) {
        $userRows += "              <tr><td style='padding: 6px 12px; border: 1px solid #e0e0e0;'>$upn</td><td style='padding: 6px 12px; border: 1px solid #e0e0e0;'>$UserDefaultPassword</td></tr>`n"
    }

    $content = @"
<html>
<body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
    <p>Greetings,</p>

    <p>Welcome to Nerdio Manager for Enterprise! Your sandbox demo environment is ready and waiting for you.</p>

    <p>You'll be prompted to set a new password on your first sign-in.</p>

    <h3>Your Login Credentials</h3>
    <table style="border-collapse: collapse; margin-bottom: 16px;">
        <tr style="background-color: #f5f5f5;">
            <th style="padding: 8px 12px; border: 1px solid #e0e0e0; text-align: left;">Username</th>
            <th style="padding: 8px 12px; border: 1px solid #e0e0e0; text-align: left;">Password</th>
        </tr>
$userRows
    </table>

    <p><strong>Login URL:</strong> <a href="$NmeUri">$NmeUri</a></p>

    <p><strong>Environment Expiration:</strong> This demo environment will be automatically destroyed on <strong>$($DestroyOnUTC.ToString('dddd, MMMM dd, yyyy a\t h:mm tt')) UTC</strong>.</p>

    <h3>Recommended First Steps</h3>
    <ol>
        <li><strong>Create your first desktop image</strong>
            <ul>
                <li><a href="https://nmehelp.getnerdio.com/hc/en-us/articles/26124301690637-Desktop-Images">Desktop Images overview</a></li>
                <li><a href="https://nmehelp.getnerdio.com/hc/en-us/articles/26124381963149-Desktop-images-set-as-image">Set as image</a></li>
            </ul>
        </li>
        <li><strong>Create a host pool</strong>
            <ul>
                <li><a href="https://nmehelp.getnerdio.com/hc/en-us/articles/26124329605517-Overview-of-host-pools">Host pools overview</a></li>
                <li><a href="https://nmehelp.getnerdio.com/hc/en-us/articles/26124319282061-Resize-re-image-a-host-pool">Resize and re-image a host pool</a></li>
            </ul>
        </li>
        <li><strong>Enable Auto-scale</strong>
            <ul>
                <li><a href="https://nmehelp.getnerdio.com/hc/en-us/articles/26124304193037-Enable-dynamic-host-pool-Auto-scaling">Dynamic host pool auto-scaling</a></li>
            </ul>
        </li>
    </ol>

    <p>If you have any questions, don't hesitate to reach out. We're excited to have you on board!</p>

    <p>Best regards,<br>The Nerdio Team</p>
</body>
</html>
"@

    $subject = "Welcome to Nerdio Manager - Your Demo Environment is Ready!"

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $SendGridApiKey")
    $headers.Add("Content-Type", "application/json")

    $body = @{
        personalizations = @(
            @{
                to = @(
                    @{
                        email = $DestEmailAddress
                    }
                )
            }
        )
        from = @{
            email = $fromEmailAddress
        }
        subject = $subject
        content = @(
            @{
                type  = "text/html"
                value = $content
            }
        )
    }

    $bodyJson = $body | ConvertTo-Json -Depth 4

    try {
        Invoke-RestMethod -Uri https://api.sendgrid.com/v3/mail/send -Method Post -Headers $headers -Body $bodyJson
        Write-Log "Welcome email sent to $DestEmailAddress."
    } catch {
        Write-Log "Failed to send welcome email: $($_.Exception.Message)" 'WARN'
    }
} else {
    Write-Log "No DestEmailAddress specified, skipping welcome email."
}

#endregion
