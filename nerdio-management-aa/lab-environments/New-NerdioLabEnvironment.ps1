# Creating a new nerdio environment

<#
    This script creates a new Nerdio lab environment in Azure, including:
    - Resource group for NME resources
    - Virtual network and subnet (optional)
    - Azure Files share for user profiles
    - FSLogix profile
    - Workspace in NME
    - Users in Entra ID with the specified default password
    - Schedule for cleanup runbook in the automation account
    - Checks for sufficient compute quota in the target region
    - Links the resource group and virtual network to NME
    
#>

# variables
param (
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-zA-Z0-9]{2,4}$')][string]$LabAbbreviation,
    [Parameter(Mandatory=$true)][string]$UserDefaultPassword = 'Nerdio123!',
    [Parameter(Mandatory=$true)][int]$UserCount,
    [string]$AzureRegion = 'centralus',
    [string]$VmFamily = 'Dsv5',
    [Parameter(Mandatory=$false)][bool]$CreateVnet = $false,
    [Parameter(Mandatory=$true)][datetime]$DestroyOnUTC
    
)

$erroractionpreference = 'stop'

# Ensure the following variables are set in the automation account:
$NmeTenantId = Get-AutomationVariable -Name 'NmeTenantId'
$NmeClientId = Get-AutomationVariable -Name 'NmeClientId'
$NmeClientSecret = Get-AutomationVariable -Name 'NmeClientSecret'
$NmeScope = Get-AutomationVariable -Name 'NmeScope'
$NmeUri = Get-AutomationVariable -Name 'NmeUri'
$NmeAppObjectId = Get-AutomationVariable -Name 'NmeAppObjectId'
$subscriptionId = Get-AutomationVariable -Name 'LabSubscriptionId'
$FSLogixVersion = Get-AutomationVariable -Name 'LatestFSLogixVersion'
$TenantDomain = Get-AutomationVariable -Name 'CustomTenantDomain'
$automationAccountName = 'nerdio-management-aa'
$AutomationRg = 'nerdio-management-rg'

# variables
$image = 'microsoftwindowsdesktop/windows-11/win11-24h2-avd/latest'
$VnetAddressRange = '10.0.0.0/16'
$SubnetAddressRange = '10.0.0.0/24'

$PlaceholderFslProfileName = 'Placeholder-DoNotUse'


# Environment name is 'Lab-' plus the lab abbreviation, with spaces removed, the last two digits of the year. 
# For example, 'Lab-2023' becomes 'Lab-23'
$Year = (Get-Date).Year.ToString().Substring(2, 2)
$EnvironmentName = 'Lab-' + $LabAbbreviation + $Year

write-output "Environment name is $EnvironmentName"

# NME resources rg name is $EnvironmentName with spaces replaced with dashes, appending -rg
$NmeResourcesRgName = $EnvironmentName  + '-rg'

# VNet name is $EnvironmentName with spaces replaced with dashes, appending -vnet
$VnetName = $EnvironmentName + '-vnet'
$VnetRG = 'lab-vnet-rg'

# Subnet name is $EnvironmentName with spaces replaced with dashes, appending -subnet
$SubNetName = $EnvironmentName + '-subnet'

# storage account name is $EnvironmentName, all lowercase, with spaces and special characters removed, and dashes removed, and length limited to 24 characters, with 'sa' appended
$StorageAccountName = ($EnvironmentName -replace '-', '').ToLower() + 'sa'
if ($StorageAccountName.Length -gt 24) {
    $StorageAccountName = $StorageAccountName.Substring(0, 24)
}

# base user name is $EnvironmentName appending -user
$BaseUserName = $LabAbbreviation + '-User'

$FslProfileName = "fslogix-profile-$($LabAbbreviation)-$($Year)"


# connect to azure using automation account managed identity
Connect-AzAccount -Identity -SubscriptionId $SubscriptionId -ErrorAction Stop | out-null
write-output "Connected to Azure subscription $SubscriptionId using automation account managed identity."
$ctx = Get-AzContext -ErrorAction Stop
$MicrosoftTenantName = $ctx.tenant.domains | Where-Object { $_ -match 'onmicrosoft' }
# authenticate to Microsoft Graph API using the automation account managed identity
Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop | Out-Null
write-output "Connected to Microsoft Graph API using automation account managed identity."
$Application = Get-MgApplicationById -Ids $NmeAppObjectId -ErrorAction Stop


# create resource group for NME resources
$NmeResourcesRg = Get-AzResourceGroup -Name $NmeResourcesRgName -ErrorAction SilentlyContinue
if ($NmeResourcesRg -eq $null) {
    Write-Output "Creating resource group $NmeResourcesRgName..."
    $NmeResourcesRg = New-AzResourceGroup -Name $NmeResourcesRgName -Location $AzureRegion -Tag @{Lab = $EnvironmentName} -ErrorAction Stop
} else {
    Write-Output "Resource group $NmeResourcesRgName already exists."
}


# create vnet and subnet for NME resources if CreateVnet is true
if ($CreateVnet) {
    $Vnet = Get-AzVirtualNetwork -Name $VnetName -ResourceGroupName $VnetRG -ErrorAction SilentlyContinue
    if ($Vnet -eq $null) {
        Write-Output "Creating virtual network $VnetName..."
        $Vnet = New-AzVirtualNetwork -Name $VnetName -ResourceGroupName $VnetRG -Location $AzureRegion -AddressPrefix $VnetAddressRange -Subnet @(
            @{
                Name           = $SubNetName
                AddressPrefix  = $SubnetAddressRange
            }
        ) -ErrorAction Stop
    }
    else {
        Write-Output "Virtual network $VnetName already exists."
    }
}
else {
    $VnetName = 'lab-vnet-default'
    $SubNetName = 'default'
}


import-module NerdioManagerPowerShell -Force
$nme= Connect-nme -ClientId $NmeClientId -ClientSecret $NmeClientSecret -TenantId $NmeTenantId -ApiScope $NmeScope -NmeUri $NmeUri
Write-Output "Connected to NME API."


# link resource group to NME
# give nme app owner permissions to the resource group
$ExistingRoleAssignment = Get-AzRoleAssignment -ObjectId $NmeAppObjectId -RoleDefinitionName 'Owner' -ResourceGroupName $NmeResourcesRgName -ErrorAction SilentlyContinue
if (-not $ExistingRoleAssignment) {
    New-AzRoleAssignment -ObjectId $NmeAppObjectId -RoleDefinitionName 'Owner' -ResourceGroupName $NmeResourcesRgName | out-null
} else {
    Write-Verbose "The app is already assigned the 'Owner' role on the resource group $NmeResourcesRgName."
}
$LinkRequest = New-NmeLinkResourceGroupRequest -IsDefault $true
$LinkJob = New-NmeLinkedResourceGroup -SubscriptionId $SubscriptionId -ResourceGroup $NmeResourcesRgName -NmeLinkResourceGroupRequest $LinkRequest -ErrorAction Stop 

# Link NME to the vnet
$Vnets = Get-NmeLinkedNetworks -ErrorAction SilentlyContinue
if ($Vnets.name -notcontains $VnetName) {
    Write-Output "Linking virtual network $VnetName to NME..."
    $LinkRequest = New-NmeLinkNetworkRestPayload -ResourceGroupName $VnetRG -SubscriptionId $subscriptionId -NetworkName $VnetName -SubnetName $SubNetName 
    $LinkJob = New-NmeLinkedNetworks -NmeLinkNetworkRestPayload $LinkRequest -ErrorAction Stop
} else {
    Write-Verbose "Virtual network $VnetName is already linked to NME."
}


# create an Azure Files share for user profiles
$sharename = 'userprofiles'
$storageaccount = Get-AzStorageAccount -ResourceGroupName $NmeResourcesRgName -Name $storageaccountname -ErrorAction SilentlyContinue
if ($storageaccount -eq $null) {
    Write-Output "Creating storage account $storageaccountname..."
    $storageaccount = New-AzStorageAccount -ResourceGroupName $NmeResourcesRgName -Name $storageaccountname -SkuName Standard_LRS -Location $AzureRegion -EnableAzureActiveDirectoryKerberosForFile $true
} else {
    Write-Verbose "Storage account $storageaccountname already exists."
}

# will need to manually grant admin consent in portal
$share = Get-AzStorageShare -Name $sharename -Context $storageaccount.Context -ErrorAction SilentlyContinue
if ($share -eq $null) {
    Write-Output "Creating Azure Files share $sharename..."
    $share = New-AzStorageShare -Name $sharename -Context $storageaccount.Context
} else {
    Write-Verbose "Azure Files share $sharename already exists."
}
$LinkStorageAccount = New-NmeAzureFilesLink -SubscriptionId $SubscriptionId -ResourceGroup $NmeResourcesRgName -AccountName $storageaccountname -ShareName $sharename -ErrorAction SilentlyContinue
# add tag NMW_APPLICATION_ID with value $NmeAppObjectId to the storage account
Update-AzTag -Tag @{NMW_APPLICATION_ID = $application.AdditionalProperties['appId']} -Operation Merge -ResourceId $storageaccount.id -ErrorAction SilentlyContinue | out-null



# create an nme fslogix profile

$ProfileOptions = '"DeleteLocalProfileWhenVHDShouldApply"=dword:00000001
"PreventLoginWithFailure"=dword:00000001
"PreventLoginWithTempProfile"=dword:00000001
"VolumeType"=string:"vhdx"'
$OfficeProfileOptions = '"IgnoreNonWVD"=dword:00000001'
$FSLConfig = Get-NmeFslogixProfile -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $FslProfileName }
if ($FSLConfig) {
    Write-Verbose "FSLogix profile $FslProfileName already exists."
}
else {
    try {
        write-output "Creating FSLogix profile $FslProfileName..."
        $Properties  = New-NmeProperties -ProfileContainer (New-NmeRegistry -Locations @("$($storageaccount.PrimaryEndpoints.File)$sharename") -Options $ProfileOptions) `
                        -Installer (New-NmeInstaller  -ForceUpdate $false -Version $FSLogixVersion ) `
                        -OfficeContainer (New-NmeRegistry -Locations "$($storageaccount.PrimaryEndpoints.File)$sharename" -Options $OfficeProfileOptions) `
                        -RedirectionsXml ''
        $FslConfig = New-NmeFslogixParamsRest_POST -Name $FslProfileName -IsDefault $true -Properties $Properties
        New-NmeFslogixProfile -NmeFsLogixParamsRest_POST $FslConfig | out-null
    } catch {
        # get placeholder fslogix profile
        write-output "Error creating FSLogix profile $FslProfileName. Getting installer version from placeholder fslogix profile $PlaceholderFslProfileName..."
        $PlaceholderFslProfile = Get-NmeFslogixProfile  | Where-Object { $_.Name -eq $PlaceholderFslProfileName }
        $FSLogixVersion = $PlaceholderFslProfile.properties.installer.version
        try {
            write-output "Creating FSLogix profile $FslProfileName..."
            $Properties  = New-NmeProperties -ProfileContainer (New-NmeRegistry -Locations @("$($storageaccount.PrimaryEndpoints.File)$sharename") -Options $ProfileOptions) `
                            -Installer (New-NmeInstaller  -ForceUpdate $false -Version $FSLogixVersion ) `
                            -OfficeContainer (New-NmeRegistry -Locations "$($storageaccount.PrimaryEndpoints.File)$sharename" -Options $OfficeProfileOptions) `
                            -RedirectionsXml ''
            $FslConfig = New-NmeFslogixParamsRest_POST -Name $FslProfileName -IsDefault $true -Properties $Properties
            New-NmeFslogixProfile -NmeFsLogixParamsRest_POST $FslConfig | out-null
        } catch {
            Write-Output "Error creating FSLogix profile $FslProfileName"
            Write-Output "Try updating the LatestFSLogixVersion variable in the automation account to the latest installer version."
            exit
        }
    }
}

# remove any fslogix profiles that are not the default
<#
$FSLConfig = Get-NmeFslogixProfile -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne $FslProfileName }
if ($FSLConfig) {
    foreach ($config in $FSLConfig) {
        Write-Output "Removing FSLogix profile $($config.Name)..."
        Remove-NmeFslogixProfileById -Id $config.id | out-null
    }
}
else {
    Write-Output "No FSLogix profiles to remove."
}
#>

# create workspace 
$NewWorkspaceName = $EnvironmentName + '-workspace'
$Workspace = Get-NmeWorkspace -ErrorAction SilentlyContinue | Where-Object { $_.id.name -eq $NewWorkspaceName }
if ($workspace -eq $null) {
    Write-Output "Creating workspace $NewWorkspaceName..."
    $Workspace = New-NmeWorkspace -NmeCreateWorkspaceRequest (New-NmeCreateWorkspaceRequest -id (New-NmeWvdObjectId -subscriptionId $SubscriptionId -resourceGroup $NmeResourcesRgName -name $NewWorkspaceName) -location westus -friendlyName "Lab Workspace" -description "Workspace for lab $environment" ) 
    # check nme job
    $job = Get-NmeJob -jobid $Workspace.job.Id
    while ($job.status -eq 'InProgress') {
        Write-Output "Waiting for workspace creation to complete..."
        Start-Sleep -Seconds 10
        $job = Get-NmeJob -jobid $Workspace.job.Id
    }
    if ($job.status -eq 'Failed') {
        Write-Output "Workspace creation failed: $($job.error.message)"
        exit
    }
    else {
        Write-Output "Workspace $NewWorkspaceName created successfully."
        $Workspace = Get-NmeWorkspace -ErrorAction SilentlyContinue | Where-Object { $_.id.name -eq $NewWorkspaceName }
    }
}
else {
    Write-Output "Workspace $NewWorkspaceName already exists."
}


$WorkspaceScopeUdateRestModels = New-NmeWorkspaceScopeUpdateRestModel -workspaceId "/subscriptions/$($workspace.id.subscriptionid)/resourceGroups/$($workspace.id.resourceGroup)/providers/Microsoft.DesktopVirtualization/workspaces/$($workspace.id.name)"
$RbacAssignmentUpdateRestModel = New-NmeRbacAssignmentUpdateRestModel -avdWorkspaces $WorkspaceScopeUdateRestModels

# get id of Wvd Admin role of app registration in entra id
$AdminRoleName = 'WVD Admin'
$AdminRoleId = ($Application.AdditionalProperties.appRoles | Where-Object { $_.displayName -eq $AdminRoleName }).id
# get service principal id of app registration in entra id
$ServicePrincipal = Get-MgServicePrincipal -Filter "Id eq '$NmeAppObjectId'" -ErrorAction Stop

# Use mggraph to create $UserCount users with the base user name and hyphen and a number from 1 to $UserCount and add to workspace
write-output "Creating $UserCount users with the base user name $BaseUserName and adding to workspace $NewWorkspaceName..."
$UserUpns = @()
for ($i = 1; $i -le $UserCount; $i++) {
    $UserName = $BaseUserName  + $i
    $UserUpn = $UserName + '@' + $TenantDomain
    Write-Verbose "Creating user $UserUpn..."
    $passwordProfile = @{ForceChangePasswordNextSignIn = $false; Password = $UserDefaultPassword;}
    $User = New-MgUser -DisplayName $UserName -MailNickname $UserName -PasswordProfile $passwordProfile -UserPrincipalName $UserUpn -CompanyName $EnvironmentName -AccountEnabled -ErrorAction Stop
    # add user to NME app registration in entra id with role 'WVD Admin'
    $params = @{
        "principalId" =$user.Id
        "resourceId" =$ServicePrincipal.Id
        "appRoleId" = $AdminRoleId
        "principalType" = "User"
        }
    $AppRoleAssignment = New-MgUserAppRoleAssignment -UserId $User.id -AppRoleId $AdminRoleId -ResourceId $ServicePrincipal.Id -PrincipalId $user.id -PrincipalType "User" -ErrorAction Stop
    $UserUpns += $UserUpn
    # add $userId to workspace
    Write-Verbose "Adding user $UserName to workspace $NewWorkspaceName..."
    $retryCount = 0
    $maxRetries = 12
    $retryInterval = 5

    while ($retryCount -lt $maxRetries) {
        try {
            Set-NmeRbacRolesAssignment -objectId $User.id -NmeRbacAssignmentUpdateRestModel $RbacAssignmentUpdateRestModel -Verbose | out-null
            break
        } catch {
            $retryCount++
            if ($retryCount -ge $maxRetries) {
                throw $_
            }
            Start-Sleep -Seconds $retryInterval
        }
    }
}

write-output "The following users were created with the default password:"
foreach ($user in $UserUpns) {
    write-output $user
}

write-output "Users can login at $nmeUri using the default password $UserDefaultPassword. They will be prompted to register for MFA."

# check if there is sufficient compute quota in the target region. There should be at least 300 Ds_v5 vCPUs available in the target region.
$Quota = Get-AzVMUsage -Location $AzureRegion -ErrorAction Stop | Where-Object { $_.Name.LocalizedValue -match "Standard $VmFamily" }
if ($Quota.Limit -lt 300) {
    Write-Output "Insufficient compute quota in region $AzureRegion for Standard $VmFamily. Quota limit is $($Quota.Limit) vCPUs."
    Write-Output "Please request a quota increase via internalsupport@getnerdio.com. Include the tenant name $MicrosoftTenantName and subscription id $subscriptionId."

}
else {
    Write-Output "Sufficient compute quota in region $AzureRegion for Standard $VmFamily. Quota limit is $($Quota.Limit) vCPUs."
}

Write-Output "Lab setup complete. Registering cleanup runbook..."


# create a schedule in the automation account to run the Cleanup-NmeLabEnvironment runbook on $DestroyOnUTC date, sending the rg name as the LabRgName parameter
$ScheduleName = $EnvironmentName + '-destroy-schedule'
$Schedule = Get-AzAutomationSchedule -Name $ScheduleName -ResourceGroupName $AutomationRg -AutomationAccountName $AutomationAccountName   -ErrorAction SilentlyContinue
# remove existing schedule if it exists
if ($Schedule -ne $null) {
    Write-Output "Removing existing schedule $ScheduleName..."
    Remove-AzAutomationSchedule -Name $ScheduleName -ResourceGroupName $AutomationRg -AutomationAccountName $AutomationAccountName -Force -ErrorAction Stop
}
$Schedule = New-AzAutomationSchedule -Name $ScheduleName -StartTime $DestroyOnUTC -OneTime -ResourceGroupName $AutomationRg -AutomationAccountName $AutomationAccountName -ErrorAction Stop
# link the schedule to the Cleanup-NmeLabEnvironment runbook
$RunbookName = 'Cleanup-NmeLabEnvironment'
$Runbook = Get-AzAutomationRunbook -Name $RunbookName -ResourceGroupName $AutomationRg -AutomationAccountName $AutomationAccountName -ErrorAction Stop
$Job = Register-AzAutomationScheduledRunbook -ResourceGroupName $AutomationRg -AutomationAccountName $AutomationAccountName -RunbookName $RunbookName -ScheduleName $ScheduleName -Parameters @{LabRgName = $NmeResourcesRgName} -ErrorAction Stop

Write-Output "--------------------------------"
write-output "WARNING: This lab will be removed $DestroyOnUTC. The resource group $NmeResourcesRgName and the Entra ID users will be deleted."


<#
# create a host pool
$hpname = $EnvironmentName + '-hp1'
$WorkspaceId = New-NmeWvdObjectId -subscriptionId $SubscriptionId -resourceGroup $NmeResourcesRgName -name $NewWorkspaceName 
$pooledparams = New-NmePooledParams -isDesktop $true -isSingleUser $false
$nmeCreateArmHostPoolRequest = New-NmeCreateArmHostPoolRequest -workspaceId $WorkspaceId -pooledParams $pooledparams -Tags @{Testing = 'PS Module'} 
New-NmeHostPool -subscriptionId $SubscriptionId -resourceGroup $NmeResourcesRgName -hostPoolName $hpname -NmeCreateArmHostPoolRequest $NmeCreateArmHostPoolRequest
$hp = Get-NmeHostPool -subscriptionId $SubscriptionId -resourceGroup $NmeResourcesRgName -hostPoolName $hpname     
$hp | ConvertTo-NmeDynamicHostPool 

$VMTemplate = New-NmeVmTemplateParams `
                -prefix ($LabAbbreviation + '-hp1') `
                -size "Standard_D2s_v5" `
                -image $image `
                -storageType StandardSSD_LRS `
                -resourceGroupId $NmeResourcesRg.ResourceId `
                -networkId $Vnet.id `
                -subnet $SubNetName `
                -diskSize 128 `
                -hasEphemeralOSDisk $false 

$ScaleCriteria = New-NmeHostUsageConfiguration `
                  -scaleIn (New-NmeHostUsage -hostChangeCount 1 -value 40 -averageTimeRangeInMinutes 15) `
                  -scaleOut (New-NmeHostUsage -hostChangeCount 1 -value 80 -averageTimeRangeInMinutes 5) 



$ASConfig = New-NmeDynamicPoolConfiguration `
                -isEnabled $false `
                -vmTemplate $vmtemplate `
                -isSingleUserDesktop $false `
                -VmNamingMode Reuse `
                -activeHostType AvailableForConnection `
                -scalingMode Default `
                -hostPoolCapacity 2 `
                -minActiveHostsCount 1 `
                -burstCapacity 0 `
                -autoScaleCriteria CPUUsage `
                -scaleInAggressiveness Low `
                -hostUsageScaleCriteria $ScaleCriteria `
                -scaleInRestriction (New-NmeScaleIntimeRestrictionConfiguration -enable $false) `
                -preStageHosts (New-NmePreStateHostsConfiguration -enable $false) `
                -removeMessaging (New-NmeWarningMessageSettings -minutesBeforeRemove 10 -message 'get out!') `
                -autoHeal (New-NmeAutoHealConfiguration -enable $false) `
                -autoScaleInterval 10  `
                -TimezoneId "Central Standard Time"         

Set-NmeHostPoolAutoScaleConfig -subscriptionId $SubscriptionId `
                               -resourceGroup $NmeResourcesRgName `
                               -hostPoolName $hp.hostPoolName `
                               -NmeDynamicPoolConfiguration $ASConfig `
                               -multiTriggers $false 

$hpas = Get-NmeHostPoolAutoScaleConfig -subscriptionId $SubscriptionId -resourceGroup $NmeResourcesRgName -hostPoolName $hp.hostPoolName
$hpas.isEnabled = $true
$job = Set-NmeHostPoolAutoScaleConfig -subscriptionId $SubscriptionId `
                                        -resourceGroup $NmeResourcesRgName `
                                        -hostPoolName $hp.hostPoolName `
                                        -NmeDynamicPoolConfiguration $hpas `
                                        -multiTriggers $false 

sleep 60

while ((Get-NmeHostPoolSessionHosts -subscriptionId $SubscriptionId -resourceGroup $NmeResourcesRgName -hostPoolName $hp.hostPoolName).hostName -contains $null) {
  Write-Output 'Waiting for hosts to be created...'
  Sleep 60
}
$hosts = Get-NmeHostPoolSessionHosts -subscriptionId $SubscriptionId -resourceGroup $NmeResourcesRgName -hostPoolName $hp.hostPoolName


#>

