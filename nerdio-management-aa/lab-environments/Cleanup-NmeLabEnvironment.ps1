param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({ $_ -match '-rg$' })]
    [string]$LabRgName
)
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

$PlaceholderFslProfileName = 'Placeholder-DoNotUse'
$EnvironmentName = $LabRgName -Replace '-rg', ''

# connect to azure using automation account managed identity
Connect-AzAccount -Identity -SubscriptionId $SubscriptionId -ErrorAction Stop | out-null
write-output "Connected to Azure subscription $SubscriptionId using automation account managed identity."
$ctx = Get-AzContext -ErrorAction Stop
$MicrosoftTenantName = $ctx.tenant.domains | Where-Object { $_ -match 'onmicrosoft' }
# authenticate to Microsoft Graph API using the automation account managed identity
Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop | Out-Null
write-output "Connected to Microsoft Graph API using automation account managed identity."


Write-Output "Rolling back changes..."
# remove fslogix profile
$FSLConfig = Get-NmeFslogixProfile -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $FslProfileName }
if ($FSLConfig) {
    if ($FSLConfig.IsDefault -eq $true) {
        # get fslogix profile with name $PlaceholderFslProfile
        Write-Output "Setting FSLogix profile $PlaceholderFslProfile as default..."
        $PlaceholderFslProfile = Get-NmeFslogixProfile  | Where-Object { $_.Name -eq $PlaceholderFslProfileName }
        $properties = New-NmeProperties_PATCH 
        $patch = New-NmeFsLogixParamsRest_PATCH -Name $PlaceholderFslProfile.Name -IsDefault $true
        
        Set-NmeFslogixProfileById -Id $PlaceholderFslProfile.id -NmeFsLogixParamsRest_PATCH $patch  | out-null 
    }
    Write-Output "Removing FSLogix profile $($FslProfileName)..."
    Remove-NmeFslogixProfileById -Id $FSLConfig.id | out-null
} else {
    Write-Output "FSLogix profile $($FslProfileName) not found."
}
# remove users from Entra ID
$Users = Get-mgUser -Property DisplayName,userPrincipalName,CompanyName,id | ? CompanyName -eq $EnvironmentName
foreach ($user in $Users) {
    Write-Output "Removing user $($user.UserPrincipalName) from Entra ID..."
    Remove-MgUser -userId $user.id -ErrorAction Stop | out-null
}
# remove resource group
Write-Output "Removing resource group $LabRgName..."
Remove-AzResourceGroup -Name $LabRgName -Force -ErrorAction Stop | out-null
Write-Output "Resource group $LabRgName removed."