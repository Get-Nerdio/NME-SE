$subscriptionId = Read-Host -Prompt "Enter the Azure subscription ID where NME will be installed:" 
$currentUser = Get-AzContext -ErrorAction SilentlyContinue
# connect to azure
if (!$currentUser) {
    Write-Host "Connecting to Azure..."
    try {
        $WarningPreference = "SilentlyContinue"
        Connect-AzAccount -Subscription $subscriptionId -UseDeviceAuthentication -ErrorAction Stop | Out-Null
        $currentUser = Get-AzContext
    } catch {
        Write-Error "Failed to connect to Azure. Please make sure you have the Az module installed and you are logged in to the correct subscription."
        exit

    }
}
else {
    Set-AzContext -Subscription $subscriptionId
}

# check if current user is subscription owner  
Write-Host "Checking owner role..." 

$ownerRole = Get-AzRoleAssignment -SignInName $currentUser.Account.Id -Scope "/subscriptions/$subscriptionId" -ErrorAction SilentlyContinue| Where-Object { $_.RoleDefinitionName -eq 'Owner' }
if ($ownerRole) {
    Write-Host -ForegroundColor Green "You are the owner of the subscription"
} else {
    Write-Host -ForegroundColor Yellow "You are not the owner of the subscription, or you are a guest in this tenant"
}

Write-Host "Checking global administrator role..."
Connect-MgGraph -scopes "User.Read, Group.Read.All" -ErrorAction SilentlyContinue -NoWelcome -UseDeviceAuthentication
$GA = Get-MgDirectoryRole -ExpandProperty members | ? DisplayName -eq 'Global Administrator'
if (($currentUser.Account.ExtendedProperties.HomeAccountId -split '\.')[0] -in $ga.Members.id) {
    Write-Host -ForegroundColor Green "You are a global administrator in the tenant"
} else {
    Write-Host -ForegroundColor Yellow "You are not a global administrator, or you are a guest in this tenant"
}