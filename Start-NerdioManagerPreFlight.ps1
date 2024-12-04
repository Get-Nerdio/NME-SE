#Requires -Modules Az.Accounts, Az.Resources, Az.OperationalInsights, Az.Storage, Az.Sql, Az.Websites, Az.Automation, Az.KeyVault, Microsoft.PowerShell.ConsoleGuiTools
<#
    .SYNOPSIS
        Nerdio Manager Preflight Script.

    .DESCRIPTION
        This script performs a pre-flight check for Nerdio Manager by attempting to create various Azure resources
        within a specified subscription and resource group. It verifies the ability to create resources such as
        Log Analytics Workspace, Storage Account, SQL Server, SQL Database, App Service Plan, Automation Account,
        and Key Vault. The script also handles cleanup of created resources.

        Authenticate to the target Azure tenant before running this script. e.g., Connect-AzAccount -UseDeviceAuthentication

    .PARAMETER SubscriptionId
        The ID of the Azure subscription where the resources will be created. This parameter is mandatory.

    .PARAMETER ResourceGroupName
        The name of the resource group where the resources will be created. This parameter is optional.
        If this parameter is not supplied, the script will prompt for the resource group name and create it.

    .PARAMETER Name
        The base name used for naming the resources. This parameter is optional and defaults to "NmePreflight".

    .NOTES
        The script requires the following Azure modules:
        Az.Accounts, Az.Resources, Az.OperationalInsights, Az.Storage, Az.Sql, Az.Websites, Az.Automation, Az.KeyVault

        Ensure you are aware of the limits on Automation Accounts and Key Vaults before running this script.
        https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#automation-limits
        https://learn.microsoft.com/en-us/azure/key-vault/general/key-vault-recovery

        TODO: Random resource names generated are unique per run. These need to be updated to be unique to the subscription and
              resource group, like Bicep does so the same resource name will be generated each time the script is run

    .EXAMPLE
        .\Start-NerdioManagerPreFlight.ps1 -SubscriptionId "17c99779-9397-4bd4-b7c0-2cde094b9646" -ResourceGroupName "rg-NerdioManagerPreflight-aue"

    .EXAMPLE 
        & ([ScriptBlock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Get-Nerdio/NME-SE/refs/heads/main/Start-NerdioManagerPreFlight.ps1'))) 
 
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "The ID of the Azure subscription where the resources will be created.")]
    [ValidateNotNullOrEmpty()]
    [System.String] $SubscriptionId, #= "17c99779-9397-4bd4-b7c0-2cde094b9646",

    [Parameter(Mandatory = $false, Position = 1, HelpMessage = "The name of the resource group where the resources will be created.")]
    [ValidateNotNullOrEmpty()]
    [System.String] $ResourceGroupName, #= "rg-NerdioManagerPreflight-aue",

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [System.String] $AppName = "NmePreflight",

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [System.String] $OutFile = $(Join-Path -Path './' -ChildPath "NerdioManagerPreflightOutput.json")
)

try {
    $Token = Get-AzAccessToken -WarningAction "SilentlyContinue" -ErrorAction "SilentlyContinue"
    if ($null -eq $Token) {
        $Msg = "Failed to retrieve Azure token. Please ensure you are authenticated before running this script."
        throw $Msg
    }
    Remove-Variable -Name Token
}
catch {
    $Msg = "Failed to retrieve Azure token. Please ensure you are authenticated before running this script."
    throw $Msg
}

#region Functions
function New-PreflightObject {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String] $ExceptionMessage,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String] $Target
    )

    if ($ExceptionMessage -match "({.*}$)") {
        $Message = ($Matches[0] | ConvertFrom-Json).error.message
        if ($Message -match "(\[.*\])") {
            $Policy = $Matches[0] | ConvertFrom-Json
        }
        else {
            $Policy = "Not found"
        }

        $Object = [PSCustomObject]@{
            Target  = $Target
            Message = $Message
            Policy  = $Policy
        }
    }
    elseif ($ExceptionMessage -match "(\[.*\])") {
        $Object = [PSCustomObject]@{
            Target  = $Target
            Message = $ExceptionMessage
            Policy  = $Matches[0] | ConvertFrom-Json
        }
    }
    else {
        $Object = [PSCustomObject]@{
            Target  = $Target
            Message = $ExceptionMessage
            Policy  = "Not found"
        }
    }

    return $Object
}
#endregion

#region Internal parameters
$Chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
$OutputArray = [System.Collections.ArrayList]@()
$Tags = @{
    "Application" = "Nerdio Manager"
    "Environment" = "Preflight"
    "CreatedDate" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}
$ResourceProviders = @("Microsoft.KeyVault",
    # "Microsoft.AAD",
    "Microsoft.Automation",
    "Microsoft.Compute",
    "Microsoft.DocumentDB",
    "Microsoft.DesktopVirtualization",
    "Microsoft.Insights",
    "Microsoft.Network",
    "Microsoft.OperationalInsights",
    "Microsoft.RecoveryServices",
    "Microsoft.Storage")
#endregion

# Start script
$Url = "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#automation-limits"
$Logo = @"
                                                                  ::::
                           ++++++++++                            ::::::
                        +++++++++++++++++                        ::::::
                      ++++++*+*++*++++++++*               ::::   ::::::   ::::
                    ++++++*          +*+++++             :::::   ::::::   ::::::
                   +++++*              +++++*           :::::    ::::::    ::::::
                   +++++                +++++          :::::     ::::::     ::::::
                  ++++*                  +++++         ::::       ::::       :::::
                  +++++                  +++++++++=::::::::                  :::::
               ++++++++                  ++++++*++-::::::::                  ::::::::
               ++++++++*                ++++++         :::::                :::::::::
                   ++++++              +++++*          ::::::              ::::::
                    +++++++           ++++++            :::::::          :::::::
                      ++++++++    ++++++++               ::::::::::::::::::::::
                       *+++++++++++++++*+                  ::::::::::::::::::
                          *++++++++*+                         ::::::::::::
"@
Write-Host ""
Write-Host -ForegroundColor "Cyan" $Logo
Write-Host ""
Write-Host -ForegroundColor "Cyan" "Welcome to the Nerdio Manager Preflight Script. This script will attempt to create various Azure resources to verify the ability to deploy Nerdio Manager."
Write-Host ""
Write-Host "Target subscription: $SubscriptionId"

# If resource group name is not supplied, prompt for it and create
if ([System.String]::IsNullOrEmpty($ResourceGroupName)) {
    do {
        $ResourceGroupName = Read-Host -Prompt "Enter the name of the resource group where the resources will be created"
    }
    while ($ResourceGroupName -notmatch "^[a-zA-Z0-9_\-\(\)\.]{1,90}$")
    Write-Host "Target resource group: $ResourceGroupName"
    if (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction "SilentlyContinue") {
        Write-Host "Resource group '$ResourceGroupName' already exists."

    }
    else {
        Write-Host "Retrieving available locations for the resource group..."
        $Region = Get-AzLocation | Where-Object { $_.RegionType -match "Physical" } | `
            Sort-Object -Property "Location" | `
            Select-Object -Property "DisplayName", "Location" | `
            Out-ConsoleGridView -Title "Select the location for the resource group" -OutputMode "Single"
        Write-Host "Selected location: '$($Region.DisplayName)'"

        do {
            $Response = Read-Host -Prompt "Include tags on the resource group? [y/n]"
        } while ($Response -notmatch "^[YyNn]$")
        if ($Response -match "^[Yy]$") {
            $params = @{
                Name        = $ResourceGroupName
                Location    = $Region.Location
                Tag         = $Tags
                ErrorAction = "Stop"
            }
            New-AzResourceGroup @params
        }
        else {
            $params = @{
                Name        = $ResourceGroupName
                Location    = $Region.Location
                ErrorAction = "Stop"
            }
            New-AzResourceGroup @params
        }
    }
}
else {
    # If the resource group name is supplied, we assume the resource group exists
    Write-Host "Target resource group: $ResourceGroupName"
}

Write-Host ""
do {
    $Response = Read-Host -Prompt "Start preflight tests? [y/n]"
} while ($Response -notmatch "^[YyNn]$")
if ($Response -match "^[Yy]$") {

    # Ask for additional options
    do {
        $Response = Read-Host -Prompt "Include resource provider checks? [y/n]"
    } while ($Response -notmatch "^[YyNn]$")
    if ($Response -match "^[Yy]$") { $CheckResourceProviders = $true }
    do {
        $Response = Read-Host -Prompt "Include Azure automation account check? [y/n]. (Note limits: $Url)"
    } while ($Response -notmatch "^[YyNn]$")
    if ($Response -match "^[Yy]$") { $CreateAutomationAccount = $true }

    #region Get the supplied subscription and resource group
    try {
        Write-Host ""
        Write-Host -ForegroundColor "Cyan" "Attempting to set the context to the subscription with ID '$SubscriptionId'."
        $Context = Get-AzSubscription -SubscriptionId $SubscriptionId | Set-AzContext -ErrorAction "Stop"
        Write-Host -ForegroundColor "Green" "[⎷] Successfully set the subscription context to '$($Context.Subscription.Name)'."
    }
    catch {
        $Msg = "$($_.Exception.Message) Please ensure the value for -SubscriptionId is correct."
        throw $Msg
    }

    try {
        Write-Host -ForegroundColor "Cyan" "Attempting to retrieve the resource group with name '$ResourceGroupName'."
        $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction "Stop"
        Write-Host -ForegroundColor "Green" "[⎷] Successfully found the resource group: '$($ResourceGroup.ResourceGroupName)'."
        Write-Host -ForegroundColor "Green" "Preflight will attempt to deploy resources into location: '$($ResourceGroup.Location)'."
    }
    catch {
        $Msg = "$($_.Exception.Message) Please ensure the value for -ResourceGroupName is correct."
        throw $Msg
    }

    # List current account's role assignment on the resource group
    if ($Env:AZD_IN_CLOUDSHELL -eq 1) {
        Write-Host ""
        Write-Host -ForegroundColor "Cyan" "Skipping listing role assignments because we're running in Azure Cloud Shell."
        Write-Host ""
    }
    else {
        Write-Host ""
        Write-Host -ForegroundColor "Cyan" "Listing current user's roles on resource group: '$($ResourceGroup.ResourceGroupName)'."
        $UserRoles = $ResourceGroup | Get-AzRoleAssignment -SignInName $Context.Account | `
            Where-Object { $_.RoleDefinitionName -in @("Owner", "Contributor") } | `
            Select-Object -Property "DisplayName", "SignInName", "RoleDefinitionName", "ObjectType" -Unique
        $UserRoles | Out-String | Write-Information -InformationAction "Continue"

        $GroupRoles = Get-AzRoleAssignment -SignInName $Context.Account -ExpandPrincipalGroups | `
            Where-Object { $_.Scope -match $ResourceGroup.ResourceId -and $_.RoleDefinitionName -in @("Owner", "Contributor") } | `
            Select-Object -Property "DisplayName", "RoleDefinitionName", "ObjectType"
        $GroupRoles | Out-String | Write-Information -InformationAction "Continue"
    }
    #endregion

    #region Check for required resource providers
    if ($CheckResourceProviders) {
        try {
            Write-Host -ForegroundColor "Cyan" "Checking for required resource providers."
            $ResourceProviders | ForEach-Object {
                $Provider = $_
                $ResourceProvider = Get-AzResourceProvider -ProviderNamespace $Provider -ErrorAction "Stop"
                if ($ResourceProvider.RegistrationState -eq "Registered") {
                    Write-Host -ForegroundColor "Green" "[⎷] Found the resource provider: '$Provider'."
                }
                else {
                    Write-Host -ForegroundColor "Red" "[x] The resource provider '$Provider' is not registered."
                    #$OutputArray.Add($(New-PreflightObject -ExceptionMessage "Resource provider '$Provider' is not registered." -Target "ResourceProvider")) | Out-Null
                }
            }
        }
        catch {
            Write-Host -ForegroundColor "Red" "[x] Failed to check for required resource providers."
            #$OutputArray.Add($(New-PreflightObject -ExceptionMessage $_.Exception.Message -Target "ResourceProvider")) | Out-Null
        }
    }
    #endregion


    #region Check whether Azure policies will block required resources
    Write-Host ""
    Write-Host -ForegroundColor "Cyan" "Checking for ability to deploy required resource types."

    # Wrap script in try/catch/finally block so that we ensure cleanup is performed
    try {

        # Attempt to create a new Azure Log Analytics Workspace
        try {
            $LogAnalyticsWorkspaceName = "log-$($AppName)-$($ResourceGroup.Location)"
            Write-Host -ForegroundColor "Cyan" "Attempting to create a new Log Analytics workspace with name: '$($LogAnalyticsWorkspaceName)'."
            $params = @{
                ResourceGroupName = $ResourceGroupName
                Name              = $LogAnalyticsWorkspaceName
                Location          = $ResourceGroup.Location
                Tag               = $Tags
                ErrorAction       = "Stop"
            }
            $LogAnalytics = New-AzOperationalInsightsWorkspace @params
            Write-Host -ForegroundColor "Green" "[⎷] Created a new Log Analytics workspace with name: '$($LogAnalytics.Name)'."
        }
        catch {
            Write-Host -ForegroundColor "Red" "[x] Failed to create a new Log Analytics workspace."
            $OutputArray.Add($(New-PreflightObject -ExceptionMessage $_.Exception.Message -Target "LogAnalytics")) | Out-Null
        }


        # Attempt to create a new storage account
        try {
            # Generate a random storage account name
            $Length = 10
            $RandomString = -join ((1..$Length) | ForEach-Object { $Chars.ToCharArray() | Get-Random })
            $StorageAccountName = ("$($AppName)$($RandomString)").ToLower()
            Write-Host -ForegroundColor "Cyan" "Attempting to create a new storage account with name: '$($StorageAccountName)'."
            $params = @{
                ResourceGroupName               = $ResourceGroupName
                Name                            = $StorageAccountName
                Location                        = $ResourceGroup.Location
                SkuName                         = "Standard_LRS"
                Kind                            = "StorageV2"
                AllowSharedKeyAccess            = $true
                PublicNetworkAccess             = "Enabled"
                RoutingChoice                   = "MicrosoftRouting"
                AllowBlobPublicAccess           = $true
                MinimumTlsVersion               = "TLS1_2"
                RequireInfrastructureEncryption = $false
                Tag                             = $Tags
                ErrorAction                     = "Stop"
            }
            $StorageAccount = New-AzStorageAccount @params
            Write-Host -ForegroundColor "Green" "[⎷] Created a new storage account with name: '$($StorageAccount.StorageAccountName)'."
        }
        catch {
            Write-Host -ForegroundColor "Red" "[x] Failed to create a new storage account."
            $OutputArray.Add($(New-PreflightObject -ExceptionMessage $_.Exception.Message -Target "StorageAccount")) | Out-Null
        }


        # Attempt to create a new SQL Server
        try {
            # Generate a random password and admin login and create a credentials object
            $Length = 64
            $Password = -join ((1..$Length) | ForEach-Object { $Chars.ToCharArray() | Get-Random })
            $Length = 12
            $AdminLogin = ( -join ((1..$Length) | ForEach-Object { $Chars.ToCharArray() | Get-Random })).ToLower()
            $Credentials = $(New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $AdminLogin, $(ConvertTo-SecureString -String $Password -AsPlainText -Force))

            # SQL Server name
            $SqlServerName = ("$($AppName)-Sql-$(Get-Random)").ToLower()

            Write-Host -ForegroundColor "Cyan" "Attempting to create a new SQL Server with name: '$SqlServerName'."
            $params = @{
                ResourceGroupName                       = $ResourceGroupName
                ServerName                              = $SqlServerName
                Location                                = $ResourceGroup.Location
                ServerVersion                           = "12.0"
                SqlAdministratorCredentials             = $Credentials
                PublicNetworkAccess                     = "Enabled"
                MinimalTlsVersion                       = "1.2"
                EnableActiveDirectoryOnlyAuthentication = $false
                Tag                                     = $Tags
                ErrorAction                             = "Stop"
            }
            New-AzSqlServer @params *> $null
            Start-Sleep -Seconds 5
            $SqlServer = Get-AzSqlServer -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName
            if ([System.String]::IsNullOrEmpty($SqlServer.ServerName)) {
                Write-Host -ForegroundColor "Red" "[x] Failed to create a new SQL Server."
                $OutputArray.Add($(New-PreflightObject -ExceptionMessage $Error[0].Exception.Message -Target "SQLServer")) | Out-Null
            }
            else {
                Write-Host -ForegroundColor "Green" "[⎷] Created a new SQL Server with name: '$($SqlServer.ServerName)'."
            }
        }
        catch {
            Write-Host -ForegroundColor "Red" "[x] Failed to create a new SQL Server."
            $OutputArray.Add($(New-PreflightObject -ExceptionMessage $_.Exception.Message -Target "SQLServer")) | Out-Null
        }


        # Attempt to create firewall rules and a new SQL Database
        if (-not ([System.String]::IsNullOrEmpty($SqlServer.ServerName))) {
            try {
                Write-Host -ForegroundColor "Cyan" "Attempting to create SQL Server firewall rules."
                $params = @{
                    ResourceGroupName = $ResourceGroupName
                    ServerName        = $SqlServerName
                    FirewallRuleName  = "AllowedIPs"
                    StartIpAddress    = "0.0.0.0"
                    EndIpAddress      = "0.0.0.0"
                    ErrorAction       = "Stop"
                }
                New-AzSqlServerFirewallRule @params *> $null
                Write-Host -ForegroundColor "Green" "[⎷] Created SQL Server firewall rules."
            }
            catch {
                Write-Host -ForegroundColor "Red" "[x] Failed to create SQL Server firewall rules."
                $OutputArray.Add($(New-PreflightObject -ExceptionMessage $_.Exception.Message -Target "SQLFirewall")) | Out-Null
            }

            try {
                $DatabaseName = "$($AppName)TestDatabase"
                Write-Host -ForegroundColor "Cyan" "Attempting to create a new SQL Database with name: '$DatabaseName'."
                $params = @{
                    ResourceGroupName = $ResourceGroupName
                    ServerName        = $SqlServer.ServerName
                    DatabaseName      = $DatabaseName
                    Edition           = "GeneralPurpose"
                    ComputeModel      = "Serverless"
                    ComputeGeneration = "Gen5"
                    VCore             = 2
                    MinimumCapacity   = 2
                    SampleName        = "AdventureWorksLT"
                    CollationName     = "SQL_Latin1_General_CP1_CI_AS"
                    Tag               = $Tags
                    ErrorAction       = "Stop"
                }
                New-AzSqlDatabase @params *> $null
                Start-Sleep -Seconds 5
                $SqlDatabase = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $SqlServer.ServerName -DatabaseName $DatabaseName
                if ([System.String]::IsNullOrEmpty($SqlDatabase.DatabaseName)) {
                    Write-Host -ForegroundColor "Red" "[x] Failed to create a new SQL Database."
                    $OutputArray.Add($(New-PreflightObject -ExceptionMessage $Error[0].Exception.Message -Target "SQLDatabase")) | Out-Null
                }
                else {
                    Write-Host -ForegroundColor "Green" "[⎷] Created a new SQL Database with name: '$($SqlDatabase.DatabaseName)'."
                }
            }
            catch {
                Write-Host -ForegroundColor "Red" "[x] Failed to create a new SQL Database."
                $OutputArray.Add($(New-PreflightObject -ExceptionMessage $_.Exception.Message -Target "SQLDatabase")) | Out-Null
            }
        }
        else {
            Write-Host -ForegroundColor "Cyan" "Skipping SQL database creation."
        }


        # Attempt to create a new App Service Plan
        try {
            Write-Host -ForegroundColor "Cyan" "Attempting to create a new App Service Plan."
            $params = @{
                ResourceGroupName = $ResourceGroupName
                Name              = "asp-$($AppName)-$($ResourceGroup.Location)"
                Location          = $ResourceGroup.Location
                Tier              = "Basic"
                Linux             = $true
                NumberOfWorkers   = 1
                WorkerSize        = "Small"
                Tag               = $Tags
                ErrorAction       = "Stop"
            }
            New-AzAppServicePlan @params *> $null
            Start-Sleep -Seconds 5
            $AppServicePlan = Get-AzAppServicePlan -ResourceGroupName $ResourceGroupName -Name $params.Name
            if ([System.String]::IsNullOrEmpty($AppServicePlan.Name)) {
                Write-Host -ForegroundColor "Red" "[x] Failed to create a new App Service Plan."
                $OutputArray.Add($(New-PreflightObject -ExceptionMessage $Error[0].Exception.Message -Target "AppServicePlan")) | Out-Null
            }
            else {
                Write-Host -ForegroundColor "Green" "[⎷] Created a new App Service Plan with name: '$($AppServicePlan.Name)'."
            }
        }
        catch {
            Write-Host -ForegroundColor "Red" "[x] Failed to create a new App Service Plan."
            $OutputArray.Add($(New-PreflightObject -ExceptionMessage $_.Exception.Message -Target "AppServicePlan")) | Out-Null
        }


        # TODO: Complete the App Service creation
        # Attempt to create a new App Service
        # if (-not ([System.String]::IsNullOrEmpty($AppServicePlan.Name))) {
        #     try {
        #         Write-Host -ForegroundColor "Cyan" "Attempting to create a new App Service."
        #         $params = @{
        #             ResourceGroupName = $ResourceGroupName
        #             Name              = ("app-$($AppName)-$(Get-Random)").ToLower()
        #             Location          = $ResourceGroup.Location
        #             AppServicePlan    = $AppServicePlan
        #             Tag               = $Tags
        #             ErrorAction       = "Stop"
        #         }
        #         $WebApp = New-AzWebApp @params *> $null
        #         Write-Host -ForegroundColor "Green" "[⎷] Created a new App Service with name: '$($WebApp.Name)'."
        #     }
        #     catch {
        #         Write-Host -ForegroundColor "Red" "[x] Failed to create a new App Service."
        #         $OutputArray.Add($(New-PreflightObject -ExceptionMessage $_.Exception.Message -Target "AppService")) | Out-Null
        #     }
        # }


        # Attempt to create a new Automation Account
        # Refer to Automation limits: https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#automation-limits"
        if ($CreateAutomationAccount) {
            try {
                $AutomationAccountName = "aa-$($AppName)-$(Get-Random)-$($ResourceGroup.Location)"
                Write-Host -ForegroundColor "Cyan" "Attempting to create a new Automation Account with name: $($AutomationAccountName)."
                $params = @{
                    ResourceGroupName          = $ResourceGroupName
                    Name                       = $AutomationAccountName
                    Location                   = $ResourceGroup.Location
                    AssignSystemIdentity       = $true
                    DisablePublicNetworkAccess = $false
                    Tag                        = $Tags
                    ErrorAction                = "Stop"
                }
                $AutomationAccount = New-AzAutomationAccount @params *> $null
                Write-Host -ForegroundColor "Cyan" "Waiting for the Automation Account to be created."
                Start-Sleep -Seconds 10
                if ([System.String]::IsNullOrEmpty($AutomationAccount.AutomationAccountName)) {
                    Write-Host -ForegroundColor "Red" "[x] Failed to create a new Automation Account."
                    $OutputArray.Add($(New-PreflightObject -ExceptionMessage $Error[0].Exception.Message -Target "AutomationAccount")) | Out-Null
                }
                else {
                    Write-Host -ForegroundColor "Green" "[⎷] Created a new Automation Account with name: '$($AutomationAccount.AutomationAccountName)'."
                }
            }
            catch {
                Write-Host -ForegroundColor "Red" "[x] Failed to create a new Automation Account."
                $OutputArray.Add($(New-PreflightObject -ExceptionMessage $_.Exception.Message -Target "AutomationAccount")) | Out-Null
            }
        }


        # Attempt to create a new Key Vault
        try {
            $KeyVaultName = "kv-Nme-$(Get-Random)-$($ResourceGroup.Location)".Substring(0, 24)
            Write-Host -ForegroundColor "Cyan" "Attempting to create a new Key Vault with name: $KeyVaultName."
            $params = @{
                ResourceGroupName = $ResourceGroupName
                Name              = $KeyVaultName
                Location          = $ResourceGroup.Location
                Tag               = $Tags
                ErrorAction       = "Stop"
            }
            New-AzKeyVault @params *> $null
            Start-Sleep -Seconds 5
            $KeyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName
            if ([System.String]::IsNullOrEmpty($KeyVault.VaultName)) {
                Write-Host -ForegroundColor "Red" "[x] Failed to create a new Key Vault."
                $OutputArray.Add($(New-PreflightObject -ExceptionMessage $Error[0].Exception.Message -Target "KeyVault")) | Out-Null
            }
            else {
                Write-Host -ForegroundColor "Green" "[⎷] Created a new Key Vault with name: '$($KeyVault.VaultName)'."
            }
        }
        catch {
        }

        Write-Host ""
        Write-Host -ForegroundColor "Green" "Nerdio Manager preflight complete."
    }
    catch {
    }
    finally {

        # Write the output array to the console
        Write-Host ""
        Write-Host -ForegroundColor "Cyan" "Writing output to file: '$OutFile'."
        $OutputArray | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutFile -Force
        Write-Output -InputObject $OutputArray

        do {
            Write-Host ""
            $Response = Read-Host -Prompt "Remove resources created during preflight test? [Y/n]"
        } while ($Response -notmatch "^[YyNn]$")
        if ($Response -match "^[Yy]$") {
            $RemoveResources = $true
        }
        else {
            $RemoveResources = $false
            Write-Host -ForegroundColor "Cyan" "Skipping resource removal."
        }

        if ($RemoveResources -eq $true) {
            # Remove the services we just created
            Write-Host ""
            Write-Host -ForegroundColor "Cyan" "Removing resources created during preflight check in resource group: '$ResourceGroupName'."
            if (-not[System.String]::IsNullOrEmpty($LogAnalytics.Name)) {
                Write-Host -ForegroundColor "Cyan" "Removing Log Analytics workspace: '$($LogAnalytics.Name)'."
                Remove-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $LogAnalytics.Name -Confirm:$false -Force -ErrorAction "Continue"
            }
            if (-not[System.String]::IsNullOrEmpty($StorageAccount.StorageAccountName)) {
                Write-Host -ForegroundColor "Cyan" "Removing storage account: '$($StorageAccount.StorageAccountName)'."
                Remove-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccount.StorageAccountName -Force -ErrorAction "Continue"
            }
            if (-not[System.String]::IsNullOrEmpty($SqlDatabase.DatabaseName)) {
                Write-Host -ForegroundColor "Cyan" "Removing SQL Database: '$($SqlDatabase.DatabaseName)'."
                Remove-AzSqlDatabase -ResourceGroupName $ResourceGroupName -DatabaseName $SqlDatabase.DatabaseName -ServerName $SqlServer.ServerName -Force -ErrorAction "Continue" | Out-Null
            }
            if (-not[System.String]::IsNullOrEmpty($SqlServer.ServerName)) {
                Write-Host -ForegroundColor "Cyan" "Removing SQL Server: '$($SqlServer.ServerName)'."
                Remove-AzSqlServer -ResourceGroupName $ResourceGroupName -ServerName $SqlServer.ServerName -Force -ErrorAction "SilentlyContinue" | Out-Null
            }
            if (-not[System.String]::IsNullOrEmpty($AppServicePlan.Name)) {
                Write-Host -ForegroundColor "Cyan" "Removing App Service Plan: '$($AppServicePlan.Name)'."
                Remove-AzAppServicePlan -ResourceGroupName $ResourceGroupName -Name $AppServicePlan.Name -Force -ErrorAction "Continue"
            }
            if (-not[System.String]::IsNullOrEmpty($AutomationAccountName.AutomationAccountName)) {
                Write-Host -ForegroundColor "Cyan" "Removing Automation Account: '$($AutomationAccount.AutomationAccountName)'."
                Remove-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccount.AutomationAccountName -Force -ErrorAction "Continue"
            }
            if (-not[System.String]::IsNullOrEmpty($KeyVault.VaultName)) {
                Write-Host -ForegroundColor "Cyan" "Removing Key Vault: '$($KeyVault.VaultName)'."
                Remove-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVault.VaultName -Force -ErrorAction "Continue"
            }
            Write-Host -ForegroundColor "Cyan" "Finished removing resources. Check resource group to confirm."
        }
    }
    #endregion
}
