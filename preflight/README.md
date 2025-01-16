# Nerdio Manager Preflight script

This script performs a pre-flight check for Nerdio Manager for Enterprise by attempting to create various Azure resources within a specified subscription and resource group. It verifies the ability to create resources that may be blocked by policy including a Log Analytics Workspace, Storage Account, SQL Server, SQL Database, App Service Plan, Automation Account, and Key Vault. Additionally, it will list the state of the required Resource Providers and roles assigned to the target resource group for the user account used to run the script.

The script is run interactively by targeting an Azure subscription, and optionally a resource group. It will attempt to create resources and capture details of the Azure policy that is blocking the creation of the resource, where possible.

The script will output the results of the success or failure to the console and write details of failures to a file in JSON format. The script also handles cleanup of created resources.

Both a local PowerShell environment (Windows, macOS, Linux) and Azure Cloud Shell are supported for running the script.
The script can take approximately 10 minutes to run.

## Usage

The target subscription id is a required parameter for the script. An existing resource group can be optionally passed, otherwise you will be prompted to create a resource group.

Example usage for specifying an Azure subscription and existing resource group is:

```powershell
.\Start-NerdioManagerPreFlight.ps1 -SubscriptionId "17c99779-9397-4bd4-b7c0-2cde094b9646" -ResourceGroupName "rg-NerdioManagerPreflight-aue"
```

Or specifying the target subscription only (you will be prompted to create a resource group):

```powershell
.\Start-NerdioManagerPreFlight.ps1 -SubscriptionId "17c99779-9397-4bd4-b7c0-2cde094b9646"
```

## Parameters

The script has the following parameters:

* SubscriptionId – required. The target subscription id (GUID)
* ResourceGroupName – optional. The resource group name in which the script will attempt to create resources. If not specified, the script will prompt for a resource group name and region, and attempt to create the resource group
* OutFile – optional. Path to a JSON file that the failure events will be written to. Defaults to `NerdioManagerPreflightOutput.json` in the same directory as the script

## Output

* JSON file - `NerdioManagerPreflightOutput.json` - in the same directory as the script, unless otherwise specified by -OutFile 
* PSCustomObject output to the pipeline showing the result of failed tests – where possible, this includes the IDs of the policies blocking resource deployment. Details of target policies are not returned by all functions

## Modules

The script requires the following modules to be installed: 

* `Az.Accounts, Az.Resources, Az.OperationalInsights, Az.Storage, Az.Sql, Az.Websites, Az.Automation, Az.KeyVault, Microsoft.PowerShell.ConsoleGuiTools`

In Azure Cloud Shell, the Az modules will already be installed. To install or update the required modules use:

```powershell
Install-Module –Name Az.Accounts, Az.Resources, Az.OperationalInsights, Az.Storage, Az.Sql, Az.Websites, Az.Automation, Az.KeyVault, Microsoft.PowerShell.ConsoleGuiTools
```

## Script Considerations 

Minimum rights required: 

* Contributor on the target resource group

## Authentication

The script requires you to authenticate to the target Azure tenant before running this script. Use the Connect-AzAccount cmdlet. For example:

```powershell
Connect-AzAccount -UseDeviceAuthentication
```

## Running the script multiple times

The script will attempt to deploy several resources including those resources that have limitations on some subscription types and resources that are soft deleted. When testing by running the script multiple times, these resources might be created and deleted several times. There are limitations on some of these resources which may cause issues when attempting to create the same resources with the same name:

* Automation accounts - in some subscription types, a limited number of Automation accounts can be deployed. These limits include deleted accounts that haven't yet been purged: [Azure subscription and service limits, quotas, and constraints](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#automation-limits)
* Key vaults - deleted key vaults may need to be purged: [Azure Key Vault recovery management with soft delete and purge protection](https://learn.microsoft.com/en-us/azure/key-vault/general/key-vault-recovery?tabs=azure-portal)

## Checks 

Checks include: 
* Role assignments on target resource group if running locally. This check is skipped in Azure Cloud Shell because the account name does not match the user’s sign-in name.
* Resource providers required by Nerdio Manager
* Attempt to create: 
    * Log Analytics 
    * Storage account 
    * SQL Server 
    * SQL Database 
    * Automation account 
    * Key vault 

## Validating in a Lab

To validate blocking policies in a lab / test environment, configure an assignment for the **Not allowed resource types** to block resource types: [Tutorial: Disallow resource types in your cloud environment](https://learn.microsoft.com/en-us/azure/governance/policy/tutorials/disallowed-resources).

Use the following resource types in the policy assignment:

```json
["Microsoft.Automation/automationAccounts","Microsoft.KeyVault/vaults","Microsoft.OperationalInsights/workspaces","Microsoft.Sql/servers","Microsoft.Sql/servers/databases","Microsoft.Storage/storageAccounts","Microsoft.Web/serverFarms"]
```
