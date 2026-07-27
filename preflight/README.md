# Nerdio Manager Preflight tools

Listed here are scripts and queries to use a preflight tools to validate the target environment before attempting to deploy Nerdio Manager.

## Test-NmeDeploymentReadiness.ps1 (recommended)

`Test-NmeDeploymentReadiness.ps1` is the current pre-flight validator. It expands on the original script below and is designed to be handed to a customer and run in **Azure Cloud Shell with a single command**. It:

* **Checks permissions without the Microsoft.Graph module.** Entra directory roles are read via `Invoke-AzRestMethod` against the Microsoft Graph REST API, reusing the existing `Connect-AzAccount` token. This avoids the `Microsoft.Graph` PowerShell module, which is frequently blocked or broken in locked-down tenants and has been a common source of failure. It confirms the signed-in user has **Global Administrator** (or **Privileged Role Administrator** + **Cloud Application Administrator**) and **Owner** on the target subscription.
* **Detects blocking Azure Policy by deploying real resources** and reports the **blocking policy by name** when a deployment (including the test resource group's own creation) is denied. There is no separate read-only policy scan - a policy only matters if it actually blocks something NME needs, and the deployability tests catch exactly those.
* **Tests resource deployability in parallel.** Throwaway copies of the resources Nerdio Manager deploys are created as background jobs, using **the exact SKUs/config from the installer template** (e.g. Storage `Standard_GRS`/`Standard_ZRS`, SQL DB `Standard S1` DTU, App Service Plan `B3` Windows, Key Vault without purge protection) so a policy that only permits a different SKU cannot produce a false pass. Errors are captured, never fatal.
* **Tests private endpoints, DNS, and App Service VNet integration together.** A private NME deployment requires an existing VNet with two subnets - one for private endpoints, one (delegated to `Microsoft.Web/serverFarms`) for App Service VNet integration - so the script asks for both subnet names together, not as separate optional steps. It deploys a private endpoint into the subnet you specify, reports the VNet's DNS configuration, and reports **which required private DNS zones are missing or not linked** to that VNet (`privatelink.database.windows.net`, `privatelink.azurewebsites.net`, `privatelink.vaultcore.azure.net`, `privatelink.blob.core.windows.net`, `privatelink.file.core.windows.net`, `privatelink.azure-automation.net`; Gov/China variants derived automatically).
* **Tests App Service outbound connectivity.** It checks whether the named App Service integration subnet is delegated to `Microsoft.Web/serverFarms` - if not, it reports that and does **not** attempt VNet integration. If delegated, it deploys a test App Service, integrates it into your subnet, and runs the outbound-endpoint checks from `NmeNetworkTest.ps1` **from inside the worker** (via the Kudu command API) so the results reflect the VNet's real routing and DNS.
* **Cleans up everything it creates** (constrained to the test resource group, plus the private endpoint in your named subnet) and **prints a colour-coded pass/warn/fail report** between `====== BEGIN REPORT ======` / `====== END REPORT ======` markers, writes a matching **self-contained HTML report** (`NmeReadinessOutput.html`) to hand to your Nerdio SE, and a JSON file for machine-readable detail. The console table and the HTML file are driven by the same palette so they look the same; the HTML is a single file with inline styles (no external assets), opens in any browser offline, and can be saved to PDF from the browser if needed. In **Azure Cloud Shell**, the report files are downloaded to your machine automatically (via the Cloud Shell `download` helper) right after the report prints; if that download prompt doesn't appear, the file can still be pulled from the current session (Cloud Shell's "Upload/Download files" toolbar) or the printed report can be copied directly. When run from **local PowerShell**, the HTML is written to the current directory for you to send from there.
* **Records the confirmed-working configuration** - who ran the test, subscription, region, resource group, the exact resource names used, tags, and the existing VNet/subnet names and DNS settings tested - so your SE has a reference configuration when it's time to install NME.

### Usage — Azure Cloud Shell (single command)

Authenticate is automatic in Cloud Shell. Run:

```powershell
$s=New-Object Net.WebClient; & ([scriptblock]::Create($s.DownloadString('https://raw.githubusercontent.com/Get-Nerdio/NME-SE/main/preflight/Test-NmeDeploymentReadiness.ps1')))
```

The script prompts for everything it needs (subscription id, region, whether to create a temporary resource group, and the private-network details). Nothing is deployed until you confirm the "what this does" summary.

### Usage — local PowerShell

Authenticate first, then run the downloaded script (parameters are optional; you are prompted for anything omitted):

```powershell
Connect-AzAccount -UseDeviceAuthentication
.\Test-NmeDeploymentReadiness.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000"
```

### Parameters

All parameters are optional; you are prompted interactively for anything omitted.

* `-SubscriptionId` – target subscription id (GUID).
* `-ResourceGroupName` – an existing **empty** resource group to test in. If omitted, a temporary `rg-nme-preflight-<rand>` is created and removed at the end.
* `-Location` – Azure region for the created resources / temporary resource group. At the region prompt you can type `?` (or `list`) to print all valid Azure region names for the subscription, then re-enter your choice.
* `-OutFile` – path for the JSON results file (defaults to `NmeReadinessOutput.json` in the working directory). The HTML report is written alongside it with the same base name.
* `-PrivateEndpointOnly` – **script-level switch** (not an interactive question) for environments that reject creating resources with public network access enabled at all. When set, the throwaway **Storage account, SQL Server, and Key Vault** are created with public network access **disabled from the start**, so a policy that blocks public-endpoint creation is surfaced up front. The Key Vault "briefly enable public access" install step is still exercised (the vault is toggled public and back), since the real installer performs it. Log Analytics and Automation are created normally (their create cmdlets don't expose a create-time public-access toggle). Example:

  ```powershell
  .\Test-NmeDeploymentReadiness.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -PrivateEndpointOnly
  ```

The signed-in account is **masked** wherever it appears in the report (the username local part is obscured, e.g. `jsmith@contoso.com` → `j***th@contoso.com`); the domain is left intact.

### Requirements

* PowerShell 7 (pre-installed in Azure Cloud Shell)
* Az modules: `Az.Accounts, Az.Resources, Az.Monitor, Az.OperationalInsights, Az.Storage, Az.Sql, Az.Websites, Az.Automation, Az.KeyVault, Az.Network, Az.PrivateDns` and `ThreadJob` (all present in Cloud Shell)
* **No** `Microsoft.Graph` module
* Minimum rights to run a full test: **Owner** on the target subscription (to create/remove the test resources)

### Future enhancements

* **Re-testable DNS/connectivity checks against an existing VNet.** When deploying into an existing customer VNet, or to a new vnet using custom dns servers, the customer may want to keep the test resources around and re-run just the DNS resolution/connectivity checks after changing DNS records or firewall rules. If those checks fail, offer to re-run them before the script exits, and have future runs detect existing resources tied to that VNet and offer to re-run just the network tests against them.
* **DNS resolution test/warning.** If the script will create both the vnet and the private dns zones, we don't need to worry about dns resolution. If using existing vnet, we want to test dns resolution. If DNS resolution has not been tested, as in the case where the user doesn't yet have the vnet info, or the script is creating the vnet but the vnet will use custom dns servers, we want the report to WARN that DNS resolution is untested. These are cases where we want to present the option to test DNS after the initial script finishes, as in the above item.

---

## Script (legacy — Start-NerdioManagerPreFlight.ps1)

This script performs a pre-flight check for Nerdio Manager for Enterprise by attempting to create various Azure resources within a specified subscription and resource group. It verifies the ability to create resources that may be blocked by policy including a Log Analytics Workspace, Storage Account, SQL Server, SQL Database, App Service Plan, Automation Account, and Key Vault. Additionally, it will list the state of the required Resource Providers and roles assigned to the target resource group for the user account used to run the script.

The script is run interactively by targeting an Azure subscription, and optionally a resource group. It will attempt to create resources and capture details of the Azure policy that is blocking the creation of the resource, where possible.

The script will output the results of the success or failure to the console and write details of failures to a file in JSON format. The script also handles cleanup of created resources.

Both a local PowerShell environment (Windows, macOS, Linux) and Azure Cloud Shell are supported for running the script. The script can take approximately 10 minutes to run.

### Usage

The target subscription id is a required parameter for the script. An existing resource group can be optionally passed, otherwise you will be prompted to create a resource group.

Example usage for specifying an Azure subscription and existing resource group is:

```powershell
.\Start-NerdioManagerPreFlight.ps1 -SubscriptionId "17c99779-9397-4bd4-b7c0-2cde094b9646" -ResourceGroupName "rg-NerdioManagerPreflight-aue"
```

Or specifying the target subscription only (you will be prompted to create a resource group):

```powershell
.\Start-NerdioManagerPreFlight.ps1 -SubscriptionId "17c99779-9397-4bd4-b7c0-2cde094b9646"
```

### Parameters

The script has the following parameters:

* SubscriptionId – required. The target subscription id (GUID)
* ResourceGroupName – optional. The resource group name in which the script will attempt to create resources. If not specified, the script will prompt for a resource group name and region, and attempt to create the resource group
* OutFile – optional. Path to a JSON file that the failure events will be written to. Defaults to `NerdioManagerPreflightOutput.json` in the same directory as the script

### Output

* JSON file - `NerdioManagerPreflightOutput.json` - in the same directory as the script, unless otherwise specified by -OutFile 
* PSCustomObject output to the pipeline showing the result of failed tests – where possible, this includes the IDs of the policies blocking resource deployment. Details of target policies are not returned by all functions

### Modules

The script requires the following modules to be installed: 

* `Az.Accounts, Az.Resources, Az.OperationalInsights, Az.Storage, Az.Sql, Az.Websites, Az.Automation, Az.KeyVault, Microsoft.PowerShell.ConsoleGuiTools`

In Azure Cloud Shell, the Az modules will already be installed. To install or update the required modules use:

```powershell
Install-Module –Name Az.Accounts, Az.Resources, Az.OperationalInsights, Az.Storage, Az.Sql, Az.Websites, Az.Automation, Az.KeyVault, Microsoft.PowerShell.ConsoleGuiTools
```

### Script Considerations 

Minimum rights required: 

* Contributor on the target resource group

### Authentication

The script requires you to authenticate to the target Azure tenant before running this script. Use the Connect-AzAccount cmdlet. For example:

```powershell
Connect-AzAccount -UseDeviceAuthentication
```

### Running the script multiple times

The script will attempt to deploy several resources including those resources that have limitations on some subscription types and resources that are soft deleted. When testing by running the script multiple times, these resources might be created and deleted several times. There are limitations on some of these resources which may cause issues when attempting to create the same resources with the same name:

* Automation accounts - in some subscription types, a limited number of Automation accounts can be deployed. These limits include deleted accounts that haven't yet been purged: [Azure subscription and service limits, quotas, and constraints](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#automation-limits)
* Key vaults - deleted key vaults may need to be purged: [Azure Key Vault recovery management with soft delete and purge protection](https://learn.microsoft.com/en-us/azure/key-vault/general/key-vault-recovery?tabs=azure-portal)

### Checks 

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

### Validating in a Lab

To validate blocking policies in a lab / test environment, configure an assignment for the **Not allowed resource types** to block resource types: [Tutorial: Disallow resource types in your cloud environment](https://learn.microsoft.com/en-us/azure/governance/policy/tutorials/disallowed-resources).

Use the following resource types in the policy assignment:

```json
["Microsoft.Automation/automationAccounts","Microsoft.KeyVault/vaults","Microsoft.OperationalInsights/workspaces","Microsoft.Sql/servers","Microsoft.Sql/servers/databases","Microsoft.Storage/storageAccounts","Microsoft.Web/serverFarms"]
```

## Kusto Query

Here's a KQL query that should list Azure policies that are configured with a **Deny** effect. Export the list polices and review for potential issues before attempting to deploy Nerdio Manager.

Run this in the **Azure Resource Graph Explorer** - the user running the query will need the **Resource Policy Reader** role, or **Reader** on the target subscription or management group. No other permissions in Azure should be required and no resources need to be deployed for testing.

```kql
policyresources
| where type == "microsoft.authorization/policyassignments"
| extend definitionId = tostring(properties.policyDefinitionId),
         assignmentEffect = tostring(properties.parameters.effect.value)
| join kind=leftouter (
    policyresources
    | where type == "microsoft.authorization/policydefinitions"
    | extend defaultEffect = tostring(properties.parameters.effect.defaultValue),
             hardCodedEffect = tostring(properties.policyRule.then.effect),
             policyDisplayName = tostring(properties.displayName)
    | project definitionId = id,
              policyDisplayName,
              hardCodedEffect,
              defaultEffect
) on definitionId
| extend resolvedEffect = case(
    isnotempty(assignmentEffect), assignmentEffect,
    isnotempty(hardCodedEffect) and hardCodedEffect !~ "[parameters('effect')]", hardCodedEffect,
    isnotempty(defaultEffect), defaultEffect,
    "unknown"
)
| where resolvedEffect == "Deny"
| project assignmentId = id,
          assignmentName = name,
          scope = properties.scope,
          policyDisplayName,
          resolvedEffect
```
