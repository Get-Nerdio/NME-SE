# Nerdio Manager Preflight tools

`Test-NmeDeploymentReadiness.ps1` is the pre-flight validator used to check the target environment before attempting to deploy Nerdio Manager. It is designed to be handed to a customer and run in **Azure Cloud Shell with a single command**.

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

### What it does

* **Checks permissions without the Microsoft.Graph module.** Entra directory roles are read via `Invoke-AzRestMethod` against the Microsoft Graph REST API, reusing the existing `Connect-AzAccount` token. This avoids the `Microsoft.Graph` PowerShell module, which is frequently blocked or broken in locked-down tenants and has been a common source of failure. It confirms the signed-in user has **Global Administrator** (or **Privileged Role Administrator** + **Cloud Application Administrator**) and **Owner** on the target subscription.
* **Detects blocking Azure Policy by deploying real resources** and reports the **blocking policy by name** when a deployment (including the test resource group's own creation) is denied. There is no separate read-only policy scan - a policy only matters if it actually blocks something NME needs, and the deployability tests catch exactly those.
* **Tests resource deployability in parallel.** Throwaway copies of the resources Nerdio Manager deploys are created as background jobs, using **the exact SKUs/config from the installer template** (e.g. Storage `Standard_GRS`/`Standard_ZRS`, SQL DB `Standard S1` DTU, App Service Plan `B3` Windows, Key Vault without purge protection) so a policy that only permits a different SKU cannot produce a false pass. The deployability checks also cover the SQL Server firewall rule `AllowAllWindowsAzureIps` (the installer's "Allow Azure services and resources" rule, skipped and reported as not applicable under `-PrivateEndpointOnly` since the installer template only creates it for public deployments), a Web App with the installer's exact site config (HTTPS-only, minimum TLS 1.3, FTPS disabled, HTTP/2, 64-bit worker, system-assigned managed identity), workspace-based Application Insights, a Key Vault RSA key (no expiration) and secret written while the vault's public access is briefly enabled (mirroring the install sequence), a Storage blob container, an Azure Monitor Data Collection Endpoint and Data Collection Rule, and a temporary Contributor role assignment at resource-group scope to the updater Automation account's managed identity (added and removed) to validate the User Access Administrator right. The SQL firewall rule was the key gap this closed: a real customer deployment failed on that rule being blocked by Azure Policy, which the previous version of this test missed because it created the SQL server/database but never the firewall rule. Errors are captured, never fatal. Note: the throwaway SQL server uses SQL authentication, while the real installer uses Entra-only authentication (`azureADOnlyAuthentication=true`), so an AAD-only-auth policy is not exercised by this test (reported as an INFO item).
* **Tests private endpoints, DNS, and App Service VNet integration together.** A private NME deployment requires an existing VNet with two subnets - one for private endpoints, one (delegated to `Microsoft.Web/serverFarms`) for App Service VNet integration - so the script asks for both subnet names together, not as separate optional steps. It deploys a private endpoint into the subnet you specify, reports the VNet's DNS configuration, and reports **which required private DNS zones are missing or not linked** to that VNet (`privatelink.database.windows.net`, `privatelink.azurewebsites.net`, `privatelink.vaultcore.azure.net`, `privatelink.blob.core.windows.net`, `privatelink.file.core.windows.net`, `privatelink.azure-automation.net`; Gov/China variants derived automatically).
* **Tests App Service outbound connectivity.** It checks whether the named App Service integration subnet is delegated to `Microsoft.Web/serverFarms` - if not, it reports that and does **not** attempt VNet integration. If delegated, it deploys a test App Service, integrates it into your subnet, and runs the outbound-endpoint checks from `NmeNetworkTest.ps1` **from inside the worker** (via the Kudu command API) so the results reflect the VNet's real routing and DNS.
* **Tests private-endpoint DNS resolution and lets you retry it in the same run.** On an existing VNet (Azure DNS **or** custom/on-prem DNS), it resolves each private endpoint's FQDN from inside the VNet and checks it resolves to that endpoint's private IP. When the FQDNs don't resolve privately yet, it prints the exact steps to rig up DNS - for **Azure Private DNS zones**, create the required zones and link them to the VNet (with a private DNS zone group on each endpoint so the A records are maintained automatically); for **custom DNS**, configure your DNS servers to resolve the privatelink FQDNs to the endpoint IPs (conditional-forwarding to Azure DNS via a forwarder/Private Resolver, or manual A records) - with links to the relevant Microsoft documentation. It then offers to **re-run just the DNS test** after you make those changes, without tearing down or re-deploying anything, looping until the names resolve or you decline.
* **Cleans up everything it creates** (constrained to the test resource group, plus the private endpoint in your named subnet) and **prints a colour-coded pass/warn/fail report** between `====== BEGIN REPORT ======` / `====== END REPORT ======` markers, writes a matching **self-contained HTML report** (`NmeReadinessOutput.html`) to hand to your Nerdio SE, and a JSON file for machine-readable detail. The console table and the HTML file are driven by the same palette so they look the same; the HTML is a single file with inline styles (no external assets), opens in any browser offline, and can be saved to PDF from the browser if needed. In **Azure Cloud Shell**, the report files are downloaded to your machine automatically (via the Cloud Shell `download` helper) right after the report prints; if that download prompt doesn't appear, the file can still be pulled from the current session (Cloud Shell's "Upload/Download files" toolbar) or the printed report can be copied directly. When run from **local PowerShell**, the HTML is written to the current directory for you to send from there.
* **Probes the operator's own machine and network path (local runs).** Beyond the in-Azure deployability tests, when run from local PowerShell the script fingerprints the machine that is actually launching the install and its egress - the class of problem that has slipped past preflight before because it only appears on the operator's path, not from inside Azure. It opens a real connection to the throwaway SQL server on **1433 from your machine** and reports whether outbound 1433 is blocked, whether the **TLS pre-login handshake completes** (a broken handshake is the signature of a TLS-inspecting proxy such as **Zscaler**), and whether SQL sees a **different source IP than your HTTPS egress** (split egress, common behind Zscaler - both IPs are printed); acquires a **database-audience token** (`https://database.windows.net/`) pinned to the subscription's owning tenant so a token/tenant mismatch that would break the installer's SQL step surfaces up front; **fingerprints the public egress IP and ASN** (flagging known Zscaler ranges) and captures the **TLS certificate issuer** presented on the path to Azure's ARM and login endpoints, warning when it is a private/enterprise root rather than a public CA (SSL inspection on the path); checks **PowerShell integrity** (version/edition, and a mixed Windows PowerShell 5.1 / PowerShell 7 module path); and reports **tenant topology** - the active context tenant vs the subscription's owning tenant, guest/B2B account status, and how many Entra tenants the account can reach - warning multi-tenant or guest operators to pin `-Tenant` on install day. Host name, PowerShell version, egress IP/ASN, and observed certificate issuers are recorded in the report. These operator-side probes are skipped or clearly labelled in **Azure Cloud Shell**, where the path tested is Cloud Shell's, not the install machine's.
* **Never reports green on an empty or aborted run.** If the run produces no result rows, the overall verdict is **INCOMPLETE** rather than defaulting to a pass; if the run aborts partway with an unhandled error, that abort is recorded as a **failure** before the report is written - so an interrupted run can never be mistaken for a clean one.
* **Records the confirmed-working configuration** - who ran the test, subscription, region, resource group, the exact resource names used, tags, and the existing VNet/subnet names and DNS settings tested - so your SE has a reference configuration when it's time to install NME.

### Future enhancements

* **Cross-run resume of a kept test environment.** Same-run DNS retry is implemented (see the private-endpoint DNS resolution bullet above). A possible future addition is keeping the test resources around after the run and having a later run detect and re-test against them - not currently implemented; each run is self-contained and cleans up after itself.
