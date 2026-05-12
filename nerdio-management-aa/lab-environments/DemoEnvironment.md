# Nerdio Demo Environment Runbooks

## Overview

Two Azure Automation runbooks manage the lifecycle of a customer-facing 
Nerdio demo environment:

- **New-NerdioDemoEnvironment.ps1** - Creates the environment (workspace, users, schedule)
- **Cleanup-NerdioDemoEnvironment.ps1** - Tears down everything created by the setup script
  and by demo users during their session

The setup script is idempotent; re-running it with the same parameters skips existing
resources. The cleanup script is scheduled automatically at the DestroyOnUTC time but can
also be run manually.

---

## What New-NerdioDemoEnvironment.ps1 Creates

| # | Resource | Naming Convention | Location |
|---|----------|-------------------|----------|
| 1 | AVD Workspace | `{Abbrev}-Demo-workspace` | autoclean-rg |
| 2 | Entra ID Users (1..N) | `{Abbrev}-User{N}@{TenantDomain}` | Entra ID |
| 3 | WVD Admin App Role Assignment | per user -> NME app service principal | Entra ID |
| 4 | NME RBAC Workspace Assignment | per user -> workspace | NME database |
| 5 | Cleanup Automation Schedule | `{Abbrev}-Demo-destroy-schedule` | Automation Account |

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| CustomerAbbreviation | Yes | - | 2-4 alphanumeric chars identifying the customer |
| UserCount | Yes | - | Number of demo users to create |
| UserDefaultPassword | No | `Nerdio123!` | Initial password (forces MFA + change on first login) |
| AzureRegion | No | `centralus` | Azure region for the workspace |
| DestroyOnUTC | Yes | - | UTC datetime when cleanup should run |
| UpdateExistingDemoEnv | No | `$false` | Set `$true` to add users/resources to an existing env |
| VariablePrefix | No | `CustomerDemo` | Prefix for Automation Account variables |

### Automation Account Variables (prefixed with VariablePrefix)

| Variable | Description |
|----------|-------------|
| `{Prefix}TenantId` | NME API app registration tenant ID |
| `{Prefix}ClientId` | NME API app registration client ID |
| `{Prefix}ClientSecret` | NME API app registration client secret (encrypted) |
| `{Prefix}Scope` | NME API scope (e.g. `api://<app-id>/.default`) |
| `{Prefix}Uri` | NME API base URI (e.g. `https://app.nerdio.net`) |
| `{Prefix}AppObjectId` | NME app registration object ID in Entra ID |
| `{Prefix}SubscriptionId` | Azure subscription containing demo resources |
| `{Prefix}TenantDomain` | Entra ID tenant domain (e.g. `contoso.onmicrosoft.com`) |
| `{Prefix}LawWorkspaceId` | Log Analytics Workspace ID for NME analytics |
| `{Prefix}NmeResourceGroup` | Resource group containing the NME deployment (SQL server, etc.) |

---

## What Demo Users Can Create During Their Session

Once logged in, demo users have WVD Admin access and can create resources through the
NME portal. The cleanup script discovers these via Log Analytics (LAW) queries and direct
database inspection. Known resource types:

| Resource Type | Azure/NME | Example Names |
|---------------|-----------|---------------|
| Host Pools | Azure + NME DB | `nmwtestpool`, `nmw-hp1` |
| Session Host VMs | Azure | `nmw-acda`, `nmwtest-149c` |
| AVD Workspaces | Azure + NME DB | `nmwworkspace`, `nmwnewworkspace` |
| Desktop Image VMs | Azure | `NMW-Image`, `NMW-Image2` |
| Storage Accounts + File Shares | Azure | `nmwazfile2demo` |
| Temp VMs (Azure Files setup) | Azure | `azfilestmp-a9d7` |
| FSLogix Configurations | NME DB/API | `nmw fsl` |
| Auto-Scale Templates | NME DB/API | `nmw as` |
| App Management Policies | NME DB/API | `nmw fire deploy` |
| Scripted Actions | NME DB/API | `nmw test` |
| AD Configurations | NME DB | `nmw fire` |
| RDP Properties Configurations | NME DB | `NMW RDP profile` |
| Scripted Actions Profiles | NME DB | `nmw sa profile` |
| Capacity Extender Profiles | NME DB | `azure extender` |
| Deployment Models (AvdModels) | NME DB | `nmw model`, `nmw fire test` |
| Shell Apps (ManagedApp) | NME DB | `NMW App`, `NMW app 2` |
| Custom Views | NME DB | `nmw custom view` |
| RBAC Role Definitions | NME DB | `NMW rbac test` |
| RBAC Role Assignments | NME DB | per user principal ID |
| User Cost Attribution (CloudClarity) | NME DB + Azure RBAC | `nmw fire` |

---

## What Cleanup-NerdioDemoEnvironment.ps1 Removes

The cleanup script runs in 12 ordered steps. Earlier steps (user deletion) prevent new
resource creation while later steps remove resources.

### Step 1 - Discover resources via LAW
- Queries Log Analytics for all successful jobs performed by demo users
- Discovers host pools from `UpdateDynamicScaleSettings` request paths
- Falls back to scanning `autoclean-rg` for any host pools Azure knows about

### Step 2 - Delete Entra ID users
- Revokes sign-in sessions (immediate token invalidation)
- Deletes demo users (identified by `CompanyName = "{Abbrev}-Demo"`)

### Step 3 - Remove RBAC assignments and role definitions
- Deletes `RoleAssignments` rows for each demo user's principal ID
- Deletes orphaned `RoleDefinitions` (custom roles with no remaining assignments)

### Step 4 - Remove host pools
- Calls `Remove-NmeHostPool` for each discovered host pool
- This also removes associated session hosts, app groups, and NME DB records

### Step 5 - Remove FSLogix configurations
- Discovers FSLogix config names from LAW (`CreateFSLogixConfiguration` jobs)
- Calls `Remove-NmeFslogixProfileById`

### Step 6 - Remove auto-scale profiles
- Discovers auto-scale profile names from LAW (`CreateAutoScaleTemplate` jobs)
- Calls `Remove-NmeAutoScaleProfileId`

### Step 7 - Remove app management policies
- Discovers policy names from LAW (`CreateAppPolicy` jobs)
- Checks both one-time and recurrent policies
- Calls `Remove-NmeAppManagementOneTimePolicyId` / `Remove-NmeAppManagementRecurrentPolicyId`

### Step 8 - Remove scripted actions
- Discovers scripted action names from LAW (`CreateWindowsScriptedAction` jobs)
- Calls `Remove-NmeScriptedAction` with Force

### Step 9 - Remove desktop image VMs
- Discovers VM names from LAW (`CreateDesktopImage` jobs, successful only)
- Removes the VM, NIC (`{name}-nic`), and OS disk from Azure

### Step 10 - Remove storage accounts and temp VMs
- Discovers storage account names from LAW (`AddFileShare` jobs)
- Removes storage accounts via `Remove-AzStorageAccount`
- Discovers temp VMs created during Azure Files setup
- Removes temp VMs, NICs, and OS disks

### Step 11 - Remove workspaces
- Removes the setup-created workspace (`{Abbrev}-Demo-workspace`) by convention name
- Discovers additional workspaces from LAW (`CreateWorkspace` jobs)
- Removes via `Remove-AzWvdWorkspace`

### Step 12 - Remove DB-only resources via direct SQL
- Resources with no API removal endpoint are deleted directly from the NME database
- FK references are nulled/deleted before the parent row is removed

| JobType | DB Table | Name Column | Pre-Cleanup (FK) |
|---------|----------|-------------|------------------|
| `CreateActiveDirectoryConfig` | ADConfigurations | FriendlyName | HostPoolADConfigurations, HostPoolScriptedActionConfigurations |
| `CreateRdpPropertiesConfig` | RdpPropertiesConfigurations | Name | HostPoolProperties |
| `CreateHostPoolScriptedActionsProfile` | HostPoolScriptedActionProfiles | Name | HostPoolScriptedActionConfigurations, HostPoolProperties |
| `CreateHostPoolCapacityExtenderProfile` | CapacityExtenderProfiles | Name | HostPoolProperties |
| `CreateOrUpdateDeploymentModel` | AvdModels | Name | (none) |
| `CreateShellApp` | ManagedApp | Name | ManagedAppVersion |
| `CreateCustomView` | CustomViews | Name | (none) |

---

## Known Gaps

### 1. User Cost Attribution / CloudClarity configs (NOT CLEANED UP)

**JobType:** `CloudClarityCreateConfig`

Demo users can create "User cost attribution" configurations. This creates:
- A record in the NME database (likely a CloudClarity-related table)
- Azure RBAC role assignments on the subscription:
  - Reader on the Log Analytics Workspace
  - Cost Management Reader on the subscription
  - Desktop Virtualization Reader on the subscription
  - Monitoring Reader on the subscription

The cleanup script has no step handling `CloudClarityCreateConfig`. Neither the LAW
discovery query nor the SQL cleanup map includes this job type. The database record and
the Azure RBAC role assignments it creates will persist after cleanup.

**Impact:** Orphaned DB record + 4 RBAC role assignments left on the subscription per
CloudClarity config created.

### 2. Failed desktop image VMs may be orphaned

The desktop image cleanup query (Step 9) filters on `Props.TaskStatus == "Success"`. If a
desktop image creation fails partway through (e.g. VM created but AD join fails), the VM,
NIC, and OS disk may still exist in Azure but won't be discovered by the LAW query.

NME typically cleans up its own failed resources, so this may not be an issue in practice,
but there is no fallback scan of `autoclean-rg` for orphaned VMs (unlike the host pool
discovery in Step 1 which does have a fallback Azure scan).

**Impact:** Potential orphaned VMs, NICs, and disks in autoclean-rg from failed desktop
image jobs.

### 3. Automation cleanup schedule is not removed

The setup script creates a one-time schedule (`{Abbrev}-Demo-destroy-schedule`) in the
Automation Account. After the cleanup runs, the expired schedule object remains in the
Automation Account. It does not cause harm (one-time schedules don't re-fire), but it
accumulates over time.

**Impact:** Cosmetic - stale schedule objects in the Automation Account.

### 4. UsersPermissions table rows may not be fully cleaned

The cleanup script removes `RoleAssignments` (Step 3) but does not explicitly delete rows
from the `UsersPermissions` table in the NME database. Host pool removal (Step 4) and
workspace removal (Step 11) may implicitly clean some of these, but permission records for
resources that no longer exist could be orphaned.

**Impact:** Potential orphaned rows in UsersPermissions table.

---

## Prerequisites

### Automation Account Modules (PowerShell 5.1)

| Module | Used For |
|--------|----------|
| Az.Accounts | Azure authentication |
| Az.Sql | SQL server/database discovery |
| Az.Compute | VM, disk removal |
| Az.Network | NIC removal |
| Az.Storage | Storage account removal |
| Az.DesktopVirtualization | Workspace and host pool queries/removal |
| Az.OperationalInsights | Log Analytics Workspace queries |
| Microsoft.Graph.Authentication | Managed identity Graph auth |
| Microsoft.Graph.Users | User CRUD |
| Microsoft.Graph.Users.Actions | Revoke sign-in sessions |

### Managed Identity Permissions

| Scope | Permission | Used For |
|-------|-----------|----------|
| Subscription (or demo RGs) | Contributor | Remove VMs, NICs, disks, storage, workspaces, host pools |
| NME Resource Group | Reader | SQL server discovery |
| Microsoft Graph | User.ReadWrite.All | Read CompanyName, delete demo users |
| NME SQL Database | db_datareader, db_datawriter | Direct SQL cleanup operations |

### SQL Connectivity

The NME SQL server is discovered by the tag `NMW_OBJECT_TYPE = PRIMARY_SQL_SERVER` on SQL
servers in the NME resource group. Authentication uses a managed identity access token for
`https://database.windows.net/`. The SQL server firewall must allow connections from the
Automation Account (e.g. "Allow Azure services").
