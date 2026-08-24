# Nerdio Modeler Import Builder

Turns your actual AVD environment into an import file for the Nerdio Modeler. Every host pool, tenant-wide, plus a per-pool review of what was found and, where permitted, what those pools actually cost last month.

One command in Azure Cloud Shell, or in local PowerShell (7 or the built-in Windows PowerShell 5.1) after `Connect-AzAccount`. Read-only. Nothing in your environment is changed.

A cost model is only as credible as the data behind it. This tool feeds the Modeler reality instead of estimates: real SKUs, real disks, real session limits, observed concurrency and working hours. Every host pool, not a sample. The savings it shows are savings you can expect to keep.

---

## Quick start

1. Open **Azure Cloud Shell** in the tenant that hosts your AVD environment (portal, `>_` icon), **PowerShell** mode.
2. Paste:

   ```powershell
   iex (irm 'https://raw.githubusercontent.com/dclawrence003/NME/main/modeler/Get-NerdioModelerJson.ps1')
   ```

3. Read the review table it prints. One row per pool; anything defaulted is spelled out in `Flags`. The run never stops to ask anything. The first lines name the signed-in account, the tenant, and every subscription in scope. If a pool you expected is missing, look there first. A run covers one tenant, and the script warns you when your account can reach others.
4. One zip downloads automatically: `modeler-import-<timestamp>.zip`. It holds the import JSON, the review CSV, the storage ledger CSV, the raw observation data, and the full console log. If someone asked you to run this, that zip is the only thing to send back.
5. Nerdio Modeler > Import > pick the JSON from the zip. Done.

**Running from a local machine instead:** the **Az.Accounts** module is all it takes. `Install-Module Az.Accounts` once, then `Connect-AzAccount`. Add `-TenantId <id>` if you have several tenants, and sign in as the account that has Reader on the environment you're scanning. The run header names the account, tenant, and subscriptions it can see, so a wrong sign-in is visible on line 2. Not signed in? The script stops immediately and tells you exactly what to run. It never half-runs.

From there, paste the exact same command. Nothing changes between Cloud Shell and local. Works in PowerShell 7 (recommended) and Windows PowerShell 5.1. No other Az modules are used; inventory, telemetry, storage, and cost are all reached over REST. The only difference: instead of a browser auto-download, the zip lands in your Downloads folder, full path printed at the end. In Cloud Shell there is nothing to install or sign into. The shell is already authenticated as the portal user.

Prefer to read the code before running it? You should:

```powershell
irm 'https://raw.githubusercontent.com/dclawrence003/NME/main/modeler/Get-NerdioModelerJson.ps1' -OutFile ./modeler.ps1
# open it, read it, then:
./modeler.ps1
```

### Parameters (all optional)

| Parameter | Default | What it does |
|---|---|---|
| `-ModelName` | `AVD Environment - Actuals` | Model name shown in the Modeler |
| `-LookbackDays` | `30` | Days of usage history analyzed |
| `-TimeZone` | `America/New_York` | Your environment's local time zone (IANA) for work-hours math. `America/Chicago`, `Europe/London`, etc. |
| `-SubscriptionId` | all visible | Narrow to specific subscription ID(s). Default is every enabled subscription the sign-in can see, listed at run start |
| `-OutFile` | timestamped | Output JSON name |
| `-SkipCosts` | off | Skip the actual-spend pull |
| `-SkipDownload` | off | Skip the Cloud Shell auto-downloads |

Parameters require the two-step (download, then run) form. `iex (irm ...)` runs with defaults.

---

## What you need

- **Reader** on the subscription(s) holding the AVD host pools and session hosts.
- Reader on the Log Analytics workspace(s) receiving AVD diagnostics.
- AVD diagnostic settings feeding `WVDConnections` somewhere, if you want usage numbers. Pools with session hosts but no telemetry still land in the JSON: flagged, 1 user, defaulted hours, named `... (no usage data)`. Pools with neither hosts nor activity are excluded from the JSON and flagged `EMPTY` in the review table.

Nothing needs to be installed. Cloud Shell ships every module the script uses, and Resource Graph is reached over REST.

---

## What it produces

**The import JSON.** Schema-4 Nerdio Modeler format, one deployment per host pool that has real compute or activity behind it. Empty shells (a pool object with no session hosts and no activity in the lookback) stay out of the JSON, because a defaulted 1-user deployment would only skew the model. They are flagged `EMPTY` in the review table and counted in the console.

**The review table and CSV.** Per pool: resource group, type, SKU, session limit, density used, observed per-host peak, peak concurrent users, MAU, observed work window and days, overtime fields, actual last-month cost (`ActualMo`, when retrievable), and a `Flags` column that names every default or adjustment applied. MAU is the count of distinct users seen in the lookback. It is informational only and never enters the JSON; it answers "the model says 24 users, we have 5,000" and feeds licensing conversations. If a value was touched, the flag says so. Nothing is changed silently.

**The storage ledger** (`...-storage-ledger.csv`). Every discovered Azure Files share and NetApp capacity pool, classified (profiles, app attach, not AVD, unknown) with evidence, confidence, serving pools, sizes, billing model, and actual cost where visible. Storage never enters the import JSON. See the FSLogix section below.

**The raw observation data.** `...-rawdata.json` holds the inventory, VM and disk specs, workspaces, usage aggregates, storage findings, the empty-pool list, cost rows, and run parameters. `...-usage-buckets.csv` holds per-pool concurrency in 15-minute slots. This is everything the model was computed from, so if the model needs tuning after review, it can be re-derived from the zip without asking anyone to run it again.

**Console summary.** Pool counts, workspaces found, usage coverage, the resource groups where session-host VMs live (that list is the Cost Management filter for manual comparisons), and cost totals split into spend attributed to session hosts and disks vs. other VM and Storage spend in the same resource groups.

---

## How it reads the environment

1. **Scope.** The run enumerates every enabled subscription the sign-in can see, prints the list, and pins it onto every Resource Graph query. `-SubscriptionId` narrows it. Nothing is left to whatever the current context happens to default to. Two windows signed into different scopes once produced 120-pool and 18-pool answers for the same environment with no way to tell from the logs. Now you can tell.
2. **Inventory.** Every host pool across those subscriptions via Azure Resource Graph: type, session limit, app group preference, resource group, region. Per-subscription pool counts print.
3. **Session hosts to VMs.** Each pool's registered hosts resolve to their VMs: size, OS disk (size and SKU), image type, ephemeral flag. The pool is represented by its most common VM size, a true majority; two D2as hosts outvote one D8as even when they run different images. Image and disk come from the most common combo among hosts of that size. Ties break deterministically, so PowerShell 5.1, 7, and Cloud Shell pick the identical spec from identical hosts.
4. **Workspace discovery.** Reads every host pool's diagnostic settings and finds all Log Analytics workspaces receiving AVD telemetry. No hunting for the right workspace, and environments that split pools across workspaces are handled automatically.
5. **Usage.** 30 days of `WVDConnections` per workspace, bucketed into 15-minute concurrency slots of distinct users. From that: peak concurrent users, observed work days (days whose user-hours reach 25% of the busiest day's), the observed work window (hours at 20% of peak or better, measured on work days), weekly in-window vs. off-window user-hours, per-pool MAU, and peak users on any single host. Day and hour averages include the quiet slots and are normalized by each weekday's actual calendar count in the lookback. A 30-day window holds five of some weekdays and four of others; uniform-week math penalized the four-count days about 20%, enough to cost a real call center its Saturday shift. Concurrency counts connected sessions. NME's console counts sessions including disconnected and reads higher; sizing is unaffected because peak and per-host density share the same basis. Pools where session counts run 15% or more above connected peaks (from `WVDAgentHealthStatus`, when present) are flagged.
6. **Assembly.** The modeling rules below, a flag for every default, and empty shells set aside: counted, flagged, never in the JSON.
7. **Profile storage.** Azure Files shares and SMB NetApp volumes that could hold FSLogix profiles, with provisioned and used capacity. When file-access diagnostics flow to Log Analytics, also which host pools use each share.
8. **Actual spend.** Last calendar month's cost for exactly those session-host VMs and OS disks, per resource group, via the Cost Management Query API.

---

## The modeling rules (what lands in the JSON, and why)

The goal is a model of how your pools actually run, so the Nerdio number is credible and the savings come from real levers: hours and true concurrency, not optimistic assumptions.

- **Users = observed peak concurrent**, not assigned users. Floored at 1 (the Modeler minimum) on pools that have hosts but showed no usage.
- **Work days and hours = observed**, not the scaling plan's schedule. Windows never cross midnight (Modeler max is 23:45); only full-day windows get trimmed.
- **Weekend and off-hours load** folds into the Modeler's overtime fields (percent of users times additional hours, applied across 7 days), reconciled so weekly compute hours match what was observed.
- **Density (users per vCPU) = observed peak users on a single host**, capped at the configured session limit. How your hosts are actually packed is what the model should price. Falls back to session limit divided by vCPUs when there is no telemetry; last resort is 1.0. Both fallbacks are flagged. The review table shows `PerHostPeak` next to `Limit`, and the gap between them is density headroom.
- **SKUs are reported exactly as found**, never substituted. The model uses the Custom workload type, which accepts any AVD SKU.
- **Disks are reported as found.** Size snaps up to the Modeler's offered tiers (128/256/512/1024/2048/4096 GB) only when the actual size isn't offered. Stopped-disk type is always Standard HDD, because disk switching is the Nerdio feature being modeled.
- **Empty pools never enter the JSON.** A pool object with no session hosts and no activity in the lookback is noise, and a fake 1-user deployment skews the totals. Empty pools are flagged `EMPTY` in the review table, listed in rawdata.json, and counted in the console.
- **Storage never enters the JSON either.** Every pool exports with fsLogix off, and everything storage lands in the ledger. See the next section.
- Not derivable from Azure, so left for manual touch-up after import: RDP egress GB (10) and custom-image build-VM hours.

---

## FSLogix profile storage: the ledger

FSLogix configuration lives in Group Policy or Intune. Nothing in Azure says "this pool uses FSLogix," and this tool will not reach inside session hosts to look. What Azure does show, with the same Reader access, is the storage the profiles could live on: Azure Files shares and SMB NetApp volumes. The tool discovers all of it and applies one rule: **storage never enters the Modeler JSON.** The import carries host pools only, an Azure compute model. Everything storage lands in the storage ledger CSV, always in the zip. The run never stops to ask anything.

Each ledger row is one billing unit: SKU and billing model (premium and provisioned-v2 bill on provisioned GB, v1 standard bills on used), provisioned and used capacity, an automatic classification (name match means profiles, msix means app attach, pvcn/mq/sftp patterns mean not AVD, everything else is unknown), pool evidence with a confidence level when file-share diagnostics exist, and actual last-month cost where cost visibility allows. Pool evidence comes from `StorageFileLogs` caller IPs correlated with session-host IPs, and the tool checks each storage account's own diagnostics workspace, not just the AVD ones. NetApp is quantified at the capacity pool, the thing Azure actually bills, with member volumes listed and shared pools flagged.

Sizes are resilient. Share stats retry once, then fall back to Azure Monitor's `FileCapacity` metric; huge shares can time the stats call out, and the metric is precomputed. A census line ends the stage: accounts scanned, skipped (named), stores sized and unsized. Gaps are visible, never silent. If profile storage should appear in a Modeler scenario, add it by hand using the ledger's numbers. The ledger is the storage conversation.

---

## The cost comparison (`ActualMo`)

For every resource group holding session-host VMs, the script queries the Cost Management Query API for last calendar month, filtered to Virtual Machines and Storage, grouped by resource. Cost is then attributed to each pool's VMs and OS disks. Amortized cost is tried first, so environments with Reservations or Savings Plans get honest numbers. Pay-as-you-go offers that reject amortized queries fall back to actual cost.

**Permissions:** the same Reader access the script already needs. Any of Owner, Contributor, Reader, or Cost Management Reader at RG or subscription scope works.

**When it skips (by design):** cost API failures are almost never RBAC. They are billing-side policy: CSP subscriptions without customer cost visibility, EA enrollments where the admin disabled "view charges," or offer types with no cost API support at all (sponsored, internal, MSDN; typical in demo and lab tenants). Each failing scope is skipped with one warning line quoting Azure's actual error. The model, review table, JSON, and downloads are never affected. `-SkipCosts` turns the pull off entirely.

Reading the numbers: `ActualMo` already includes whatever your current scaling setup saves you. The comparison is Nerdio-run vs. how the environment is managed today. That's the honest comparison, and the one that shows where Nerdio's value actually comes from.

---

## No Cloud Shell?

Two fallbacks, in order:

1. **Local PowerShell.** Same command, same output. See "Running from a local machine" in the Quick start. This also covers workspaces that reject queries from public networks; run from inside the customer network and the query usually passes.
2. **Portal-paste KQL**, in the `fallback/` folder, for tenants where both shells are off the table:
   - `modeler-make-json.kql`: run it in the Log Analytics workspace that receives AVD diagnostics (find it: any host pool > Diagnostic settings). One result row holds check columns (`WorkspaceCheck`, pool counts, `FlaggedPools`) plus the complete import JSON in the `ModelerImportJson` cell. Export to CSV, then one command unwraps it. Instructions are in the file header, Windows and Mac.
   - `modeler-detail-grid.kql`: optional per-pool magnifier when a flag needs investigating.

   Caveats vs. the script: you find the workspace yourself, extra workspaces are a commented one-line edit, and there is no storage ledger or cost pull.

---

## Troubleshooting

| Symptom | Meaning |
|---|---|
| `WorkspaceCheck: FAIL`, or all pools show "no telemetry" | No `WVDConnections` data is reachable. Diagnostics were never enabled, or they flow to a workspace the account can't read |
| `Found 0 diagnostic workspace(s)` | No host pool has diagnostic settings; usage will be defaulted for every pool |
| Cost lines skipped with an error message | Billing-side policy or unsupported offer (see the cost section); everything else completed |
| A pool shows defaults with `VM spec defaulted` | The pool has no registered session hosts to sample |
| Pools flagged `EMPTY` in the review CSV but missing from the JSON | By design. The pool exists in Azure but has no session hosts and no activity in the lookback. A defaulted deployment would skew the model, so it's reported instead of exported |
| Peak = 1 pools show odd windows | With one observed user, any active hour counts as "working." Noise on near-idle pools, meaningless at real load |
| A workspace prints `BLOCKED BY ITS NETWORK SETTINGS` | The workspace only accepts queries from approved networks (Network Security Perimeter, public query access off, or private link). Not a permissions problem. Run the same command from inside the customer network (local PowerShell on a VPN or corporate machine), or allow the runner's IP in the workspace's networking settings |
| Fewer pools than expected | Check the run's opening lines: signed-in account, tenant, and the subscription list. The usual cause is the wrong tenant; `Connect-AzAccount -TenantId <id>` and run again. A run covers one tenant, and the script names any others your account can reach |
| Storage ledger rows have an empty `ServesPools` | File-share diagnostics aren't flowing to Log Analytics, so share-to-pool mapping has no evidence. Sizes and costs are still correct; ask the AVD admin which pools use the share |
| `THIS COPY IS STALE` warning, or an old version number on the first line | The machine is running old code, usually a saved `modeler.ps1` or a replayed command pinned to an old commit. Delete saved copies and re-paste the Quick start command. The raw URL also caches for about 5 minutes right after an update |
| Auto-download didn't fire | Use Cloud Shell's Manage files > Download and enter the printed filename |

---
