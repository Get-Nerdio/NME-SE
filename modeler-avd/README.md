# Nerdio Modeler Import Builder

Turns your **actual AVD environment** — every host pool, tenant-wide — into an import file for the Nerdio Modeler, plus a per-pool review of what was found and (where permitted) what those pools **actually cost last month**.

One command in Azure Cloud Shell — or in local PowerShell (7 or the built-in Windows PowerShell 5.1) after `Connect-AzAccount`. Read-only. Nothing in your environment is changed.

A cost model is only as credible as the data behind it. This tool feeds the Modeler reality instead of estimates: real SKUs, real disks, real session limits, observed concurrency and working hours — from every host pool, not a sample. The result is a model that dials in Nerdio's value against how your environment actually runs, so the savings it shows are savings you can expect to keep.

---

## Quick start

1. Open **Azure Cloud Shell** in the tenant that hosts your AVD environment (portal, `>_` icon), **PowerShell** mode.
2. Paste:

   ```powershell
   iex (irm 'https://raw.githubusercontent.com/dclawrence003/NME/main/modeler/Get-NerdioModelerJson.ps1')
   ```

3. Read the review table it prints (one row per pool — anything defaulted is spelled out in `Flags`). The run never stops to ask anything. It opens by naming the **signed-in account, tenant, and every subscription in scope** — if a pool you expected is missing, that header is where to look first (a run covers **one tenant**; the script warns when your account can reach others).
4. One zip downloads automatically: `modeler-import-<timestamp>.zip` — the import JSON, the review CSV, the **storage ledger CSV**, the raw observation data, and the run's full console log. If someone asked you to run this, **that zip is the only thing to send back**.
5. Nerdio Modeler → **Import** → pick the JSON (from the zip). Done.

**Running from a local machine instead:** the **Az.Accounts** module is all it takes (`Install-Module Az.Accounts` once, then `Connect-AzAccount` — add `-TenantId <id>` if you have several tenants, and sign in **as the account that has Reader on the environment you're scanning**; the run header names the account, tenant, and subscriptions it can see, so a wrong sign-in is visible on line 2). Not signed in? The script stops immediately with that exact instruction — it never half-runs. Then paste **the exact same command** — nothing about it changes between Cloud Shell and local. Works in PowerShell 7 (recommended) *and* the built-in Windows PowerShell 5.1. No other Az modules are used — inventory, telemetry, storage, and cost are all reached over REST. The only difference: instead of a browser auto-download, the zip is saved to your **Downloads** folder (full path printed at the end of the run). In Cloud Shell there is nothing to install or sign into — the shell is already authenticated as the portal user.

Prefer to read code before running it (you should):

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
| `-TimeZone` | `America/New_York` | Your environment's local time zone (IANA) for work-hours math — `America/Chicago`, `Europe/London`, etc. |
| `-SubscriptionId` | all visible | Narrow to specific subscription ID(s). Default: every enabled subscription the sign-in can see, listed at run start |
| `-OutFile` | timestamped | Output JSON name |
| `-SkipCosts` | off | Skip the actual-spend pull |
| `-SkipDownload` | off | Skip the Cloud Shell auto-downloads |

Parameters require the two-step (download-then-run) form — `iex (irm ...)` runs with defaults.

---

## What you need

- **Reader** on the subscription(s) holding the AVD host pools and session hosts.
- Access to the Log Analytics workspace(s) receiving AVD diagnostics (Reader there too).
- AVD diagnostic settings feeding `WVDConnections` somewhere, if you want usage numbers. Pools without telemetry still land in the JSON — flagged, with 1 user and defaulted hours, named `... (no usage data)`.

Nothing needs to be installed: Cloud Shell ships every module the script uses, and Resource Graph is reached over REST.

---

## What it produces

**The import JSON** — schema-4 Nerdio Modeler format, one deployment per host pool, every pool in the tenant.

**The review table / CSV** — per pool: resource group, type, SKU, session limit, density used, observed per-host peak, peak concurrent users, `MAU` (distinct users seen in the lookback — informational only, never in the JSON; it answers "the model says 24 users, we have 5,000" and feeds licensing conversations), observed work window and days, overtime fields, actual last-month cost (`ActualMo`, when retrievable), and a `Flags` column that names every default or adjustment applied. If a value was touched, it says so — nothing is changed silently.

**The storage ledger** — `...-storage-ledger.csv`: every discovered Azure Files share and NetApp capacity pool, classified (profiles / app attach / not AVD / unknown) with evidence, confidence, serving pools, sizes, billing model, and actual cost where visible. Storage never enters the import JSON. See the FSLogix section below.

**The raw observation data** — `...-rawdata.json` (inventory, VM and disk specs, workspaces, usage aggregates, storage findings and confirmed mappings, cost rows, run parameters) and `...-usage-buckets.csv` (per-pool concurrency in 15-minute slots). This is everything the modeling rules were computed *from*, so if the model needs tuning after review, it can be re-derived from the zip — without asking you to run anything again.

**Console summary** — pool counts, workspaces found, usage coverage, the resource groups where session-host VMs live (that list is the Cost Management filter for manual comparisons), and cost totals split into *attributed to session hosts + disks* vs. *other VM/Storage spend in the same resource groups*.

---

## How it reads the environment

1. **Scope** — the run enumerates every enabled subscription the sign-in can see, prints the list, and pins it onto every Resource Graph query (`-SubscriptionId` narrows it). Nothing is left to whatever the current context happens to default to — two windows signed into different scopes once produced 120-pool and 18-pool answers for "the same environment" with no way to tell from the logs.
2. **Inventory** — every host pool across those subscriptions via Azure Resource Graph (type, session limit, app group preference, RG, region), with per-subscription pool counts printed.
3. **Session hosts → VMs** — each pool's registered hosts resolved to their VM resource IDs, then VM size, OS disk (size + SKU), image type, ephemeral flag. The pool is represented by its **most common VM size** (a true majority — two D2as hosts outvote one D8as even if they run different images), then the most common image/disk combo among hosts of that size; every tie breaks deterministically, so PowerShell 5.1, 7, and Cloud Shell pick the identical spec from identical hosts.
4. **Workspace discovery** — reads every host pool's diagnostic settings and finds **all** Log Analytics workspaces receiving AVD telemetry. No "which workspace?" hunting; environments that split pools across workspaces are handled automatically.
5. **Usage** — 30 days of `WVDConnections` per workspace: 15-minute concurrency buckets (distinct users) produce peak concurrent users, observed work days (days whose per-occurrence user-hours reach ≥25% of the busiest day's), the observed work window (hours ≥20% of peak, measured on work days), weekly in-window vs. off-window user-hours, per-pool MAU, and peak concurrent users on any single host. Day and hour averages are zero-inclusive and normalized by each weekday's actual calendar count in the lookback (a 30-day window holds five of some weekdays and four of others — uniform-week math penalized the four-count days ~20%, enough to cost a real call center its Saturday shift). Concurrency counts **connected** sessions; NME's console counts sessions including disconnected and reads higher — sizing is unaffected because peak and per-host density share the same basis, and pools where session counts run ≥15% above connected peaks (from `WVDAgentHealthStatus`, when present) are flagged.
6. **Assembly** — the modeling rules below, a flag for every default.
7. **Profile storage** — Azure Files shares and SMB NetApp volumes that hold FSLogix profiles, with provisioned and used capacity — and, when file-access diagnostics flow to Log Analytics, which host pools use each share (see the FSLogix section below).
8. **Actual spend** — last calendar month's cost for exactly those session-host VMs and OS disks, per resource group, via the Cost Management Query API (see below).

---

## The modeling rules (what lands in the JSON, and why)

The goal is a model of how your pools **actually run**, so the Nerdio number is credible and the savings come from real levers — hours and true concurrency — not from optimistic assumptions.

- **Users = observed peak concurrent**, not assigned users. Floored at 1 (Modeler minimum) on zero-utilization pools.
- **Work days/hours = observed**, not the scaling plan's schedule. Windows never cross midnight (Modeler max 23:45); only full-day windows get trimmed.
- **Weekend + off-hours load** folds into the Modeler's overtime fields (% of users × additional hours, applied across 7 days), reconciled so weekly compute hours match observation.
- **Density (users per vCPU) = observed peak users on a single host** (capped at the configured session limit), because how your hosts are actually packed is what the model should price. Falls back to session limit ÷ vCPUs when there's no telemetry; last resort 1.0 — both fallbacks flagged. The review table shows `PerHostPeak` next to `Limit`: the gap between them is density headroom.
- **SKUs are reported exactly as found** — never substituted. The model uses the Custom workload type, which accepts any AVD SKU.
- **Disks reported as found** (Premium SSD / Standard SSD / Standard HDD); size snapped **up** to the Modeler's offered tiers (128/256/512/1024/2048/4096 GB) only when the actual size isn't offered. Stopped-disk type is always Standard HDD — disk switching is the Nerdio feature being modeled.
- **FSLogix profile storage is modeled from the storage itself** — one small "FSLogix — \<share\>" deployment per discovered profile store, carrying the measured GB (see the FSLogix section below). Individual pools keep fsLogix off so storage is never double-counted.
- Not derivable from Azure, so left for manual touch-up after import: RDP egress GB (10), custom-image build-VM hours.

---

## FSLogix profile storage — the ledger

FSLogix's *configuration* lives in Group Policy or Intune — nothing in Azure says "this pool uses FSLogix," and this tool will not reach inside session hosts to look. What Azure does show, with the same Reader access, is the *storage the profiles could live on*: Azure Files shares and SMB NetApp volumes. The tool discovers all of it and applies one simple rule: **storage never enters the Modeler JSON.** The import carries host pools only — an Azure *compute* model — and everything storage lands in the **storage ledger CSV** (`…-storage-ledger.csv`, always in the zip). The run never stops to ask anything.

Each ledger row is one billing unit with: SKU and billing model (premium and provisioned-v2 bill **provisioned** GB, v1 standard bills **used**), provisioned and used capacity, an automatic classification (name-matched → profiles, `msix` → app attach, `pvcn-`/`mq`/`sftp` patterns → not AVD, else unknown), pool evidence with confidence when file-share diagnostics exist (`StorageFileLogs` caller IPs correlated with session-host IPs — the tool also checks each storage account's own diagnostics workspace, not just the AVD ones), and actual last-month cost where cost visibility allows. **NetApp is quantified at the capacity pool** — the thing Azure actually bills — with member volumes listed and shared pools flagged.

Sizes are resilient: share stats retry once, then fall back to Azure Monitor's `FileCapacity` metric (huge shares can time the stats call out; the metric is precomputed), and a census line ends the stage — accounts scanned, skipped (named), stores sized and unsized — so gaps are visible, never silent. If profile storage should appear in a Modeler scenario, add it by hand in the Modeler using the ledger's numbers — the ledger is the storage conversation.

---

## The cost comparison (`ActualMo`)

For every resource group holding session-host VMs, the script queries the **Cost Management Query API** for last calendar month, filtered to Virtual Machines + Storage services, grouped by resource — then attributes cost to each pool's VMs and OS disks. **Amortized** cost is tried first (so environments with Reservations or Savings Plans get honest numbers), falling back to actual cost on pay-as-you-go offers that don't support amortized queries.

**Permissions:** the same Reader access the script already needs is sufficient — any of Owner / Contributor / Reader / Cost Management Reader at RG or subscription scope.

**When it skips (by design):** cost API failures are almost never RBAC. They're billing-side policy — CSP subscriptions without customer cost visibility enabled, EA enrollments where the admin disabled "view charges," or offer types with no cost API support at all (sponsored / internal / MSDN — typical in demo and lab tenants). Each failing scope is skipped with one warning line quoting Azure's actual error; the model, review table, JSON, and downloads are never affected. `-SkipCosts` turns the pull off entirely.

Reading the numbers: `ActualMo` already includes whatever your current scaling setup saves you. The comparison is *Nerdio-run vs. how the environment is managed today* — the honest one, and the one that shows where Nerdio's value actually comes from.

---

## No Cloud Shell? The fallback

Some tenants block Cloud Shell. The `fallback/` folder holds the same logic as portal-paste queries:

1. `modeler-make-json.kql` — run in the Log Analytics workspace that receives AVD diagnostics (find it: any host pool → Diagnostic settings). One result row: check columns (`WorkspaceCheck`, pool counts, `FlaggedPools`) plus the complete import JSON in the `ModelerImportJson` cell. Export → CSV, then one command unwraps it (instructions in the file header, Windows and Mac).
2. `modeler-detail-grid.kql` — optional per-pool magnifier when a flag needs investigating.

Fallback caveats vs. the script: you find the workspace yourself, extra workspaces are a commented one-line edit, and there's no cost pull.

---

## Troubleshooting

| Symptom | Meaning |
|---|---|
| `WorkspaceCheck: FAIL` / all pools "no telemetry" | No `WVDConnections` data reachable — diagnostics never enabled, or they flow to a workspace the account can't read |
| `Found 0 diagnostic workspace(s)` | No host pool has diagnostic settings — usage will be defaulted for every pool |
| Cost lines skipped with an error message | Billing-side policy or unsupported offer (see cost section); everything else completed |
| A pool shows defaults with `VM spec defaulted` | Pool has no registered session hosts to sample |
| Peak = 1 pools show odd windows | With one observed user, any active hour counts as "working" — noise on near-idle pools, meaningless at real load |
| Fewer pools than expected | Check the run's opening lines: signed-in account, tenant, and the subscription list. The usual cause is the wrong tenant — `Connect-AzAccount -TenantId <id>` and run again. A run covers one tenant; the script names any others your account can reach |
| Storage ledger rows have empty `ServesPools` | File-share diagnostics aren't flowing to Log Analytics, so share→pool mapping has no evidence — sizes and costs are still correct; ask the AVD admin which pools use the share |
| `THIS COPY IS STALE` warning, or an old version number on the first line | The machine is running old code — usually a saved `modeler.ps1` or a replayed command pinned to an old commit. Delete saved copies and re-paste the Quick-start command. (The raw URL also caches ~5 minutes right after an update) |
| Auto-download didn't fire | Use Cloud Shell's **Manage files → Download** and enter the printed filename |

---

*Read-only by design: every call is a GET or a query. Version and change notes are in the script header.*
