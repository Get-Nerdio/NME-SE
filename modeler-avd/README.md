# Nerdio Modeler Import Builder

Turns your **actual AVD environment** — every host pool, tenant-wide — into an import file for the Nerdio Modeler, plus a per-pool review of what was found and (where permitted) what those pools **actually cost last month**.

One command in Azure Cloud Shell. Read-only. Nothing in your environment is changed.

A cost model is only as credible as the data behind it. This tool feeds the Modeler reality instead of estimates: real SKUs, real disks, real session limits, observed concurrency and working hours — from every host pool, not a sample. The result is a model that dials in Nerdio's value against how your environment actually runs, so the savings it shows are savings you can expect to keep.

---

## Quick start

1. Open **Azure Cloud Shell** in the tenant that hosts your AVD environment (portal, `>_` icon), **PowerShell** mode.
2. Paste:

   ```powershell
   iex (irm 'https://raw.githubusercontent.com/dclawrence003/NME/main/modeler/Get-NerdioModelerJson.ps1')
   ```

3. Read the review table it prints (one row per pool — anything defaulted is spelled out in `Flags`).
4. Two files download automatically: `modeler-import-<timestamp>.json` and `modeler-import-<timestamp>-review.csv`.
5. Nerdio Modeler → **Import** → pick the JSON. Done.

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
| `-SubscriptionId` | all visible | Scope to specific subscription ID(s) |
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

**The review table / CSV** — per pool: resource group, type, SKU, session limit, density used, observed per-host peak, peak concurrent users, observed work window and days, overtime fields, actual last-month cost (`ActualMo`, when retrievable), and a `Flags` column that names every default or adjustment applied. If a value was touched, it says so — nothing is changed silently.

**Console summary** — pool counts, workspaces found, usage coverage, the resource groups where session-host VMs live (that list is the Cost Management filter for manual comparisons), and cost totals split into *attributed to session hosts + disks* vs. *other VM/Storage spend in the same resource groups*.

---

## How it reads the environment

1. **Inventory** — every host pool in the tenant via Azure Resource Graph (type, session limit, app group preference, RG, region).
2. **Session hosts → VMs** — each pool's registered hosts resolved to their VM resource IDs, then VM size, OS disk (size + SKU), image type, ephemeral flag. The most common spec in a pool represents it.
3. **Workspace discovery** — reads every host pool's diagnostic settings and finds **all** Log Analytics workspaces receiving AVD telemetry. No "which workspace?" hunting; environments that split pools across workspaces are handled automatically.
4. **Usage** — 30 days of `WVDConnections` per workspace: 15-minute concurrency buckets (distinct users) produce peak concurrent users, observed work days (days reaching ≥25% of pool peak), the observed work window (hours ≥20% of peak, measured on primary days), weekly in-window vs. off-window user-hours, and peak concurrent users on any single host.
5. **Assembly** — the modeling rules below, a flag for every default.
6. **Actual spend** — last calendar month's cost for exactly those session-host VMs and OS disks, per resource group, via the Cost Management Query API (see below).

---

## The modeling rules (what lands in the JSON, and why)

The goal is a model of how your pools **actually run**, so the Nerdio number is credible and the savings come from real levers — hours and true concurrency — not from optimistic assumptions.

- **Users = observed peak concurrent**, not assigned users. Floored at 1 (Modeler minimum) on zero-utilization pools.
- **Work days/hours = observed**, not the scaling plan's schedule. Windows never cross midnight (Modeler max 23:45); only full-day windows get trimmed.
- **Weekend + off-hours load** folds into the Modeler's overtime fields (% of users × additional hours, applied across 7 days), reconciled so weekly compute hours match observation.
- **Density (users per vCPU) = observed peak users on a single host** (capped at the configured session limit), because how your hosts are actually packed is what the model should price. Falls back to session limit ÷ vCPUs when there's no telemetry; last resort 1.0 — both fallbacks flagged. The review table shows `PerHostPeak` next to `Limit`: the gap between them is density headroom.
- **SKUs are reported exactly as found** — never substituted. The model uses the Custom workload type, which accepts any AVD SKU.
- **Disks reported as found** (Premium SSD / Standard SSD / Standard HDD); size snapped **up** to the Modeler's offered tiers (128/256/512/1024/2048/4096 GB) only when the actual size isn't offered. Stopped-disk type is always Standard HDD — disk switching is the Nerdio feature being modeled.
- Not derivable from Azure, so left for manual touch-up after import: FSLogix (defaults off), RDP egress GB (10), custom-image build-VM hours.

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
| Auto-download didn't fire | Use Cloud Shell's **Manage files → Download** and enter the printed filename |

---

*Read-only by design: every call is a GET or a query. Version and change notes are in the script header.*
