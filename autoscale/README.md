# Scaling Plan → NME Auto-Scale Profile

Turns your Azure Virtual Desktop **scaling plans** into exact entries for Nerdio Manager's **Create Auto-Scale Profile** screen — an HTML page with one profile card per host pool, laid out the way the NME screen is, plus a review CSV of every number and where it came from.

One command in Azure Cloud Shell. Read-only. Nothing in your environment is changed.

Moving from native scaling plans to NME auto-scale shouldn't change how your environment behaves on day one. The two systems describe scaling in different languages — schedules and phases on one side, continuous triggers and pre-staging on the other — so a straight field-for-field copy doesn't exist. This tool translates behavior-for-behavior: the profile it prescribes holds the same overnight floors, the same seat headroom, the same ramp times, and the same logoff rules your plan enforces today. Once NME is running and gathering telemetry, optimize from there — with changes you chose, not surprises baked into the migration.

---

## Quick start

1. Open **Azure Cloud Shell** in the tenant that hosts your AVD environment (portal, `>_` icon), **PowerShell** mode.
2. Paste:

   ```powershell
   iex (irm 'https://raw.githubusercontent.com/dclawrence003/NME/main/autoscale/Get-NerdioAutoscaleSheet.ps1')
   ```

3. A review table prints (one row per pool + schedule), and one zip downloads automatically: `nme-autoscale-profiles-<timestamp>.zip` — the HTML, the review CSV, and the run's console log. If someone asked you to run this, that zip is the only thing to send back.
4. Open the HTML. For each host pool, open its Auto-scale settings in NME and enter the card top to bottom — toggles, pills, and day chips read exactly as the NME controls do.

Prefer to read code before running it (you should):

```powershell
irm 'https://raw.githubusercontent.com/dclawrence003/NME/main/autoscale/Get-NerdioAutoscaleSheet.ps1' -OutFile ./autoscale.ps1
# open it, read it, then:
./autoscale.ps1
```

### Parameters (all optional)

| Parameter | Default | What it does |
|---|---|---|
| `-SubscriptionId` | all visible | Scope to specific subscription ID(s) |
| `-OutFile` | timestamped | Output HTML file name (`-review.csv` follows it) |
| `-SkipDownload` | off | Skip the Cloud Shell auto-downloads |

Parameters require the two-step (download-then-run) form — `iex (irm ...)` runs with defaults.

---

## What you need

**Reader** on the subscription(s) holding the scaling plans and host pools. That's all — no Log Analytics access, no NME API, nothing installed. Cloud Shell ships every module the script uses. Inventory comes from Resource Graph; each plan's schedules and full properties are then read directly over ARM (Resource Graph doesn't carry pooled schedules).

---

## What it produces

**The profile page (.html)** — one card per host pool with an enabled scaling plan, laid out in the same order and idiom as NME's Create Auto-Scale Profile screen: sections, toggles, aggressiveness pills, work-day chips. Just the values to enter — open it next to NME and copy down the card. Weekend and other secondary schedules appear as additional pre-stage schedule blocks on the same card ("Use multiple schedules"). A compact Notes list on each card calls out every place the two systems express things differently — nothing is translated silently. Plans that need no data entry (assigned-but-not-enabled, no schedules, unassigned, personal) are summarized below the cards, and the pools with no plan at all sit in a collapsible list at the end.

**The review CSV** — one row per pool + schedule with the computed numbers (min active, pre-stage hosts, trigger thresholds, aggressiveness, scale-in delay) and a `Flags` column naming anything that needs a second look.

**Console summary** — the same review table and plan counts.

---

## How the translation works

An Azure scaling plan is schedule-driven: four phases per schedule, a capacity threshold, and minimum-host percentages. NME auto-scale is trigger-driven: sizing, one scaling trigger, pre-staging, and scale-in rules. Every plan behavior lands on a specific NME field:

- **Trigger = Available sessions, always.** Azure's capacity threshold counts active *and* disconnected sessions against the capacity of available hosts; NME's Available-sessions trigger uses the same accounting, so the mimic is faithful in disconnect-heavy environments too. (Average-sessions triggers ignore disconnected sessions and are not used here.) Scale out: up to 2 hosts when available sessions drop below `ceil(base × session limit × (100 − threshold%) / 100)` for 5 minutes. Scale in: up to 1 host when available sessions exceed that buffer plus one full host, for 15 minutes — Azure's remove-only-while-under-threshold rule, expressed in seats.
- **Base capacity = all registered hosts, Burst = 0.** A power-management plan never creates or deletes hosts, so the whole pool is the base and burst stays off.
- **Min active hosts = `ceil(ramp-down minimum % × base)`.** The ramp-down minimum carries into off-peak, making it the overnight floor. When schedules disagree, the **highest** wins — the profile never guarantees less than the plan did — and the sheet says which schedule raised it.
- **Scale-in aggressiveness maps 1:1** from ramp-down behavior: stop at zero sessions → **Low**; stop at zero *active* sessions → **Medium**; forced logoff → **High**, with NME Messaging carrying the plan's wait minutes and notification text **verbatim**.
- **Each Azure schedule becomes one pre-stage schedule**: its days, its ramp-up start time, `ceil(ramp-up minimum % × base)` hosts ready by start, and a scale-in delay spanning ramp-up start → ramp-down start (holding the daytime floor the way Azure's ramp-up minimum persists through peak). Multiple schedules (weekday/weekend) → turn on **Use multiple schedules**. NME's Alternative Schedule tab stays reserved for holidays and exceptions.
- **Load balancing = the plan's ramp-up/peak algorithm.** Azure allows a different algorithm per phase; NME uses one value. If your plan switches (say, depth-first at ramp-down), the sheet notes it — Rolling Drain Mode is the NME-native lever for that, best revisited after day one.
- **Exclusion tag**: NME excludes hosts per host, not by tag — the sheet names the currently-tagged hosts so you can exclude exactly them.
- **Time zone**: the plan's zone, printed on every sheet. Enter times as shown, no conversion.

Everything NME offers beyond the plan's vocabulary — CPU/RAM triggers, burst capacity, rolling drain, auto-heal — stays at defaults. Day one mimics; optimization comes after, informed by real telemetry.

### Scope

Pooled host pools with power-management (GA) scaling plans. Personal plans are listed but not translated yet. Dynamic autoscaling plans (the preview that creates/deletes hosts) are flagged for manual review — their base/burst math is different by nature. Pools where a plan is assigned but **not enabled** are listed as skips: Azure isn't scaling them today, so faithful mimicry means no profile there either.

---

## No Cloud Shell? The fallback

Some tenants block Cloud Shell. `fallback/nerdio-scalingplan-translator.kql` runs a best-effort version as a portal-paste query in **Azure Resource Graph Explorer** (portal search → "Resource Graph Explorer", paste, Run — full instructions in the file header). Know its limits: Resource Graph does not index pooled schedules in all tenants, so the fallback can come back empty where the script succeeds — the script's direct ARM reads are the reliable path. When it does return rows, they come one per pool + schedule (read the `Sheet` column, combine schedules by hand per the header's rules), with no auto-download.

---

## Troubleshooting

| Symptom | Meaning |
|---|---|
| "No scaling plans found" | None exist in the scoped subscriptions, or the account lacks Reader there — check `-SubscriptionId` and access |
| A pool shows `POOL NOT VISIBLE` | The plan references a pool in a subscription outside the current scope — re-run with `-SubscriptionId` covering it |
| A plan shows `NO HOST POOLS ASSIGNED` | The plan isn't attached to any pool, so Azure isn't scaling with it — nothing to enter in NME |
| A sheet shows 0 session hosts | The pool has no registered hosts, so every host-count number is 0 — register hosts and re-run |
| `no session limit` flag | The pool has no max session limit; Available-sessions math needs one — the card's Notes explain how to size the trigger once you set it |
| `session limit looks like a placeholder` | The pool's limit is implausibly large (e.g. 999999); trigger numbers use it verbatim — set the real per-host capacity and re-run |
| `dynamic plan - manual review` | The plan creates/deletes hosts (preview); review the card by hand before trusting base/burst |
| Auto-download didn't fire | Use Cloud Shell's **Manage files → Download** and enter the printed filename |

---

*Read-only by design: every call is a read. Version and change notes are in the script header. Sibling tool: [`modeler/`](../modeler/) builds a Nerdio Modeler import from the same environment's actual usage.*

---

*`test/Create-TestScalingPlans.ps1` is a demo-tenant fixture that **creates** two test scaling plans (and removes them with `-Remove`) for exercising this tool. Unlike everything else in this repo, it writes resources — read its header before running. Not needed for normal use.*
