# NME Field Tools

Practical, read-only tools for AVD environments moving to — or evaluating — Nerdio Manager for Enterprise. Each tool is one Azure Cloud Shell command and has its own README with full instructions.

| Tool | What it does |
|---|---|
| [`modeler/`](modeler/) | Builds a Nerdio Modeler import file from your environment's **actual usage** — every host pool tenant-wide, real SKUs and disks, observed concurrency and working hours, an FSLogix storage ledger CSV, plus last month's actual spend where cost visibility allows. Runs in Cloud Shell or local PowerShell (7 or 5.1) with the same one command |
| [`autoscale/`](autoscale/) | Translates your Azure **scaling plans** into exact, line-by-line entries for NME's Create Auto-Scale Profile screen — day-one behavior mimicry, one plain-text sheet per host pool |

Both tools change nothing in your environment: every call is a read. Each folder also ships a `fallback/` query for tenants where Cloud Shell is blocked.
