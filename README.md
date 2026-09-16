# NME Field Tools

Read-only tools for AVD environments evaluating or moving to Nerdio Manager for Enterprise. Each tool is one Azure Cloud Shell command, and each folder has its own README with the full instructions.

| Tool | What it does |
|---|---|
| [`modeler/`](modeler/) | Builds a Nerdio Modeler import file from your environment's **actual usage**: every host pool tenant-wide, real SKUs and disks, observed concurrency and working hours, blue/green slot pairs merged into one deployment per family, tenant-wide peak and distinct-user counts (counts only, no names anywhere in the output), an FSLogix storage ledger CSV, last month's actual spend split into VMs and disks, and the Azure agreement discount measured against retail. Runs in Cloud Shell or local PowerShell (7 or 5.1) with the same one command |
| [`autoscale/`](autoscale/) | Translates your Azure **scaling plans** into exact, line-by-line entries for NME's Create Auto-Scale Profile screen. Day-one behavior mimicry, one card per host pool |

Neither tool changes anything in your environment. Every call is a read. Each folder also ships a `fallback/` query for tenants where Cloud Shell is blocked.
