# NME Field Tools

Read-only tools for environments evaluating or moving to Nerdio Manager for Enterprise. Each tool is one command in the cloud shell of the platform it reads (Azure Cloud Shell, or AWS CloudShell for the AWS modeler), and each folder has its own README with the full instructions.

| Tool | What it does |
|---|---|
| [`modeler/`](modeler/) | Builds a Nerdio Modeler import file from your environment's **actual usage**: every host pool tenant-wide, real SKUs and disks, observed concurrency and working hours, blue/green slot pairs merged into one deployment per family, tenant-wide peak and distinct-user counts (counts only, no names anywhere in the output), an FSLogix storage ledger CSV, last month's actual spend split into VMs and disks, and the Azure agreement discount measured against retail. Runs in Cloud Shell or local PowerShell (7 or 5.1) with the same one command |
| [`autoscale/`](autoscale/) | Translates your Azure **scaling plans** into exact, line-by-line entries for NME's Create Auto-Scale Profile screen. Day-one behavior mimicry, one card per host pool |
| [`modeler-aws/`](modeler-aws/) | The AWS counterpart of the modeler, for estates moving **from Amazon WorkSpaces, WorkSpaces Pools, WorkSpaces Applications (AppStream) or EC2-hosted VDI to AVD**: inventory, CloudWatch concurrency and connected hours, Cost Explorer spend, and a Modeler import file that proposes the AVD equivalent per group. One command in AWS CloudShell. First test candidate (v0.1.1) |

None of the tools changes anything in your environment. Every call is a read. The Azure folders also ship a `fallback/` query for tenants where Cloud Shell is blocked.
