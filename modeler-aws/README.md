# Nerdio Modeler Import Builder for AWS

Reads a customer's AWS virtual desktop estate and writes a Nerdio Modeler import file with the AVD equivalent proposed for each group.  One command in AWS CloudShell.  Read-only.  Nothing in the account is changed.

This is the AWS version of the Azure tool in [`modeler/`](../modeler/).  Same outputs, same privacy rules, different plumbing.  AWS spreads VDI across several products, so this tool reads each one: WorkSpaces Personal, WorkSpaces Pools, WorkSpaces Applications (the product formerly called AppStream 2.0), and EC2 hosts you point it at.

**Status: v0.1.1, first test candidate.**  Every call it makes is checked offline against the AWS API definitions.  It has not run against a live AWS account yet.  See "First run" below.

---

## Quick start

1. Open **AWS CloudShell** in the account (the terminal icon in the console toolbar).  Any region works; the tool scans every enabled region.
2. Paste:

   ```bash
   curl -sSL https://raw.githubusercontent.com/dclawrence003/NME/main/modeler-aws/nerdio_modeler_aws.py | python3 -
   ```

3. Read the review table.  One row per group.  Anything defaulted is spelled out in `Flags`.  The run never stops to ask anything.  The first lines show the account, the principal type, and the regions it will scan.  If something you expected is missing, look there first.
4. One zip lands in the CloudShell home folder: `modeler-aws-<timestamp>.zip`.  Download it with **Actions > Download file** (top right of CloudShell) and paste the zip path the run printed.  If someone asked you to run this, that zip is the only thing to send back.
5. Nerdio Modeler > Import > pick the JSON from the zip.

Parameters go after the dash:

```bash
curl -sSL https://raw.githubusercontent.com/dclawrence003/NME/main/modeler-aws/nerdio_modeler_aws.py | python3 - --check --regions us-east-1
```

Want to read the code first?  Save it, then run it:

```bash
curl -sSL https://raw.githubusercontent.com/dclawrence003/NME/main/modeler-aws/nerdio_modeler_aws.py -o nerdio_modeler_aws.py
python3 nerdio_modeler_aws.py
```

**From a laptop:** `pip install boto3`, sign in with the AWS CLI (`aws configure`, or `aws sso login --profile name` and add `--profile name`), then run the same command.  The zip lands in your home folder.

### Parameters (all optional)

| Parameter | Default | What it does |
|---|---|---|
| `--check` | off | First-run mode.  Probes the price list even when there are no WorkSpaces to price.  The service access check prints with or without it |
| `--model-name` | `AVD Environment - From AWS` | Model name shown in the Modeler |
| `--lookback-days` | `30` | Days of usage history.  CloudWatch keeps 5-minute data for 63 days; past 60 the tool switches to hourly slots |
| `--time-zone` | `America/New_York` | The estate's local time zone (IANA) for work-hours math |
| `--regions us-east-1 us-west-2` | every enabled region | Narrow the scan |
| `--proposal pooled|personal|both` | `pooled` | How WorkSpaces Personal directories are written: AVD pooled multi-session sized on measured concurrency, like-for-like personal desktops, or both (delete one in the Modeler) |
| `--pooled-vm-size` | `Standard_D8s_v5` | Host size for pooled proposals |
| `--pooled-density` | `2.0` | Users per vCPU for pooled proposals.  The biggest assumption in the file.  It is written into every flag |
| `--azure-region` | mapped from the AWS region | Force one Azure region for every deployment |
| `--ec2-tag Key=Value` | off | Treat EC2 instances with this tag as VDI hosts (Citrix, Omnissa, RDSH).  Repeatable |
| `--ec2-name-regex` | off | Same, by Name tag pattern |
| `--ec2-as none|personal|pooled` | `none` | Whether EC2 hosts go into the Modeler JSON, and as what.  Users are a placeholder until broker data arrives |
| `--all-accounts` | off | AWS Organizations: assume `--role-name` into every active account |
| `--account id ...` | off | Assume `--role-name` into specific accounts |
| `--role-name` | `OrganizationAccountAccessRole` | Role for the two options above |
| `--skip-costs` | off | Skip Cost Explorer |
| `--skip-prices` | off | Skip the WorkSpaces price list |
| `--skip-usage-report` | off | Skip reading WorkSpaces Applications usage reports from S3 |
| `--out-dir` | home folder | Where the zip goes |
| `--demo` | off | Synthetic estate, no AWS calls.  Shows what the outputs look like.  Needs `nerdio_modeler_aws_demo.py` next to the script |

---

## What you need

A signed-in principal with the AWS managed policy **ReadOnlyAccess**, or this policy:

```json
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Resource": "*", "Action": [
  "sts:GetCallerIdentity", "ec2:DescribeRegions", "ec2:DescribeInstances",
  "workspaces:Describe*", "appstream:Describe*", "appstream:List*",
  "cloudwatch:GetMetricData", "cloudwatch:ListMetrics",
  "ce:GetCostAndUsage", "pricing:GetProducts",
  "s3:GetObject", "s3:ListBucket",
  "organizations:ListAccounts", "sts:AssumeRole"]}]}
```

The S3 lines are for the WorkSpaces Applications usage report bucket.  The Organizations and AssumeRole lines are only needed with `--all-accounts` or `--account`.

Cost Explorer has to be enabled on the account.  It usually is.  First-time enablement takes up to 24 hours.  In a member account of an Organization the payer may have turned off linked-account access; the run says so and carries on without costs.  Each Cost Explorer call costs $0.01.  A run makes six to eight of them.

Nothing to install in CloudShell.  Python 3 and boto3 are already there.

---

## First run

There is no AWS account behind this release yet.  Here is what is covered and what is not.

Done: an offline stand-in for AWS (`nerdio_modeler_aws_demo.py`) validates every request against the real botocore service definitions and checks every synthetic response against the real output shape.  A wrong parameter name or a field that does not exist in the API fails there.  `python3 tests/test_offline.py` runs the whole pipeline against it, 60-odd checks.

Not done: behavior only a live account can show.  Whether a given WorkSpace generation emits a metric, how Cost Explorer spells its usage types, how the price list spells its attributes.  All three degrade to a blank with a flag rather than a crash.

What to do with an empty or near-empty account:

1. Run `... | python3 - --check`.
2. Look at the `SERVICE ACCESS CHECK` block at the end.  One line per service: ok, denied, or unavailable, by region.  That tells you the script reached the right APIs with the right permissions, even with nothing to inventory.
3. Open the zip.  The JSON has zero deployments (nothing to import yet), the review CSV is header only, and `rawdata.json` has `serviceAccess`, the regions checked, and the cost summary.
4. If you can, create two WorkSpaces (one AlwaysOn, one AutoStop), connect once from a client, wait an hour, run again.  That exercises the per-WorkSpace metrics, the usage math and the price estimate.

On a customer account, run `--skip-costs --regions <theirs>` first.  That is inventory and CloudWatch only and finishes in a minute.  Then run it plain.  Send back the zip and the console output when something looks off; the fix is usually a few lines.

---

## What it produces

**The import JSON.**  Schema-4 Nerdio Modeler format, one deployment per group, pre-flighted against the Modeler's own import rules (users at least 1, density at least 0.1, a known disk tier, consistent overtime, a window that ends by 11:45 PM).  A file this script writes imports.

**The review table and CSV.**  Per group: account, AWS region and the Azure region it maps to, type, count (WorkSpaces, pool capacity, fleet instances, or EC2 hosts), running modes, platform, max sessions per instance on multi-session fleets, peak concurrent users and when, MAU where identities exist, user-hours, average connected hours per WorkSpace, WorkSpaces that never connected, AutoStop count, observed window, days and overtime, user-volume GB provisioned and used, the proposal (experience, VM size, density, hosts it implies with 15% headroom), the per-WorkSpace monthly estimate from the price list, and `Flags`.

**Account-wide counts.**  Peak concurrent users across everything (series added per 15-minute slot), distinct WorkSpaces users, and distinct users across every identified source.  No AWS API ties a Pools session to a person.  The per-user fee line on the bill is the closest thing, and the run prints it.

**The concurrency buckets** (`-usage-buckets.csv`).  Per group, per 15-minute UTC slot: concurrent users and running capacity.

**The cost rows** (`-cost.csv`).  Last full month and month to date from Cost Explorer, amortized and unblended.  Every service on the bill, so the VDI share of the AWS total is visible.  Then WorkSpaces and AppStream by usage type and linked account, and by region.  Usage types that read as per-user fees are totaled separately; their quantity is the number of distinct users AWS charged for.

**The raw data** (`-rawdata.json`).  Inventory, per-WorkSpace usage, groups with their usage aggregates and windows, cost summary, price rows, telemetry coverage, service access results, errors.  No user names, no tokens.

**The console log.**  The full transcript.

**No person is named anywhere in the output.**  WorkSpaces user names and usage-report user ids are hashed with a salt minted for the run, kept in memory, and written as counts.  The signed-in principal is recorded as account id plus `user`, `role` or `root`.

---

## How it reads AWS

1. **Identity and scope.**  `sts:GetCallerIdentity`, then the enabled regions.  With `--all-accounts`, every active account in the Organization through the named role.
2. **WorkSpaces Personal.**  Directories, every WorkSpace (bundle, compute type, running mode, AutoStop timeout, volumes, OS), bundles, last known user connection.  Usage per WorkSpace from CloudWatch: `UserConnected` for presence, `Available` for running hours, `UserVolumeDiskUsage` for how full the user volume is (the FSLogix sizing input).  WorkSpaces group by directory and compute type.  A group's concurrency per slot is the count of its WorkSpaces with a user connected.
3. **WorkSpaces Pools.**  Capacity settings, plus `ActiveUserSessionCapacity` (concurrent sessions) and `ActualUserSessionCapacity` (running capacity) from CloudWatch.  The dimension name is discovered with `ListMetrics`, not assumed.
4. **WorkSpaces Applications.**  Fleets with instance type, fleet type, platform, stream view and max sessions per instance; stacks; usage report subscriptions.  Concurrency from `ActiveUserSessionCapacity` on multi-session fleets and `InUseCapacity` on single-session fleets, capacity from `ActualCapacity`.  When usage reports are on, the daily session CSVs in the lookback are read from S3 for distinct users and user-hours per fleet.
5. **EC2 (opt-in).**  Instances matching your tag or name pattern, with running hours from CloudWatch `CPUUtilization` sample counts.  AWS has no session data for broker-based VDI, so these rows carry inventory and hours only.  Users and density come from the broker.
6. **Costs.**  Cost Explorer as described above.
7. **Prices.**  The WorkSpaces price list for each region in use, to estimate each WorkSpace's monthly cost: AlwaysOn at the monthly rate, AutoStop as the monthly fee plus the hourly rate times running hours.  The estimate is a cross-check.  The bill is the truth.
8. **Assembly.**  Windows, days and overtime come from the concurrency series with the same rules as the Azure tool.  Work days are days whose average user-hours reach 25% of the busiest day.  The window is the hours on work days whose average concurrency reaches 20% of peak.  Off-window load folds into the Modeler's overtime fields.  Then the proposals below, a flag for every default, and the import pre-flight.

---

## The modeling rules

- **WorkSpaces Personal directories** become AVD pooled multi-session deployments by default.  Users = measured peak concurrent in the group, host size `--pooled-vm-size`, density `--pooled-density`.  AWS runs these one VM per user.  The consolidation is the point of the proposal, and the density is where the assumption lives, so it is printed in every flag.  GPU bundles stay personal 1:1 on an NV size.  `--proposal personal` writes like-for-like personal desktops instead (users = WorkSpace count, D-series size mapped from the bundle).  `--proposal both` writes both.
- **WorkSpaces Pools** become pooled deployments sized on peak concurrent sessions.  AWS gives each session its own instance; the AVD proposal shares hosts.
- **Multi-session fleets** keep their packing: max sessions per instance divided by the instance's vCPUs becomes the AVD density, on the D-series size with the same vCPU count.  Single-session fleets get the pooled proposal.  GPU fleets get an NV multi-session proposal at a quarter of the pooled density, flagged for review.
- **Stream view** decides the experience.  APP fleets are RemoteApp (experience 4).  DESKTOP fleets and everything else are pooled desktops (experience 1).  Personal proposals are experience 2.
- **Region** maps from the AWS region to a nearby Azure region (us-east-1 to eastus, eu-west-1 to northeurope, and so on).  `--azure-region` overrides.  Unmapped regions fall back to eastus with a flag.
- **Disks** are 128 GB Premium on every proposal.  Change them in the Modeler.  Stopped-disk type is Standard HDD, the Nerdio feature being modeled.
- **Storage never enters the JSON.**  User-volume GB provisioned and measured used GB are in the review CSV for the FSLogix conversation.

---

## What AWS cannot tell us

| Gap | What the tool does |
|---|---|
| Who uses a WorkSpaces Pool | MAU is blank for pools.  The bill's per-user fee quantity is printed as the account-level count |
| Who uses a fleet when usage reports are off | Concurrency still comes from CloudWatch.  MAU is blank.  Usage reports are not retroactive, so turn them on now if the fleet matters |
| Sessions on EC2-hosted VDI | Inventory and running hours only.  The broker has the users |
| Anything older than 63 days at 5-minute resolution | Hourly slots past 60 days.  The last known user connection per WorkSpace is in the raw data |
| Hours while an AutoStop WorkSpace is stopped | Nothing is emitted, which is the point.  Running hours count `Available` datapoints |

---

## Troubleshooting

| Symptom | Meaning |
|---|---|
| `access denied` on a service in one region | The principal cannot read that service there.  Everything else continues.  Grant ReadOnlyAccess and run again |
| `TELEMETRY NOT FOUND` | No CloudWatch data came back for any group.  Check `cloudwatch:GetMetricData` on the principal, and that the WorkSpaces existed inside the lookback |
| `Cost Explorer unavailable` | Not enabled on the account, or linked-account access is off at the payer.  Run from the payer account, or accept the run without costs |
| Fleets show `MAU` blank | Usage reports are not enabled for WorkSpaces Applications.  Turn them on in the console, wait a day, run again |
| `usage too sparse to derive a window` | Fewer than a handful of connected slots in the lookback.  The window defaults and all load lands in overtime |
| `THIS COPY IS STALE` | An old download.  Run the `curl` line again |
| `no AWS credentials in this shell` | Local run without a signed-in CLI.  `aws configure` or `aws sso login`, then run again |
| Step 1 takes several minutes | CloudWatch returns three metrics per WorkSpace for the whole lookback.  A thousand WorkSpaces is a few million datapoints.  It finishes |

---

## Files

| File | Purpose |
|---|---|
| `nerdio_modeler_aws.py` | The tool.  One file, standard library plus boto3 |
| `nerdio_modeler_aws_demo.py` | Offline stand-in for AWS used by `--demo` and the tests.  Not for customers |
| `tests/test_offline.py` | End-to-end offline test.  `python3 tests/test_offline.py` |
| `VERSION` | Published version.  The tool compares itself against it at start |
