# Nerdio Modeler Import Builder for AWS

Turns a customer's AWS virtual desktop estate into an import file for the Nerdio Modeler, with the AVD equivalent proposed deployment by deployment. One command in AWS CloudShell. Read-only. Nothing in the account is changed.

This is the AWS counterpart of the Azure tool in [`modeler/`](../modeler/). Same idea, same outputs, same privacy rules, different plumbing: AWS spreads VDI across several products with different telemetry, so this tool reads each one and reconciles them.

**Status: v0.1.0, first test candidate.** The collector is complete and every call it makes is validated offline against the AWS API definitions, but it has not yet run against a live AWS account. See "Testing it for the first time" before you point it at a customer.

---

## Quick start

1. Open **AWS CloudShell** in the customer's account (the terminal icon in the console toolbar). Pick a region where the WorkSpaces live; the tool scans every enabled region regardless.
2. Paste:

   ```bash
   curl -sSL https://raw.githubusercontent.com/dclawrence003/NME/main/modeler-aws/nerdio_modeler_aws.py -o nerdio_modeler_aws.py && python3 nerdio_modeler_aws.py
   ```

3. Read the review table it prints. One row per group (a WorkSpaces directory split by compute type, a WorkSpaces Pool, a WorkSpaces Applications fleet, or the EC2 hosts you pointed it at). Anything defaulted is spelled out in `Flags`. The run never stops to ask anything. The first lines name the account, the principal type, and every region it will scan; if something you expected is missing, look there first.
4. One zip lands in the CloudShell home folder: `modeler-aws-<timestamp>.zip`. It holds the import JSON, the review CSV, the concurrency buckets, the cost rows, the raw observation data, and the console log. Download it with **Actions > Download file** (top right of CloudShell) and paste the zip path the run printed. If someone asked you to run this, that zip is the only thing to send back.
5. Nerdio Modeler > Import > pick the JSON from the zip.

**Running from a laptop instead:** `pip install boto3`, sign in with the AWS CLI (`aws configure`, or `aws sso login --profile <name>` and add `--profile <name>`), then run the same command. The zip lands in your home folder.

Prefer to read the code first? You should. The `curl` above saves it as `nerdio_modeler_aws.py`; open it, then run `python3 nerdio_modeler_aws.py`.

### Parameters (all optional)

| Parameter | Default | What it does |
|---|---|---|
| `--model-name` | `AVD Environment - From AWS` | Model name shown in the Modeler |
| `--lookback-days` | `30` | Days of usage history. CloudWatch keeps 5-minute data for 63 days; past 60 the tool switches to hourly slots |
| `--time-zone` | `America/New_York` | The estate's local time zone (IANA) for work-hours math |
| `--regions us-east-1 us-west-2` | every enabled region | Narrow the scan |
| `--proposal pooled|personal|both` | `pooled` | How WorkSpaces Personal directories are written: as AVD pooled multi-session sized on measured concurrency (the default), like-for-like personal desktops, or both (then delete one in the Modeler) |
| `--pooled-vm-size` | `Standard_D8s_v5` | Host size for pooled proposals |
| `--pooled-density` | `2.0` | Users per vCPU for pooled proposals. The single most important assumption in the file; it is written into every flag |
| `--azure-region` | mapped from the AWS region | Force one Azure region for every deployment |
| `--ec2-tag Key=Value` | off | Treat EC2 instances with this tag as VDI hosts (Citrix, Omnissa, RDSH). Repeatable |
| `--ec2-name-regex` | off | Same, by Name tag pattern |
| `--ec2-as none|personal|pooled` | `none` | Whether EC2 hosts enter the Modeler JSON, and as what. Users are a placeholder until broker data arrives |
| `--all-accounts` | off | AWS Organizations: assume `--role-name` into every active account |
| `--account <id> ...` | off | Assume `--role-name` into specific accounts |
| `--role-name` | `OrganizationAccountAccessRole` | Role used for the two options above |
| `--skip-costs` | off | Skip Cost Explorer |
| `--skip-prices` | off | Skip the WorkSpaces price list (the per-WorkSpace estimate) |
| `--skip-usage-report` | off | Skip reading WorkSpaces Applications usage reports from S3 |
| `--out-dir` | home folder | Where the zip goes |
| `--demo` | off | Synthetic estate, no AWS calls. For seeing what the outputs look like |

---

## What you need

- A signed-in principal with the AWS managed policy **ReadOnlyAccess**, or this minimal policy:

  ```json
  {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Resource": "*", "Action": [
    "sts:GetCallerIdentity", "ec2:DescribeRegions", "ec2:DescribeInstances",
    "workspaces:Describe*", "appstream:Describe*", "appstream:List*",
    "cloudwatch:GetMetricData", "cloudwatch:ListMetrics",
    "ce:GetCostAndUsage", "pricing:GetProducts",
    "s3:GetObject", "s3:ListBucket",
    "organizations:ListAccounts", "sts:AssumeRole"]}]}
  ```

  The S3 lines are for the WorkSpaces Applications usage report bucket only; the Organizations and AssumeRole lines are only needed with `--all-accounts` or `--account`.
- **Cost Explorer enabled** on the account (it usually is; first-time enablement takes up to 24 hours). In a member account of an Organization, the payer may have turned off linked-account access to Cost Explorer; the run says so and carries on without costs.
- Nothing to install in CloudShell. `boto3` is preinstalled.

Every Cost Explorer call costs AWS's published $0.01. A run makes six to eight of them.

---

## What it produces

**The import JSON.** Schema-4 Nerdio Modeler format, one deployment per group, pre-flighted against the Modeler's own import rules (users at least 1, density at least 0.1, known disk tiers, consistent overtime, a window that ends by 11:45 PM). A file this script writes imports.

**The review table and CSV.** Per group: account, AWS region and the Azure region it maps to, type, count (WorkSpaces, pool capacity, fleet instances, or EC2 hosts), running modes, platform, max sessions per instance for multi-session fleets, peak concurrent users and when, MAU where identities exist, user-hours, average connected hours per WorkSpace, how many WorkSpaces never connected, how many are AutoStop, the observed window, days and overtime, user-volume GB provisioned and used, the proposal (experience, VM size, density, hosts it implies with 15% headroom), the per-WorkSpace monthly cost estimate from the price list, and `Flags` naming every default and assumption.

**Account-wide counts.** Peak concurrent users across everything (series added per 15-minute slot), distinct WorkSpaces users, and distinct users across every identified source. Pools users are not identified by any AWS API; the per-user fee line on the bill is the closest thing, and the run prints it.

**The concurrency buckets** (`-usage-buckets.csv`). Per group, per 15-minute UTC slot: concurrent users and running capacity. Everything the window math used.

**The cost rows** (`-cost.csv`). Last full month and month to date from Cost Explorer, amortized and unblended: every service on the bill (so the VDI share of the AWS total is visible), then WorkSpaces and AppStream by usage type and linked account, and by region. Usage types that read as per-user fees are totaled separately; their quantity is the number of distinct users AWS charged for.

**The raw data** (`-rawdata.json`). Inventory, per-WorkSpace usage facts, groups with their usage aggregates and windows, cost summary, price rows, telemetry coverage, and errors. No user names, no tokens.

**No person is named anywhere in the output.** WorkSpaces user names and usage-report user ids are hashed with a salt minted for the run, kept in memory, and written as counts. The signed-in principal is recorded as account id plus `user`, `role` or `root`; its name is not.

---

## How it reads the environment

1. **Identity and scope.** `sts:GetCallerIdentity`, then the enabled regions of the account. With `--all-accounts`, every active account in the Organization through the named role.
2. **WorkSpaces Personal.** Directories, every WorkSpace (bundle, compute type, running mode, AutoStop timeout, volumes, OS), bundles, and last known user connection. Usage from CloudWatch per WorkSpace: `UserConnected` for presence, `Available` for running hours, `UserVolumeDiskUsage` for how full the user volume is (that is the FSLogix sizing input). WorkSpaces group by directory and compute type; the group's concurrency per slot is the count of its WorkSpaces with a user connected.
3. **WorkSpaces Pools.** Each pool's capacity settings, and `ActiveUserSessionCapacity` (concurrent sessions) with `ActualUserSessionCapacity` (running capacity) from CloudWatch. The dimension name is discovered with `ListMetrics`, not assumed.
4. **WorkSpaces Applications (AppStream 2.0).** Fleets with instance type, fleet type, platform, stream view and max sessions per instance; stacks; usage report subscriptions. Concurrency from `ActiveUserSessionCapacity` on multi-session fleets and `InUseCapacity` on single-session fleets, capacity from `ActualCapacity`. When usage reports are on, the daily session CSVs in the lookback are read from S3 for distinct users and user-hours per fleet.
5. **EC2 (opt-in).** Instances matching your tag or name pattern, with running hours from CloudWatch `CPUUtilization` sample counts. AWS has no session data for broker-based VDI, so these rows carry inventory and hours only; users and density come from the broker.
6. **Costs.** Cost Explorer as described above.
7. **Prices.** The WorkSpaces price list for each region in use (`pricing:GetProducts`), to estimate each WorkSpace's monthly cost: AlwaysOn at the monthly rate, AutoStop as the monthly fee plus the hourly rate times running hours. The estimate is a cross-check; the bill is the truth.
8. **Assembly.** Windows, days and overtime are derived from the concurrency series with the same rules as the Azure tool: work days are days whose average user-hours reach 25% of the busiest day, the window is the hours on work days whose average concurrency reaches 20% of peak, and off-window load folds into the Modeler's overtime fields. Then the proposals below, a flag for every default, and the import pre-flight.

---

## The modeling rules (what lands in the JSON, and why)

- **WorkSpaces Personal directories** become AVD pooled multi-session deployments by default: users = measured peak concurrent in the group, host size `--pooled-vm-size`, density `--pooled-density`. AWS runs these one VM per user; the consolidation is the point of the proposal, and the density is where the assumption lives, so it is printed in every flag. GPU bundles stay personal 1:1 on an NV size. `--proposal personal` writes like-for-like personal desktops instead (users = WorkSpace count, D-series size mapped from the bundle), and `--proposal both` writes both.
- **WorkSpaces Pools** become pooled deployments sized on peak concurrent sessions. AWS gives each session its own instance; the AVD proposal shares hosts.
- **Multi-session fleets** keep their packing: max sessions per instance divided by the instance's vCPUs becomes the AVD density, on the D-series size with the same vCPU count. Single-session fleets get the pooled proposal; GPU fleets get an NV multi-session proposal at a quarter of the pooled density, flagged for review.
- **Stream view** decides the experience: APP fleets are RemoteApp (experience 4), DESKTOP fleets and everything else are pooled desktops (experience 1), personal proposals are experience 2.
- **Region** maps from the AWS region to a nearby Azure region (us-east-1 to eastus, eu-west-1 to northeurope, and so on); `--azure-region` overrides, and unmapped regions fall back to eastus with a flag.
- **Disks** are 128 GB Premium on every proposal; the Modeler prices them and you can change them there. Stopped-disk type is Standard HDD, the Nerdio feature being modeled.
- **Storage never enters the JSON.** User-volume GB provisioned and measured used GB are in the review CSV for the FSLogix conversation.
- **Empty groups** (a fleet with no instances and no sessions, a pool at zero with no sessions) are still written, at 1 user, flagged; there is no AWS equivalent of an empty host pool shell worth hiding.

---

## What AWS cannot tell us (and how the tool says so)

| Gap | What happens |
|---|---|
| Who uses a WorkSpaces Pool | Pools sessions are not tied to identities in any read API. MAU is blank for pools; the bill's per-user fee quantity is printed as the account-level count |
| Who uses a fleet, when usage reports are off | Concurrency still comes from CloudWatch; MAU is blank and the flag says to enable usage reports (they are not retroactive) |
| Sessions on EC2-hosted VDI | Inventory and running hours only; the review says the broker has the users |
| Whether a WorkSpace is in use beyond CloudWatch's 63 days of 5-minute data | The last known user connection timestamp is in the raw data per WorkSpace; past 60 days the tool uses hourly slots |
| Hours while an AutoStop WorkSpace is stopped | Nothing is emitted, which is the point; running hours count `Available` datapoints |

---

## Testing it for the first time

There is no AWS sandbox behind this release. Three layers of checking are in place, and the fourth is you.

1. **Offline model validation (done).** `nerdio_modeler_aws_demo.py` stands in for AWS. Every request the collector makes is validated against the real botocore service definitions, so a wrong parameter name fails here the way it would against AWS, and every synthetic response is checked against the real output shape, so a field the collector reads must exist in the API. `python3 tests/test_offline.py` runs the whole pipeline and 60-odd checks against it.
2. **The demo.** `python3 nerdio_modeler_aws.py --demo` writes a complete zip from the synthetic estate, so you can see every output before a customer does.
3. **Your own account, if you can get one.** A free-tier account with two WorkSpaces (one AlwaysOn, one AutoStop) exercises most of the code for a few dollars. Create them, connect once from a client, wait an hour, run the tool.
4. **A customer account.** Run it with `--skip-costs --regions <their region>` first: that is inventory and CloudWatch only, and it finishes in a minute. Read the review table and the flags. Then run it plain. Things that would surprise us on a first live run, in order of likelihood: a CloudWatch metric that is present in the docs but absent for a particular WorkSpace generation (the tool reports empty series as "no usage data", it does not crash); a Cost Explorer usage type naming scheme that does not match the `user` heuristic (the raw rows are all in the cost CSV either way); a price-list attribute spelled differently than expected (the estimate goes blank, flagged). None of these affect the import JSON's validity.

Send back the zip and the console output and the fix is usually a few lines.

---

## Troubleshooting

| Symptom | Meaning |
|---|---|
| `access denied` on a service in one region | The principal cannot read that service there. Everything else continues. Grant ReadOnlyAccess and re-run |
| `TELEMETRY NOT FOUND` | No CloudWatch data came back for any group. Check `cloudwatch:GetMetricData` on the principal, and that the WorkSpaces existed inside the lookback |
| `Cost Explorer unavailable` | Not enabled on the account, or linked-account access is off at the payer. Run from the payer account, or accept the run without costs |
| Fleets show `MAU` blank | Usage reports are not enabled for WorkSpaces Applications. Turn them on in the console (Usage reports), wait a day, re-run; history before that day does not exist |
| A group shows `usage too sparse to derive a window` | Fewer than a handful of connected slots in the lookback; the window defaults and all load lands in overtime |
| `THIS COPY IS STALE` | An old download. Re-run the `curl` line |
| `no AWS credentials in this shell` | Local run without a signed-in CLI. `aws configure` or `aws sso login`, then run again |
| The run takes several minutes on step 1 | CloudWatch returns three metrics per WorkSpace for the whole lookback; a thousand WorkSpaces is a few million datapoints. It is normal and it finishes |

---

## Files

| File | Purpose |
|---|---|
| `nerdio_modeler_aws.py` | The tool. One file, standard library plus boto3 |
| `nerdio_modeler_aws_demo.py` | Offline stand-in for AWS used by `--demo` and the tests. Not for customers |
| `tests/test_offline.py` | End-to-end offline test. `python3 tests/test_offline.py` |
| `VERSION` | Published version; the tool compares itself against it at start |
