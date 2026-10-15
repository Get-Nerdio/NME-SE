#!/usr/bin/env python3
"""
Offline end-to-end test for nerdio_modeler_aws.py. NOT for customers.

Runs the real collector against the stubbed AWS in nerdio_modeler_aws_demo.py (every request
validated against the botocore service model, every response checked against the output shape),
then checks the zip, the Modeler JSON, the review CSV, the buckets, the cost rows, and that no
invented user name appears anywhere in the output.

    python3 tests/test_offline.py          (from the modeler-aws folder; no pytest needed)
"""
import csv
import glob
import json
import os
import shutil
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import nerdio_modeler_aws as m            # noqa: E402
import nerdio_modeler_aws_demo as demo    # noqa: E402

FAILS = []
def check(name, cond, detail=''):
    print(('ok   ' if cond else 'FAIL ') + name + (('  ' + str(detail)) if (detail and not cond) else ''))
    if not cond: FAILS.append(name)

def run(args):
    out = tempfile.mkdtemp(prefix='modeler-aws-test-')
    rc = m.main(['--demo', '--out-dir', out] + args, client_factory=demo.make_demo_factory(7))
    return rc, out

def main():
    # ---------------------------------------------------------------- default run
    rc, out = run([])
    check('exit code 0', rc == 0, rc)
    zips = glob.glob(os.path.join(out, 'modeler-aws-*.zip'))
    check('one zip written', len(zips) == 1, zips)
    names = zipfile.ZipFile(zips[0]).namelist()
    for suffix in ('.json', '-review.csv', '-usage-buckets.csv', '-cost.csv', '-rawdata.json', '-console.log'):
        check('zip holds *%s' % suffix, any(n.endswith(suffix) and not (suffix == '.json' and n.endswith('-rawdata.json')) for n in names), names)
    model_path = [p for p in glob.glob(os.path.join(out, 'modeler-aws-*.json')) if not p.endswith('-rawdata.json')][0]
    model = json.load(open(model_path))
    raw = json.load(open(glob.glob(os.path.join(out, '*-rawdata.json'))[0]))
    review = list(csv.DictReader(open(glob.glob(os.path.join(out, '*-review.csv'))[0])))
    buckets = list(csv.DictReader(open(glob.glob(os.path.join(out, '*-usage-buckets.csv'))[0])))
    costs = list(csv.DictReader(open(glob.glob(os.path.join(out, '*-cost.csv'))[0])))
    log = open(glob.glob(os.path.join(out, '*-console.log'))[0]).read()

    # ---------------------------------------------------------------- Modeler JSON
    check('schema 4', model.get('schema') == 4)
    deps = model['deployments']
    check('7 deployments in default (pooled) mode', len(deps) == 7, len(deps))
    check('no pre-flight corrections needed', not m.preflight(json.loads(json.dumps(deps))), 'the file needed fixes on re-check')
    for d in deps:
        check('deployment %s imports: users>=1, density>=0.1, window inside the day' % d['name'][:30],
              d['users']['total'] >= 1 and d['workload']['maxUsersPerVCpu'] >= 0.1 and d['autoScale']['workStartHour'] * 60 + d['autoScale']['workDurationMinutes'] <= 1425
              and d['workload']['disk']['size'] in m.DISK_TIERS and d['experience'] in (1, 2, 3, 4) and d['workload']['type'] == 5)
    by_name = {d['name']: d for d in deps}
    corp = next(d for n, d in by_name.items() if n.startswith('corp-desktops STANDARD pooled'))
    check('corp STANDARD pooled proposal uses the measured peak as users', corp['users']['total'] == 45, corp['users']['total'])
    check('corp STANDARD window is office hours Mon-Fri', corp['autoScale']['workDays'] == [1, 2, 3, 4, 5] and 6 <= corp['autoScale']['workStartHour'] <= 8 and 540 <= corp['autoScale']['workDurationMinutes'] <= 720,
          (corp['autoScale']['workStartHour'], corp['autoScale']['workDurationMinutes']))
    ops = next(d for n, d in by_name.items() if n.startswith('ops-247'))
    check('ops-247 reads as a 7-day, round-the-clock pool', ops['autoScale']['workDays'] == [1, 2, 3, 4, 5, 6, 7] and ops['autoScale']['workDurationMinutes'] >= 1380, ops['autoScale'])
    gfx = next(d for n, d in by_name.items() if 'GRAPHICS' in n)
    check('GPU WorkSpace stays personal 1:1 on an NV size', gfx['experience'] == 2 and gfx['workload']['vmSize'].startswith('Standard_NV') and gfx['workload']['maxUsersPerVCpu'] == 1.0)
    erp = next(d for n, d in by_name.items() if n.startswith('erp-apps'))
    check('multi-session fleet keeps its packing: 10 per 2 vCPU = 5.0, RemoteApp', erp['workload']['maxUsersPerVCpu'] == 5.0 and erp['experience'] == 4 and erp['users']['total'] == 45, erp['workload'])
    pool = next(d for n, d in by_name.items() if n.startswith('contractor-pool'))
    check('WorkSpaces Pool sized on ActiveUserSessionCapacity peak 14', pool['users']['total'] == 14, pool['users'])
    cad = next(d for n, d in by_name.items() if n.startswith('cad-desktop'))
    check('GPU fleet proposes an NV multi-session size', cad['workload']['vmSize'].startswith('Standard_NV'))
    check('region mapped us-east-1 -> eastus', all(d['region'] == 'eastus' for d in deps))

    # ---------------------------------------------------------------- review CSV
    check('review has one row per group (7)', len(review) == 7, len(review))
    r_corp = next(r for r in review if r['Group'] == 'corp-desktops' and r['Subgroup'] == 'STANDARD')
    check('66 corp STANDARD WorkSpaces, 60 AutoStop, 6 never connected, MAU 66', r_corp['Count'] == '66' and r_corp['AutoStop'] == '60' and r_corp['NeverConnected'] == '6' and r_corp['MAU'] == '66', r_corp)
    check('user volume used GB measured from UserVolumeDiskUsage', float(r_corp['UserVolumeUsedGb']) > 0 and r_corp['UserVolumeMeasured'] == '66', r_corp['UserVolumeUsedGb'])
    check('per-WorkSpace cost estimate priced every WorkSpace', r_corp['EstPriced'] == '66/66' and float(r_corp['EstMonthlyCostUsd']) > 0, r_corp['EstPriced'])
    check('pooled hosts for peak 45 at 2.0/vCPU on D8 with 15% headroom = 4', r_corp['ProposalHosts'] == '4', r_corp['ProposalHosts'])
    r_erp = next(r for r in review if r['Group'] == 'erp-apps')
    check('fleet MAU comes from the usage report (120 users)', r_erp['MAU'] == '120', r_erp['MAU'])
    check('flags name every default', all('proposal' in r['Flags'] or 'fleet' in r['Flags'] or 'pool' in r['Flags'] for r in review))

    # ---------------------------------------------------------------- buckets, costs, tenant
    check('buckets carry 15-minute UTC slots for every group', len(set(b['GroupKey'] for b in buckets)) == 7 and all(b['SlotUtc'].endswith(('00:00Z', '15:00Z', '30:00Z', '45:00Z')) for b in buckets[:200]))
    peak_from_buckets = max(int(b['ConcurrentUsers']) for b in buckets if b['Group'] == 'corp-desktops' and b['Subgroup'] == 'STANDARD')
    check('review peak equals the bucket peak', peak_from_buckets == int(r_corp['PeakUsers']), (peak_from_buckets, r_corp['PeakUsers']))
    ten = raw['tenant']
    check('tenant peak is the per-slot sum across groups', ten['peakConcurrentUsers'] >= 45 + 10 + 11, ten)
    check('distinct users: 92 WorkSpaces, 212 with the usage report', ten['distinctUsersWorkSpacesPersonal'] == 92 and ten['distinctUsersAllSources'] == 212, ten)
    check('cost rows: service totals, usage types, regions for two periods', len(costs) >= 30 and any(r['usage_type'].endswith('UserFee') for r in costs))
    check('users from the bill recorded', raw['costSummary']['last full month']['users_from_bill'].get('USE1-AppStream:UserFee') == 132, raw['costSummary'])
    check('access denied in us-west-2 was reported, not fatal', 'us-west-2: access denied' in log and 'Model written' in log)
    check('missing usage-report days are silent', 'NoSuchKey' not in log)

    # ---------------------------------------------------------------- privacy
    leaked = []
    for p in glob.glob(os.path.join(out, 'modeler-aws-*')):
        if p.endswith('.zip'): continue
        text = open(p, errors='replace').read()
        for u in demo.FIXTURE_USERS:
            if u in text: leaked.append((os.path.basename(p), u)); break
        if 'demo.invalid' in text and not p.endswith('-rawdata.json'): leaked.append((os.path.basename(p), 'demo.invalid'))
    check('no invented user name in any output file', not leaked, leaked)
    rawtext = open(glob.glob(os.path.join(out, '*-rawdata.json'))[0]).read()
    check('rawdata has no UserName field and no tokens', '"UserName"' not in rawtext and '"user_token"' not in rawtext and '"salt"' not in rawtext.lower())
    check('rawdata identity is masked to account and principal type', raw['meta']['identity'].get('principalMasked') is True and 'Arn' not in json.dumps(raw['meta']))

    # ---------------------------------------------------------------- options
    rc2, out2 = run(['--proposal', 'both', '--ec2-tag', 'workload=vdi', '--ec2-as', 'personal', '--pooled-density', '3', '--lookback-days', '14', '--time-zone', 'America/Chicago', '--skip-prices'])
    model2 = json.load(open([p for p in glob.glob(os.path.join(out2, 'modeler-aws-*.json')) if not p.endswith('-rawdata.json')][0]))
    names2 = [d['name'] for d in model2['deployments']]
    check('--proposal both writes personal and pooled per WorkSpaces group', any('like for like' in n for n in names2) and any('pooled proposal' in n for n in names2))
    check('--ec2-as personal writes the EC2 hosts', any(n.startswith('EC2 VDI hosts') for n in names2), names2)
    check('--pooled-density flows into the proposals', any(d['workload']['maxUsersPerVCpu'] == 3.0 for d in model2['deployments']))
    review2 = list(csv.DictReader(open(glob.glob(os.path.join(out2, '*-review.csv'))[0])))
    check('--skip-prices leaves the estimate blank', all(r['EstMonthlyCostUsd'] == '' for r in review2))
    check('EC2 row carries running hours and the broker note', any(r['Type'] == 'EC2' and 'broker' in r['Flags'] and float(r['AvgConnectedHours']) > 0 for r in review2))
    rc3, out3 = run(['--regions', 'eu-west-1', '--skip-costs'])
    review3 = list(csv.DictReader(open(glob.glob(os.path.join(out3, '*-review.csv'))[0])))
    check('a region with nothing in it yields an empty, valid model', rc3 == 0 and review3 == [])
    for d in (out, out2, out3): shutil.rmtree(d, ignore_errors=True)

    print('\n%d failure(s)' % len(FAILS))
    return 1 if FAILS else 0

if __name__ == '__main__':
    sys.exit(main())
