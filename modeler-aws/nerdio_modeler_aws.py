#!/usr/bin/env python3
"""
Nerdio Modeler import builder for AWS VDI estates  (modeler-aws)

Reads what a customer runs for virtual desktops on AWS, how it is used, and what it
costs, then writes a Nerdio Modeler import file that proposes the AVD equivalent.
Every call is a read. Nothing in the account is changed.

Covers:
  * Amazon WorkSpaces Personal      (one desktop per user; AlwaysOn or AutoStop)
  * Amazon WorkSpaces Pools         (non-persistent pooled desktops; end of support Dec 31, 2027, no new
                                     customers after Jul 31, 2026: accounts without it read 'not offered')
  * Amazon WorkSpaces Applications  (formerly AppStream 2.0; single- and multi-session fleets)
  * EC2-hosted VDI (Citrix, Omnissa, RDSH) by tag or name pattern, inventory and running hours only

Run it in AWS CloudShell (boto3 is preinstalled) or anywhere the AWS CLI is signed in:

    curl -sSL https://raw.githubusercontent.com/dclawrence003/NME/main/modeler-aws/nerdio_modeler_aws.py | python3 -

Parameters go after the dash:  ... | python3 - --check --regions us-east-1

Outputs one zip: the Modeler import JSON, a per-group review CSV, 15-minute concurrency
buckets, the cost rows, the raw observation data, and the console log.

No person is named anywhere in the output. WorkSpaces user names and usage-report user ids are
hashed with a salt minted for the run, kept in memory only, and written as counts.

RELEASE RULE: bump VERSION (the file next to this script) in the same commit as SCRIPT_VERSION.
"""
import argparse
import collections
import csv
import datetime as dt
import hashlib
import io
import json
import math
import os
import random
import re
import sys
import time
import uuid
import zipfile

SCRIPT_VERSION = 'v0.1.2'
TOOL_NAME = 'nerdio_modeler_aws.py'
VERSION_URL = 'https://raw.githubusercontent.com/dclawrence003/NME/main/modeler-aws/VERSION'

# ============================================================================ console
class Console:
    """Prints like the Azure tool ([i] / [+] / [!]) and keeps a transcript for the zip."""
    def __init__(self):
        self.lines = []
        self.warnings = 0
    def _emit(self, tag, msg):
        line = '%s %s' % (tag, msg)
        self.lines.append(line)
        print(line, flush=True)
    def info(self, msg): self._emit('[i]', msg)
    def ok(self, msg): self._emit('[+]', msg)
    def warn(self, msg):
        self.warnings += 1
        self._emit('[!]', msg)
    def raw(self, msg):
        self.lines.append(msg)
        print(msg, flush=True)

LOG = Console()

# ============================================================================ tables
# WorkSpaces compute types: vCPU, RAM GiB, like-for-like AVD personal size, GPU flag.
WS_COMPUTE = {
    'VALUE':                  dict(vcpu=1, ram=2, azure='Standard_D2s_v5', gpu=False),
    'STANDARD':               dict(vcpu=2, ram=4, azure='Standard_D2s_v5', gpu=False),
    'PERFORMANCE':            dict(vcpu=2, ram=8, azure='Standard_D2s_v5', gpu=False),
    'POWER':                  dict(vcpu=4, ram=16, azure='Standard_D4s_v5', gpu=False),
    'POWERPRO':               dict(vcpu=8, ram=32, azure='Standard_D8s_v5', gpu=False),
    'GENERALPURPOSE_4XLARGE': dict(vcpu=16, ram=64, azure='Standard_D16s_v5', gpu=False),
    'GENERALPURPOSE_8XLARGE': dict(vcpu=32, ram=128, azure='Standard_D32s_v5', gpu=False),
    'GRAPHICS':               dict(vcpu=4, ram=16, azure='Standard_NV6ads_A10_v5', gpu=True),
    'GRAPHICS_G4DN':          dict(vcpu=4, ram=16, azure='Standard_NV6ads_A10_v5', gpu=True),
    'GRAPHICSPRO':            dict(vcpu=16, ram=64, azure='Standard_NV18ads_A10_v5', gpu=True),
    'GRAPHICSPRO_G4DN':       dict(vcpu=16, ram=64, azure='Standard_NV18ads_A10_v5', gpu=True),
}
# WorkSpaces Applications (AppStream 2.0) instance types: vCPU and RAM GiB. Anything not
# listed falls back to the EC2 size-suffix rule (large 2, xlarge 4, 2xlarge 8 ...) and is flagged.
APPSTREAM_SPECS = {
    'stream.standard.small': (1, 2), 'stream.standard.medium': (2, 4), 'stream.standard.large': (2, 8),
    'stream.standard.xlarge': (4, 16), 'stream.standard.2xlarge': (8, 32),
    'stream.compute.large': (2, 3.75), 'stream.compute.xlarge': (4, 7.5), 'stream.compute.2xlarge': (8, 15),
    'stream.compute.4xlarge': (16, 30), 'stream.compute.8xlarge': (32, 60),
    'stream.memory.large': (2, 15.25), 'stream.memory.xlarge': (4, 30.5), 'stream.memory.2xlarge': (8, 61),
    'stream.memory.4xlarge': (16, 122), 'stream.memory.8xlarge': (32, 244),
    'stream.memory.z1d.large': (2, 16), 'stream.memory.z1d.xlarge': (4, 32), 'stream.memory.z1d.2xlarge': (8, 64),
    'stream.memory.z1d.3xlarge': (12, 96), 'stream.memory.z1d.6xlarge': (24, 192), 'stream.memory.z1d.12xlarge': (48, 384),
    'stream.graphics-design.large': (2, 7.5), 'stream.graphics-design.xlarge': (4, 15.25),
    'stream.graphics-design.2xlarge': (8, 30.5), 'stream.graphics-design.4xlarge': (16, 61),
    'stream.graphics.g4dn.xlarge': (4, 16), 'stream.graphics.g4dn.2xlarge': (8, 32), 'stream.graphics.g4dn.4xlarge': (16, 64),
    'stream.graphics.g4dn.8xlarge': (32, 128), 'stream.graphics.g4dn.12xlarge': (48, 192), 'stream.graphics.g4dn.16xlarge': (64, 256),
    'stream.graphics.g5.xlarge': (4, 16), 'stream.graphics.g5.2xlarge': (8, 32), 'stream.graphics.g5.4xlarge': (16, 64),
    'stream.graphics.g5.8xlarge': (32, 128), 'stream.graphics.g5.12xlarge': (48, 192), 'stream.graphics.g5.16xlarge': (64, 256),
    'stream.graphics.g5.24xlarge': (96, 384),
    'stream.graphics-pro.4xlarge': (16, 122), 'stream.graphics-pro.8xlarge': (32, 244), 'stream.graphics-pro.16xlarge': (64, 488),
}
SIZE_SUFFIX_VCPU = {'nano': 1, 'micro': 1, 'small': 1, 'medium': 2, 'large': 2, 'xlarge': 4, '2xlarge': 8, '3xlarge': 12, '4xlarge': 16,
                    '6xlarge': 24, '8xlarge': 32, '9xlarge': 36, '12xlarge': 48, '16xlarge': 64, '18xlarge': 72, '24xlarge': 96,
                    '32xlarge': 128, '48xlarge': 192}
# AWS region -> the Azure region the Modeler should price. Override everything with --azure-region.
REGION_MAP = {
    'us-east-1': 'eastus', 'us-east-2': 'eastus2', 'us-west-1': 'westus', 'us-west-2': 'westus2',
    'ca-central-1': 'canadacentral', 'ca-west-1': 'canadacentral', 'sa-east-1': 'brazilsouth',
    'eu-west-1': 'northeurope', 'eu-west-2': 'uksouth', 'eu-west-3': 'francecentral', 'eu-central-1': 'germanywestcentral',
    'eu-central-2': 'switzerlandnorth', 'eu-north-1': 'swedencentral', 'eu-south-1': 'italynorth', 'eu-south-2': 'spaincentral',
    'ap-southeast-1': 'southeastasia', 'ap-southeast-2': 'australiaeast', 'ap-southeast-3': 'southeastasia', 'ap-southeast-4': 'australiaeast',
    'ap-northeast-1': 'japaneast', 'ap-northeast-2': 'koreacentral', 'ap-northeast-3': 'japanwest', 'ap-south-1': 'centralindia',
    'ap-south-2': 'southindia', 'ap-east-1': 'eastasia', 'af-south-1': 'southafricanorth', 'me-south-1': 'uaenorth',
    'me-central-1': 'uaenorth', 'il-central-1': 'israelcentral',
}
# Azure D-series v5 by vCPU count, for like-for-like mapping of AWS instance sizes.
AZURE_BY_VCPU = {1: 'Standard_D2s_v5', 2: 'Standard_D2s_v5', 4: 'Standard_D4s_v5', 8: 'Standard_D8s_v5', 16: 'Standard_D16s_v5',
                 32: 'Standard_D32s_v5', 48: 'Standard_D48s_v5', 64: 'Standard_D64s_v5', 96: 'Standard_D96s_v5'}
DISK_TIERS = [128, 256, 512, 1024, 2048, 4096]
# The Modeler's administrative task defaults, copied from the Azure tool so both files import identically.
ADMIN_TASKS = json.loads('{"0":[{"id":0,"isEnabled":true,"hoursWithoutNerdio":5,"hoursWithNerdio":0.5},{"id":1,"isEnabled":true,"hoursWithoutNerdio":2,"hoursWithNerdio":0.5},{"id":2,"isEnabled":true,"hoursWithoutNerdio":16,"hoursWithNerdio":4},{"id":3,"isEnabled":true,"hoursWithoutNerdio":20,"hoursWithNerdio":0.5},{"id":4,"isEnabled":false,"hoursWithoutNerdio":0,"hoursWithNerdio":2},{"id":5,"isEnabled":true,"hoursWithoutNerdio":16,"hoursWithNerdio":4}],"1":[{"id":6,"isEnabled":true,"hoursWithoutNerdio":5,"hoursWithNerdio":0.5},{"id":7,"isEnabled":true,"hoursWithoutNerdio":10,"hoursWithNerdio":2},{"id":8,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":0.5},{"id":9,"isEnabled":true,"hoursWithoutNerdio":2,"hoursWithNerdio":0.5},{"id":10,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":5}],"2":[{"id":11,"isEnabled":true,"hoursWithoutNerdio":10,"hoursWithNerdio":2.5},{"id":12,"isEnabled":true,"hoursWithoutNerdio":8,"hoursWithNerdio":0.5},{"id":13,"isEnabled":true,"hoursWithoutNerdio":10,"hoursWithNerdio":0.5},{"id":14,"isEnabled":true,"hoursWithoutNerdio":8,"hoursWithNerdio":2},{"id":15,"isEnabled":true,"hoursWithoutNerdio":5,"hoursWithNerdio":1},{"id":16,"isEnabled":true,"hoursWithoutNerdio":20,"hoursWithNerdio":2},{"id":17,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":0.5},{"id":18,"isEnabled":true,"hoursWithoutNerdio":10,"hoursWithNerdio":2},{"id":19,"isEnabled":true,"hoursWithoutNerdio":2.5,"hoursWithNerdio":0.5},{"id":20,"isEnabled":true,"hoursWithoutNerdio":8,"hoursWithNerdio":2},{"id":21,"isEnabled":true,"hoursWithoutNerdio":2,"hoursWithNerdio":0.5},{"id":22,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":0},{"id":23,"isEnabled":true,"hoursWithoutNerdio":3,"hoursWithNerdio":0.5},{"id":24,"isEnabled":true,"hoursWithoutNerdio":5,"hoursWithNerdio":1},{"id":25,"isEnabled":true,"hoursWithoutNerdio":2,"hoursWithNerdio":1},{"id":26,"isEnabled":false,"hoursWithoutNerdio":0,"hoursWithNerdio":0.5}]}')
GLOBAL_SETTINGS = json.loads('{"enterpriseDiscount":0,"windows365Discount":0,"azureType":1,"nerdioLicenseCost":{"type":0,"perUserCost":null,"windows365PerUserCost":null,"monthMinimumCost":null},"nerdioResourceCost":3}')
VDI_SERVICE_RX = re.compile(r'workspaces|appstream', re.I)

# ============================================================================ small helpers
def utcnow():
    return dt.datetime.now(dt.timezone.utc)

def iso(t):
    if t is None: return None
    if isinstance(t, (dt.datetime,)):
        if t.tzinfo is None: t = t.replace(tzinfo=dt.timezone.utc)
        return t.astimezone(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    return str(t)

def get_tz(name):
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        LOG.warn('Time zone %r not available in this Python; work-hours math falls back to UTC.' % name)
        return dt.timezone.utc

def to_local(t, tz):
    return t.astimezone(tz)

def paginate(fn, result_key, token_in='NextToken', token_out='NextToken', **params):
    """Walks any NextToken-style API without depending on boto3 paginators, so stubbed clients
    behave exactly like real ones."""
    token = None
    out = []
    while True:
        p = dict(params)
        if token: p[token_in] = token
        resp = fn(**p)
        out.extend(resp.get(result_key) or [])
        token = resp.get(token_out)
        if not token: break
    return out

def vcpu_for_instance_type(itype, flags=None):
    if itype in APPSTREAM_SPECS: return APPSTREAM_SPECS[itype][0]
    suffix = (itype or '').rsplit('.', 1)[-1].lower()
    if suffix in SIZE_SUFFIX_VCPU:
        if flags is not None: flags.append('vCPU for %s taken from the size suffix (%d); verify' % (itype, SIZE_SUFFIX_VCPU[suffix]))
        return SIZE_SUFFIX_VCPU[suffix]
    if flags is not None: flags.append('vCPU for %s unknown; assumed 4' % itype)
    return 4

def azure_size_for_vcpu(v):
    for k in sorted(AZURE_BY_VCPU):
        if k >= v: return AZURE_BY_VCPU[k]
    return AZURE_BY_VCPU[96]

def snap_disk(gb):
    for t in DISK_TIERS:
        if t >= gb: return t
    return DISK_TIERS[-1]

class UserHasher:
    """Opaque per-run tokens for user identities. The salt dies with the process; only counts are written."""
    def __init__(self):
        self.salt = uuid.uuid4().hex
    def token(self, name):
        if not name: return None
        return hashlib.sha256((self.salt + str(name).strip().lower()).encode('utf-8')).hexdigest()[:20]

# ============================================================================ usage math (ported from the Azure tool)
class Lookback:
    """[start, end) aligned to the slot grid, plus how many of each weekday the window holds in local time."""
    def __init__(self, days, tz, end=None, slot_minutes=15):
        self.days = days
        self.tz = tz
        self.slot_minutes = slot_minutes
        end = end or utcnow()
        end = end.replace(second=0, microsecond=0)
        end = end - dt.timedelta(minutes=end.minute % slot_minutes)
        self.end = end
        self.start = end - dt.timedelta(days=days)
        self.dow_cal = [0] * 7   # Monday=0 .. Sunday=6, count of each weekday (local dates) in the window
        d = to_local(self.start, tz).date()
        last = to_local(self.end - dt.timedelta(minutes=1), tz).date()
        while d <= last:
            self.dow_cal[d.weekday()] += 1
            d += dt.timedelta(days=1)
    @property
    def slot_hours(self): return self.slot_minutes / 60.0
    @property
    def weeks(self): return self.days / 7.0

def usage_from_series(series, lb):
    """series: {slot_start_utc (datetime) -> concurrent users}. Same rules as the Azure tool's
    Get-UsageFromSeries: peak; work days = days whose average user-hours reach 25% of the busiest
    day; work window = hours (on work days) whose average concurrency reaches 20% of peak;
    weekly off-window user-hours feed the Modeler's overtime fields."""
    if not series: return None
    tz = lb.tz; sh = lb.slot_hours
    peak = 0; peak_at = None
    day_uh = [0.0] * 7
    local = {}
    for k in sorted(series):
        v = int(series[k])
        lt = to_local(k, tz); local[k] = lt
        if v > peak: peak, peak_at = v, k
        day_uh[lt.weekday()] += v * sh
    day_uh = [day_uh[d] / max(lb.dow_cal[d], 1) for d in range(7)]
    max_day = max(day_uh) if day_uh else 0.0
    work_dows = [d for d in range(7) if day_uh[d] > 0 and day_uh[d] >= max_day * 0.25]
    modeler_days = sorted(d + 1 for d in work_dows)          # Modeler: 1=Monday .. 7=Sunday
    day_slots = sum(max(lb.dow_cal[d], 1) * (60.0 / lb.slot_minutes) for d in work_dows)
    hour_sum = [0.0] * 24
    for k, lt in local.items():
        if lt.weekday() in work_dows: hour_sum[lt.hour] += int(series[k])
    hrs = [h for h in range(24) if day_slots > 0 and (hour_sum[h] / day_slots) >= peak * 0.20]
    start = end = duration = None
    if hrs:
        start, end = min(hrs), max(hrs); duration = (end - start + 1) * 60
    total_uh = 0.0; in_uh = 0.0
    for k, lt in local.items():
        v = int(series[k]); total_uh += v * sh
        if start is not None and lt.weekday() in work_dows and start <= lt.hour <= end: in_uh += v * sh
    weekly_uh = round(total_uh / lb.weeks, 1); weekly_in = round(in_uh / lb.weeks, 1)
    hourly = [0.0] * 24
    for k, lt in local.items():
        if lt.weekday() in work_dows: hourly[lt.hour] += int(series[k])
    hourly = [round(h / day_slots, 1) if day_slots else 0.0 for h in hourly]
    return dict(PeakConcurrentUsers=peak, PeakAtUtc=iso(peak_at), StartHour=start, WorkDurationMinutes=duration,
                WorkDays=modeler_days, WeeklyOffUH=round(weekly_uh - weekly_in, 1), TotalUserHours=round(total_uh, 1),
                HourlyProfile=hourly, SlotsWithUsers=sum(1 for v in series.values() if v > 0))

def resolve_window(u, peak):
    """Modeler UI bounds applied to a usage row (window cannot cross midnight, overtime fields consistent)."""
    start = u.get('StartHour') if u else None
    start_hr = int(start) if start is not None else 9
    dur_raw = int(u['WorkDurationMinutes']) if u and u.get('WorkDurationMinutes') else 540
    max_dur = 1425 - 60 * start_hr
    duration = min(dur_raw, max_dur)
    work_days = list(u['WorkDays']) if u and u.get('WorkDays') else [1, 2, 3, 4, 5]
    off_uh = float(u['WeeklyOffUH']) if u and u.get('WeeklyOffUH') else 0.0
    ot_hours, ot_pct = 1, 0
    if peak > 0 and off_uh > 0:
        raw = off_uh / 7.0 / peak
        if raw > 1.0: ot_hours = int(math.ceil(raw))
        ot_pct = int(min(100, round(100.0 * off_uh / 7.0 / (peak * ot_hours))))
    sparse = bool(peak > 0 and u and u.get('StartHour') is None)
    return dict(start=start_hr, duration=duration, duration_raw=dur_raw, days=work_days, off_uh=off_uh,
                ot_hours=ot_hours, ot_pct=ot_pct, sparse=sparse)

def window_text(w):
    return '%d:00+%gh' % (w['start'], round(w['duration'] / 60.0, 2))

def overtime_text(w):
    return '%d%% x %dh' % (w['ot_pct'], w['ot_hours'] if w['ot_pct'] > 0 else 1)

# ============================================================================ Modeler deployment
def new_deployment(name, peak, win, experience, region, vm_size, disk_gb, disk_sku, density, custom_image=False):
    return collections.OrderedDict([
        ('mode', 'avd'), ('name', name),
        ('users', collections.OrderedDict([('total', max(1, int(peak))), ('absentPercent', 0), ('overtimeEnabled', win['ot_pct'] > 0),
                                           ('overtimePercent', win['ot_pct']), ('overtimeHours', win['ot_hours'] if win['ot_pct'] > 0 else 0)])),
        ('experience', experience), ('region', region),
        ('workload', collections.OrderedDict([('type', 5), ('vmSize', vm_size),
                                              ('disk', collections.OrderedDict([('isEphemeral', False), ('size', disk_gb), ('type', disk_sku)])),
                                              ('maxUsersPerVCpu', round(density, 2)), ('stoppedDiskType', 'Standard_LRS'), ('rdpEgressGb', 10)])),
        ('image', collections.OrderedDict([('type', 2), ('monthlyRunningHours', 6), ('vmSize', 'Standard_D2s_v5'), ('isCisHardenedImage', False)]) if custom_image
                  else collections.OrderedDict([('type', 1), ('isCisHardenedImage', False)])),
        ('autoScale', collections.OrderedDict([('type', 0), ('workDays', list(win['days'])), ('workStartHour', win['start']), ('workStartMinutes', 0),
                                               ('workDurationMinutes', win['duration'])])),
        ('fsLogix', collections.OrderedDict([('enabled', False)])),
        ('administrative', collections.OrderedDict([('tasks', ADMIN_TASKS), ('hourlyRate', 100), ('isEnabled', False)])),
        ('savings', collections.OrderedDict([('reservedInstances', collections.OrderedDict([('count', 0), ('years', 1)]))])),
    ])

def preflight(deployments):
    """Replays the Modeler's own import checks (same rules the Azure tool enforces) and corrects in place."""
    fixes = []
    for d in deployments:
        w = d['workload']; us = d['users']; a = d['autoScale']
        if not d.get('name'): d['name'] = 'Unnamed group'; fixes.append('an unnamed deployment was named "Unnamed group"')
        if not us['total'] >= 1: fixes.append('%s: users.total %s -> 1' % (d['name'], us['total'])); us['total'] = 1
        if not d.get('region'): fixes.append('%s: region was empty -> eastus (check it)' % d['name']); d['region'] = 'eastus'
        if d['experience'] not in (1, 2, 3, 4): fixes.append('%s: experience %s -> 1' % (d['name'], d['experience'])); d['experience'] = 1
        if w['type'] != 5: fixes.append('%s: workload type -> 5' % d['name']); w['type'] = 5
        if not w['maxUsersPerVCpu'] >= 0.1: fixes.append('%s: maxUsersPerVCpu %s -> 0.1 (Modeler minimum)' % (d['name'], w['maxUsersPerVCpu'])); w['maxUsersPerVCpu'] = 0.1
        if not w['rdpEgressGb'] > 0: w['rdpEgressGb'] = 10
        if w['disk']['type'] not in ('Standard_LRS', 'StandardSSD_LRS', 'Premium_LRS'): fixes.append('%s: disk type -> Premium_LRS' % d['name']); w['disk']['type'] = 'Premium_LRS'
        if w['disk']['size'] not in DISK_TIERS:
            s = snap_disk(int(w['disk']['size'])); fixes.append('%s: disk size %s -> %d (Modeler tier)' % (d['name'], w['disk']['size'], s)); w['disk']['size'] = s
        if w['stoppedDiskType'] not in ('Standard_LRS', 'StandardSSD_LRS', 'Premium_LRS'): w['stoppedDiskType'] = 'Standard_LRS'
        if d['image']['type'] == 2 and not d['image'].get('monthlyRunningHours', 0) > 0: d['image']['monthlyRunningHours'] = 6
        if not (0 <= us['absentPercent'] <= 100): us['absentPercent'] = 0
        ot_bad = (us['overtimeEnabled'] and (us['overtimePercent'] <= 0 or us['overtimeHours'] <= 0)) or \
                 ((not us['overtimeEnabled']) and (us['overtimePercent'] != 0 or us['overtimeHours'] != 0)) or us['overtimePercent'] > 100
        if ot_bad: fixes.append('%s: overtime fields were inconsistent -> overtime off' % d['name']); us['overtimeEnabled'] = False; us['overtimePercent'] = 0; us['overtimeHours'] = 0
        if not a['workDays']: fixes.append('%s: empty work days -> Mon-Fri' % d['name']); a['workDays'] = [1, 2, 3, 4, 5]
        if not (0 <= a['workStartHour'] <= 23): fixes.append('%s: work start hour -> 9' % d['name']); a['workStartHour'] = 9
        if not a['workDurationMinutes'] > 0: fixes.append('%s: work duration -> 540' % d['name']); a['workDurationMinutes'] = 540
        if a['workStartHour'] * 60 + a['workDurationMinutes'] > 1425:
            a['workDurationMinutes'] = 1425 - 60 * a['workStartHour']; fixes.append('%s: window trimmed to end by 11:45 PM' % d['name'])
    return fixes

# ============================================================================ AWS access
class Aws:
    """Thin wrapper over boto3 so the whole collector can run against stubbed clients (--demo, tests)."""
    def __init__(self, session=None, client_factory=None, profile=None):
        self.session = session
        self.factory = client_factory
        self.profile = profile
        self.config = None
        if client_factory is None:
            import boto3
            from botocore.config import Config
            self.session = session or (boto3.Session(profile_name=profile) if profile else boto3.Session())
            self.config = Config(retries={'max_attempts': 10, 'mode': 'standard'}, user_agent_extra='nerdio-modeler-aws/%s' % SCRIPT_VERSION,
                                 connect_timeout=10, read_timeout=60)
    def client(self, service, region=None, credentials=None):
        if self.factory: return self.factory(service, region, credentials)
        kw = dict(region_name=region, config=self.config)
        if credentials:
            kw.update(aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'])
        return self.session.client(service, **kw)
    def available_regions(self, service):
        if self.factory:
            try: return self.factory('__regions__', service, None)
            except Exception: return []
        try: return self.session.get_available_regions(service)
        except Exception: return []

def error_code(exc):
    try: return exc.response['Error']['Code']
    except Exception: return exc.__class__.__name__

def error_message(exc):
    try: return str(exc.response['Error'].get('Message') or '')
    except Exception: return str(exc)

def is_access_denied(exc):
    return error_code(exc) in ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation', 'UnrecognizedClientException',
                               'AuthFailure', 'InvalidClientTokenId', 'ExpiredToken', 'ExpiredTokenException')

# Refusals that are about the account, not the policy. No IAM grant changes these, so they are reported as
# 'not offered' and never counted against the principal:
#   OptInRequired / SubscriptionRequiredException   the account has not enabled the service or region
#   PendingVerification                             a new account AWS has not finished verifying
#   WorkSpaces Pools end of support                 AccessDeniedException whose message says the service takes no new
#                                                   customers (since Jul 31, 2026; support ends Dec 31, 2027)
def not_offered_reason(exc):
    code = error_code(exc); msg = error_message(exc)
    if code in ('OptInRequired', 'SubscriptionRequiredException', 'PendingVerification'): return code
    if 'no longer available to new customers' in msg or 'end-of-support' in msg: return 'not offered to new customers'
    return None

ACCESS = {}   # (service, region) -> 'ok' | 'denied' | 'not offered' | 'unavailable' | 'error'; printed at the end so an empty account still shows what was reachable
_REGION_RX = re.compile(r'^[a-z]{2}-[a-z]+-\d$')
def _record_access(label, status):
    words = label.split()
    service = 'Cost Explorer' if words[0] == 'Cost' else words[0]
    region = next((w for w in words if _REGION_RX.match(w)), 'global')
    prev = ACCESS.get((service, region))
    if prev == 'denied': return                                   # a denial is the headline for that service and region
    if status == 'not offered' and prev == 'ok': return           # one API not offered does not make the service unreadable
    if prev == 'not offered' and status == 'ok': ACCESS[(service, region)] = 'ok'; return
    if prev in (None, 'ok') or status != 'ok': ACCESS[(service, region)] = status

def safe(label, fn, default=None, quiet=False, quiet_codes=()):
    """Runs one read. Access denied and unavailable endpoints are reported, never fatal."""
    import botocore.exceptions as be
    try:
        result = fn()
        _record_access(label, 'ok')
        return result
    except be.EndpointConnectionError:
        _record_access(label, 'unavailable')
        if not quiet: LOG.info('%s: service endpoint not reachable here (region not enabled for it); skipped.' % label)
    except be.ClientError as e:
        code = error_code(e)
        if code in quiet_codes: return default
        reason = not_offered_reason(e)
        if reason:
            _record_access(label, 'not offered')
            LOG.info('%s: not offered on this account (%s: %s). Not a permissions problem; skipped.' % (label, reason, error_message(e)[:160]))
        elif is_access_denied(e):
            _record_access(label, 'denied')
            LOG.warn('%s: access denied (%s: %s). Grant the read-only policy in the README and run again; everything else continues.' % (label, code, error_message(e)[:120]))
        else:
            _record_access(label, 'error')
            LOG.warn('%s: %s: %s' % (label, code, str(e)[:200]))
    except be.NoCredentialsError:
        LOG.warn('%s: no AWS credentials in this shell. In CloudShell this cannot happen; locally run `aws configure` or `aws sso login` first.' % label)
        raise
    except be.BotoCoreError as e:
        _record_access(label, 'error')
        LOG.warn('%s: %s' % (label, str(e)[:200]))
    except Exception as e:  # keep the run alive; name the failure
        _record_access(label, 'error')
        LOG.warn('%s: %s: %s' % (label, e.__class__.__name__, str(e)[:200]))
    return default

def print_access_check():
    """One line per service: where the reads worked, where they were refused. The thing to look at on a first run."""
    if not ACCESS: return
    LOG.raw('')
    LOG.ok('SERVICE ACCESS CHECK (reads attempted this run):')
    by = collections.defaultdict(lambda: collections.defaultdict(list))
    for (service, region), status in sorted(ACCESS.items()):
        by[service][status].append(region)
    for service in sorted(by):
        parts = []
        for status in ('ok', 'denied', 'not offered', 'unavailable', 'error'):
            regs = by[service].get(status)
            if regs: parts.append('%s: %s' % (status, ', '.join(regs) if len(regs) <= 6 else '%d regions' % len(regs)))
        LOG.raw('    %-14s %s' % (service, '; '.join(parts)))
    denied = sorted(set(s for (s, r), st in ACCESS.items() if st == 'denied'))
    if denied: LOG.warn('Denied somewhere: %s. The README has the minimal read-only policy.' % ', '.join(denied))

# ============================================================================ CloudWatch series
class MetricPuller:
    """GetMetricData in batches. Each query is (key, namespace, metric, dimensions, stat). Returns
    {key: {slot_start_utc: value}} on the lookback's slot grid."""
    def __init__(self, cw, lb, period, region='global'):
        self.cw = cw; self.lb = lb; self.period = period; self.region = region
        self.calls = 0; self.datapoints = 0
    def pull(self, queries, batch=150):
        out = {}
        for i in range(0, len(queries), batch):
            chunk = queries[i:i + batch]
            ids = {}
            mdq = []
            for n, (key, ns, metric, dims, stat) in enumerate(chunk):
                qid = 'q%d' % n; ids[qid] = key
                mdq.append({'Id': qid, 'ReturnData': True,
                            'MetricStat': {'Metric': {'Namespace': ns, 'MetricName': metric, 'Dimensions': [{'Name': k, 'Value': v} for k, v in dims]},
                                           'Period': self.period, 'Stat': stat}})
            token = None
            while True:
                kw = dict(MetricDataQueries=mdq, StartTime=self.lb.start, EndTime=self.lb.end, ScanBy='TimestampAscending')
                if token: kw['NextToken'] = token
                resp = safe('CloudWatch GetMetricData %s' % self.region, lambda: self.cw.get_metric_data(**kw))
                self.calls += 1
                if not resp: break
                for r in resp.get('MetricDataResults', []):
                    key = ids.get(r['Id'])
                    if key is None: continue
                    d = out.setdefault(key, {})
                    for ts, v in zip(r.get('Timestamps', []), r.get('Values', [])):
                        if ts.tzinfo is None: ts = ts.replace(tzinfo=dt.timezone.utc)
                        d[ts.astimezone(dt.timezone.utc)] = v
                        self.datapoints += 1
                token = resp.get('NextToken')
                if not token: break
        return out

def discover_dimension(cw, namespace, metric, want_dim, region='global'):
    """ListMetrics tells us which dimension name a service uses (pools, fleets), instead of guessing."""
    found = {}
    def fn():
        token = None
        while True:
            kw = dict(Namespace=namespace, MetricName=metric)
            if token: kw['NextToken'] = token
            resp = cw.list_metrics(**kw)
            for m in resp.get('Metrics', []):
                for d in m.get('Dimensions', []):
                    if d['Name'].lower() == want_dim.lower(): found[d['Value']] = d['Name']
            token = resp.get('NextToken')
            if not token: return found
    safe('CloudWatch ListMetrics %s/%s %s' % (namespace, metric, region), fn)
    return found

# ============================================================================ collectors
class Estate:
    def __init__(self):
        self.accounts = []            # [{id, name, source}]
        self.regions_checked = {}     # account -> [regions]
        self.directories = []         # WorkSpaces directories (personal and pools)
        self.workspaces = []          # WorkSpaces personal desktops (no user names)
        self.bundles = {}             # bundle id -> dict
        self.pools = []               # WorkSpaces Pools
        self.fleets = []              # AppStream fleets
        self.stacks = []
        self.usage_reports = []       # AppStream usage report subscriptions
        self.ec2 = []                 # opt-in EC2 inventory
        self.groups = {}              # group key -> dict(series, meta)
        self.ws_usage = {}            # workspace id -> per-WorkSpace usage facts
        self.user_tokens = collections.defaultdict(set)   # group key -> set(token)  (memory only)
        self.all_tokens = set()
        self.costs = []               # cost rows
        self.cost_summary = {}
        self.prices = {}              # region -> list of WorkSpaces price rows
        self.telemetry = dict(metrics_calls=0, datapoints=0, groups_with_data=0, notes=[])
        self.errors = []
        self.sessions_report = {}     # fleet key -> dict(users set (memory), sessions, hours)

def collect_account(aws, est, acct, creds, args, lb, hasher):
    """Everything for one account: regions, inventory, metrics, S3 usage reports, EC2."""
    acct_id = acct['id']
    ec2_global = aws.client('ec2', region='us-east-1', credentials=creds)
    enabled = safe('EC2 DescribeRegions', lambda: [r['RegionName'] for r in ec2_global.describe_regions(AllRegions=False)['Regions']], default=[])
    if not enabled:
        enabled = sorted(set(aws.available_regions('workspaces')) | set(aws.available_regions('appstream')))
        LOG.warn('Could not list enabled regions; trying every region where WorkSpaces or AppStream exists (%d).' % len(enabled))
    if args.regions: enabled = [r for r in enabled if r in args.regions]
    ws_regions = set(aws.available_regions('workspaces')) or set(enabled)
    as_regions = set(aws.available_regions('appstream')) or set(enabled)
    est.regions_checked[acct_id] = enabled
    LOG.info('Account %s: %d enabled region(s): %s' % (acct_id, len(enabled), ', '.join(enabled)))
    period = 900 if lb.days <= 60 else 3600
    for region in enabled:
        cw = aws.client('cloudwatch', region=region, credentials=creds)
        puller = MetricPuller(cw, lb, period, region)
        if region in ws_regions:
            collect_workspaces_region(aws, est, acct_id, creds, region, args, lb, hasher, puller)
        if region in as_regions:
            collect_appstream_region(aws, est, acct_id, creds, region, args, lb, hasher, puller)
        if args.ec2_tag or args.ec2_name_regex:
            collect_ec2_region(aws, est, acct_id, creds, region, args, lb, puller)
        est.telemetry['metrics_calls'] += puller.calls; est.telemetry['datapoints'] += puller.datapoints

def dir_label(d):
    return d.get('WorkspaceDirectoryName') or d.get('Alias') or d.get('DirectoryName') or d.get('DirectoryId')

def collect_workspaces_region(aws, est, acct_id, creds, region, args, lb, hasher, puller):
    ws = aws.client('workspaces', region=region, credentials=creds)
    dirs = safe('WorkSpaces DescribeWorkspaceDirectories %s' % region, lambda: paginate(ws.describe_workspace_directories, 'Directories'))
    if dirs is None: return
    for d in dirs:
        est.directories.append(dict(account=acct_id, region=region, id=d['DirectoryId'], label=dir_label(d), type=d.get('WorkspaceType', 'PERSONAL'),
                                    directory_type=d.get('DirectoryType'), identity=d.get('UserIdentityType'), tenancy=d.get('Tenancy'), state=d.get('State')))
    wss = safe('WorkSpaces DescribeWorkspaces %s' % region, lambda: paginate(ws.describe_workspaces, 'Workspaces'), default=[])
    pools = safe('WorkSpaces DescribeWorkspacesPools %s' % region, lambda: paginate(ws.describe_workspaces_pools, 'WorkspacesPools'), default=[])
    if not dirs and not wss and not pools:
        return
    LOG.ok('%s: %d WorkSpaces director%s, %d personal WorkSpaces, %d pool(s).' % (region, len(dirs), 'y' if len(dirs) == 1 else 'ies', len(wss), len(pools)))
    # bundles (Amazon-owned and custom) for the ids in use
    bundle_ids = sorted(set([w.get('BundleId') for w in wss if w.get('BundleId')] + [p.get('BundleId') for p in pools if p.get('BundleId')]))
    for i in range(0, len(bundle_ids), 25):
        chunk = bundle_ids[i:i + 25]
        rows = safe('WorkSpaces DescribeWorkspaceBundles %s' % region, lambda: paginate(ws.describe_workspace_bundles, 'Bundles', BundleIds=chunk), default=[])
        for b in rows:
            est.bundles[b['BundleId']] = dict(id=b['BundleId'], name=b.get('Name'), owner=b.get('Owner'), compute=(b.get('ComputeType') or {}).get('Name'),
                                             root_gb=_gb((b.get('RootStorage') or {}).get('Capacity')), user_gb=_gb((b.get('UserStorage') or {}).get('Capacity')),
                                             description=b.get('Description'))
    # connection status (last known user connection), 25 ids per call
    last_conn = {}
    ids = [w['WorkspaceId'] for w in wss]
    for i in range(0, len(ids), 25):
        chunk = ids[i:i + 25]
        rows = safe('WorkSpaces DescribeWorkspacesConnectionStatus %s' % region,
                    lambda: paginate(ws.describe_workspaces_connection_status, 'WorkspacesConnectionStatus', WorkspaceIds=chunk), default=[])
        for r in rows: last_conn[r['WorkspaceId']] = r
    dir_by_id = {d['DirectoryId']: d for d in dirs}
    # per-WorkSpace records (no user names: a salted token in memory, counts in the output)
    group_members = collections.defaultdict(list)
    for w in wss:
        props = w.get('WorkspaceProperties') or {}
        compute = props.get('ComputeTypeName') or (est.bundles.get(w.get('BundleId')) or {}).get('compute') or 'UNKNOWN'
        d = dir_by_id.get(w.get('DirectoryId'), {'DirectoryId': w.get('DirectoryId')})
        gkey = 'ws:%s:%s:%s:%s' % (acct_id, region, w.get('DirectoryId'), compute)
        tok = hasher.token(w.get('UserName'))
        if tok: est.user_tokens[gkey].add(tok); est.all_tokens.add(tok)
        lc = last_conn.get(w['WorkspaceId'], {})
        rec = dict(account=acct_id, region=region, id=w['WorkspaceId'], directory=w.get('DirectoryId'), directory_label=dir_label(d), compute=compute,
                   bundle=w.get('BundleId'), running_mode=props.get('RunningMode'), autostop_minutes=props.get('RunningModeAutoStopTimeoutInMinutes'),
                   root_gb=props.get('RootVolumeSizeGib'), user_gb=props.get('UserVolumeSizeGib'), os=props.get('OperatingSystemName'),
                   protocols=props.get('Protocols'), state=w.get('State'), connection_state=lc.get('ConnectionState'),
                   last_user_connection=iso(lc.get('LastKnownUserConnectionTimestamp')), group=gkey, has_user=bool(tok))
        est.workspaces.append(rec)
        group_members[gkey].append(rec)
    # usage: UserConnected (presence), Available (running), UserVolumeDiskUsage (profile sizing) per WorkSpace
    queries = []
    for w in wss:
        wid = w['WorkspaceId']
        queries.append((('uc', wid), 'AWS/WorkSpaces', 'UserConnected', [('WorkspaceId', wid)], 'Maximum'))
        queries.append((('av', wid), 'AWS/WorkSpaces', 'Available', [('WorkspaceId', wid)], 'Maximum'))
        queries.append((('uv', wid), 'AWS/WorkSpaces', 'UserVolumeDiskUsage', [('WorkspaceId', wid)], 'Maximum'))
    series = puller.pull(queries) if queries else {}
    for gkey, members in group_members.items():
        conc = collections.Counter(); running = collections.Counter()
        for rec in members:
            uc = series.get(('uc', rec['id']), {}); av = series.get(('av', rec['id']), {}); uv = series.get(('uv', rec['id']), {})
            connected_slots = sum(1 for v in uc.values() if v and v > 0)
            running_slots = sum(1 for v in av.values() if v and v > 0)
            days_active = len(set(to_local(k, lb.tz).date() for k, v in uc.items() if v and v > 0))
            used_pct = max(uv.values()) if uv else None
            est.ws_usage[rec['id']] = dict(connected_hours=round(connected_slots * lb.slot_hours, 1), running_hours=round(running_slots * lb.slot_hours, 1),
                                           days_active=days_active, metric_points=len(uc),
                                           user_volume_used_gb=(round(rec['user_gb'] * used_pct / 100.0, 1) if (used_pct is not None and rec.get('user_gb')) else None))
            for k, v in uc.items():
                if v and v > 0: conc[k] += 1
            for k, v in av.items():
                if v and v > 0: running[k] += 1
        first = members[0]
        est.groups[gkey] = dict(kind='WorkSpacesPersonal', account=acct_id, region=region, label=first['directory_label'], subgroup=first['compute'],
                                count=len(members), series=dict(conc), capacity_series=dict(running), directory=first['directory'],
                                running_modes=collections.Counter(m['running_mode'] for m in members), os=collections.Counter(m['os'] for m in members),
                                user_gb=sum((m.get('user_gb') or 0) for m in members), root_gb=sum((m.get('root_gb') or 0) for m in members),
                                mau=len(est.user_tokens.get(gkey, ())), flags=[])
    # pools
    for p in pools:
        pid = p['PoolId']
        est.pools.append(dict(account=acct_id, region=region, id=pid, name=p.get('PoolName'), state=p.get('State'), bundle=p.get('BundleId'),
                              directory=p.get('DirectoryId'), running_mode=p.get('RunningMode'), capacity=p.get('CapacityStatus') or {},
                              timeouts=p.get('TimeoutSettings') or {}, created=iso(p.get('CreatedAt'))))
    if pools:
        dim = discover_dimension(aws.client('cloudwatch', region=region, credentials=creds), 'AWS/WorkSpaces', 'ActiveUserSessionCapacity', 'PoolId', region)
        queries = []
        for p in pools:
            pid = p['PoolId']; dname = dim.get(pid, 'PoolId')
            queries.append((('pa', pid), 'AWS/WorkSpaces', 'ActiveUserSessionCapacity', [(dname, pid)], 'Maximum'))
            queries.append((('pc', pid), 'AWS/WorkSpaces', 'ActualUserSessionCapacity', [(dname, pid)], 'Maximum'))
        pseries = puller.pull(queries)
        for p in pools:
            pid = p['PoolId']; gkey = 'pool:%s:%s:%s' % (acct_id, region, pid)
            b = est.bundles.get(p.get('BundleId')) or {}
            active = {k: int(round(v)) for k, v in pseries.get(('pa', pid), {}).items()}
            cap = {k: int(round(v)) for k, v in pseries.get(('pc', pid), {}).items()}
            est.groups[gkey] = dict(kind='WorkSpacesPool', account=acct_id, region=region, label=p.get('PoolName') or pid, subgroup=b.get('compute') or 'UNKNOWN',
                                    count=max([v for v in cap.values()] or [(p.get('CapacityStatus') or {}).get('ActualUserSessions') or 0]),
                                    series=active, capacity_series=cap, running_modes=collections.Counter([p.get('RunningMode')]), os=collections.Counter(),
                                    user_gb=0, root_gb=0, mau=None, flags=['AWS pool: one streaming instance per session; AVD proposal is multi-session'])

def _gb(capacity):
    try: return int(float(str(capacity)))
    except Exception: return None

def collect_appstream_region(aws, est, acct_id, creds, region, args, lb, hasher, puller):
    ap = aws.client('appstream', region=region, credentials=creds)
    fleets = safe('AppStream DescribeFleets %s' % region, lambda: paginate(ap.describe_fleets, 'Fleets'))
    if fleets is None: return
    if not fleets: return
    stacks = safe('AppStream DescribeStacks %s' % region, lambda: paginate(ap.describe_stacks, 'Stacks'), default=[])
    subs = safe('AppStream DescribeUsageReportSubscriptions %s' % region, lambda: paginate(ap.describe_usage_report_subscriptions, 'UsageReportSubscriptions'), default=[])
    LOG.ok('%s: %d WorkSpaces Applications (AppStream) fleet(s), %d stack(s), usage reports %s.' % (region, len(fleets), len(stacks), 'ON' if subs else 'off'))
    for s in stacks:
        est.stacks.append(dict(account=acct_id, region=region, name=s.get('Name'), home_folders=any(c.get('ConnectorType') == 'HOMEFOLDERS' for c in s.get('StorageConnectors', [])),
                               app_settings=bool((s.get('ApplicationSettings') or {}).get('Enabled'))))
    for s in subs:
        est.usage_reports.append(dict(account=acct_id, region=region, bucket=s.get('S3BucketName'), schedule=s.get('Schedule'), last=iso(s.get('LastGeneratedReportDate'))))
    queries = []
    for f in fleets:
        name = f['Name']
        multi = int(f.get('MaxSessionsPerInstance') or 1) > 1
        queries.append((('inuse', name), 'AWS/AppStream', 'InUseCapacity', [('Fleet', name)], 'Maximum'))
        queries.append((('actual', name), 'AWS/AppStream', 'ActualCapacity', [('Fleet', name)], 'Maximum'))
        if multi: queries.append((('sessions', name), 'AWS/AppStream', 'ActiveUserSessionCapacity', [('Fleet', name)], 'Maximum'))
    fseries = puller.pull(queries)
    for f in fleets:
        name = f['Name']; gkey = 'fleet:%s:%s:%s' % (acct_id, region, name)
        flags = []
        vcpu = vcpu_for_instance_type(f.get('InstanceType'), flags)
        multi = int(f.get('MaxSessionsPerInstance') or 1) > 1
        est.fleets.append(dict(account=acct_id, region=region, name=name, instance_type=f.get('InstanceType'), vcpu=vcpu, fleet_type=f.get('FleetType'),
                               platform=f.get('Platform'), stream_view=f.get('StreamView'), state=f.get('State'), max_sessions_per_instance=f.get('MaxSessionsPerInstance') or 1,
                               max_user_duration_s=f.get('MaxUserDurationInSeconds'), disconnect_timeout_s=f.get('DisconnectTimeoutInSeconds'),
                               idle_disconnect_s=f.get('IdleDisconnectTimeoutInSeconds'), capacity=f.get('ComputeCapacityStatus') or {}, image=f.get('ImageName')))
        inuse = {k: int(round(v)) for k, v in fseries.get(('inuse', name), {}).items()}
        actual = {k: int(round(v)) for k, v in fseries.get(('actual', name), {}).items()}
        sessions = {k: int(round(v)) for k, v in fseries.get(('sessions', name), {}).items()} if multi else inuse
        if f.get('FleetType') == 'ELASTIC': flags.append('Elastic fleet: only InUseCapacity is reported by AWS')
        est.groups[gkey] = dict(kind='AppStreamFleet', account=acct_id, region=region, label=name, subgroup=f.get('InstanceType'),
                                count=max(list(actual.values()) or [(f.get('ComputeCapacityStatus') or {}).get('Running') or 0]),
                                series=sessions, capacity_series=actual, instance_series=inuse, running_modes=collections.Counter([f.get('FleetType')]),
                                os=collections.Counter([f.get('Platform')]), user_gb=0, root_gb=0, mau=None, flags=flags,
                                vcpu=vcpu, multi=multi, max_sessions=int(f.get('MaxSessionsPerInstance') or 1), stream_view=f.get('StreamView'))
    if subs and not args.skip_usage_report:
        read_usage_reports(aws, est, acct_id, creds, region, subs, lb, hasher)

def read_usage_reports(aws, est, acct_id, creds, region, subs, lb, hasher):
    """Daily sessions CSVs: user tokens per fleet (MAU), sessions and user-hours. Best effort; a missing day is skipped."""
    s3 = aws.client('s3', region=region, credentials=creds)
    for s in subs:
        bucket = s.get('S3BucketName')
        if not bucket: continue
        days = 0; rows = 0
        d = to_local(lb.start, dt.timezone.utc).date()
        last = to_local(lb.end, dt.timezone.utc).date()
        while d <= last:
            key = 'sessions/schedule=DAILY/year=%04d/month=%02d/day=%02d/daily-session-report-%04d-%02d-%02d.csv' % (d.year, d.month, d.day, d.year, d.month, d.day)
            body = safe('S3 GetObject usage report %s %s' % (d.isoformat(), region), lambda: s3.get_object(Bucket=bucket, Key=key)['Body'].read(), quiet=True, quiet_codes=('NoSuchKey', '404'))
            d += dt.timedelta(days=1)
            if not body: continue
            days += 1
            text = body.decode('utf-8', 'replace') if isinstance(body, (bytes, bytearray)) else str(body)
            for r in csv.DictReader(io.StringIO(text)):
                rows += 1
                fleet = r.get('fleet_name') or r.get('FleetName'); user = r.get('authentication_type_user_id') or r.get('user_id') or r.get('UserId')
                if not fleet: continue
                gkey = 'fleet:%s:%s:%s' % (acct_id, region, fleet)
                rec = est.sessions_report.setdefault(gkey, dict(sessions=0, user_hours=0.0, days=set()))
                rec['sessions'] += 1
                try: rec['user_hours'] += float(r.get('session_duration_in_seconds') or 0) / 3600.0
                except ValueError: pass
                rec['days'].add(d.isoformat())
                tok = hasher.token(user)
                if tok: est.user_tokens[gkey].add(tok); est.all_tokens.add(tok)
        LOG.ok('%s: usage report bucket read: %d daily file(s), %d session row(s) in the lookback (user ids hashed, counts only).' % (region, days, rows))
        if days == 0: est.telemetry['notes'].append('%s: usage report subscription exists but no daily files were readable in the lookback (bucket %s)' % (region, bucket))

def collect_ec2_region(aws, est, acct_id, creds, region, args, lb, puller):
    ec2 = aws.client('ec2', region=region, credentials=creds)
    filters = [{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]
    for t in (args.ec2_tag or []):
        k, _, v = t.partition('=')
        filters.append({'Name': 'tag:%s' % k, 'Values': [v or '*']})
    reservations = safe('EC2 DescribeInstances %s' % region, lambda: paginate(ec2.describe_instances, 'Reservations', Filters=filters), default=[])
    rx = re.compile(args.ec2_name_regex, re.I) if args.ec2_name_regex else None
    instances = []
    for r in reservations:
        for i in r.get('Instances', []):
            name = next((t['Value'] for t in i.get('Tags', []) if t['Key'] == 'Name'), '')
            if rx and not rx.search(name or ''): continue
            instances.append(dict(account=acct_id, region=region, id=i['InstanceId'], name=name, type=i.get('InstanceType'), state=(i.get('State') or {}).get('Name'),
                                  platform=i.get('PlatformDetails') or i.get('Platform') or 'Linux/UNIX', launched=iso(i.get('LaunchTime')),
                                  tags={t['Key']: t['Value'] for t in i.get('Tags', []) if t['Key'] != 'Name'}))
    if not instances: return
    LOG.ok('%s: %d EC2 instance(s) matched the VDI filter.' % (region, len(instances)))
    queries = [(('cpu', i['id']), 'AWS/EC2', 'CPUUtilization', [('InstanceId', i['id'])], 'SampleCount') for i in instances]
    series = puller.pull(queries)
    for i in instances:
        s = series.get(('cpu', i['id']), {})
        i['running_hours'] = round(sum(1 for v in s.values() if v and v > 0) * lb.slot_hours, 1)
        i['vcpu'] = vcpu_for_instance_type(i['type'])
        est.ec2.append(i)
    gkey = 'ec2:%s:%s' % (acct_id, region)
    running = collections.Counter()
    for i in instances:
        for k, v in series.get(('cpu', i['id']), {}).items():
            if v and v > 0: running[k] += 1
    est.groups[gkey] = dict(kind='EC2', account=acct_id, region=region, label='EC2 VDI hosts', subgroup=', '.join(sorted(set(i['type'] for i in instances))),
                            count=len(instances), series={}, capacity_series=dict(running), running_modes=collections.Counter(i['state'] for i in instances),
                            os=collections.Counter(i['platform'] for i in instances), user_gb=0, root_gb=0, mau=None,
                            flags=['EC2 hosts: AWS has no session data for broker-based VDI; users and density must come from the broker (Citrix Director, Horizon events)'])

# ============================================================================ Cost Explorer
def month_bounds(ref=None):
    ref = (ref or utcnow()).date()
    first_this = ref.replace(day=1)
    last_month_end = first_this
    last_month_start = (first_this - dt.timedelta(days=1)).replace(day=1)
    return [('last full month', last_month_start.isoformat(), last_month_end.isoformat()),
            ('month to date', first_this.isoformat(), (ref + dt.timedelta(days=1)).isoformat())]

def collect_costs(aws, est, creds, args):
    ce = aws.client('ce', region='us-east-1', credentials=creds)
    metrics = ['AmortizedCost', 'UnblendedCost', 'UsageQuantity']
    for label, start, end in month_bounds():
        if start >= end: continue
        by_service = safe('Cost Explorer by service (%s)' % label, lambda: _ce_all(ce, start, end, metrics, [{'Type': 'DIMENSION', 'Key': 'SERVICE'}], None))
        if by_service is None:
            est.cost_summary.setdefault('errors', []).append('%s: Cost Explorer unavailable' % label)
            return
        total = 0.0; vdi_services = []
        for g in by_service:
            svc = g['Keys'][0]; amt = float(g['Metrics']['AmortizedCost']['Amount'])
            total += amt
            if VDI_SERVICE_RX.search(svc): vdi_services.append(svc)
            est.costs.append(dict(period=label, start=start, end=end, account='', service=svc, usage_type='', region='',
                                  amortized=round(amt, 2), unblended=round(float(g['Metrics']['UnblendedCost']['Amount']), 2),
                                  quantity=round(float(g['Metrics']['UsageQuantity']['Amount']), 3), unit=g['Metrics']['UsageQuantity'].get('Unit', '')))
        est.cost_summary[label] = dict(total_amortized=round(total, 2), vdi_services=vdi_services)
        if not vdi_services:
            LOG.info('Cost Explorer (%s): no WorkSpaces or AppStream line on the bill; AWS total %.2f.' % (label, total))
            continue
        flt = {'Dimensions': {'Key': 'SERVICE', 'Values': vdi_services}}
        detail = safe('Cost Explorer by usage type (%s)' % label, lambda: _ce_all(ce, start, end, metrics, [{'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'}, {'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}], flt), default=[])
        vdi_total = 0.0; users_from_bill = collections.defaultdict(float)
        for g in detail:
            ut, acct_id = g['Keys'][0], g['Keys'][1]
            amt = float(g['Metrics']['AmortizedCost']['Amount']); qty = float(g['Metrics']['UsageQuantity']['Amount'])
            vdi_total += amt
            est.costs.append(dict(period=label, start=start, end=end, account=acct_id, service='(WorkSpaces/AppStream)', usage_type=ut, region='',
                                  amortized=round(amt, 2), unblended=round(float(g['Metrics']['UnblendedCost']['Amount']), 2), quantity=round(qty, 3),
                                  unit=g['Metrics']['UsageQuantity'].get('Unit', '')))
            if re.search(r'user', ut, re.I): users_from_bill[ut] += qty
        by_region = safe('Cost Explorer by region (%s)' % label, lambda: _ce_all(ce, start, end, metrics, [{'Type': 'DIMENSION', 'Key': 'REGION'}, {'Type': 'DIMENSION', 'Key': 'SERVICE'}], flt), default=[])
        for g in by_region:
            est.costs.append(dict(period=label, start=start, end=end, account='', service=g['Keys'][1], usage_type='', region=g['Keys'][0],
                                  amortized=round(float(g['Metrics']['AmortizedCost']['Amount']), 2), unblended=round(float(g['Metrics']['UnblendedCost']['Amount']), 2),
                                  quantity=round(float(g['Metrics']['UsageQuantity']['Amount']), 3), unit=g['Metrics']['UsageQuantity'].get('Unit', '')))
        est.cost_summary[label].update(vdi_amortized=round(vdi_total, 2), users_from_bill={k: round(v) for k, v in users_from_bill.items()})
        LOG.ok('Cost Explorer (%s): AWS total %.2f, WorkSpaces/AppStream %.2f amortized across %d usage type(s).' % (label, total, vdi_total, len(detail)))
        if users_from_bill: LOG.info('  user-fee usage types on the bill (distinct users AWS charged for): %s' % ', '.join('%s=%d' % (k, round(v)) for k, v in users_from_bill.items()))
    if args.ec2_tag:
        for label, start, end in month_bounds():
            for t in args.ec2_tag:
                k, _, v = t.partition('=')
                rows = safe('Cost Explorer by tag %s (%s)' % (k, label), lambda: _ce_all(ce, start, end, metrics, [{'Type': 'DIMENSION', 'Key': 'SERVICE'}], {'Tags': {'Key': k, 'Values': [v]}}), default=[], quiet=True)
                for g in rows:
                    est.costs.append(dict(period=label, start=start, end=end, account='', service=g['Keys'][0], usage_type='tag %s=%s' % (k, v), region='',
                                          amortized=round(float(g['Metrics']['AmortizedCost']['Amount']), 2), unblended=round(float(g['Metrics']['UnblendedCost']['Amount']), 2),
                                          quantity=round(float(g['Metrics']['UsageQuantity']['Amount']), 3), unit=g['Metrics']['UsageQuantity'].get('Unit', '')))

def _ce_all(ce, start, end, metrics, group_by, flt):
    out = []; token = None
    while True:
        kw = dict(TimePeriod={'Start': start, 'End': end}, Granularity='MONTHLY', Metrics=metrics, GroupBy=group_by)
        if flt: kw['Filter'] = flt
        if token: kw['NextPageToken'] = token
        resp = ce.get_cost_and_usage(**kw)
        for rt in resp.get('ResultsByTime', []): out.extend(rt.get('Groups', []))
        token = resp.get('NextPageToken')
        if not token: return out

# ============================================================================ WorkSpaces prices (best effort)
def collect_prices(aws, est, creds, regions):
    pr = aws.client('pricing', region='us-east-1', credentials=creds)
    for region in regions:
        rows = []; token = None; pages = 0; t0 = time.time()
        def page():
            kw = dict(ServiceCode='AmazonWorkSpaces', FormatVersion='aws_v1', MaxResults=100,
                      Filters=[{'Type': 'TERM_MATCH', 'Field': 'regionCode', 'Value': region}, {'Type': 'TERM_MATCH', 'Field': 'operatingSystem', 'Value': 'Windows'}])
            if token: kw['NextToken'] = token
            return pr.get_products(**kw)
        while True:
            resp = safe('Pricing GetProducts WorkSpaces %s' % region, page, quiet=True)
            if not resp: break
            pages += 1
            for item in resp.get('PriceList', []):
                try: rows.append(_parse_price(json.loads(item) if isinstance(item, str) else item))
                except Exception: continue
            token = resp.get('NextToken')
            if not token or pages >= 80 or time.time() - t0 > 120: break
        rows = [r for r in rows if r]
        if rows:
            est.prices[region] = rows
            LOG.ok('%s: %d WorkSpaces price rows read (used for the per-WorkSpace estimate; the bill is the truth).' % (region, len(rows)))
        else:
            LOG.info('%s: WorkSpaces price list not read (pricing API unavailable or filters unmatched); per-WorkSpace estimates skipped.' % region)

def _parse_price(prod):
    a = {k.lower(): v for k, v in (prod.get('product', {}).get('attributes') or {}).items()}
    terms = (prod.get('terms') or {}).get('OnDemand') or {}
    price = None; unit = None
    for t in terms.values():
        for pd in (t.get('priceDimensions') or {}).values():
            try: price = float(pd['pricePerUnit'].get('USD')); unit = pd.get('unit')
            except Exception: continue
    if price is None: return None
    def pick(*names):
        for n in names:
            for k, v in a.items():
                if n in k: return v
        return None
    return dict(bundle=pick('bundledescription', 'bundle', 'group'), running_mode=pick('runningmode'), license=pick('license'),
                root_gb=_gb_from_text(pick('rootvolume')), user_gb=_gb_from_text(pick('uservolume')), software=pick('softwareincluded'),
                os=pick('operatingsystem'), vcpu=pick('vcpu'), memory=pick('memory'), price=price, unit=unit, sku=prod.get('product', {}).get('sku'))

def _gb_from_text(s):
    if not s: return None
    m = re.search(r'(\d+)', str(s))
    return int(m.group(1)) if m else None

def estimate_workspace_cost(rec, usage, prices):
    """Monthly estimate for one WorkSpace from the price list: AlwaysOn = monthly rate; AutoStop = monthly fee + hourly x connected hours.
    License 'Included', no bundled software; nearest volume sizes. Returns (usd, note) or (None, reason)."""
    if not prices: return None, 'no price list'
    norm = lambda x: re.sub(r'[^a-z0-9]', '', str(x or '').lower())
    want = norm(rec.get('compute')).replace('g4dn', '')
    pool = [p for p in prices if p.get('bundle')]
    cands = [p for p in pool if norm(p['bundle']).replace('g4dn', '') == want]
    if not cands and want: cands = [p for p in pool if norm(p['bundle']).startswith(want) and not (want == 'power' and norm(p['bundle']).startswith('powerpro'))]
    cands = [p for p in cands if (p.get('license') or 'included').lower().startswith('incl') and (p.get('software') in (None, 'None', 'none', ''))] or cands
    if not cands: return None, 'no price row for %s' % rec.get('compute')
    def vol_gap(p): return abs((p.get('root_gb') or 0) - (rec.get('root_gb') or 0)) + abs((p.get('user_gb') or 0) - (rec.get('user_gb') or 0))
    mode = (rec.get('running_mode') or 'ALWAYS_ON').upper()
    if mode == 'ALWAYS_ON':
        m = [p for p in cands if (p.get('running_mode') or '').lower().replace('_', '').replace(' ', '') in ('alwayson',) and (p.get('unit') or '').lower().startswith('mo')]
        if not m: return None, 'no AlwaysOn monthly row'
        p = min(m, key=vol_gap)
        return round(p['price'], 2), 'AlwaysOn monthly rate%s' % ('' if vol_gap(p) == 0 else ', nearest volume sizes')
    hourly = [p for p in cands if (p.get('running_mode') or '').lower().replace('_', '').replace(' ', '') == 'autostop' and (p.get('unit') or '').lower().startswith('h')]
    monthly = [p for p in cands if (p.get('running_mode') or '').lower().replace('_', '').replace(' ', '') == 'autostop' and (p.get('unit') or '').lower().startswith('mo')]
    if not hourly or not monthly: return None, 'no AutoStop rows'
    ph = min(hourly, key=vol_gap); pm = min(monthly, key=vol_gap)
    hours = (usage or {}).get('running_hours') or (usage or {}).get('connected_hours') or 0.0
    return round(pm['price'] + ph['price'] * hours, 2), 'AutoStop: monthly fee + %.0f running hours' % hours

# ============================================================================ assembly
def assemble(est, args, lb):
    deployments = []; review = []
    azure_region_for = lambda r: args.azure_region or REGION_MAP.get(r, 'eastus')
    for gkey, g in est.groups.items():
        flags = list(g.get('flags', []))
        if g['kind'] == 'EC2':
            # no sessions on the AWS side: the window comes from when the hosts were running
            u = usage_from_series(g.get('capacity_series') or {}, lb)
            peak = 0
            win = resolve_window(u, u['PeakConcurrentUsers'] if u else 0)
            if u: est.telemetry['groups_with_data'] += 1
            else: flags.append('no CloudWatch data for these instances in the lookback; window defaulted')
            win['ot_pct'] = 0; win['ot_hours'] = 1
        else:
            u = usage_from_series(g['series'], lb)
            peak = u['PeakConcurrentUsers'] if u else 0
            if u and peak > 0: est.telemetry['groups_with_data'] += 1
            win = resolve_window(u, peak)
            if win['sparse']: flags.append('usage too sparse to derive a window - defaulted 9:00+9h; all load lands in overtime')
            if not u or not g['series']: flags.append('no CloudWatch usage data in the lookback; users set to 1, window defaulted')
        region = azure_region_for(g['region'])
        if g['region'] not in REGION_MAP and not args.azure_region: flags.append('no Azure region mapped for %s; eastus used' % g['region'])
        mau = g.get('mau')
        if g['kind'] == 'AppStreamFleet' and est.sessions_report.get(gkey): mau = len(est.user_tokens.get(gkey, ()))
        rows_common = dict(Account=g['account'], Region=g['region'], AzureRegion=region, Type=g['kind'], Group=g['label'], Subgroup=g.get('subgroup') or '',
                           Count=g['count'], RunningMode='; '.join('%s x%d' % (k, v) for k, v in sorted(g['running_modes'].items(), key=lambda kv: str(kv[0]))),
                           Platform='; '.join('%s x%d' % (k, v) for k, v in sorted(g['os'].items(), key=lambda kv: str(kv[0]))),
                           PeakUsers=peak, PeakAtUtc=(u or {}).get('PeakAtUtc') or '', MAU=mau if mau is not None else '', UserHours=(u or {}).get('TotalUserHours', 0),
                           Window=window_text(win), Days=','.join(str(d) for d in win['days']), Overtime=overtime_text(win))
        name_base = '%s %s' % (g['label'], g.get('subgroup') or '')
        if g['kind'] == 'WorkSpacesPersonal':
            spec = WS_COMPUTE.get(g['subgroup'], dict(vcpu=2, ram=4, azure='Standard_D2s_v5', gpu=False))
            if g['subgroup'] not in WS_COMPUTE: flags.append('unknown WorkSpaces compute type %s; sized as 2 vCPU' % g['subgroup'])
            members = [w for w in est.workspaces if w['group'] == gkey]
            never = sum(1 for w in members if not (est.ws_usage.get(w['id'], {}).get('connected_hours') or 0) > 0)
            if never: flags.append('%d of %d WorkSpaces had no connection in the lookback' % (never, len(members)))
            autostop = sum(1 for w in members if w.get('running_mode') == 'AUTO_STOP')
            avg_hours = round(sum(est.ws_usage.get(w['id'], {}).get('connected_hours') or 0 for w in members) / max(len(members), 1), 1)
            used_gb = [est.ws_usage.get(w['id'], {}).get('user_volume_used_gb') for w in members]
            used_gb = [x for x in used_gb if x is not None]
            est_cost = 0.0; priced = 0
            for w in members:
                usd, note = estimate_workspace_cost(w, est.ws_usage.get(w['id']), est.prices.get(g['region']))
                if usd is not None: est_cost += usd; priced += 1
            mode = args.proposal
            if spec['gpu'] and mode == 'pooled': mode = 'personal'; flags.append('GPU bundle: kept personal (1:1) in the proposal')
            disk = snap_disk(max(128, int(spec.get('root', 80)) if False else 128))
            if mode in ('personal', 'both'):
                dep = new_deployment('%s personal, like for like (%d WorkSpaces)' % (name_base.strip(), len(members)), len(members), win, 2, region, spec['azure'], 128, 'Premium_LRS', 1.0)
                deployments.append(dep)
            if mode in ('pooled', 'both'):
                dens = args.pooled_density
                dep = new_deployment('%s pooled proposal (%d WorkSpaces, peak %d)' % (name_base.strip(), len(members), max(1, peak)), peak, win, 1, region, args.pooled_vm_size, 128, 'Premium_LRS', dens)
                deployments.append(dep)
                flags.append('pooled proposal: %s at %.1f users per vCPU (set with --pooled-density); AWS runs these 1:1' % (args.pooled_vm_size, dens))
            pooled_vcpu = int(re.search(r'D(\d+)', args.pooled_vm_size).group(1)) if re.search(r'D(\d+)', args.pooled_vm_size) else 8
            hosts_pooled = max(1, int(math.ceil(peak / (args.pooled_density * pooled_vcpu) * 1.15))) if peak > 0 else 1
            review.append(dict(rows_common, MultiSession='', AutoStop=autostop, AvgConnectedHours=avg_hours, NeverConnected=never,
                               UserVolumeGb=g['user_gb'], UserVolumeUsedGb=(round(sum(used_gb), 1) if used_gb else ''), UserVolumeMeasured=len(used_gb),
                               ProposalExperience='personal' if mode == 'personal' else ('pooled' if mode == 'pooled' else 'both'),
                               ProposalVmSize=spec['azure'] if mode == 'personal' else args.pooled_vm_size, ProposalDensity=1.0 if mode == 'personal' else args.pooled_density,
                               ProposalHosts=len(members) if mode == 'personal' else hosts_pooled,
                               EstMonthlyCostUsd=(round(est_cost, 2) if priced else ''), EstPriced='%d/%d' % (priced, len(members)), Flags='; '.join(flags)))
        elif g['kind'] == 'WorkSpacesPool':
            spec = WS_COMPUTE.get(g['subgroup'], dict(vcpu=2, ram=4, azure='Standard_D2s_v5', gpu=False))
            dep = new_deployment('%s pooled proposal (WorkSpaces Pool, peak %d sessions)' % (g['label'], max(1, peak)), peak, win, 1, region, args.pooled_vm_size, 128, 'Premium_LRS', args.pooled_density)
            deployments.append(dep)
            flags.append('pooled proposal: %s at %.1f users per vCPU (--pooled-density)' % (args.pooled_vm_size, args.pooled_density))
            pooled_vcpu = int(re.search(r'D(\d+)', args.pooled_vm_size).group(1)) if re.search(r'D(\d+)', args.pooled_vm_size) else 8
            review.append(dict(rows_common, MultiSession='', AutoStop='', AvgConnectedHours='', NeverConnected='', UserVolumeGb='', UserVolumeUsedGb='', UserVolumeMeasured='',
                               ProposalExperience='pooled', ProposalVmSize=args.pooled_vm_size, ProposalDensity=args.pooled_density,
                               ProposalHosts=max(1, int(math.ceil(peak / (args.pooled_density * pooled_vcpu) * 1.15))) if peak > 0 else 1,
                               EstMonthlyCostUsd='', EstPriced='', Flags='; '.join(flags)))
        elif g['kind'] == 'AppStreamFleet':
            vcpu = g.get('vcpu') or 4
            exp = 4 if (g.get('stream_view') or 'APP') == 'APP' else 1
            if g.get('multi'):
                dens = max(0.1, g['max_sessions'] / float(vcpu))
                vm = azure_size_for_vcpu(vcpu)
                flags.append('multi-session fleet: %d sessions per %d-vCPU instance kept as density %.2f on %s' % (g['max_sessions'], vcpu, dens, vm))
            elif 'graphics' in (g.get('subgroup') or '').lower():
                dens = max(0.25, args.pooled_density / 4.0); vm = 'Standard_NV12ads_A10_v5'
                flags.append('GPU fleet: AVD proposal is multi-session on %s at %.2f users per vCPU; review the GPU sizing' % (vm, dens))
            else:
                dens = args.pooled_density; vm = args.pooled_vm_size
                flags.append('single-session fleet: AVD proposal is multi-session on %s at %.1f users per vCPU (--pooled-density)' % (vm, dens))
            dep = new_deployment('%s (%s fleet, peak %d sessions)' % (g['label'], g.get('subgroup'), max(1, peak)), peak, win, exp, region, vm, 128, 'Premium_LRS', dens)
            deployments.append(dep)
            vm_vcpu = int(re.search(r'[DN]V?(\d+)', vm).group(1)) if re.search(r'[DN]V?(\d+)', vm) else vcpu
            sr = est.sessions_report.get(gkey)
            review.append(dict(rows_common, MultiSession=g['max_sessions'] if g.get('multi') else 1, AutoStop='', AvgConnectedHours='', NeverConnected='', UserVolumeGb='', UserVolumeUsedGb='', UserVolumeMeasured='',
                               ProposalExperience='remoteapp' if exp == 4 else 'pooled', ProposalVmSize=vm, ProposalDensity=round(dens, 2),
                               ProposalHosts=max(1, int(math.ceil(peak / (dens * vm_vcpu) * 1.15))) if peak > 0 else 1,
                               EstMonthlyCostUsd='', EstPriced='', Flags='; '.join(flags + (['usage report: %d sessions, %.0f user-hours' % (sr['sessions'], sr['user_hours'])] if sr else []))))
        elif g['kind'] == 'EC2':
            members = [i for i in est.ec2 if i['account'] == g['account'] and i['region'] == g['region']]
            if args.ec2_as in ('personal', 'pooled'):
                vcpus = sorted(collections.Counter(i['vcpu'] for i in members).items(), key=lambda kv: -kv[1])
                vm = azure_size_for_vcpu(vcpus[0][0]) if vcpus else 'Standard_D4s_v5'
                users = len(members) if args.ec2_as == 'personal' else max(1, peak)
                dep = new_deployment('EC2 VDI hosts %s (%d instances, %s)' % (g['region'], len(members), args.ec2_as), users, win, 2 if args.ec2_as == 'personal' else 1, region, vm, 128, 'Premium_LRS',
                                     1.0 if args.ec2_as == 'personal' else args.pooled_density)
                deployments.append(dep)
                flags.append('EC2 deployment written as %s per --ec2-as; users are a placeholder until broker data arrives' % args.ec2_as)
            else:
                flags.append('not in the Modeler JSON (--ec2-as none); listed for the inventory and running hours')
            running_hours = round(sum(i.get('running_hours') or 0 for i in members), 1)
            review.append(dict(rows_common, MultiSession='', AutoStop='', AvgConnectedHours=round(running_hours / max(len(members), 1), 1), NeverConnected=sum(1 for i in members if not i.get('running_hours')),
                               UserVolumeGb='', UserVolumeUsedGb='', UserVolumeMeasured='', ProposalExperience=args.ec2_as, ProposalVmSize='', ProposalDensity='', ProposalHosts='',
                               EstMonthlyCostUsd='', EstPriced='', Flags='; '.join(flags)))
        g['usage'] = u; g['window'] = win; g['flags'] = flags
    fixes = preflight(deployments)
    for f in fixes: LOG.warn('Import pre-flight corrected: %s' % f)
    LOG.ok('Import pre-flight: %d/%d deployments pass the Modeler import checks%s.' % (len(deployments), len(deployments), ' (%d value(s) corrected above)' % len(fixes) if fixes else ''))
    return deployments, review

def tenant_summary(est, lb):
    """Peak concurrency across every group (series added per slot) and the distinct-user union where identities exist."""
    total = collections.Counter()
    for g in est.groups.values():
        for k, v in g['series'].items(): total[k] += v
    peak = max(total.values()) if total else 0
    peak_at = min((k for k, v in total.items() if v == peak), default=None) if peak else None
    ws_users = set()
    for k, s in est.user_tokens.items():
        if k.startswith('ws:'): ws_users |= s
    return dict(peakConcurrentUsers=peak, peakAtUtc=iso(peak_at), peakAtLocal=(to_local(peak_at, lb.tz).strftime('%a %b %d, %I:%M %p (%Z)') if peak_at else None),
                distinctUsersWorkSpacesPersonal=len(ws_users), distinctUsersAllSources=len(est.all_tokens),
                distinctUsersBasis='union of salted per-run tokens: WorkSpaces user names and AppStream usage-report user ids; Pools users are not identified by AWS APIs',
                workspacesPersonal=len(est.workspaces), pools=len(est.pools), fleets=len(est.fleets), ec2=len(est.ec2),
                userHoursInLookback=round(sum((g.get('usage') or {}).get('TotalUserHours', 0) for g in est.groups.values()), 1))

# ============================================================================ writers
def write_outputs(est, deployments, review, args, lb, stamp, run_meta):
    out_dir = args.out_dir
    base = os.path.join(out_dir, 'modeler-aws-%s' % stamp)
    model = collections.OrderedDict([('schema', 4), ('name', args.model_name),
                                     ('description', 'Generated from AWS actuals (WorkSpaces, Pools, AppStream), lookback %dd, %s; proposal mode %s, pooled density %.1f users per vCPU on %s'
                                      % (lb.days, utcnow().strftime('%Y-%m-%d'), args.proposal, args.pooled_density, args.pooled_vm_size)),
                                     ('deployments', deployments), ('globalSettings', GLOBAL_SETTINGS)])
    files = []
    p = base + '.json'; json.dump(model, open(p, 'w'), indent=1); files.append(p)
    # review CSV
    cols = ['Account', 'Region', 'AzureRegion', 'Type', 'Group', 'Subgroup', 'Count', 'RunningMode', 'Platform', 'MultiSession', 'PeakUsers', 'PeakAtUtc', 'MAU', 'UserHours',
            'AvgConnectedHours', 'NeverConnected', 'AutoStop', 'Window', 'Days', 'Overtime', 'UserVolumeGb', 'UserVolumeUsedGb', 'UserVolumeMeasured',
            'ProposalExperience', 'ProposalVmSize', 'ProposalDensity', 'ProposalHosts', 'EstMonthlyCostUsd', 'EstPriced', 'Flags']
    p = base + '-review.csv'
    with open(p, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore'); w.writeheader()
        for r in review: w.writerow(r)
    files.append(p)
    # usage buckets
    p = base + '-usage-buckets.csv'
    with open(p, 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['GroupKey', 'Type', 'Group', 'Subgroup', 'SlotUtc', 'ConcurrentUsers', 'RunningCapacity'])
        for gkey, g in est.groups.items():
            keys = sorted(set(g['series']) | set(g.get('capacity_series') or {}))
            for k in keys:
                w.writerow([gkey, g['kind'], g['label'], g.get('subgroup') or '', iso(k), int(g['series'].get(k, 0)), int((g.get('capacity_series') or {}).get(k, 0))])
    files.append(p)
    # cost rows
    p = base + '-cost.csv'
    with open(p, 'w', newline='') as f:
        cols_c = ['period', 'start', 'end', 'account', 'service', 'usage_type', 'region', 'amortized', 'unblended', 'quantity', 'unit']
        w = csv.DictWriter(f, fieldnames=cols_c); w.writeheader()
        for r in est.costs: w.writerow(r)
    files.append(p)
    # raw data (no user names, no tokens)
    raw = collections.OrderedDict([
        ('meta', run_meta),
        ('tenant', tenant_summary(est, lb)),
        ('accounts', est.accounts), ('regionsChecked', est.regions_checked),
        ('directories', est.directories), ('bundles', est.bundles), ('pools', est.pools), ('fleets', est.fleets), ('stacks', est.stacks),
        ('usageReportSubscriptions', est.usage_reports), ('ec2', est.ec2),
        ('workspaces', est.workspaces),
        ('workspaceUsage', est.ws_usage),
        ('groups', {k: dict(kind=g['kind'], account=g['account'], region=g['region'], label=g['label'], subgroup=g.get('subgroup'), count=g['count'],
                            runningModes=dict(g['running_modes']), platforms=dict(g['os']), usage=g.get('usage'), window=g.get('window'), flags=g.get('flags'),
                            mau=(len(est.user_tokens.get(k, ())) or None), sessionsReport=({kk: (vv if kk != 'days' else len(vv)) for kk, vv in est.sessions_report[k].items()} if k in est.sessions_report else None))
                    for k, g in est.groups.items()}),
        ('costSummary', est.cost_summary), ('prices', {r: len(v) for r, v in est.prices.items()}), ('priceRows', est.prices),
        ('telemetry', est.telemetry), ('errors', est.errors),
        ('serviceAccess', {'%s %s' % k: v for k, v in sorted(ACCESS.items())}),
    ])
    p = base + '-rawdata.json'; json.dump(raw, open(p, 'w'), indent=1, default=str); files.append(p)
    p = base + '-console.log'; open(p, 'w').write('\n'.join(LOG.lines) + '\n'); files.append(p)
    zp = base + '.zip'
    with zipfile.ZipFile(zp, 'w', zipfile.ZIP_DEFLATED) as z:
        for f in files: z.write(f, os.path.basename(f))
    return zp, files

def print_review(review):
    cols = [('Type', 18), ('Group', 28), ('Subgroup', 22), ('Count', 5), ('PeakUsers', 5), ('MAU', 5), ('Window', 10), ('Days', 13), ('Overtime', 9), ('ProposalHosts', 6)]
    LOG.raw('')
    LOG.raw(' '.join(h[:w].ljust(w) for h, w in cols))
    for r in review:
        LOG.raw(' '.join(str(r.get(h, ''))[:w].ljust(w) for h, w in cols))
    LOG.raw('')
    for r in review:
        if r.get('Flags'): LOG.raw('  %s / %s: %s' % (r['Group'], r['Subgroup'], r['Flags']))

# ============================================================================ main
def parse_args(argv):
    ap = argparse.ArgumentParser(description='Nerdio Modeler import builder for AWS VDI estates (read-only).')
    ap.add_argument('--model-name', default='AVD Environment - From AWS')
    ap.add_argument('--lookback-days', type=int, default=30)
    ap.add_argument('--time-zone', default='America/New_York', help='IANA time zone for work-hours math')
    ap.add_argument('--regions', nargs='*', help='limit to these AWS regions (default: every enabled region)')
    ap.add_argument('--profile', help='AWS CLI profile (local runs only)')
    ap.add_argument('--all-accounts', action='store_true', help='AWS Organizations: assume --role-name into every account')
    ap.add_argument('--account', nargs='*', help='specific account id(s) to assume --role-name into')
    ap.add_argument('--role-name', default='OrganizationAccountAccessRole')
    ap.add_argument('--ec2-tag', action='append', help='Key=Value tag that marks EC2-hosted VDI instances (repeatable)')
    ap.add_argument('--ec2-name-regex', help='regex on the Name tag that marks EC2-hosted VDI instances')
    ap.add_argument('--ec2-as', choices=['none', 'personal', 'pooled'], default='none', help='write EC2 hosts into the Modeler JSON as this experience')
    ap.add_argument('--proposal', choices=['pooled', 'personal', 'both'], default='pooled', help='how WorkSpaces Personal directories are written: AVD pooled multi-session (default), like-for-like personal, or both')
    ap.add_argument('--pooled-vm-size', default='Standard_D8s_v5')
    ap.add_argument('--pooled-density', type=float, default=2.0, help='users per vCPU for pooled proposals')
    ap.add_argument('--azure-region', help='force one Azure region for every deployment (default: mapped from the AWS region)')
    ap.add_argument('--skip-costs', action='store_true'); ap.add_argument('--skip-prices', action='store_true'); ap.add_argument('--skip-usage-report', action='store_true')
    ap.add_argument('--out-dir', default=os.path.expanduser('~'))
    ap.add_argument('--check', action='store_true', help='first-run mode: also probe the price list in this shell\'s region when no WorkSpaces exist; the service access check prints either way')
    ap.add_argument('--demo', action='store_true', help='run against a built-in synthetic estate (no AWS calls); for seeing the outputs')
    ap.add_argument('--demo-seed', type=int, default=7)
    return ap.parse_args(argv)

def shell_region(aws, args):
    if args.regions: return args.regions[0]
    r = None
    try: r = aws.session.region_name if aws.session else None
    except Exception: r = None
    return r or os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION') or 'us-east-1'

def check_version():
    try:
        import urllib.request
        with urllib.request.urlopen(VERSION_URL + '?nocache=%d' % random.randint(1, 10 ** 9), timeout=5) as r:
            latest = r.read().decode().strip()
        if latest and latest != SCRIPT_VERSION:
            LOG.warn('THIS COPY IS STALE: it is %s, but the published version is %s. Re-download before sending results.' % (SCRIPT_VERSION, latest))
    except Exception:
        pass

def main(argv=None, client_factory=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    t0 = time.time()
    LOG.lines.clear()
    ACCESS.clear()   # per run, like the log; the test harness runs main() several times in one process
    LOG.info('%s %s' % (TOOL_NAME, SCRIPT_VERSION))
    try:
        import boto3 as _b3, botocore as _bc
        LOG.info('Python %d.%d.%d, boto3 %s, botocore %s' % (sys.version_info[0], sys.version_info[1], sys.version_info[2], _b3.__version__, _bc.__version__))
    except Exception:
        LOG.warn('boto3 is not installed. In CloudShell it is preinstalled; locally run: pip install boto3')
        return 2
    if args.demo and client_factory is None:
        from nerdio_modeler_aws_demo import make_demo_factory  # noqa: F401 (separate file next to this script)
        client_factory = make_demo_factory(args.demo_seed)
        LOG.warn('DEMO MODE: synthetic estate, no AWS calls. Nothing in this output is real.')
    else:
        check_version()
    tz = get_tz(args.time_zone)
    lb = Lookback(args.lookback_days, tz, end=(dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc) if args.demo else None))
    hasher = UserHasher()
    aws = Aws(client_factory=client_factory, profile=args.profile)
    est = Estate()
    # identity and scope
    sts = aws.client('sts', region='us-east-1')
    try:
        ident = safe('STS GetCallerIdentity', lambda: sts.get_caller_identity())
    except Exception:
        ident = None
    if not ident:
        LOG.warn('Cannot read the caller identity; stopping. In CloudShell this means the shell is not signed in; locally run `aws sts get-caller-identity` to check.')
        return 2
    home = ident['Account']
    arn = ident.get('Arn', '')
    ptype = 'role' if ':assumed-role/' in arn or ':role/' in arn else ('root' if arn.endswith(':root') else 'user')
    LOG.info('Signed in as an IAM %s in account %s. (The principal name is not recorded.)' % (ptype, home))
    accounts = [dict(id=home, name='current', source='caller')]
    if args.all_accounts or args.account:
        org = aws.client('organizations', region='us-east-1')
        if args.all_accounts:
            rows = safe('Organizations ListAccounts', lambda: paginate(org.list_accounts, 'Accounts'), default=[])
            for a in rows:
                if a.get('Status') == 'ACTIVE' and a['Id'] != home: accounts.append(dict(id=a['Id'], name=a.get('Name'), source='organization'))
        for a in (args.account or []):
            if a != home and a not in [x['id'] for x in accounts]: accounts.append(dict(id=a, name='', source='--account'))
    est.accounts = accounts
    LOG.info('Scope: %d account(s): %s' % (len(accounts), ', '.join(a['id'] for a in accounts)))
    run_meta = collections.OrderedDict([('tool', TOOL_NAME), ('version', SCRIPT_VERSION), ('generatedUtc', iso(utcnow())),
                                        ('parameters', {k: v for k, v in vars(args).items() if k not in ('profile',)}),
                                        ('identity', dict(account=home, principalType=ptype, principalMasked=True)),
                                        ('lookback', dict(startUtc=iso(lb.start), endUtc=iso(lb.end), days=lb.days, slotMinutes=lb.slot_minutes, timeZone=args.time_zone)),
                                        ('notes', ['CloudWatch keeps 5-minute data 63 days and hourly data 15 months; lookbacks over 60 days use hourly slots',
                                                   'user identities are salted per-run tokens held in memory; only counts are written'])])
    # per account
    for acct in accounts:
        creds = None
        if acct['id'] != home:
            role_arn = 'arn:aws:iam::%s:role/%s' % (acct['id'], args.role_name)
            resp = safe('STS AssumeRole %s' % role_arn, lambda: sts.assume_role(RoleArn=role_arn, RoleSessionName='nerdio-modeler-aws'))
            if not resp:
                est.errors.append('account %s skipped: could not assume %s' % (acct['id'], args.role_name)); continue
            creds = resp['Credentials']
        LOG.info('[1/4] Account %s: inventory and usage...' % acct['id'])
        collect_account(aws, est, acct, creds, args, lb, hasher)
    LOG.info('[2/4] Cost Explorer (last full month and month to date; a few cents of API fees)...')
    if args.skip_costs: LOG.info('skipped (--skip-costs)')
    else: collect_costs(aws, est, None, args)
    LOG.info('[3/4] WorkSpaces price list for the per-WorkSpace estimate...')
    ws_regions = sorted(set(w['region'] for w in est.workspaces))
    if not ws_regions and args.check:
        ws_regions = [shell_region(aws, args)]
        LOG.info('--check: no WorkSpaces to price, probing the price list for %s anyway.' % ws_regions[0])
    if args.skip_prices or not ws_regions: LOG.info('skipped (%s)' % ('--skip-prices' if args.skip_prices else 'no personal WorkSpaces found; add --check to probe the price list anyway'))
    else: collect_prices(aws, est, None, ws_regions)
    LOG.info('[4/4] Assembling deployments...')
    deployments, review = assemble(est, args, lb)
    print_review(review)
    ten = tenant_summary(est, lb)
    LOG.ok('ACCOUNT-WIDE, COUNTS ONLY: peak %d concurrent user(s)%s; %d distinct WorkSpaces users, %d distinct across every identified source; '
           '%d personal WorkSpaces, %d pool(s), %d fleet(s), %d EC2 host(s).' %
           (ten['peakConcurrentUsers'], ' at %s' % ten['peakAtLocal'] if ten['peakAtLocal'] else '', ten['distinctUsersWorkSpacesPersonal'], ten['distinctUsersAllSources'],
            ten['workspacesPersonal'], ten['pools'], ten['fleets'], ten['ec2']))
    if est.telemetry['groups_with_data'] == 0 and est.groups:
        LOG.warn('TELEMETRY NOT FOUND: no CloudWatch usage data came back for any group. Check that the signed-in principal can call cloudwatch:GetMetricData; every deployment is defaulted to 1 user.')
    print_access_check()
    stamp = utcnow().strftime('%Y%m%d-%H%M')
    os.makedirs(args.out_dir, exist_ok=True)
    zp, files = write_outputs(est, deployments, review, args, lb, stamp, run_meta)
    LOG.ok('Model written: %s (%d deployments)' % (os.path.basename(files[0]), len(deployments)))
    LOG.ok('Zip: %s' % zp)
    LOG.info('CloudShell: Actions menu (top right) > Download file > paste the zip path above. Local: the zip is in %s.' % args.out_dir)
    LOG.info('Done in %.0f s with %d warning(s).' % (time.time() - t0, LOG.warnings))
    # the console log inside the zip was written before these last lines; rewrite it so the zip has the full transcript
    try:
        log_path = [f for f in files if f.endswith('-console.log')][0]
        open(log_path, 'w').write('\n'.join(LOG.lines) + '\n')
        with zipfile.ZipFile(zp, 'w', zipfile.ZIP_DEFLATED) as z:
            for f in files: z.write(f, os.path.basename(f))
    except Exception:
        pass
    return 0

if __name__ == '__main__':
    sys.exit(main())
