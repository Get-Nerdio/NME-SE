#!/usr/bin/env python3
"""
Offline stand-in for AWS, used by `nerdio_modeler_aws.py --demo` and by tests/test_offline.py.

It is not a mock that returns whatever the caller wants. Every request the collector makes is
validated against the real botocore service model (wrong parameter names fail here the way they
would fail against AWS), and every synthetic response is checked against the real output shape
(a field the collector reads must exist in the API). The estate it describes is invented:
two WorkSpaces directories, one WorkSpaces Pool, two WorkSpaces Applications fleets, one month
of CloudWatch-shaped usage, a Cost Explorer bill and a slice of the WorkSpaces price list.

NOT for customers. Nothing here touches AWS.
"""
import csv
import datetime as dt
import io
import json
import random

import botocore.session
from botocore import xform_name
from botocore.exceptions import ClientError
from botocore.validate import validate_parameters

UTC = dt.timezone.utc
HOME_ACCOUNT = '111122223333'
FIXTURE_USERS = []          # the invented user names; tests assert none of them leaks into any output


# ------------------------------------------------------------------------------- shape checking
def _check_shape(value, shape, path='$'):
    """Structural check of a synthetic response against the botocore output shape."""
    t = shape.type_name
    if value is None:
        return
    if t == 'structure':
        if not isinstance(value, dict): raise AssertionError('%s: expected dict' % path)
        for k, v in value.items():
            if k not in shape.members: raise AssertionError('%s: field %r is not in the API output shape %s' % (path, k, shape.name))
            _check_shape(v, shape.members[k], path + '.' + k)
    elif t == 'list':
        if not isinstance(value, list): raise AssertionError('%s: expected list' % path)
        for i, v in enumerate(value): _check_shape(v, shape.member, '%s[%d]' % (path, i))
    elif t == 'map':
        if not isinstance(value, dict): raise AssertionError('%s: expected map' % path)
        for k, v in value.items(): _check_shape(v, shape.value, '%s[%r]' % (path, k))
    elif t == 'timestamp':
        if not isinstance(value, dt.datetime): raise AssertionError('%s: expected datetime' % path)
    elif t in ('integer', 'long'):
        if not isinstance(value, int) or isinstance(value, bool): raise AssertionError('%s: expected int' % path)
    elif t in ('float', 'double'):
        if not isinstance(value, (int, float)): raise AssertionError('%s: expected number' % path)
    elif t == 'boolean':
        if not isinstance(value, bool): raise AssertionError('%s: expected bool' % path)
    elif t == 'string':
        if not isinstance(value, str): raise AssertionError('%s: expected str' % path)
    elif t == 'blob':
        pass


class StubClient:
    """Looks like a boto3 client for the operations the collector uses."""
    def __init__(self, service, region, responders, model_cache):
        self.service = service; self.region = region; self.responders = responders
        if service not in model_cache:
            model_cache[service] = botocore.session.get_session().get_service_model(service)
        self.model = model_cache[service]
        self._ops = {xform_name(op): op for op in self.model.operation_names}
    def __getattr__(self, name):
        if name.startswith('_') or name not in self._ops:
            raise AttributeError(name)
        op = self._ops[name]
        def call(**params):
            om = self.model.operation_model(op)
            if om.input_shape is not None:
                validate_parameters(params, om.input_shape)   # raises ParamValidationError like boto3 would
            elif params:
                raise AssertionError('%s.%s takes no parameters' % (self.service, op))
            fn = self.responders.get((self.service, op))
            if fn is None:
                raise AssertionError('demo has no responder for %s.%s in %s' % (self.service, op, self.region))
            resp = fn(self.region, params)
            if om.output_shape is not None:
                _check_shape(resp, om.output_shape, '%s.%s' % (self.service, op))
            return resp
        return call


def denied(service, op, msg='User is not authorized to perform this operation'):
    return ClientError({'Error': {'Code': 'AccessDeniedException', 'Message': msg}}, op)


# ------------------------------------------------------------------------------- the invented estate
def build_estate(seed):
    rng = random.Random(seed)
    users = ['user%03d@demo.invalid' % i for i in range(1, 400)]
    FIXTURE_USERS[:] = users
    uit = iter(users)
    dirs = [
        dict(DirectoryId='d-1111111111', Alias='corp-desktops', DirectoryName='corp.demo.invalid', WorkspaceDirectoryName='corp-desktops', DirectoryType='AD_CONNECTOR',
             State='REGISTERED', Tenancy='SHARED', WorkspaceType='PERSONAL', UserIdentityType='AWS_DIRECTORY_SERVICE'),
        dict(DirectoryId='d-2222222222', Alias='ops-247', DirectoryName='ops.demo.invalid', WorkspaceDirectoryName='ops-247', DirectoryType='AD_CONNECTOR',
             State='REGISTERED', Tenancy='SHARED', WorkspaceType='PERSONAL', UserIdentityType='AWS_DIRECTORY_SERVICE'),
        dict(DirectoryId='d-3333333333', Alias='contractor-pool', WorkspaceDirectoryName='contractor-pool', DirectoryType='AWS_IAM_IDENTITY_CENTER',
             State='REGISTERED', WorkspaceType='POOLS', UserIdentityType='AWS_IAM_IDENTITY_CENTER'),
    ]
    bundles = {
        'wsb-standard': dict(BundleId='wsb-standard', Name='Standard with Windows 11', Owner='AMAZON', ComputeType={'Name': 'STANDARD'}, RootStorage={'Capacity': '80'}, UserStorage={'Capacity': '50'}, State='AVAILABLE'),
        'wsb-power': dict(BundleId='wsb-power', Name='Power with Windows 11', Owner='AMAZON', ComputeType={'Name': 'POWER'}, RootStorage={'Capacity': '175'}, UserStorage={'Capacity': '100'}, State='AVAILABLE'),
        'wsb-perf': dict(BundleId='wsb-perf', Name='Performance with Windows 11', Owner='AMAZON', ComputeType={'Name': 'PERFORMANCE'}, RootStorage={'Capacity': '80'}, UserStorage={'Capacity': '100'}, State='AVAILABLE'),
        'wsb-gfx': dict(BundleId='wsb-gfx', Name='Graphics.g4dn with Windows Server 2022', Owner='AMAZON', ComputeType={'Name': 'GRAPHICS'}, RootStorage={'Capacity': '100'}, UserStorage={'Capacity': '100'}, State='AVAILABLE'),
        'wsb-pool': dict(BundleId='wsb-pool', Name='Standard Pools bundle', Owner='AMAZON', ComputeType={'Name': 'STANDARD'}, RootStorage={'Capacity': '80'}, UserStorage={'Capacity': '0'}, State='AVAILABLE'),
    }
    workspaces = []   # (record, pattern)
    def ws(dirid, bundle, compute, mode, pattern, root, user, n=1, os_name='WINDOWS_11'):
        for _ in range(n):
            i = len(workspaces) + 1
            rec = dict(WorkspaceId='ws-%010x' % i, DirectoryId=dirid, UserName=next(uit), State='AVAILABLE', BundleId=bundle, ComputerName='WSAMZN-%06X' % i,
                       WorkspaceProperties=dict(RunningMode=mode, RunningModeAutoStopTimeoutInMinutes=60 if mode == 'AUTO_STOP' else None, RootVolumeSizeGib=root,
                                                UserVolumeSizeGib=user, ComputeTypeName=compute, OperatingSystemName=os_name, Protocols=['DCV']))
            rec['WorkspaceProperties'] = {k: v for k, v in rec['WorkspaceProperties'].items() if v is not None}
            workspaces.append((rec, pattern(rng)))
    def office(rng):
        start = 7 + rng.random() * 2.5; end = start + 8.5 + rng.random() * 1.5; attend = 0.75 + rng.random() * 0.2
        days = set(rng.sample(range(30), int(round(30 * 5 / 7 * attend))))
        return dict(kind='office', start=start, end=end, days=days, disk=20 + rng.random() * 25)
    def engineer(rng):
        start = 6.5 + rng.random() * 2; end = start + 10 + rng.random() * 2.5
        return dict(kind='office', start=start, end=end, days=set(range(30)), evening=rng.random() < 0.4, disk=40 + rng.random() * 40)
    def never(rng): return dict(kind='never', disk=2.0)
    def shift(rng):
        s = rng.choice([0, 8, 16]); return dict(kind='shift', start=s, end=s + 8.3, disk=10 + rng.random() * 15)
    ws('d-1111111111', 'wsb-standard', 'STANDARD', 'AUTO_STOP', office, 80, 50, n=60)
    ws('d-1111111111', 'wsb-power', 'POWER', 'ALWAYS_ON', engineer, 175, 100, n=10)
    ws('d-1111111111', 'wsb-gfx', 'GRAPHICS', 'ALWAYS_ON', engineer, 100, 100, n=1, os_name='UNKNOWN')
    ws('d-1111111111', 'wsb-standard', 'STANDARD', 'ALWAYS_ON', never, 80, 50, n=6)
    ws('d-2222222222', 'wsb-perf', 'PERFORMANCE', 'ALWAYS_ON', shift, 80, 100, n=15)
    pool = dict(PoolId='wspool-aaaaaaaaaa', PoolArn='arn:aws:workspaces:us-east-1:%s:workspacespool/wspool-aaaaaaaaaa' % HOME_ACCOUNT, PoolName='contractor-pool',
                State='RUNNING', BundleId='wsb-pool', DirectoryId='d-3333333333', RunningMode='AUTO_STOP',
                CapacityStatus=dict(AvailableUserSessions=12, DesiredUserSessions=20, ActualUserSessions=20, ActiveUserSessions=8),
                TimeoutSettings=dict(DisconnectTimeoutInSeconds=900, IdleDisconnectTimeoutInSeconds=600, MaxUserDurationInSeconds=36000), CreatedAt=dt.datetime(2025, 3, 1, tzinfo=UTC))
    fleets = [
        dict(Arn='arn:aws:appstream:us-east-1:%s:fleet/erp-apps' % HOME_ACCOUNT, Name='erp-apps', DisplayName='ERP applications', ImageName='erp-image-2026-08', InstanceType='stream.standard.large',
             FleetType='ON_DEMAND', ComputeCapacityStatus=dict(Desired=6, Running=6, InUse=4, Available=2, DesiredUserSessions=60, AvailableUserSessions=28, ActiveUserSessions=32, ActualUserSessions=60),
             MaxUserDurationInSeconds=57600, DisconnectTimeoutInSeconds=900, State='RUNNING', CreatedTime=dt.datetime(2024, 11, 2, tzinfo=UTC), IdleDisconnectTimeoutInSeconds=600,
             StreamView='APP', Platform='WINDOWS_SERVER_2022', MaxSessionsPerInstance=10),
        dict(Arn='arn:aws:appstream:us-east-1:%s:fleet/cad-desktop' % HOME_ACCOUNT, Name='cad-desktop', DisplayName='CAD desktops', ImageName='cad-image-2026-06', InstanceType='stream.graphics.g4dn.xlarge',
             FleetType='ALWAYS_ON', ComputeCapacityStatus=dict(Desired=6, Running=6, InUse=3, Available=3), MaxUserDurationInSeconds=57600, DisconnectTimeoutInSeconds=900,
             State='RUNNING', CreatedTime=dt.datetime(2025, 6, 2, tzinfo=UTC), IdleDisconnectTimeoutInSeconds=900, StreamView='DESKTOP', Platform='WINDOWS_SERVER_2019', MaxSessionsPerInstance=1),
    ]
    stacks = [dict(Arn='arn:aws:appstream:us-east-1:%s:stack/erp' % HOME_ACCOUNT, Name='erp', StorageConnectors=[dict(ConnectorType='HOMEFOLDERS', ResourceIdentifier='appstream2-36fb080bb8-us-east-1-%s' % HOME_ACCOUNT)],
                   ApplicationSettings=dict(Enabled=True, SettingsGroup='erp'), CreatedTime=dt.datetime(2024, 11, 2, tzinfo=UTC)),
              dict(Arn='arn:aws:appstream:us-east-1:%s:stack/cad' % HOME_ACCOUNT, Name='cad', StorageConnectors=[], CreatedTime=dt.datetime(2025, 6, 2, tzinfo=UTC))]
    erp_users = [next(uit) for _ in range(120)]
    ec2 = [dict(InstanceId='i-0%015x' % i, InstanceType='m6i.2xlarge', State={'Name': 'running'}, PlatformDetails='Windows', LaunchTime=dt.datetime(2025, 1, 10, tzinfo=UTC),
                Tags=[{'Key': 'Name', 'Value': 'ctx-vda-%02d' % i}, {'Key': 'workload', 'Value': 'vdi'}]) for i in range(1, 5)]
    return dict(rng=rng, dirs=dirs, bundles=bundles, workspaces=workspaces, pool=pool, fleets=fleets, stacks=stacks, erp_users=erp_users, ec2=ec2)


# ------------------------------------------------------------------------------- synthetic metrics
NY_OFFSET = dt.timedelta(hours=-4)   # the demo month is September/October 2026, US Eastern daylight time

def _local(ts): return ts + NY_OFFSET

def ws_connected(pattern, ts):
    """1 when the invented user is connected at UTC slot start ts."""
    lt = _local(ts); h = lt.hour + lt.minute / 60.0
    if pattern['kind'] == 'never': return 0
    if pattern['kind'] == 'shift':
        return 1 if (pattern['start'] <= h < pattern['end']) and (lt.weekday() < 6 or lt.hour % 3 == 0) else 0
    day_index = (lt.date() - dt.date(2026, 9, 1)).days
    if lt.weekday() >= 5 and not pattern.get('evening'): return 0
    if day_index not in pattern['days'] and lt.weekday() < 5: return 0
    if pattern['start'] <= h < pattern['end'] and lt.weekday() < 5: return 1
    if pattern.get('evening') and lt.weekday() < 5 and 19 <= h < 21.5: return 1
    return 0

def pool_sessions(ts):
    lt = _local(ts); h = lt.hour + lt.minute / 60.0
    if lt.weekday() >= 5: return 0
    if 8 <= h < 18: return int(round(14 * min(1.0, (h - 7.5) / 2.0) * (1.0 if h < 16 else max(0.2, (18 - h) / 2.0))))
    return 0

def fleet_sessions(name, ts):
    lt = _local(ts); h = lt.hour + lt.minute / 60.0
    if name == 'erp-apps':
        if lt.weekday() >= 5: return 3 if 9 <= h < 15 else 0
        return int(round(45 * max(0.0, min(1.0, (h - 6.5) / 2.5)) * (1.0 if h < 17 else max(0.0, (19.5 - h) / 2.5))))
    if name == 'cad-desktop':
        if lt.weekday() >= 5: return 0
        return 4 if 8 <= h < 17 else (1 if 17 <= h < 20 else 0)
    return 0

def fleet_instances(name, ts):
    if name == 'erp-apps':
        s = fleet_sessions(name, ts); return max(2, int(-(-s // 10)) + 1) if s else 2
    if name == 'cad-desktop': return 6
    return 0


# ------------------------------------------------------------------------------- responders
def make_demo_factory(seed=7):
    est = build_estate(seed)
    model_cache = {}
    ws_by_id = {rec['WorkspaceId']: (rec, pat) for rec, pat in est['workspaces']}

    def sts_identity(region, p):
        return dict(UserId='AROAEXAMPLE:demo', Account=HOME_ACCOUNT, Arn='arn:aws:sts::%s:assumed-role/DemoReadOnly/demo' % HOME_ACCOUNT)

    def ec2_regions(region, p):
        return dict(Regions=[dict(RegionName=r, Endpoint='ec2.%s.amazonaws.com' % r, OptInStatus='opt-in-not-required') for r in ('us-east-1', 'us-west-2', 'eu-west-1')])

    def ws_dirs(region, p):
        if region == 'us-west-2': raise denied('workspaces', 'DescribeWorkspaceDirectories')
        if region != 'us-east-1': return dict(Directories=[])
        return dict(Directories=[dict(d) for d in est['dirs']])

    def ws_list(region, p):
        if region != 'us-east-1': return dict(Workspaces=[])
        rows = [dict(rec) for rec, _ in est['workspaces']]
        page = 25; start = int(p.get('NextToken') or 0)
        out = dict(Workspaces=rows[start:start + page])
        if start + page < len(rows): out['NextToken'] = str(start + page)
        return out

    def ws_pools(region, p):
        if region == 'eu-west-1': raise denied('workspaces', 'DescribeWorkspacesPools', 'Amazon WorkSpaces Pools is no longer available to new customers as of 7/30/2026. Refer to https://docs.aws.amazon.com/workspaces/latest/adminguide/wsp-pools-end-of-support.html')   # the real end-of-support refusal
        if region != 'us-east-1': return dict(WorkspacesPools=[])
        return dict(WorkspacesPools=[dict(est['pool'])])

    def ws_bundles(region, p):
        ids = p.get('BundleIds') or list(est['bundles'])
        return dict(Bundles=[dict(est['bundles'][b]) for b in ids if b in est['bundles']])

    def ws_conn(region, p):
        out = []
        for wid in p.get('WorkspaceIds', []):
            rec, pat = ws_by_id[wid]
            last = None if pat['kind'] == 'never' else dt.datetime(2026, 9, 30, 21, 5, tzinfo=UTC)
            row = dict(WorkspaceId=wid, ConnectionState='DISCONNECTED', ConnectionStateCheckTimestamp=dt.datetime(2026, 10, 1, 0, 0, tzinfo=UTC))
            if last: row['LastKnownUserConnectionTimestamp'] = last
            out.append(row)
        return dict(WorkspacesConnectionStatus=out)

    def cw_list_metrics(region, p):
        if p.get('MetricName') == 'ActiveUserSessionCapacity' and region == 'us-east-1':
            return dict(Metrics=[dict(Namespace='AWS/WorkSpaces', MetricName='ActiveUserSessionCapacity', Dimensions=[dict(Name='PoolId', Value=est['pool']['PoolId'])])])
        return dict(Metrics=[])

    def cw_get_metric_data(region, p):
        start = p['StartTime']; end = p['EndTime']; results = []
        for q in p['MetricDataQueries']:
            ms = q['MetricStat']; metric = ms['Metric']['MetricName']; dims = {d['Name']: d['Value'] for d in ms['Metric']['Dimensions']}; period = ms['Period']
            ts_list = []; vals = []
            t = start
            while t < end:
                v = None
                if metric in ('UserConnected', 'Available', 'UserVolumeDiskUsage') and 'WorkspaceId' in dims:
                    rec, pat = ws_by_id.get(dims['WorkspaceId'], (None, None))
                    if rec is None: v = None
                    else:
                        conn = max(ws_connected(pat, t + dt.timedelta(seconds=o)) for o in range(0, period, 300))
                        if metric == 'UserConnected': v = float(conn) if (rec['WorkspaceProperties']['RunningMode'] == 'ALWAYS_ON' or conn) else None
                        elif metric == 'Available':
                            if rec['WorkspaceProperties']['RunningMode'] == 'ALWAYS_ON': v = 1.0
                            else: v = 1.0 if conn or ws_connected(pat, t - dt.timedelta(minutes=45)) else None
                        else: v = round(100.0 * pat['disk'] / rec['WorkspaceProperties']['UserVolumeSizeGib'], 1) if (conn or rec['WorkspaceProperties']['RunningMode'] == 'ALWAYS_ON') else None
                elif dims.get('PoolId') == est['pool']['PoolId']:
                    s = max(pool_sessions(t + dt.timedelta(seconds=o)) for o in range(0, period, 300))
                    v = float(s) if metric == 'ActiveUserSessionCapacity' else float(max(20, s))
                elif 'Fleet' in dims:
                    name = dims['Fleet']
                    s = max(fleet_sessions(name, t + dt.timedelta(seconds=o)) for o in range(0, period, 300))
                    if metric == 'ActiveUserSessionCapacity': v = float(s)
                    elif metric == 'InUseCapacity': v = float(min(fleet_instances(name, t), int(-(-s // 10)) if name == 'erp-apps' else s))
                    elif metric == 'ActualCapacity': v = float(fleet_instances(name, t))
                elif 'InstanceId' in dims and metric == 'CPUUtilization':
                    lt = _local(t); v = 3.0 if (lt.weekday() < 5 and 6 <= lt.hour < 20) else None
                if v is not None:
                    ts_list.append(t); vals.append(v)
                t += dt.timedelta(seconds=period)
            results.append(dict(Id=q['Id'], Label=metric, Timestamps=ts_list, Values=vals, StatusCode='Complete'))
        return dict(MetricDataResults=results, Messages=[])

    def as_fleets(region, p):
        if region != 'us-east-1': return dict(Fleets=[])
        return dict(Fleets=[dict(f) for f in est['fleets']])

    def as_stacks(region, p):
        if region != 'us-east-1': return dict(Stacks=[])
        return dict(Stacks=[dict(s) for s in est['stacks']])

    def as_subs(region, p):
        if region != 'us-east-1': return dict(UsageReportSubscriptions=[])
        return dict(UsageReportSubscriptions=[dict(S3BucketName='appstream-logs-%s-us-east-1-demo' % HOME_ACCOUNT, Schedule='DAILY', LastGeneratedReportDate=dt.datetime(2026, 10, 1, tzinfo=UTC))])

    class _Body:
        def __init__(self, b): self.b = b
        def read(self): return self.b

    def s3_get(region, p):
        key = p['Key']
        import re
        m = re.search(r'daily-session-report-(\d{4})-(\d{2})-(\d{2})\.csv$', key)
        if not m: raise ClientError({'Error': {'Code': 'NoSuchKey', 'Message': 'missing'}}, 'GetObject')
        day = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if day.weekday() >= 5 and day.day % 3: raise ClientError({'Error': {'Code': 'NoSuchKey', 'Message': 'missing'}}, 'GetObject')
        rng = random.Random(day.toordinal())
        buf = io.StringIO(); w = csv.writer(buf)
        cols = ['user_session_id', 'aws_account_id', 'region', 'session_start_time', 'session_end_time', 'session_duration_in_seconds', 'user_id', 'user_arn', 'authentication_type',
                'authentication_type_user_id', 'fleet_name', 'stack_name', 'instance_type', 'eni_private_ip_address', 'connected_at_least_once', 'client_ip_addresses',
                'google_drive_enabled', 'one_drive_enabled', 'home_folders_storage_location', 'user_settings_clipboard_copy_from_local_device', 'user_settings_clipboard_copy_to_local_device',
                'user_settings_file_upload', 'user_settings_file_download', 'user_settings_printing_to_local_device', 'application_settings_enabled', 'domain_joined', 'max_session_duration',
                'session_type', 'stream_view', 'streaming_experience_settings_protocol', 'instance_id', 'is_multisession']
        w.writerow(cols)
        n = 70 if day.weekday() < 5 else 4
        for i in range(n):
            u = rng.choice(est['erp_users']); start = dt.datetime(day.year, day.month, day.day, 12, 0, tzinfo=UTC) + dt.timedelta(minutes=rng.randint(0, 420))
            dur = rng.randint(1800, 5 * 3600)
            w.writerow(['s-%s-%03d' % (day.isoformat(), i), HOME_ACCOUNT, 'us-east-1', start.isoformat(), (start + dt.timedelta(seconds=dur)).isoformat(), dur, u, 'arn:aws:appstream:us-east-1:%s:user/%s' % (HOME_ACCOUNT, u),
                        'SAML', 'SAML:' + u, 'erp-apps', 'erp', 'stream.standard.large', '10.0.1.%d' % rng.randint(2, 250), 'true', '203.0.113.%d' % rng.randint(2, 250), 'false', 'false',
                        'appstream2-36fb080bb8-us-east-1-%s' % HOME_ACCOUNT, 'ENABLED', 'ENABLED', 'ENABLED', 'ENABLED', 'ENABLED', 'true', 'Y', 57600, 'ON_DEMAND', 'APPLICATION', 'UDP', 'i-0demo', 'true'])
        return dict(Body=_Body(buf.getvalue().encode('utf-8')), ContentType='text/csv')

    def ce_cost(region, p):
        gb = [g['Key'] for g in p.get('GroupBy', [])]; flt = p.get('Filter') or {}
        tp = p['TimePeriod']
        scale = 1.0 if tp['Start'].endswith('-01') and not tp['End'].endswith('-01') else 1.0
        def g(keys, amt, qty, unit='Hrs'):
            return dict(Keys=keys, Metrics={'AmortizedCost': {'Amount': '%.6f' % amt, 'Unit': 'USD'}, 'UnblendedCost': {'Amount': '%.6f' % (amt * 1.01), 'Unit': 'USD'}, 'UsageQuantity': {'Amount': '%.3f' % qty, 'Unit': unit}})
        if gb == ['SERVICE'] and not flt:
            groups = [g(['Amazon WorkSpaces'], 11840.55, 7000.0), g(['Amazon AppStream'], 6420.10, 5200.0), g(['Amazon Elastic Compute Cloud - Compute'], 22100.0, 70000.0),
                      g(['EC2 - Other'], 4100.0, 50000.0, 'GB-Mo'), g(['Amazon Simple Storage Service'], 900.0, 120000.0, 'GB-Mo'), g(['AmazonCloudWatch'], 230.0, 1e6, 'Metrics')]
        elif gb == ['USAGE_TYPE', 'LINKED_ACCOUNT']:
            groups = [g(['USE1-WorkSpaces:Standard:AutoStop:Monthly', HOME_ACCOUNT], 66 * 9.75, 66, 'Month'), g(['USE1-WorkSpaces:Standard:AutoStop:Hourly', HOME_ACCOUNT], 60 * 150 * 0.30, 9000.0),
                      g(['USE1-WorkSpaces:Power:AlwaysOn', HOME_ACCOUNT], 10 * 69.0, 10, 'Month'), g(['USE1-WorkSpaces:Performance:AlwaysOn', HOME_ACCOUNT], 15 * 48.0, 15, 'Month'),
                      g(['USE1-WorkSpaces:Graphics.g4dn:AlwaysOn', HOME_ACCOUNT], 1 * 518.0, 1, 'Month'), g(['USE1-WorkSpacesPools:Standard:Hourly', HOME_ACCOUNT], 1900.0, 7200.0),
                      g(['USE1-WorkSpacesPools:UserFee', HOME_ACCOUNT], 64 * 4.19, 64, 'Users'),
                      g(['USE1-AppStream:stream.standard.large:Hrs', HOME_ACCOUNT], 1420.0, 7100.0), g(['USE1-AppStream:stream.graphics.g4dn.xlarge:Hrs', HOME_ACCOUNT], 4320.0, 4320.0),
                      g(['USE1-AppStream:UserFee', HOME_ACCOUNT], 132 * 4.19, 132, 'Users')]
        elif gb == ['REGION', 'SERVICE']:
            groups = [g(['us-east-1', 'Amazon WorkSpaces'], 11840.55, 7000.0), g(['us-east-1', 'Amazon AppStream'], 6420.10, 5200.0)]
        elif gb == ['SERVICE'] and 'Tags' in flt:
            groups = [g(['Amazon Elastic Compute Cloud - Compute'], 1620.0, 2880.0), g(['EC2 - Other'], 210.0, 2000.0, 'GB-Mo')]
        else:
            groups = []
        return dict(ResultsByTime=[dict(TimePeriod=dict(Start=tp['Start'], End=tp['End']), Total={}, Groups=groups, Estimated=tp['End'] > '2026-10-01')],
                    GroupDefinitions=[dict(Type='DIMENSION', Key=k) for k in gb], DimensionValueAttributes=[])

    def pricing_products(region, p):
        rows = []
        def prod(bundle, mode, unit, price, root, user, vcpu, mem):
            sku = 'SKU%s%s%s%s' % (bundle[:3].upper(), mode[:2].upper(), root, user)
            return json.dumps(dict(product=dict(sku=sku, attributes=dict(bundleDescription=bundle, runningMode=mode, license='Included', rootVolume='%d GB' % root, userVolume='%d GB' % user,
                                                                        softwareIncluded='None', operatingSystem='Windows', regionCode='us-east-1', vcpu=str(vcpu), memory='%d GB' % mem, servicecode='AmazonWorkSpaces')),
                                   terms=dict(OnDemand={sku + '.JRTCKXETXF': dict(priceDimensions={sku + '.JRTCKXETXF.6YS6EN2CT7': dict(unit=unit, pricePerUnit={'USD': '%.4f' % price})})})))
        for root, user in ((80, 50), (80, 100), (175, 100)):
            rows.append(prod('Standard', 'AlwaysOn', 'Month', 35.0 + (user + root) * 0.03, root, user, 2, 4))
            rows.append(prod('Standard', 'AutoStop', 'Month', 9.75, root, user, 2, 4)); rows.append(prod('Standard', 'AutoStop', 'Hour', 0.30, root, user, 2, 4))
            rows.append(prod('Performance', 'AlwaysOn', 'Month', 48.0 + (user + root) * 0.03, root, user, 2, 8))
            rows.append(prod('Power', 'AlwaysOn', 'Month', 69.0 + (user + root) * 0.03, root, user, 4, 16))
            rows.append(prod('Power', 'AutoStop', 'Month', 19.0, root, user, 4, 16)); rows.append(prod('Power', 'AutoStop', 'Hour', 0.68, root, user, 4, 16))
            rows.append(prod('Graphics.g4dn', 'AlwaysOn', 'Month', 518.0, root, user, 4, 16))
        page = 60; start = int(p.get('NextToken') or 0)
        out = dict(FormatVersion='aws_v1', PriceList=rows[start:start + page])
        if start + page < len(rows): out['NextToken'] = str(start + page)
        return out

    def ec2_instances(region, p):
        if region != 'us-east-1': return dict(Reservations=[])
        filt = {f['Name']: f['Values'] for f in p.get('Filters', [])}
        if filt.get('tag:workload') and 'vdi' not in filt['tag:workload']: return dict(Reservations=[])
        return dict(Reservations=[dict(ReservationId='r-demo', OwnerId=HOME_ACCOUNT, Instances=[dict(i) for i in est['ec2']])])

    responders = {
        ('sts', 'GetCallerIdentity'): sts_identity,
        ('ec2', 'DescribeRegions'): ec2_regions, ('ec2', 'DescribeInstances'): ec2_instances,
        ('workspaces', 'DescribeWorkspaceDirectories'): ws_dirs, ('workspaces', 'DescribeWorkspaces'): ws_list, ('workspaces', 'DescribeWorkspacesPools'): ws_pools,
        ('workspaces', 'DescribeWorkspaceBundles'): ws_bundles, ('workspaces', 'DescribeWorkspacesConnectionStatus'): ws_conn,
        ('cloudwatch', 'ListMetrics'): cw_list_metrics, ('cloudwatch', 'GetMetricData'): cw_get_metric_data,
        ('appstream', 'DescribeFleets'): as_fleets, ('appstream', 'DescribeStacks'): as_stacks, ('appstream', 'DescribeUsageReportSubscriptions'): as_subs,
        ('s3', 'GetObject'): s3_get,
        ('ce', 'GetCostAndUsage'): ce_cost,
        ('pricing', 'GetProducts'): pricing_products,
    }

    def factory(service, region, credentials):
        if service == '__regions__':   # Aws.available_regions(service) asks the factory for the region list of a service
            return {'workspaces': ['us-east-1', 'us-west-2', 'eu-west-1'], 'appstream': ['us-east-1', 'us-west-2', 'eu-west-1']}.get(region, [])
        return StubClient(service, region, responders, model_cache)
    return factory
