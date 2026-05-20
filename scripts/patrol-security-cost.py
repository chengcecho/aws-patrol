#!/usr/bin/env python3
"""AWS Security + Cost analysis."""
import boto3, json, sys
from datetime import datetime, timedelta, timezone

import os
PROFILE = os.environ.get('AWS_PATROL_PROFILE', os.environ.get('AWS_PROFILE', 'default'))
REGIONS = os.environ.get('AWS_PATROL_REGIONS', 'us-west-2,eu-west-2,ap-southeast-1').split(',')
session = boto3.Session(profile_name=PROFILE)
now = datetime.now(timezone.utc)
result = {'timestamp': now.isoformat(), 'security': {}, 'cost': {}}

# ============ SECURITY ============
print("[Security] Checking IAM...", file=sys.stderr)
iam = session.client('iam')

# 1. IAM: users without MFA
try:
    users = iam.list_users()['Users']
    no_mfa = []
    for u in users:
        mfa = iam.list_mfa_devices(UserName=u['UserName'])['MFADevices']
        if not mfa:
            # Check if user has console access
            try:
                iam.get_login_profile(UserName=u['UserName'])
                no_mfa.append({'user': u['UserName'], 'created': str(u['CreateDate']), 'hasConsole': True})
            except:
                no_mfa.append({'user': u['UserName'], 'created': str(u['CreateDate']), 'hasConsole': False})
    result['security']['iamNoMFA'] = no_mfa
    print(f"  Users without MFA: {len(no_mfa)}/{len(users)}", file=sys.stderr)
except Exception as e:
    print(f"  IAM error: {e}", file=sys.stderr)
    result['security']['iamNoMFA'] = []

# 2. IAM: access keys older than 90 days
try:
    old_keys = []
    for u in users:
        keys = iam.list_access_keys(UserName=u['UserName'])['AccessKeyMetadata']
        for k in keys:
            age = (now - k['CreateDate']).days
            if age > 90:
                old_keys.append({'user': u['UserName'], 'keyId': k['AccessKeyId'], 'ageDays': age, 'status': k['Status']})
    result['security']['oldAccessKeys'] = old_keys
    print(f"  Access keys > 90 days: {len(old_keys)}", file=sys.stderr)
except Exception as e:
    result['security']['oldAccessKeys'] = []

# 3. Root account usage
try:
    summary = iam.get_account_summary()['SummaryMap']
    result['security']['accountSummary'] = {
        'users': summary.get('Users', 0),
        'groups': summary.get('Groups', 0),
        'roles': summary.get('Roles', 0),
        'policies': summary.get('Policies', 0),
        'mfaEnabled': summary.get('AccountMFAEnabled', 0),
        'accessKeysPerUser': summary.get('AccessKeysPerUserQuota', 0)
    }
except:
    pass

for region in REGIONS:
    print(f"[Security] {region}...", file=sys.stderr)
    ec2 = session.client('ec2', region_name=region)
    s3 = session.client('s3', region_name=region) if region == 'us-west-2' else None
    
    # 4. Security Groups: open to 0.0.0.0/0
    try:
        sgs = ec2.describe_security_groups()['SecurityGroups']
        open_sgs = []
        for sg in sgs:
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port = rule.get('FromPort', 'ALL')
                        proto = rule.get('IpProtocol', '-1')
                        if proto == '-1' or port in [22, 3389, 3306, 5432, 6379, 27017, 9200]:
                            open_sgs.append({
                                'sgId': sg['GroupId'], 'sgName': sg.get('GroupName',''),
                                'port': port, 'protocol': proto, 'region': region,
                                'risk': 'HIGH' if port in [22, 3389, 3306] or proto == '-1' else 'MEDIUM'
                            })
        if 'openSecurityGroups' not in result['security']:
            result['security']['openSecurityGroups'] = []
        result['security']['openSecurityGroups'].extend(open_sgs)
        print(f"  Open SGs: {len(open_sgs)}", file=sys.stderr)
    except Exception as e:
        print(f"  SG error: {e}", file=sys.stderr)

    # 5. Public EBS snapshots
    try:
        snaps = ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']
        public_snaps = []
        for snap in snaps[:50]:  # limit to avoid timeout
            attrs = ec2.describe_snapshot_attribute(SnapshotId=snap['SnapshotId'], Attribute='createVolumePermission')
            for perm in attrs.get('CreateVolumePermissions', []):
                if perm.get('Group') == 'all':
                    public_snaps.append({'snapshotId': snap['SnapshotId'], 'region': region})
        if 'publicSnapshots' not in result['security']:
            result['security']['publicSnapshots'] = []
        result['security']['publicSnapshots'].extend(public_snaps)
    except:
        pass

    # 6. Unencrypted EBS volumes
    try:
        vols = ec2.describe_volumes()['Volumes']
        unencrypted = [{'volumeId': v['VolumeId'], 'size': v['Size'], 'region': region} 
                       for v in vols if not v.get('Encrypted', False)]
        if 'unencryptedVolumes' not in result['security']:
            result['security']['unencryptedVolumes'] = []
        result['security']['unencryptedVolumes'].extend(unencrypted)
        print(f"  Unencrypted volumes: {len(unencrypted)}/{len(vols)}", file=sys.stderr)
    except:
        pass

# 7. S3 public buckets
try:
    s3_client = session.client('s3')
    buckets = s3_client.list_buckets()['Buckets']
    public_buckets = []
    for b in buckets:
        try:
            acl = s3_client.get_bucket_acl(Bucket=b['Name'])
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') in ['http://acs.amazonaws.com/groups/global/AllUsers',
                                           'http://acs.amazonaws.com/groups/global/AuthenticatedUsers']:
                    public_buckets.append({'bucket': b['Name'], 'permission': grant.get('Permission','')})
        except:
            pass
        try:
            pabs = s3_client.get_public_access_block(Bucket=b['Name'])
            conf = pabs['PublicAccessBlockConfiguration']
            if not all([conf.get('BlockPublicAcls'), conf.get('BlockPublicPolicy'), 
                       conf.get('IgnorePublicAcls'), conf.get('RestrictPublicBuckets')]):
                public_buckets.append({'bucket': b['Name'], 'note': 'PublicAccessBlock not fully enabled'})
        except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
            public_buckets.append({'bucket': b['Name'], 'note': 'No PublicAccessBlock configured'})
        except:
            pass
    result['security']['publicBuckets'] = public_buckets
    result['security']['totalBuckets'] = len(buckets)
    print(f"  S3 public/risky: {len(public_buckets)}/{len(buckets)}", file=sys.stderr)
except Exception as e:
    print(f"  S3 error: {e}", file=sys.stderr)

# ============ COST ============
print("\n[Cost] Analyzing...", file=sys.stderr)
ce = session.client('ce', region_name='us-east-1')

# 1. Last 30 days cost by service
try:
    cost_resp = ce.get_cost_and_usage(
        TimePeriod={'Start': (now - timedelta(days=30)).strftime('%Y-%m-%d'), 'End': now.strftime('%Y-%m-%d')},
        Granularity='MONTHLY',
        Metrics=['UnblendedCost'],
        GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
    )
    services = []
    for period in cost_resp['ResultsByTime']:
        for group in period['Groups']:
            amt = float(group['Metrics']['UnblendedCost']['Amount'])
            if amt > 0.01:
                services.append({'service': group['Keys'][0], 'cost': round(amt, 2)})
    services.sort(key=lambda x: x['cost'], reverse=True)
    result['cost']['byService'] = services
    result['cost']['total30d'] = round(sum(s['cost'] for s in services), 2)
    print(f"  Total 30d: ${result['cost']['total30d']}", file=sys.stderr)
except Exception as e:
    print(f"  Cost error: {e}", file=sys.stderr)

# 2. Daily trend (last 14 days)
try:
    daily = ce.get_cost_and_usage(
        TimePeriod={'Start': (now - timedelta(days=14)).strftime('%Y-%m-%d'), 'End': now.strftime('%Y-%m-%d')},
        Granularity='DAILY',
        Metrics=['UnblendedCost']
    )
    result['cost']['dailyTrend'] = [
        {'date': p['TimePeriod']['Start'], 'cost': round(float(p['Total']['UnblendedCost']['Amount']), 2)}
        for p in daily['ResultsByTime']
    ]
except:
    pass

# 3. Savings Plans / RI coverage
try:
    ri_resp = ce.get_reservation_coverage(
        TimePeriod={'Start': (now - timedelta(days=30)).strftime('%Y-%m-%d'), 'End': now.strftime('%Y-%m-%d')},
        Granularity='MONTHLY'
    )
    for period in ri_resp['CoveragesByTime']:
        total = period.get('Total', {}).get('CoverageHours', {})
        result['cost']['riCoverage'] = {
            'coveragePercent': total.get('CoverageHoursPercentage', '0'),
            'onDemandHours': total.get('OnDemandHours', '0'),
            'reservedHours': total.get('ReservedHours', '0')
        }
except Exception as e:
    print(f"  RI coverage error: {e}", file=sys.stderr)

try:
    sp_resp = ce.get_savings_plans_coverage(
        TimePeriod={'Start': (now - timedelta(days=30)).strftime('%Y-%m-%d'), 'End': now.strftime('%Y-%m-%d')},
        Granularity='MONTHLY'
    )
    for period in sp_resp['SavingsPlansCoverages']:
        result['cost']['spCoverage'] = {
            'coveragePercent': period.get('Coverage', {}).get('CoveragePercentage', '0'),
            'spendCovered': period.get('Coverage', {}).get('SpendCoveredBySavingsPlans', '0'),
            'onDemandCost': period.get('Coverage', {}).get('OnDemandCost', '0')
        }
except Exception as e:
    print(f"  SP coverage error: {e}", file=sys.stderr)

# SP utilization (last 7 days daily)
print("[Cost] SP utilization...", file=sys.stderr)
try:
    sp_util = ce.get_savings_plans_utilization(
        TimePeriod={'Start': (now - timedelta(days=7)).strftime('%Y-%m-%d'), 'End': now.strftime('%Y-%m-%d')},
        Granularity='DAILY'
    )
    sp_util_daily = []
    for r in sp_util.get('SavingsPlansUtilizationsByTime', []):
        u = r['Utilization']
        sp_util_daily.append({
            'date': r['TimePeriod']['Start'],
            'utilPct': u.get('UtilizationPercentage', '0'),
            'commitment': u.get('TotalCommitment', '0'),
            'used': u.get('UsedCommitment', '0'),
            'unused': u.get('UnusedCommitment', '0')
        })
    sp_total = sp_util.get('Total', {}).get('Utilization', {})
    result['cost']['spUtilization'] = {
        'daily': sp_util_daily,
        'avgUtilPct': sp_total.get('UtilizationPercentage', '0'),
        'totalCommitment': sp_total.get('TotalCommitment', '0'),
        'totalUsed': sp_total.get('UsedCommitment', '0'),
        'totalUnused': sp_total.get('UnusedCommitment', '0')
    }
    print(f"  SP Util 7d avg: {sp_total.get('UtilizationPercentage', '?')}%", file=sys.stderr)
except Exception as e:
    print(f"  SP util error: {e}", file=sys.stderr)

# SP daily coverage (last 7 days)
print("[Cost] SP daily coverage...", file=sys.stderr)
try:
    sp_cov_daily = ce.get_savings_plans_coverage(
        TimePeriod={'Start': (now - timedelta(days=7)).strftime('%Y-%m-%d'), 'End': now.strftime('%Y-%m-%d')},
        Granularity='DAILY'
    )
    result['cost']['spCoverageDaily'] = [
        {'date': r['TimePeriod']['Start'],
         'coveragePct': r['Coverage'].get('CoveragePercentage', '0'),
         'spSpend': r['Coverage'].get('SpendCoveredBySavingsPlans', '0'),
         'onDemand': r['Coverage'].get('OnDemandCost', '0')}
        for r in sp_cov_daily.get('SavingsPlansCoverages', [])
    ]
except Exception as e:
    print(f"  SP cov daily error: {e}", file=sys.stderr)

# RI coverage by service (RDS + ElastiCache, last 7 days daily)
print("[Cost] RI coverage by service...", file=sys.stderr)
for svc_name, svc_filter in [
    ('rds', 'Amazon Relational Database Service'),
    ('elasticache', 'Amazon ElastiCache')
]:
    try:
        ri_svc = ce.get_reservation_coverage(
            TimePeriod={'Start': (now - timedelta(days=7)).strftime('%Y-%m-%d'), 'End': now.strftime('%Y-%m-%d')},
            Granularity='DAILY',
            Filter={'Dimensions': {'Key': 'SERVICE', 'Values': [svc_filter]}}
        )
        daily = []
        for r in ri_svc.get('CoveragesByTime', []):
            t = r['Total']['CoverageHours']
            daily.append({
                'date': r['TimePeriod']['Start'],
                'coveragePct': t.get('CoverageHoursPercentage', '0'),
                'riHours': t.get('ReservedHours', '0'),
                'onDemandHours': t.get('OnDemandHours', '0')
            })
        result['cost'][f'riCoverage_{svc_name}'] = daily
        if daily:
            avg_cov = sum(float(d['coveragePct']) for d in daily) / len(daily)
            print(f"  RI {svc_name} coverage 7d avg: {avg_cov:.1f}%", file=sys.stderr)
    except Exception as e:
        print(f"  RI {svc_name} error: {e}", file=sys.stderr)

# Active Savings Plans list
print("[Cost] Active Savings Plans...", file=sys.stderr)
try:
    sp_client = session.client('savingsplans')
    sp_list = sp_client.describe_savings_plans(
        states=['active']
    )['savingsPlans']
    result['cost']['activeSavingsPlans'] = [
        {'id': sp['savingsPlanId'], 'type': sp.get('savingsPlanType',''),
         'commitment': sp.get('commitment',''), 'start': str(sp.get('start','')),
         'end': str(sp.get('end','')), 'paymentOption': sp.get('paymentOption','')}
        for sp in sp_list
    ]
    print(f"  Active SPs: {len(sp_list)}", file=sys.stderr)
except Exception as e:
    print(f"  SP list error: {e}", file=sys.stderr)

# Active RDS + ElastiCache RIs
print("[Cost] Active RIs...", file=sys.stderr)
try:
    rds_client = session.client('rds', region_name='us-west-2')
    rds_ris = rds_client.describe_reserved_db_instances()['ReservedDBInstances']
    result['cost']['activeRdsRIs'] = [
        {'id': r['ReservedDBInstanceId'], 'class': r['DBInstanceClass'],
         'engine': r.get('ProductDescription',''), 'count': r['DBInstanceCount'],
         'state': r['State'], 'start': str(r.get('StartTime','')),
         'duration': r.get('Duration',0)}
        for r in rds_ris if r['State'] == 'active'
    ]
    print(f"  Active RDS RIs: {len(result['cost']['activeRdsRIs'])}", file=sys.stderr)
except Exception as e:
    print(f"  RDS RI error: {e}", file=sys.stderr)

try:
    ec_client = session.client('elasticache', region_name='us-west-2')
    ec_ris = ec_client.describe_reserved_cache_nodes()['ReservedCacheNodes']
    result['cost']['activeElastiCacheRIs'] = [
        {'id': r['ReservedCacheNodeId'], 'type': r['CacheNodeType'],
         'count': r['CacheNodeCount'], 'state': r['State'],
         'start': str(r.get('StartTime','')), 'duration': r.get('Duration',0)}
        for r in ec_ris if r['State'] == 'active'
    ]
    print(f"  Active ElastiCache RIs: {len(result['cost']['activeElastiCacheRIs'])}", file=sys.stderr)
except Exception as e:
    print(f"  EC RI error: {e}", file=sys.stderr)

# 4. Idle/underutilized resources
for region in REGIONS:
    ec2 = session.client('ec2', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    
    # Stopped instances (still incur EBS costs)
    try:
        stopped = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}])
        for res in stopped['Reservations']:
            for inst in res['Instances']:
                name = ''
                for t in inst.get('Tags', []):
                    if t['Key'] == 'Name': name = t['Value']
                if 'stoppedInstances' not in result['cost']:
                    result['cost']['stoppedInstances'] = []
                stop_time = inst.get('StateTransitionReason', '')
                result['cost']['stoppedInstances'].append({
                    'id': inst['InstanceId'], 'name': name, 'type': inst.get('InstanceType',''),
                    'region': region, 'reason': stop_time
                })
    except:
        pass
    
    # Unattached EBS volumes
    try:
        vols = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])['Volumes']
        for v in vols:
            if 'unattachedVolumes' not in result['cost']:
                result['cost']['unattachedVolumes'] = []
            result['cost']['unattachedVolumes'].append({
                'volumeId': v['VolumeId'], 'size': v['Size'], 'type': v.get('VolumeType',''),
                'region': region
            })
    except:
        pass
    
    # Unused Elastic IPs
    try:
        eips = ec2.describe_addresses()['Addresses']
        for eip in eips:
            if not eip.get('AssociationId'):
                if 'unusedEIPs' not in result['cost']:
                    result['cost']['unusedEIPs'] = []
                result['cost']['unusedEIPs'].append({
                    'ip': eip.get('PublicIp',''), 'allocationId': eip.get('AllocationId',''), 'region': region
                })
    except:
        pass

    # Old snapshots (> 180 days)
    try:
        snaps = ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']
        cutoff = now - timedelta(days=180)
        for s in snaps:
            if s['StartTime'].replace(tzinfo=timezone.utc) < cutoff:
                if 'oldSnapshots' not in result['cost']:
                    result['cost']['oldSnapshots'] = []
                result['cost']['oldSnapshots'].append({
                    'snapshotId': s['SnapshotId'], 'size': s.get('VolumeSize', 0),
                    'startTime': str(s['StartTime']), 'region': region
                })
    except:
        pass

print(f"  Stopped instances: {len(result['cost'].get('stoppedInstances', []))}", file=sys.stderr)
print(f"  Unattached volumes: {len(result['cost'].get('unattachedVolumes', []))}", file=sys.stderr)
print(f"  Unused EIPs: {len(result['cost'].get('unusedEIPs', []))}", file=sys.stderr)
print(f"  Old snapshots (>180d): {len(result['cost'].get('oldSnapshots', []))}", file=sys.stderr)

# 5. Rightsizing: EC2 instances with avg CPU < 5% (from patrol data)
try:
    with open(os.path.join(OUT_DIR, 'aws-patrol-detail.json')) as f:
        patrol = json.load(f)
    low_cpu = [e for e in patrol['ec2'] if e.get('cpu') is not None and e['cpu'] < 5]
    result['cost']['lowCpuInstances'] = low_cpu
    print(f"  Low CPU (<5%) instances: {len(low_cpu)}", file=sys.stderr)
except:
    pass

OUT_DIR = os.environ.get('AWS_PATROL_OUTPUT', os.getcwd())
out = os.path.join(OUT_DIR, 'aws-security-cost.json')
with open(out, 'w') as f:
    json.dump(result, f, indent=2, default=str)

print(f"\nDone! Written to {out}", file=sys.stderr)
