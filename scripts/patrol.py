#!/usr/bin/env python3
"""AWS detailed patrol: EC2 CPU, RDS metrics, CloudWatch alarms."""
import boto3, json, sys
from datetime import datetime, timedelta, timezone

import os
PROFILE = os.environ.get('AWS_PATROL_PROFILE', os.environ.get('AWS_PROFILE', 'default'))
REGIONS = os.environ.get('AWS_PATROL_REGIONS', 'us-west-2,eu-west-2,ap-southeast-1').split(',')
session = boto3.Session(profile_name=PROFILE)
now = datetime.now(timezone.utc)
start = now - timedelta(minutes=30)

def cw_latest(cw, ns, metric, dim_name, dim_value, stat='Average'):
    """Get latest CloudWatch metric value."""
    try:
        r = cw.get_metric_statistics(
            Namespace=ns, MetricName=metric,
            Dimensions=[{'Name': dim_name, 'Value': dim_value}],
            StartTime=start, EndTime=now,
            Period=300, Statistics=[stat]
        )
        pts = r.get('Datapoints', [])
        if pts:
            pts.sort(key=lambda x: x['Timestamp'])
            return round(pts[-1].get(stat, 0), 2)
    except:
        pass
    return None

result = {'timestamp': now.isoformat(), 'ec2': [], 'rds': [], 'alarms': [], 'elb': []}

for region in REGIONS:
    print(f"[{region}] Starting...", file=sys.stderr)
    ec2 = session.client('ec2', region_name=region)
    rds = session.client('rds', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    elbv2 = session.client('elbv2', region_name=region)

    # EC2
    pages = ec2.get_paginator('describe_instances').paginate(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    for page in pages:
        for res in page['Reservations']:
            for i in res['Instances']:
                iid = i['InstanceId']
                name = ''
                for t in i.get('Tags', []):
                    if t['Key'] == 'Name': name = t['Value']
                
                cpu = cw_latest(cw, 'AWS/EC2', 'CPUUtilization', 'InstanceId', iid)
                net_in = cw_latest(cw, 'AWS/EC2', 'NetworkIn', 'InstanceId', iid, 'Sum')
                net_out = cw_latest(cw, 'AWS/EC2', 'NetworkOut', 'InstanceId', iid, 'Sum')
                
                # Status check
                try:
                    st = ec2.describe_instance_status(InstanceIds=[iid])['InstanceStatuses']
                    sys_st = st[0]['SystemStatus']['Status'] if st else 'N/A'
                    inst_st = st[0]['InstanceStatus']['Status'] if st else 'N/A'
                except:
                    sys_st = inst_st = 'N/A'
                
                alerts = []
                if cpu is not None and cpu > 80: alerts.append('CPU>80%')
                if sys_st != 'ok' and sys_st != 'N/A': alerts.append(f'SysCheck:{sys_st}')
                if inst_st != 'ok' and inst_st != 'N/A': alerts.append(f'InstCheck:{inst_st}')
                
                result['ec2'].append({
                    'id': iid, 'name': name, 'type': i.get('InstanceType', ''),
                    'region': region, 'az': i.get('Placement', {}).get('AvailabilityZone', ''),
                    'ip': i.get('PrivateIpAddress', ''),
                    'cpu': cpu, 'networkInMB': round(net_in/1048576, 1) if net_in else None,
                    'networkOutMB': round(net_out/1048576, 1) if net_out else None,
                    'sysStatus': sys_st, 'instStatus': inst_st,
                    'alerts': alerts
                })
                print(f"  EC2 {iid} ({name}) CPU={cpu}%", file=sys.stderr)
    
    # RDS
    try:
        dbs = rds.describe_db_instances()['DBInstances']
    except:
        dbs = []
    for db in dbs:
        dbid = db['DBInstanceIdentifier']
        cpu = cw_latest(cw, 'AWS/RDS', 'CPUUtilization', 'DBInstanceIdentifier', dbid)
        free_mem = cw_latest(cw, 'AWS/RDS', 'FreeableMemory', 'DBInstanceIdentifier', dbid)
        conns = cw_latest(cw, 'AWS/RDS', 'DatabaseConnections', 'DBInstanceIdentifier', dbid)
        free_stor = cw_latest(cw, 'AWS/RDS', 'FreeStorageSpace', 'DBInstanceIdentifier', dbid)
        read_iops = cw_latest(cw, 'AWS/RDS', 'ReadIOPS', 'DBInstanceIdentifier', dbid)
        write_iops = cw_latest(cw, 'AWS/RDS', 'WriteIOPS', 'DBInstanceIdentifier', dbid)
        
        free_mem_mb = round(free_mem/1048576, 1) if free_mem else None
        free_stor_gb = round(free_stor/1073741824, 1) if free_stor else None
        
        alerts = []
        if cpu is not None and cpu > 80: alerts.append('CPU>80%')
        if free_mem_mb is not None and free_mem_mb < 500: alerts.append('LowMemory')
        if free_stor_gb is not None and free_stor_gb < 10: alerts.append('LowStorage')
        
        result['rds'].append({
            'id': dbid, 'engine': db.get('Engine',''), 'engineVer': db.get('EngineVersion',''),
            'class': db.get('DBInstanceClass',''), 'status': db.get('DBInstanceStatus',''),
            'region': region, 'multiAZ': db.get('MultiAZ', False),
            'storageGB': db.get('AllocatedStorage', 0),
            'cpu': cpu, 'freeMemMB': free_mem_mb, 'connections': conns,
            'freeStorageGB': free_stor_gb, 'readIOPS': read_iops, 'writeIOPS': write_iops,
            'alerts': alerts
        })
        print(f"  RDS {dbid} CPU={cpu}% FreeMem={free_mem_mb}MB", file=sys.stderr)
    
    # CloudWatch Alarms
    try:
        for state in ['ALARM', 'INSUFFICIENT_DATA']:
            alarms = cw.describe_alarms(StateValue=state)['MetricAlarms']
            for a in alarms:
                result['alarms'].append({
                    'name': a.get('AlarmName',''), 'state': a.get('StateValue',''),
                    'metric': a.get('MetricName',''), 'namespace': a.get('Namespace',''),
                    'threshold': a.get('Threshold', 0),
                    'region': region,
                    'reason': a.get('StateReason','')[:200]
                })
    except:
        pass
    
    # ELB
    try:
        lbs = elbv2.describe_load_balancers()['LoadBalancers']
        for lb in lbs:
            tgs = elbv2.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])['TargetGroups']
            tg_info = []
            for tg in tgs:
                health = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])['TargetHealthDescriptions']
                targets = [{'id': t['Target']['Id'], 'port': t['Target'].get('Port',0),
                            'health': t['TargetHealth']['State']} for t in health]
                unhealthy = [t for t in targets if t['health'] != 'healthy']
                tg_info.append({'name': tg['TargetGroupName'], 'targets': targets, 'unhealthyCount': len(unhealthy)})
            result['elb'].append({
                'name': lb.get('LoadBalancerName',''), 'type': lb.get('Type',''),
                'state': lb.get('State',{}).get('Code',''), 'dns': lb.get('DNSName',''),
                'region': region, 'targetGroups': tg_info
            })
    except:
        pass

# Health Events (via User Notifications API)
print("[health] Fetching Health events...", file=sys.stderr)
health_events = []
try:
    notif = session.client('notifications', region_name='us-west-2')
    since = now - timedelta(days=7)
    pages = notif.get_paginator('list_managed_notification_events').paginate(
        source='aws.health', startTime=since)
    for page in pages:
        for evt in page.get('managedNotificationEvents', []):
            ne = evt.get('notificationEvent', {})
            headline = ne.get('messageComponents', {}).get('headline', '')
            sub = evt.get('managedNotificationConfigurationArn', '').rsplit('/', 1)[-1]
            health_events.append({
                'headline': headline,
                'category': sub,
                'type': ne.get('notificationType', ''),
                'time': evt.get('creationTime', ''),
                'region': ne.get('sourceEventMetadata', {}).get('eventOriginRegion', ''),
            })
            print(f"  Health: {headline[:80]}", file=sys.stderr)
except Exception as e:
    print(f"  Health events error: {e}", file=sys.stderr)
result['healthEvents'] = health_events

# SMS Registration status
print("[sms] Checking sender registrations...", file=sys.stderr)
sms_registrations = []
try:
    sms = session.client('pinpoint-sms-voice-v2', region_name='us-west-2')
    regs = sms.describe_registrations().get('Registrations', [])
    for r in regs:
        sms_registrations.append({
            'id': r['RegistrationId'],
            'type': r['RegistrationType'],
            'status': r['RegistrationStatus'],
        })
        print(f"  SMS Reg: {r['RegistrationType']} = {r['RegistrationStatus']}", file=sys.stderr)
except Exception as e:
    print(f"  SMS reg error: {e}", file=sys.stderr)
result['smsRegistrations'] = sms_registrations

# Summary
ec2_alerts = [e for e in result['ec2'] if e['alerts']]
rds_alerts = [r for r in result['rds'] if r['alerts']]
alarm_firing = [a for a in result['alarms'] if a['state'] == 'ALARM']

action_required = [h for h in health_events if '[Action Required]' in h.get('headline', '')]
sms_issues = [s for s in sms_registrations if s['status'] not in ('COMPLETE', 'CLOSED')]

result['summary'] = {
    'ec2Total': len(result['ec2']),
    'ec2WithAlerts': len(ec2_alerts),
    'rdsTotal': len(result['rds']),
    'rdsWithAlerts': len(rds_alerts),
    'alarmsFireing': len(alarm_firing),
    'elbTotal': len(result['elb']),
    'healthEventsTotal': len(health_events),
    'healthActionRequired': len(action_required),
    'smsIssues': len(sms_issues),
}

OUT_DIR = os.environ.get('AWS_PATROL_OUTPUT', os.getcwd())
out = os.path.join(OUT_DIR, 'aws-patrol-detail.json')
with open(out, 'w') as f:
    json.dump(result, f, indent=2, default=str)

print(f"\nDone! {result['summary']}", file=sys.stderr)
