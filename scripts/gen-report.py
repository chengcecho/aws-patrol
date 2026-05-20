#!/usr/bin/env python3
"""Generate the daily patrol HTML report from template + collected data."""
import json, sys, os

SKILL_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get('AWS_PATROL_OUTPUT', os.getcwd())
tpl_path = os.path.join(SKILL_DIR, '..', 'assets', 'report-template.html')
out_path = os.path.join(BASE, 'daily-report.html')

# Read template
with open(tpl_path) as f:
    html = f.read()

# Accept data as JSON arguments or use defaults for today
data = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}

def r(key, default='—'):
    return str(data.get(key, default))

# Simple replacements
replacements = {
    '{{DATE}}': r('date', '2026-04-08'),
    '{{WEEKDAY}}': r('weekday', '周三'),
    '{{TIME}}': r('time', '09:00'),
    '{{EC2_COUNT}}': r('ec2Count', '86'),
    '{{RDS_COUNT}}': r('rdsCount', '34'),
    '{{ELB_COUNT}}': r('elbCount', '28'),
    '{{COST_TOTAL}}': r('costTotal', '70,005'),
    '{{COST_DAILY}}': r('costDaily', '2,334'),
    '{{UNATTACHED_VOL}}': r('unattachedVol', '19'),
    '{{UNUSED_EIP}}': r('unusedEip', '1'),
    '{{LOW_CPU}}': r('lowCpu', '53'),
    '{{OLD_SNAP}}': r('oldSnap', '1'),
    '{{SP_UTIL_PCT}}': r('spUtilPct', '100'),
    '{{SP_COV_PCT}}': r('spCovPct', '51.5'),
    '{{RDS_RI_PCT}}': r('rdsRiPct', '34.6'),
    '{{EC_RI_PCT}}': r('ecRiPct', '18.4'),
    '{{NO_MFA}}': r('noMfa', '31/35'),
    '{{UNENC_EBS}}': r('unencEbs', '201/205'),
    '{{OPEN_SG}}': r('openSg', '17'),
    '{{OLD_KEYS}}': r('oldKeys', '13'),
    '{{S3_RISK}}': r('s3Risk', '4/19'),
}

for k, v in replacements.items():
    html = html.replace(k, v)

# High CPU items
high_cpu = data.get('highCpu', [
    {'name': 'kafka-prod-server-02', 'cpu': 50.6, 'level': 'orange'},
    {'name': 'kafka-prod-server-03', 'cpu': 48.9, 'level': 'orange'},
    {'name': 'kafka-prod-server-01', 'cpu': 45.5, 'level': 'orange'},
    {'name': 'skywalking-mysql-prod', 'cpu': 52.1, 'level': 'red'},
    {'name': 'pa-prod-big-live-ro', 'cpu': 35.5, 'level': 'yellow'},
    {'name': 'log ES data 节点 (×6)', 'cpu': 28.5, 'level': 'yellow'},
])
cpu_html = ''
for item in high_cpu:
    level = item.get('level', 'yellow')
    cpu_html += f'<div class="highlight-row"><span class="dot {level}"></span>{item["name"]}<span style="margin-left:auto;font-weight:600;color:{"#f87171" if level=="red" else "#fb923c" if level=="orange" else "#fbbf24"}">{item["cpu"]}%</span></div>'
html = html.replace('{{HIGH_CPU_ITEMS}}', cpu_html)

# SP/RI details
sp_details = data.get('spRiDetails', 
    'SP: $27.06/h 承诺 (3个活跃) · RDS RI: 31个实例 · Redis RI: 60个节点')
html = html.replace('{{SP_RI_DETAILS}}', sp_details)

# Health items
health = data.get('health', [
    {'type': 'warn', 'title': '[Action Required] WorkMail 2027-03-31 停服', 'desc': '8个组织 34个邮箱需迁移'},
    {'type': 'warn', 'title': '[Action Required] RDS MySQL 8.0 标准支持到期', 'desc': '15个 MySQL 8.0 实例需升级'},
    {'type': 'info', 'title': 'VPN 连接相关通知 ×4', 'desc': ''},
])
health_html = ''
for h in health:
    cls = 'danger' if h['type'] == 'danger' else 'warn' if h['type'] == 'warn' else 'info'
    desc_html = f'<div class="alert-desc">{h["desc"]}</div>' if h.get('desc') else ''
    health_html += f'<div class="alert-item {cls}"><div class="alert-title">{h["title"]}</div>{desc_html}</div>'
html = html.replace('{{HEALTH_ITEMS}}', health_html)

# SMS items
sms = data.get('sms', [
    {'name': 'US_TEN_DLC_CAMPAIGN', 'status': 'REQUIRES_UPDATES', 'level': 'red'},
    {'name': 'FI_SENDER_ID', 'status': 'REVIEWING', 'level': 'yellow'},
    {'name': 'SG_SENDER_ID / US_TEN_DLC_BRAND', 'status': 'COMPLETE', 'level': 'green'},
])
sms_html = ''
for s in sms:
    sms_html += f'<div class="item-row"><span class="item-name">{s["name"]}</span><span class="tag {s["level"]}">{s["status"]}</span></div>'
html = html.replace('{{SMS_ITEMS}}', sms_html)

# Action items / timeline
actions = data.get('actions', [
    {'date': '⚠️ 尽快处理', 'level': 'urgent', 'title': 'US_TEN_DLC_CAMPAIGN 需更新', 'desc': 'SMS 注册状态 REQUIRES_UPDATES，影响美国短信发送', 'daysLeft': '', 'daysLevel': 'red'},
    {'date': '2026-07', 'level': 'warning', 'title': 'RDS MySQL 8.0 标准支持到期', 'desc': '15个实例需升级到 8.4，否则进入扩展支持收费 (+20%)', 'daysLeft': '~90天', 'daysLevel': 'yellow'},
    {'date': '2026-08-29', 'level': 'info', 'title': 'Compute SP $0.01/h 到期', 'desc': '金额极小，可忽略或续购', 'daysLeft': '143天', 'daysLevel': 'blue'},
    {'date': '2026-12-09', 'level': 'warning', 'title': 'Compute SP $15/h + RDS RI + Redis RI 到期', 'desc': 'SP $15/h + RDS RI 31实例 + Redis RI 12节点，需提前评估续购', 'daysLeft': '245天', 'daysLevel': 'yellow'},
    {'date': '2027-03-31', 'level': 'warning', 'title': 'Amazon WorkMail 停服', 'desc': '8个组织 34个邮箱需迁移到 Google Workspace / M365', 'daysLeft': '357天', 'daysLevel': 'yellow'},
    {'date': '2027-04-08', 'level': 'info', 'title': 'Compute SP $12.05/h 到期', 'desc': '最大 SP 到期，需提前规划续购', 'daysLeft': '365天', 'daysLevel': 'blue'},
    {'date': '持续推进', 'level': 'info', 'title': 'Aurora MySQL 5.7 升级', 'desc': '12个实例仍在 5.7（已进入扩展支持收费）', 'daysLeft': '收费中', 'daysLevel': 'red'},
])
actions_html = '<div class="timeline">'
for a in actions:
    days_tag = f'<span class="tl-tag days-{a.get("daysLevel","blue")}">{a["daysLeft"]}</span>' if a.get('daysLeft') else ''
    actions_html += f'''<div class="tl-item {a['level']}">
      <div class="tl-date">{a['date']}{days_tag}</div>
      <div class="tl-title">{a['title']}</div>
      <div class="tl-desc">{a.get('desc','')}</div>
    </div>'''
actions_html += '</div>'
html = html.replace('{{ACTION_ITEMS}}', actions_html)

with open(out_path, 'w') as f:
    f.write(html)
print(f"Written to {out_path}")
