---
name: aws-patrol
description: Automated AWS infrastructure patrol — collects EC2/RDS/ELB metrics, security posture (IAM MFA, SG, EBS encryption, S3), cost analysis (SP/RI coverage & utilization), Health events, and SMS registration status. Generates a visual HTML report card with Puppeteer screenshot for messaging delivery. Use when you need daily/periodic AWS monitoring, cost optimization checks, security audits, or automated reporting on AWS infrastructure health.
---

# AWS Patrol

Automated AWS infrastructure monitoring, security audit, and cost analysis with visual report generation.

## Prerequisites

- Python 3.8+ with `boto3`
- AWS credentials configured (profile or env vars)
- Node.js + Puppeteer (for screenshot generation)
- Required AWS permissions: ReadOnlyAccess (EC2, RDS, ELB, CloudWatch, IAM, S3, Cost Explorer, Savings Plans, Health, Pinpoint SMS)

## Configuration (Environment Variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_PATROL_PROFILE` | `AWS_PROFILE` or `default` | AWS profile name |
| `AWS_PATROL_REGIONS` | `us-west-2,eu-west-2,ap-southeast-1` | Comma-separated regions |
| `AWS_PATROL_OUTPUT` | Current directory | Output directory for JSON/HTML/PNG |

## Workflow

### 1. Collect Resource Metrics

```bash
python3 scripts/patrol.py
```

Outputs `aws-patrol-detail.json` with:
- EC2: CPU, network, status checks (alerts if CPU>80% or status check failed)
- RDS: CPU, memory, connections, storage, IOPS (alerts if CPU>80%, low memory, low storage)
- ELB: target group health, unhealthy targets
- CloudWatch alarms in ALARM state
- AWS Health events (last 7 days)
- SMS/Pinpoint sender registration status

### 2. Collect Security & Cost Data

```bash
python3 scripts/patrol-security-cost.py
```

Outputs `aws-security-cost.json` with:
- **Security**: IAM users without MFA, old access keys (>90d), open security groups (0.0.0.0/0 on sensitive ports), unencrypted EBS, public S3 buckets
- **Cost**: 30-day total & daily trend, SP utilization & coverage (7-day daily), RDS/ElastiCache RI coverage, active SPs & RIs, waste detection (stopped instances, unattached volumes, unused EIPs, old snapshots, low-CPU instances)

### 3. Generate Visual Report

```bash
python3 scripts/gen-report.py '<JSON>'
```

Accepts a JSON argument with fields:
- `date`, `weekday`, `ec2Count`, `rdsCount`, `elbCount`
- `costTotal`, `costDaily`, `unattachedVol`, `unusedEip`, `lowCpu`, `oldSnap`
- `spUtilPct`, `spCovPct`, `rdsRiPct`, `ecRiPct`
- `noMfa`, `unencEbs`, `openSg`, `oldKeys`, `s3Risk`
- `highCpu` (array: `{name, cpu, type, level}`)
- `spRiDetails` (string summary)
- `health` (array: `{type, title, desc}`)
- `sms` (array: `{name, status, level}`)
- `actions` (array: `{date, level, title, desc, daysLeft, daysLevel}`)

Outputs `daily-report.html`.

### 4. Screenshot & Deliver

```bash
# Start HTTP server
python3 -m http.server 18923 &
# Screenshot
node -e "const p=require('puppeteer');(async()=>{const b=await p.launch({headless:'new',args:['--no-sandbox']});const pg=await b.newPage();await pg.setViewport({width:520,height:800,deviceScaleFactor:2});await pg.goto('http://localhost:18923/daily-report.html',{waitUntil:'networkidle0'});await pg.screenshot({path:'daily-report.png',fullPage:true});await b.close()})()"
# Stop server
kill %1
```

Send `daily-report.png` via messaging with a brief summary.

## Scheduling (Cron Example)

Set up a daily 9:00 AM patrol via OpenClaw cron (systemEvent → main session):

```
每天 9:00 运行 aws-patrol 巡检流程，采集数据 → 生成报告 → 截图推送
```

## Anomaly Investigation

When high CPU, Health alerts, or SMS issues are detected, don't just report numbers — investigate root cause (check CloudWatch trends, recent deployments, process-level metrics) and include analysis in the report.
