# CloudGuard

CloudGuard is a Python-based AWS security dashboard that scans your AWS environment for common cloud misconfigurations and surfaces the findings through a Flask web app. It runs real AWS checks via `boto3`, stores scan history in PostgreSQL, and is deployed as a Dockerized app on EC2 behind Gunicorn, with GitHub Actions handling automated deployment.

## Table of Contents

- [Screenshots](#screenshots)
- [Live Features](#live-features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Deployment](#deployment)
- [Environment Variables](#environment-variables)
- [Purpose](#purpose)
- [Future Enhancements](#future-enhancements)

## Screenshots

### Dashboard Overview
Main CloudGuard dashboard displaying scan metadata, severity summaries, risk metrics, and overall security posture across the AWS environment.

![Dashboard Overview](screenshots/Dashboard_Overview.png)

### Risk Overview
Security score visualization showing total findings, open risks, critical findings, and an overall security score.

![Risk Overview](screenshots/Risk_overview.png)

### Scan History & Export
Review previous scans and export findings as a PDF or CSV file.

![Scan History](screenshots/Scan_History_download.png)

### Security Checks
Detailed AWS account and S3 bucket security findings with severity classification and remediation recommendations.

![Security Checks](screenshots/Security_Checks.png)

### Security Trend Over Time
Historical trend visualization tracking PASS, WARNING, CRITICAL, and INFO findings across multiple scans to show how security posture changes over time.

![Security Trend Over Time](screenshots/Severity_Trend_Over_Time.png)

## Live Features

**S3 Security Checks**
- Public Access Block detection
- Server-side encryption validation
- S3 versioning checks
- Bucket logging checks
- Bucket policy exposure detection

**AWS Account Security Checks**
- CloudTrail enabled verification
- CloudTrail logging status validation
- Multi-region CloudTrail validation
- Root account MFA verification
- IAM access key age checks
- IAM access key usage checks
- EC2 security group auditing
- RDS security checks

**Dashboard Features**
- Severity-based findings (PASS, WARNING, CRITICAL, INFO)
- Security score calculation
- Scan history stored in PostgreSQL
- Color-coded findings
- Severity summary counters
- Security score trend visualization
- Historical severity trend visualization
- PDF report export
- CSV report export

**Automation Features**
- Scheduled automated scans using APScheduler
- Critical finding detection
- Email alert framework
- GitHub Actions CI/CD deployment pipeline

## Tech Stack

| Category | Tools |
|---|---|
| Language | Python |
| Web Framework | Flask |
| ORM | SQLAlchemy |
| Database | PostgreSQL (Neon) |
| Containerization | Docker |
| App Server | Gunicorn |
| Cloud | AWS EC2, S3, IAM, CloudTrail, RDS |
| AWS SDK | boto3 |
| Scheduling | APScheduler |
| CI/CD | GitHub Actions |

## Architecture

**Request path:**

```
User → AWS EC2 → Docker Container → Gunicorn → Flask Application → PostgreSQL (Neon)
```

**Scanning path:**

```
Flask Application → boto3 → AWS APIs → S3, IAM, CloudTrail, EC2, RDS
```

## Deployment

CloudGuard is deployed as a Docker container on AWS EC2 and served using Gunicorn.

Continuous deployment runs through GitHub Actions. Every push to `main` automatically:

1. Connects to the EC2 instance over SSH
2. Pulls the latest source code
3. Stops and removes the existing container
4. Rebuilds the Docker image
5. Starts the updated container

## Environment Variables

**Required**

```
DATABASE_URL=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
```

**Optional (email alerts)**

```
ALERT_EMAIL_FROM=
ALERT_EMAIL_PASSWORD=
ALERT_EMAIL_TO=
```

> Secrets are never committed to this repository.

## Purpose

I built CloudGuard as a hands-on cloud security project — both to build real experience and to have a substantial portfolio piece. It's meant to demonstrate:

- AWS security auditing
- Flask application development
- Dockerized deployments
- PostgreSQL database integration
- CI/CD automation
- Cloud security monitoring
- Automated reporting
- Production troubleshooting and debugging

## Future Enhancements

- User authentication and RBAC
- Additional AWS service checks
- Real-time notifications
- Multi-account AWS scanning
- Compliance reporting (CIS/NIST)
