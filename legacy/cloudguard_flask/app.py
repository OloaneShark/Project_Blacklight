"""
AWS Bucket implemented on June 17, 2026 at 9:47 am est
Added CloudTrail security validation and remediation checks on  June 20, 2026 at 2:52 pm est
Deployed CloudGuard to AWS EC2 with Docker and PostgreSQL on June 21, 2026 at 5:19 pm est
"""

from io import BytesIO, StringIO
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from dotenv import load_dotenv
from models import db, Scan, BucketResult, Finding, AccountFinding
from flask import Flask, render_template, redirect, url_for, send_file
from scanner import list_s3_buckets
from email.message import EmailMessage
from apscheduler.schedulers.background import BackgroundScheduler
from scanner import list_s3_buckets
import csv
import json
import os
import glob
import smtplib

load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


def calculate_risk_level(score):
    if score >= 90:
        return "LOW"
    elif score >= 70:
        return "MEDIUM"
    elif score >= 50:
        return "HIGH"
    else:
        return "CRITICAL"


def save_report_to_database(report_data):
    existing_scan = Scan.query.filter_by(
        scan_time=report_data["scan_time"]
    ).first()
    
    if existing_scan:
        print("Scan already saved to database")
        return
    
    new_scan = Scan(
        scan_time=report_data["scan_time"],
        total_buckets=report_data["total_buckets"],
        average_score=report_data["average_score"]
    )
    
    db.session.add(new_scan)
    db.session.commit()
    
    for finding in report_data.get("account_findings", []):
        if isinstance(finding, dict):
            severity = finding.get("severity", "INFO")
            message = finding.get("message", "")
            recommendation = finding.get("recommendation", "")
        else:
            message = finding

            if finding.startswith("PASS"):
                severity = "PASS"
            elif finding.startswith("WARNING"):
                severity = "WARNING"
            elif finding.startswith("CRITICAL"):
                severity = "CRITICAL"
            else:
                severity = "INFO"

            recommendation = "No remediation provided."

        new_account_finding = AccountFinding(
            scan_id=new_scan.id,
            severity=severity,
            message=message,
            recommendation=recommendation
        )

        db.session.add(new_account_finding)
    
    for bucket in report_data["buckets"]:
        
        new_bucket = BucketResult(
            scan_id=new_scan.id,
            bucket_name=bucket["bucket_name"],
            security_score=bucket["security_score"]
        )
        
        db.session.add(new_bucket)
        db.session.flush()
        
        for finding in bucket["findings"]:
            if isinstance(finding, dict):
                severity = finding.get("severity", "INFO")
                message = finding.get("message", "")
                recommendation = finding.get("recommendation", "No recommendation provided.")
            else:
                message = finding
                
                if finding.startswith("PASS"):
                    severity = "PASS"
                elif finding.startswith("WARNING"):
                    severity = "WARNING"
                elif finding.startswith("CRITICAL"):
                    severity = "CRITICAL"
                else:
                    severity = "INFO"

                recommendation = "No remediation provided."
                
            new_finding = Finding(
                bucket_result_id=new_bucket.id,
                severity=severity,
                message=message,
                recommendation=recommendation
            )
            
            db.session.add(new_finding)
            
    db.session.commit()
    
    print("Scan saved to database")
    
    critical_findings = get_critical_findings(new_scan)
    
    if critical_findings:
        print("CRITICAL SECURITY ALERT")
        print(f"{len(critical_findings)} critical findings detected")
        
        for finding in critical_findings:
            print(f"- [{finding['source']}] {finding['message']}")
            
        send_critical_alert_email(critical_findings)


def get_report_files():
    report_files = glob.glob("reports/*.json")
    return sorted(report_files, key=os.path.getctime, reverse=True)
    

def get_last_report():
    report_files = get_report_files()
    
    if not report_files:
        return{}
    
    latest_report = report_files[0]
    
    with open(latest_report, "r") as file:
        return json.load(file)
    

def get_scan_history():
    scans = Scan.query.order_by(Scan.id.desc()).all()
    
    history = []
    
    for scan in scans:   
        history.append({
            "id": scan.id,
            "scan_time": scan.scan_time,
            "average_score": scan.average_score,
            "total_buckets": scan.total_buckets
        })
    
    return history


def get_critical_findings(scan):
    critical_findings = []
    
    for finding in scan.account_findings:
        if finding.severity == "CRITICAL":
            critical_findings.append({
                "source": "Account",
                "message": finding.message,
                "recommendation": finding.recommendation
            })
            
    for bucket in scan.bucket_results:
        for finding in bucket.findings:
            if finding.severity == "CRITICAL":
                critical_findings.append({
                    "source": bucket.bucket_name,
                    "message": finding.message,
                    "recommendation": finding.recommendation
                })
            
    return critical_findings


def send_critical_alert_email(critical_findings):
    sender = os.getenv("ALERT_EMAIL_FROM")
    password = os.getenv("ALERT_EMAIL_PASSWORD")
    recipient = os.getenv("ALERT_EMAIL_TO")
    
    if not sender or not password or not recipient:
        print("Email alert skipped: missing email environment variables")
        return
    
    message = EmailMessage()
    message["Subject"] = "CloudGuard Critical Security Alert"
    message["From"] = sender
    message["To"] = recipient
    
    body = "CloudGuard detected critical security findings:\n\n"
    
    for finding in critical_findings:
        body += f"- [{finding['source']}] {finding['message']}\n"
        if finding["recommendation"]:
            body += f"  Recommended Fix: {finding['recommendation']}\n"
        body += "\n"
        
    message.set_content(body)
    
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender, password)
            smtp.send_message(message)
            
        print("Critical alert email sent")
        
    except Exception as e:
        print(f"Email alert failed: {e}")
    
    
@app.route("/")
def dashboard():
    latest_scan = Scan.query.order_by(Scan.id.desc()).first()
    
    if not latest_scan:
        return render_template(
            "dashboard.html",
            report_data = {
                "scan_time": "No scans yet",
                "total_buckets": 0,
                "average_score": 0,
                "buckets": [],
                "account_findings": []
            },
            scan_history=[],
            severity_counts= {
                "PASS": 0,
                "WARNING": 0,
                "CRITICAL": 0,
                "INFO": 0
            },
            score_trend=[],
            severity_trend=[]
        )
        
    report_data = {
        "scan_time": latest_scan.scan_time,
        "total_buckets": latest_scan.total_buckets,
        "average_score": latest_scan.average_score,
        "buckets": [],
        "account_findings": []
    }
    
    severity_counts = {
        "PASS": 0,
        "WARNING": 0,
        "CRITICAL": 0,
        "INFO": 0
    }
    
    for bucket in latest_scan.bucket_results:
        bucket_data = {
            "bucket_name": bucket.bucket_name,
            "security_score": bucket.security_score,
            "risk_level": calculate_risk_level(bucket.security_score),
            "findings": [
                {
                    "severity": finding.severity,
                    "message": finding.message,
                    "recommendation": finding.recommendation
                }
                for finding in bucket.findings
            ]
        }
        
        report_data["buckets"].append(bucket_data)
        
    for finding in latest_scan.account_findings:
        report_data["account_findings"].append({
            "severity": finding.severity,
            "message": finding.message,
            "recommendation": finding.recommendation
        })
        
    for bucket in report_data["buckets"]:
        for finding in bucket["findings"]:
            severity =  finding["severity"]
            
            if severity == ("PASS"):
                severity_counts["PASS"] += 1
            elif severity == ("WARNING"):
                severity_counts["WARNING"] += 1
            elif severity == ("CRITICAL"):
                severity_counts["CRITICAL"] += 1
            elif severity == ("INFO"):
                severity_counts["INFO"] += 1
        
    scan_history = get_scan_history()
    
    trend_data = Scan.query.order_by(Scan.id.asc()).all()
    
    score_trend = [
        {
            "scan_time": scan.scan_time,
            "average_score": scan.average_score
        }
        for scan in trend_data
    ]
    
    severity_trend = []
    
    for scan in trend_data:
        counts = {
            "scan_time": scan.scan_time,
            "PASS": 0,
            "WARNING": 0,
            "CRITICAL": 0,
            "INFO": 0
        }
        
        for bucket in scan.bucket_results:
            for finding in bucket.findings:
                if finding.message.startswith("PASS"):
                    counts["PASS"] += 1
                elif finding.message.startswith("WARNING"):
                    counts["WARNING"] += 1
                elif finding.message.startswith("CRITICAL"):
                    counts["CRITICAL"] += 1
                elif finding.message.startswith("INFO"):
                    counts["INFO"] += 1
                    
        severity_trend.append(counts)
    
    return render_template(
        "dashboard.html",
        report_data=report_data,
        scan_history=scan_history,
        severity_counts=severity_counts,
        score_trend=score_trend,
        severity_trend=severity_trend
    )
    

@app.route("/scan")
def run_scan():
    list_s3_buckets()
    latest_report = get_last_report()
    save_report_to_database(latest_report)
    return redirect(url_for("dashboard"))


@app.route("/report/<int:scan_id>")
def view_report(scan_id):
    selected_scan = Scan.query.get_or_404(scan_id)
    
    report_data = {
        "scan_time": selected_scan.scan_time,
        "total_buckets": selected_scan.total_buckets,
        "average_score": selected_scan.average_score,
        "buckets": [],
        "account_findings": []
    }
    
    severity_counts = {
        "PASS": 0,
        "WARNING": 0,
        "CRITICAL": 0,
        "INFO": 0
    }
    
    for bucket in selected_scan.bucket_results:
        bucket_data = {
            "bucket_name": bucket.bucket_name,
            "security_score": bucket.security_score,
            "risk_level": calculate_risk_level(bucket.security_score),
            "findings": [
                {
                    "severity": finding.severity,
                    "message": finding.message,
                    "recommendation": finding.recommendation
                }
                for finding in bucket.findings
            ]
        }
        
        report_data["buckets"].append(bucket_data)
        
        for finding in selected_scan.account_findings:
            report_data["account_findings"].append({
                "severity": finding.severity,
                "message": finding.message,
                "recommendation": finding.recommendation
            })
        
    for bucket in report_data["buckets"]:
        for finding in bucket["findings"]:
            severity = finding["severity"]
            
            if severity == ("PASS"):
                severity_counts["PASS"] += 1
            elif severity == ("WARNING"):
                severity_counts["WARNING"] += 1
            elif severity == ("CRITICAL"):
                severity_counts["CRITICAL"] += 1
            elif severity == ("INFO"):
                severity_counts["INFO"] += 1
        
    scan_history = get_scan_history()
    
    trend_data = Scan.query.order_by(Scan.id.asc()).all()

    score_trend = [
        {
            "scan_time": scan.scan_time,
            "average_score": scan.average_score
        }
        for scan in trend_data
    ]
    
    severity_trend = []
    
    for scan in trend_data:
        counts = {
            "scan_time": scan.scan_time,
            "PASS": 0,
            "WARNING": 0,
            "CRITICAL": 0,
            "INFO": 0
        }
        
        for bucket in scan.bucket_results:
            for finding in bucket.findings:
                if finding.message.startswith("PASS"):
                    counts["PASS"] += 1
                elif finding.message.startswith("WARNING"):
                    counts["WARNING"] += 1
                elif finding.message.startswith("CRITICAL"):
                    counts["CRITICAL"] += 1
                elif finding.message.startswith("INFO"):
                    counts["INFO"] += 1
                    
        severity_trend.append(counts)
    
    return render_template(
        "dashboard.html",
        report_data=report_data,
        scan_history=scan_history,
        severity_counts=severity_counts,
        score_trend=score_trend,
        severity_trend=severity_trend
    )


@app.route("/download-report/<int:scan_id>")
def download_report(scan_id):
    selected_scan = Scan.query.get_or_404(scan_id)
    
    buffer = BytesIO()
    
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()
    elements = []
    
    elements.append(
        Paragraph(f"CloudGuard Security Report - {selected_scan.scan_time}", styles["Title"])
    )
    
    elements.append(
        Paragraph(f"Average Score: {selected_scan.average_score}/100", styles["Normal"])
    )
    
    elements.append(
        Paragraph(f"Total Buckets: {selected_scan.total_buckets}", styles["Normal"])
    )
    
    elements.append(Spacer(1, 20))
    
    for bucket in selected_scan.bucket_results:
        elements.append(
            Paragraph(f"Bucket: {bucket.bucket_name}", styles["Heading2"])
        )
        
        elements.append(
            Paragraph(f"Security Score: {bucket.security_score}/100", styles["Normal"])
        )
        
        for finding in bucket.findings:

            message = finding.message

            if message.startswith(f"{finding.severity}:"):
                display_text = message
            else:
                display_text = f"{finding.severity}: {message}"

            elements.append(
                Paragraph(display_text, styles["Normal"])
            )
            
            if finding.recommendation and finding.recommendation != "No remediation provided.":
                elements.append(
                    Paragraph(f"Recommended Fix: {finding.recommendation}", styles["Normal"])
                )
            
        elements.append(Spacer(1, 10))
        
    doc.build(elements)
    
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"cloudguard_report_{selected_scan.scan_time}.pdf",
        mimetype="application/pdf"
    )


@app.route("/download-csv/<int:scan_id>")
def download_csv(scan_id):
    selected_scan = Scan.query.get_or_404(scan_id)
    
    output = StringIO()
    writer = csv.writer(output)
    
    writer.writerow(["scan Time", "Scope", "Resource", "Severity", "Message", "Recommendation"])
    
    for finding in selected_scan.account_findings:
        writer.writerow([
            selected_scan.scan_time,
            "Account",
            "AWS Acocunt",
            finding.severity,
            finding.message,
            finding.recommendation or ""
        ])
        
    for bucket in selected_scan.bucket_results:
        for finding in bucket.findings:
            writer.writerow([
                selected_scan.scan_time,
                "S3 Bucket",
                bucket.bucket_name,
                finding.severity,
                finding.message,
                finding.recommendation  or ""
            ])
            
    output.seek(0)
    
    return send_file(
        BytesIO(output.getvalue().encode("utf-8")),
        as_attachment=True,
        download_name=f"cloudguard_findings_{selected_scan.scan_time}.csv",
        mimetype="text/csv"
    )


with app.app_context():
    db.create_all()


def scheduled_scan():
    print("Running scheduled CloudGuard scan...")

    with app.app_context():
        report = list_s3_buckets()

        if report:
            print("Scheduled scan returned report")
            print(f"Scheduled scan time: {report['scan_time']}")

            try:
                save_report_to_database(report)
                print("Scheduled scan saved to database")
            except Exception as e:
                print(f"Scheduled scan database save failed: {e}")
        else:
            print("Scheduled scan did not return a report")

    print("Scheduled scan complete")
    
    
scheduler = BackgroundScheduler()

scheduler.add_job(func=scheduled_scan, trigger="interval", hours=24)

scheduler.start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)