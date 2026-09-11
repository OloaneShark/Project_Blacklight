
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_time = db.Column(db.String(100), nullable=False)
    total_buckets = db.Column(db.Integer, nullable=False)
    average_score = db.Column(db.Integer, nullable=False)
    
    bucket_results = db.relationship("BucketResult", backref="scan", lazy=True)
    account_findings = db.relationship("AccountFinding", backref="scan", lazy=True, cascade="all, delete-orphan")
    

class BucketResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False)
    bucket_name = db.Column(db.String(255), nullable=False)
    security_score = db.Column(db.Integer, nullable=False)
    
    findings = db.relationship("Finding", backref="bucket_result", lazy=True)
    

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bucket_result_id = db.Column(db.Integer, db.ForeignKey("bucket_result.id"))
    severity = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text)
    

class AccountFinding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"))
    severity = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text)