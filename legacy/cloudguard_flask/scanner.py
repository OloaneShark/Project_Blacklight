
import os
import json
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone


def list_s3_buckets():
    s3 = boto3.client("s3")
    response = s3.list_buckets()
    ec2 = boto3.client("ec2")
    rds = boto3.client("rds")
    
    report_lines = []
    bucket_reports = []
    
    os.makedirs("reports", exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    txt_report_path = f"reports/cloudguard_report_{timestamp}.txt"
    json_report_path = f"reports/cloudguard_report_{timestamp}.json"
    
    buckets = response.get("Buckets", [])

    if not buckets:
        print("No S3 buckets found.")
        return
        
    total_buckets = 0
    total_score = 0

    account_findings = []
    
    cloudtrail_passed = check_cloudtrail(account_findings)
    mfa_passed = check_root_mfa(account_findings)
    iam_keys_passed = check_iam_access_key_age(account_findings)
        
    check_security_groups(ec2, account_findings)
    check_rds_instances(rds, account_findings)
        
    for bucket in buckets:
        bucket_name = bucket["Name"]
        score = 100
        findings = []
        
        print(f"Bucket: {bucket_name}")
        report_lines.append(f"Bucket: {bucket_name}")

        public_access_passed = check_public_access_block(s3, bucket_name, findings)
        encryption_passed = check_bucket_encryption(s3, bucket_name, findings)
        versioning_passed = check_bucket_versioning(s3, bucket_name, findings)
        logging_passed = check_bucket_logging(s3, bucket_name, findings)
        policy_passed = check_bucket_policy(s3, bucket_name, findings)
        
        if not public_access_passed:
            score -= 50

        if not encryption_passed:
            score -= 25

        if not versioning_passed:
            score -= 10
            
        if not logging_passed:
            score -= 10
            
        if not policy_passed:
            score -= 50
        
        print()
        print("Findings Summary:")

        warning_count = 0

        for finding in findings:
            if isinstance(finding, dict):
                if finding["severity"] == "WARNING":
                    warning_count += 1
                    
                print(f"- {finding['severity']}: {finding['message']}")
                print(f"  Recommendation: {finding['recommendation']}")
                
                report_lines.append(f"- {finding['severity']}: {finding['message']}")
                report_lines.append(f"  Recommendation: {finding['recommendation']}")
                
            else:
                if "WARNING" in finding:
                    warning_count += 1
                    
                print(f"- {finding}")
                report_lines.append(f"- {finding}")
            
        print(f"Warnings: {warning_count}")
        report_lines.append(f"Warnings: {warning_count}")
            
        total_buckets += 1
        total_score += score
        
        print(f"Security Score: {score}/100")
        print()
        
        report_lines.append(f"Security Score: {score}/100")
        report_lines.append("")
        
        bucket_report = {
            "bucket_name": bucket_name,
            "findings": findings,
            "security_score": score
        }
        bucket_reports.append(bucket_report)
        
    average_score = total_score / total_buckets
    
    full_json_report= {
        "scan_time": timestamp,
        "total_buckets": total_buckets,
        "average_score": round(average_score),
        "account_findings": account_findings,
        "buckets": bucket_reports
    }
    
    print("Scan Summary:")
    print(f"Buckets Scanned: {total_buckets}")
    print(f"Average Score: {average_score:.0f}/100")
    
    report_lines.append("Scan Summary:")
    report_lines.append(f"Buckets Scanned: {total_buckets}")
    report_lines.append(f"Average Score: {average_score:.0f}/100")
    
    with open(txt_report_path, "w") as report_file:
        report_file.write("\n".join(report_lines))
    
    with open(json_report_path, "w") as json_file:
        json.dump(full_json_report, json_file, indent=4)
        
    print(f"Text report saved to: {txt_report_path}")
    print(f"JSON report saved to: {json_report_path}")
    return full_json_report


def add_finding(findings, severity, message, recommendation):
    finding = {
        "severity": severity,
        "message": message,
        "recommendation": recommendation
    }

    findings.append(finding)
    print(f"{severity}: {message}")


def check_public_access_block(s3, bucket_name, findings):
    
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]

        all_blocked = (
            config.get("BlockPublicAcls")
            and config.get("IgnorePublicAcls")
            and config.get("BlockPublicPolicy")
            and config.get("RestrictPublicBuckets")
        )

        if all_blocked:
            finding = f"PASS: Public Access Block is fully enabled for bucket {bucket_name}"
            findings.append(finding)
            print(finding)
            return True
        else:
            finding = f"WARNING: Public Access Block is partially enabled for bucket {bucket_name}"
            findings.append(finding)
            print(finding)
            return False

    except ClientError as error:
        error_code = error.response["Error"]["Code"]

        if error_code == "NoSuchPublicAccessBlockConfiguration":
            findings.append("CRITICAL: Public Access Block is disabled")
            print("CRITICAL: Public Access Block is disabled")
            return False
        else:
            findings.append(f"ERROR: Public Access check failed - {error_code}")
            print(f"ERROR: Public Access check failed - {error_code}")
            return False


def check_bucket_encryption(s3, bucket_name, findings):
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)

        rules = response["ServerSideEncryptionConfiguration"]["Rules"]
        encryption_type = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]

        if encryption_type == "AES256":
            finding = f"PASS: Bucket {bucket_name} uses SSE-S3 encryption (AES256)"
            findings.append(finding)
            print(finding)
            return True
        
        elif encryption_type == "aws:kms":
            finding = f"PASS: Bucket {bucket_name} uses SSE-KMS encryption"
            findings.append(finding)
            print(finding)
            return True
        
        else:
            finding = f"PASS: Bucket {bucket_name} uses encryption type {encryption_type}"
            findings.append(finding)
            print(finding)
            return True
    
    except ClientError as error:
        error_code = error.response["Error"]["Code"]

        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            finding = f"WARNING: Encryption is disabled for bucket {bucket_name}"
            findings.append(finding)
            print(finding)
            return False
        else:
            finding = (f"ERROR: Encryption check failed for bucket {bucket_name} - {error_code}")
            findings.append(finding)
            print(finding)
        
        
def check_bucket_versioning(s3, bucket_name, findings):
    response = s3.get_bucket_versioning(Bucket=bucket_name)

    versioning_status = response.get("Status")

    if versioning_status == "Enabled":
        add_finding(
            findings,
            "PASS",
            f"Versioning is enabled for bucket {bucket_name}",
            "No remediation needed"
        )
        return True
    else:
        add_finding(
            findings,
            "WARNING",
            f"Versioning is disabled for bucket {bucket_name}",
            "Enable S3 Versioning to help protect objects from accidental deletion or overwrite"
        )
        return False
    
    
def check_bucket_logging(s3, bucket_name, findings):
    response = s3.get_bucket_logging(Bucket=bucket_name)

    logging_config = response.get("LoggingEnabled")

    if logging_config:
        add_finding(
            findings,
            "PASS",
            f"Bucket logging is enabled for bucket {bucket_name}",
            "No remediation needed."
        )
        return True
    
    else:
        add_finding(
            findings,
            "WARNING",
            f"Bucket logging is disabled for bucket {bucket_name}",
            "Enable S3 server access logging or use CloudTrail data events to track object-level access activity"
        )
        return False
    
    
def check_bucket_policy(s3, bucket_name, findings):
    try:
        response = s3.get_bucket_policy(Bucket=bucket_name)
        policy = response.get("Policy")
        
        if policy:
            policy_data = json.loads(policy)
            statements = policy_data["Statement"]

            public_policy_found = False
            
            for statement in statements:
                principal = statement.get("Principal")
                
                if principal == "*":
                    public_policy_found = True
                elif isinstance(principal, dict) and principal.get("AWS") == "*":
                    public_policy_found = True
            
            if public_policy_found:
                finding = f"CRITICAL: Bucket policy allows public access for bucket {bucket_name}"
                findings.append(finding)
                print(finding)
                return False
            else:
                finding = f"PASS: Bucket policy does not allow public access for bucket {bucket_name}"
                findings.append(finding)
                print(finding)
                return True
            
        else:
            findings.append("PASS: No bucket policy found")
            print("PASS: No bucket policy found")
            return True

    except ClientError as error:
        error_code = error.response["Error"]["Code"]

        if error_code == "NoSuchBucketPolicy":
            findings.append("PASS: No bucket policy found")
            print("PASS: No bucket policy found")
            return True
        else:
            findings.append(f"ERROR: Bucket policy check failed - {error_code}")
            print(f"ERROR: Bucket policy check failed - {error_code}")
            return False
        
        
def check_cloudtrail(findings):
    cloudtrail = boto3.client("cloudtrail")
    
    try:
        response = cloudtrail.describe_trails()
        trails = response.get("trailList", [])
        
        if not trails:
            finding = "WARNING: No CloudTrail trails found"
            findings.append(finding)
            print(finding)
            return False
        
        logging_trail_found = False
        
        for trail in trails:
            trail_name = trail["Name"]
            is_multi_region = trail.get("IsMultiRegionTrail", False)
            
            status = cloudtrail.get_trail_status(Name=trail_name)
            
            if status.get("IsLogging") and is_multi_region:
                logging_trail_found = True
                
        if logging_trail_found:
            finding = "PASS: CloudTrail is enabled, logging, and multi-region"
            findings.append(finding)
            print(finding)
            return True
        else:
            finding = "WARNING: CloudTrail exists but is not logging as a multi-region trail"
            findings.append(finding)
            print(finding)
            return False
        
    except Exception as e:
        finding = f"WARNING: Could not check CloudTrail - {str(e)}"
        findings.append(finding)
        print(finding)
        return False


def check_root_mfa(findings):
    iam = boto3.client("iam")
    
    try:
        summary = iam.get_account_summary()
        
        mfa_enabled = summary["SummaryMap"].get("AccountMFAEnabled")
        
        if mfa_enabled:
            finding = "PASS: Root account MFA is enabled"
            findings.append(finding)
            print(finding)
            return True
        else:
            finding = "WARNING: Root account MFA is not enabled"
            findings.append(finding)
            print(finding)
            return False
        
    except Exception as e:
        finding = f"WARNING: Could not check root MFA - {str(e)}"
        findings.append(finding)
        print(finding)
        return False


def check_iam_access_key_age(findings):
    iam = boto3.client("iam")
    
    try:
        users = iam.list_users().get("Users", [])
        user_count = len(users)
        key_count = 0
        
        if not users:
            finding = "INFO: Checked 0 IAM users and 0 access keys"
            findings.append(finding)
            print(finding)
        
            finding = "PASS: No IAM users found"
            findings.append(finding)
            print(finding)
            return True
        
        old_key_found = False
        
        for user in users:
            username = user["UserName"]
            access_keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            
            for key in access_keys:
                created_date = key["CreateDate"]
                age_days = (datetime.now(timezone.utc) - created_date).days
                key_count += 1
                
                if age_days > 90:
                    finding = f"WARNING: IAM access key for {username} is {age_days} days old"
                    findings.append(finding)
                    print(finding)
                    old_key_found = True
                    
                access_keys_id = key["AccessKeyId"]
                
                last_used_response = iam.get_access_key_last_used(
                    AccessKeyId = access_keys_id
                )
                
                last_used_info = last_used_response.get("AccessKeyLastUsed", {})
                last_used_date = last_used_info.get("LastUsedDate")
                
                if last_used_date is None:
                    finding = f"WARNING: IAM access key for {username} has never been used"
                    findings.append(finding)
                    print(finding)
                    return True
                
                else:
                    unused_days = (datetime.now(timezone.utc) - last_used_date).days
                    
                    if unused_days > 90:
                        finding = (
                            f"WARNING: IAM access key for {username} has not been used in {unused_days} days"
                        )
                        findings.append(finding)
                        print(finding)
                        old_key_found = True
        
        finding = f"INFO: Checked {user_count} IAM users and {key_count} access keys"
        findings.append(finding)
        print(finding)  
        if old_key_found:
            return False
        
        finding = "PASS: IAM access keys are under 90 days old"
        findings.append(finding)
        print(finding)
        return True
    
    except Exception as e:
        finding = f"WARNING: Could not check IAM access keys - {str(e)}"
        findings.append(finding)
        print(finding)
        return False


def check_security_groups(ec2, findings):
    response = ec2.describe_security_groups()
    
    for sg in response["SecurityGroups"]:
        group_name =  sg["GroupName"]
        group_id = sg["GroupId"]
        
        for permission in sg["IpPermissions"]:
            from_port = permission.get("FromPort")
            
            for ip_range in permission.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")
                
                if cidr == "0.0.0.0/0" and from_port == 22:
                    add_finding(
                        findings,
                        "CRITICAL",
                        f"Security Group {group_name} ({group_id}) allows SSH from anywhere (0.0.0.0/0)",
                        "Restrict SSH access to trusted IP addresses only."
                    )
                    
                elif cidr == "0.0.0.0/0" and from_port == 5000:
                    add_finding(
                        findings,
                        "WARNING",
                        f"Security Group {group_name} ({group_id}) allows public access to port 5000",
                        "For production, place the app behind HTTPS on ports 80/443 and restrict direct access to port 5000"
                    )


def check_rds_instances(rds, findings):
    try:
        response = rds.describe_db_instances()
        db_instances = response.get("DBInstances", [])
        
        if not db_instances:
            add_finding(findings,"INFO", "No RDS database instances found", "No remediation needed.")
            return True
        
        passed = True
        
        for db in db_instances:
            db_id = db["DBInstanceIdentifier"]
            publicly_accessible = db.get("PubliclyAccessible", False)
            storage_exncrypted = db.get("StorageEncrypted", False)
            
            if publicly_accessible:
                add_finding(
                    findings,
                    "CRITICAL",
                    f"RDS instance {db_id} is publicly accessible",
                    "Disable public accessibility and restrict access through private subnets and security groups."
                )
                passed = False
                
            else:
                add_finding(
                    findings,
                    "PASS",
                    f"RDS instance {db_id} storage is encrypted",
                    "No remediation needed"
                )
                
        return passed
    
    except Exception as e:
        add_finding(
            findings,
            "WARNING",
            f"Could not check RDS instances - {str(e)}",
            "Verify that the AWS credentials have permisison to call rds:DescribeDBInstances."
        )
        return False


if __name__ == "__main__":
    print("CloudGuard Security Scan")
    print("Chekcing S3 buckets...")
    print()
    
    list_s3_buckets()