"""
AEGIS-ATK-001: Credential Abuse

Simulates an attacker who has stolen the access keys of the IAM user
"test-analyst". It does recon with those keys, hits permission walls, then
reads sensitive data. Every API call is reported to the AegisCloud backend,
labelled with the MITRE ATT&CK technique it represents.

Lab use only: everything targets the local LocalStack environment.
"""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3
import requests
from botocore.exceptions import ClientError

ENDPOINT = "http://localhost:4566"           # LocalStack
BACKEND = "http://localhost:8000/api/events"  # AegisCloud FastAPI backend
REGION = "us-east-1"

BUCKET = "aegiscloud-sensitive-data"
OBJECT_KEY = "customer-data.csv"

ATTACK_ID = "AEGIS-ATK-001"
VICTIM_USER = "test-analyst"
# Reserved documentation range (RFC 5737). The real calls come from localhost,
# so we declare a simulated attacker IP to make the telemetry realistic.
SIMULATED_SOURCE_IP = "203.0.113.50"

# Error codes that mean "IAM said no", as opposed to a technical failure.
DENIED_CODES = {
    "AccessDenied", "AccessDeniedException",
    "UnauthorizedOperation", "UnauthorizedAccess",
}

# Shared MITRE catalog: attack-simulator/credential-abuse/scenario.py -> project root
ROOT = Path(__file__).resolve().parents[2]
TECHNIQUES = json.loads(
    (ROOT / "mitre" / "techniques.json").read_text(encoding="utf-8-sig")
)


def load_credentials():
    key = os.environ.get("AEGIS_ACCESS_KEY")
    secret = os.environ.get("AEGIS_SECRET_KEY")
    if not key or not secret:
        sys.exit("Set AEGIS_ACCESS_KEY and AEGIS_SECRET_KEY first (see the README steps).")
    return key, secret


def make_client(service, key, secret):
    return boto3.client(
        service,
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id=key,
        aws_secret_access_key=secret,
    )


def report(technique_id, action, resource, result, error_code):
    """Send one telemetry event to the backend (our stand-in for CloudTrail)."""
    tech = TECHNIQUES[technique_id]
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": "attacker-workstation",
        "event_type": "cloud_api_call",
        "user": VICTIM_USER,
        "source_ip": SIMULATED_SOURCE_IP,
        "severity": "low" if result == "allowed" else "medium",
        "description": f"{action} on {resource}: {result}",
        "api_action": action,
        "resource": resource,
        "result": result,
        "error_code": error_code,
        "attack_id": ATTACK_ID,
        "expected_technique": technique_id,
        "expected_technique_name": tech["name"],
        "expected_tactics": tech["tactics"],
    }
    try:
        requests.post(BACKEND, json=[event], timeout=5).raise_for_status()
    except requests.RequestException as exc:
        print(f"    (warning: could not report to backend: {exc})")


def attempt(step, technique_id, action, resource, call):
    """Run one API call, classify the outcome, report it, then pause briefly."""
    tech = TECHNIQUES[technique_id]
    print(f"\n[{step}] {tech['name']} ({technique_id})")
    print(f"    {action} on {resource}")
    error_code = None
    try:
        call()
        result = "allowed"
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        result = "denied" if error_code in DENIED_CODES else "error"
    print(f"    -> {result.upper()}" + (f" ({error_code})" if error_code else ""))
    report(technique_id, action, resource, result, error_code)
    time.sleep(1)
    return result


def main():
    key, secret = load_credentials()
    sts = make_client("sts", key, secret)
    iam = make_client("iam", key, secret)
    ec2 = make_client("ec2", key, secret)
    s3 = make_client("s3", key, secret)

    print(f"=== {ATTACK_ID}: Credential Abuse as '{VICTIM_USER}' ===")

    results = [
        attempt(1, "T1078.004", "sts:GetCallerIdentity", "*",
                lambda: sts.get_caller_identity()),
        attempt(2, "T1087.004", "iam:ListUsers", "*",
                lambda: iam.list_users()),
        attempt(3, "T1580", "ec2:DescribeVpcs", "*",
                lambda: ec2.describe_vpcs()),
        attempt(4, "T1619", "s3:ListAllMyBuckets", "*",
                lambda: s3.list_buckets()),
        attempt(5, "T1619", "s3:ListBucket", BUCKET,
                lambda: s3.list_objects_v2(Bucket=BUCKET)),
        attempt(6, "T1530", "s3:GetObject", f"{BUCKET}/{OBJECT_KEY}",
                lambda: s3.get_object(Bucket=BUCKET, Key=OBJECT_KEY)["Body"].read()),
    ]

    print(
        f"\n=== Done: {results.count('allowed')} allowed, "
        f"{results.count('denied')} denied, {results.count('error')} errors ==="
    )


if __name__ == "__main__":
    main()