"""
AegisCloud AI - Phase 3.4: human-approved response engine.

The AI analyst only PROPOSES actions. This tool turns those proposals into an
approval queue, checks every one in code, and executes an action ONLY after a
human approves it. Every step is written to an audit log.

Action life cycle:
    proposed -> executed | failed          (after a human approves)
    proposed -> rejected                   (a human says no)
    (not approvable) rejected_by_validation   the code refused the proposal
    simulated / recorded                   actions the lab cannot really perform

Commands (from incident-engine, venv active, ELASTIC_PASSWORD set):
    python response.py queue                       # build the queue from AI analyses
    python response.py list                        # show the queue
    python response.py approve ACTION_ID --by NAME [--dry-run]
    python response.py reject  ACTION_ID --by NAME [--reason "..."]
    python response.py audit                       # show the audit log

NOTE: the free LocalStack edition does not enforce IAM, so verification here is
a read-back of the configuration (is the key Inactive? is the policy attached?),
not proof that an attacker was blocked. On real AWS the same calls block access.
"""
import argparse
import json
import os
from datetime import datetime, timezone

import boto3
from elasticsearch import ConflictError, Elasticsearch, NotFoundError

from analyst import ALLOWED_ACTIONS

INCIDENTS = "aegiscloud-incidents"
ACTIONS = "aegiscloud-actions"
AUDIT = "aegiscloud-audit"
LOCALSTACK = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")
QUARANTINE_POLICY = "AegisCloud-Quarantine"
BUCKET_SID = "AegisCloudDenyCompromisedIdentity"


# ---------- helpers ----------
def now():
    return datetime.now(timezone.utc).isoformat()


def es_client():
    return Elasticsearch("http://localhost:9200",
                         basic_auth=("elastic", os.environ["ELASTIC_PASSWORD"]))


def aws(service):
    # LocalStack accepts any credentials; these are the emulator's default admin.
    return boto3.client(service, endpoint_url=LOCALSTACK, region_name="us-east-1",
                        aws_access_key_id="test", aws_secret_access_key="test")


def audit(es, action_id, event, by, detail=None):
    es.index(index=AUDIT, document={
        "time": now(), "action_id": action_id, "event": event,
        "by": by, "detail": detail or {}})


def clean_resource(raw):
    if not raw or raw == "*":
        return None
    return str(raw).replace("arn:aws:s3:::", "")


def incident_buckets(inc):
    return {clean_resource(e.get("resource")).split("/")[0]
            for e in inc.get("evidence") or []
            if str(e.get("api_action", "")).startswith("s3:") and clean_resource(e.get("resource"))}


def incident_identities(inc):
    """Identities of the incident: who acted, plus IAM users the attacker touched."""
    ids = set(inc.get("users") or [])
    for e in inc.get("evidence") or []:
        if str(e.get("api_action", "")).startswith("iam:") and e.get("resource") not in (None, "*"):
            ids.add(e["resource"])
    return ids


# ---------- validation (code, not the LLM, decides what is allowed) ----------
def validate(inc, action, target):
    users = set(inc.get("users") or [])
    buckets = incident_buckets(inc)
    if action not in ALLOWED_ACTIONS:
        return False, f"'{action}' is not in the allow-list"
    if action == "disable_access_key":
        if target not in users:
            return False, f"target '{target}' is not an identity of this incident {sorted(users)}"
    elif action == "apply_deny_policy":
        if target not in users and target not in buckets:
            return False, (f"target '{target}' is neither an identity {sorted(users)} "
                           f"nor a bucket {sorted(buckets)} seen in this incident")
    elif action == "block_source_ip":
        if target != inc.get("source_ip"):
            return False, f"target '{target}' is not the incident source IP"
    return True, "ok"


# ---------- queue ----------
def cmd_queue(es):
    res = es.search(index=INCIDENTS, size=200, query={"exists": {"field": "ai_analysis"}})
    added = refreshed = 0
    for h in res["hits"]["hits"]:
        inc = h["_source"]
        analysis = (inc.get("ai_analysis") or {}).get("analysis") or {}
        for k, a in enumerate(analysis.get("recommended_actions") or [], start=1):
            if not isinstance(a, dict) or not a.get("action"):
                continue
            aid = f"{inc['incident_id']}:ACT{k}"
            ok, note = validate(inc, a["action"], a.get("target"))
            doc = {"action_id": aid, "incident_id": inc["incident_id"],
                   "action": a["action"], "target": a.get("target"),
                   "reason": a.get("reason"),
                   "status": "proposed" if ok else "rejected_by_validation",
                   "validation": note, "created_at": now()}
            try:
                es.create(index=ACTIONS, id=aid, document=doc)
                audit(es, aid, "queued", "system", {"status": doc["status"], "validation": note})
                added += 1
            except ConflictError:
                old = es.get(index=ACTIONS, id=aid)["_source"]
                if old["status"] in ("proposed", "rejected_by_validation"):
                    doc["created_at"] = old["created_at"]
                    es.index(index=ACTIONS, id=aid, document=doc)
                    refreshed += 1
    es.indices.refresh(index=ACTIONS)
    print(f"Queue updated: {added} new, {refreshed} refreshed.")
    cmd_list(es)


def cmd_list(es):
    try:
        res = es.search(index=ACTIONS, size=200, query={"match_all": {}},
                        sort=[{"created_at": {"order": "asc", "unmapped_type": "date"}}])
    except NotFoundError:
        print("Queue is empty. Run: python response.py queue")
        return
    for h in res["hits"]["hits"]:
        a = h["_source"]
        print(f"{a['action_id']:20s} {a['status']:24s} {a['action']:20s} -> {a.get('target')}")
        if a["status"] == "rejected_by_validation":
            print(f"{'':20s} refused by code: {a['validation']}")


def cmd_audit(es):
    try:
        res = es.search(index=AUDIT, size=200, query={"match_all": {}},
                        sort=[{"time": {"order": "asc", "unmapped_type": "date"}}])
    except NotFoundError:
        print("Audit log is empty.")
        return
    for h in res["hits"]["hits"]:
        a = h["_source"]
        print(f"{a['time']}  {a['action_id']:20s} {a['event']:10s} by {a['by']}  {json.dumps(a['detail'])[:160]}")


# ---------- executors ----------
def do_disable_access_key(identity):
    iam = aws("iam")
    keys = iam.list_access_keys(UserName=identity)["AccessKeyMetadata"]
    for k in keys:
        iam.update_access_key(UserName=identity, AccessKeyId=k["AccessKeyId"], Status="Inactive")
    after = iam.list_access_keys(UserName=identity)["AccessKeyMetadata"]
    return {"keys_disabled": [k["AccessKeyId"] for k in keys],
            "verified": bool(after) and all(k["Status"] == "Inactive" for k in after)}


def do_deny_identity(identity):
    iam = aws("iam")
    doc = {"Version": "2012-10-17",
           "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    iam.put_user_policy(UserName=identity, PolicyName=QUARANTINE_POLICY,
                        PolicyDocument=json.dumps(doc))
    got = iam.get_user_policy(UserName=identity, PolicyName=QUARANTINE_POLICY)
    return {"policy": QUARANTINE_POLICY, "verified": got["PolicyName"] == QUARANTINE_POLICY}


def do_deny_bucket(bucket, identities):
    iam, s3 = aws("iam"), aws("s3")
    principals = [iam.get_user(UserName=u)["User"]["Arn"] for u in identities]
    statement = {"Sid": BUCKET_SID, "Effect": "Deny", "Principal": {"AWS": principals},
                 "Action": "s3:*",
                 "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]}
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except Exception:
        policy = {"Version": "2012-10-17", "Statement": []}
    policy["Statement"] = [s for s in policy.get("Statement", []) if s.get("Sid") != BUCKET_SID]
    policy["Statement"].append(statement)
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    back = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    return {"bucket": bucket, "denied": principals,
            "verified": any(s.get("Sid") == BUCKET_SID for s in back["Statement"])}


def execute(inc, a):
    action, target = a["action"], a.get("target")
    users = inc.get("users") or []
    if action == "disable_access_key":
        return "executed", do_disable_access_key(target)
    if action == "apply_deny_policy":
        if target in users:
            return "executed", do_deny_identity(target)
        return "executed", do_deny_bucket(target, users)
    if action == "block_source_ip":
        return "simulated", {"note": "the lab has no network control plane; recorded only"}
    if action == "collect_more_evidence":
        return "recorded", {"note": "manual follow-up for the analyst"}
    if action == "notify_team":
        return "executed", {"note": "logged; no external notification channel configured"}
    raise ValueError(f"no executor for {action}")


# ---------- approve / reject ----------
def load_action(es, aid):
    try:
        return es.get(index=ACTIONS, id=aid)["_source"]
    except NotFoundError:
        raise SystemExit(f"Unknown action id: {aid}. Run: python response.py list")


def cmd_approve(es, aid, by, dry_run):
    a = load_action(es, aid)
    if a["status"] != "proposed":
        raise SystemExit(f"Action is '{a['status']}', only 'proposed' actions can be approved.")
    inc = es.get(index=INCIDENTS, id=a["incident_id"])["_source"]
    ok, note = validate(inc, a["action"], a.get("target"))   # re-check at approval time
    if not ok:
        raise SystemExit(f"Refused by validation: {note}")
    if dry_run:
        print(f"[dry run] would execute {a['action']} -> {a.get('target')}. Nothing changed.")
        return
    audit(es, aid, "approved", by)
    try:
        status, result = execute(inc, a)
    except Exception as exc:
        status, result = "failed", {"error": str(exc)}
    es.update(index=ACTIONS, id=aid, doc={
        "status": status, "decided_by": by, "decided_at": now(), "result": result,
        "enforcement_note": "LocalStack free does not enforce IAM: verified configuration only"})
    audit(es, aid, status, by, result)
    print(f"{aid}: {status}  {json.dumps(result)}")


def cmd_reject(es, aid, by, reason):
    a = load_action(es, aid)
    if a["status"] != "proposed":
        raise SystemExit(f"Action is '{a['status']}', only 'proposed' actions can be rejected.")
    es.update(index=ACTIONS, id=aid, doc={
        "status": "rejected", "decided_by": by, "decided_at": now(), "reject_reason": reason})
    audit(es, aid, "rejected", by, {"reason": reason})
    print(f"{aid}: rejected")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("queue")
    sub.add_parser("list")
    sub.add_parser("audit")
    p = sub.add_parser("approve")
    p.add_argument("action_id")
    p.add_argument("--by", required=True)
    p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("reject")
    p.add_argument("action_id")
    p.add_argument("--by", required=True)
    p.add_argument("--reason", default="")
    args = ap.parse_args()

    es = es_client()
    if args.cmd == "queue":
        cmd_queue(es)
    elif args.cmd == "list":
        cmd_list(es)
    elif args.cmd == "audit":
        cmd_audit(es)
    elif args.cmd == "approve":
        cmd_approve(es, args.action_id, args.by, args.dry_run)
    elif args.cmd == "reject":
        cmd_reject(es, args.action_id, args.by, args.reason)


if __name__ == "__main__":
    main()
