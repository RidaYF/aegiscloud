"""
AegisCloud incident engine (Phase 3.1)

Reads the alerts produced by Kibana's detection rules, correlates alerts that
come from the same source IP within a time window into ONE incident, enriches
it with MITRE ATT&CK details and the raw events as evidence, and stores it in
the "aegiscloud-incidents" index. The AI analyst (Phase 3.2) reads these incidents.

Usage:
    python engine.py --once          # process alerts one time and exit
    python engine.py                 # keep running, refresh every 15 seconds
"""
import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from elasticsearch import Elasticsearch, NotFoundError

ES_URL = "http://localhost:9200"
ALERTS_INDEX = ".alerts-security.alerts-default"   # where Kibana stores alerts
EVENTS_INDEX = "aegiscloud-events"                 # raw telemetry (evidence)
INCIDENTS_INDEX = "aegiscloud-incidents"           # our output

LOOKBACK = timedelta(hours=24)                # how far back we read alerts
CORRELATION_WINDOW = timedelta(minutes=30)    # max gap inside one incident
EVIDENCE_BEFORE = timedelta(minutes=10)       # evidence window around alerts
EVIDENCE_AFTER = timedelta(minutes=1)

ROOT = Path(__file__).resolve().parents[1]    # project root
TECHNIQUES = json.loads(
    (ROOT / "mitre" / "techniques.json").read_text(encoding="utf-8-sig")
)

# Order of tactics along an attack ("kill chain")
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Impact",
]
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def parse_ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def get(doc, path, default=None):
    """Read a field whether the document stores it as a flat dotted key
    ("kibana.alert.severity") or as nested objects."""
    if not isinstance(doc, dict):
        return default
    if path in doc:
        return doc[path]
    parts = path.split(".")
    for i in range(1, len(parts)):
        head = ".".join(parts[:i])
        if head in doc:
            sub = get(doc[head], ".".join(parts[i:]))
            if sub is not None:
                return sub
    return default


def normalize_alert(src):
    """Reduce a raw Kibana alert document to the few fields we need."""
    ip = get(src, "source_ip") or get(src, "source_ip.keyword")
    if not ip:  # threshold alerts keep the grouped value here
        for term in get(src, "kibana.alert.threshold_result.terms", []) or []:
            if str(term.get("field", "")).startswith("source_ip"):
                ip = term.get("value")

    tactics, techniques = [], []
    for threat in get(src, "kibana.alert.rule.threat", []) or []:
        name = get(threat, "tactic.name")
        if name and name not in tactics:
            tactics.append(name)
        for tech in threat.get("technique", []) or []:
            subs = tech.get("subtechnique") or []
            ids = [s["id"] for s in subs] if subs else [tech["id"]]
            for tid in ids:
                if tid not in techniques:
                    techniques.append(tid)

    return {
        "uuid": get(src, "kibana.alert.uuid"),
        "ts": parse_ts(src["@timestamp"]),
        "rule_name": get(src, "kibana.alert.rule.name", ""),
        "severity": get(src, "kibana.alert.severity", "low"),
        "risk_score": get(src, "kibana.alert.risk_score", 0),
        "source_ip": ip or "unknown",
        "tactics": tactics,
        "techniques": techniques,
        "api_action": get(src, "api_action"),
        "resource": get(src, "resource"),
        "event_count": get(src, "kibana.alert.threshold_result.count"),
    }


def fetch_alerts(es):
    since = (datetime.now(timezone.utc) - LOOKBACK).isoformat()
    try:
        res = es.search(
            index=ALERTS_INDEX, size=1000,
            query={"range": {"@timestamp": {"gte": since}}},
            sort=[{"@timestamp": "asc"}],
        )
    except NotFoundError:
        return []
    alerts = [normalize_alert(h["_source"]) for h in res["hits"]["hits"]]
    return [a for a in alerts if a["rule_name"].startswith("AegisCloud")]


def cluster_alerts(alerts):
    """Correlation: same source IP, gaps between alerts <= CORRELATION_WINDOW."""
    by_ip = {}
    for a in alerts:
        by_ip.setdefault(a["source_ip"], []).append(a)
    clusters = []
    for ip, items in by_ip.items():
        items.sort(key=lambda a: a["ts"])
        current = [items[0]]
        for a in items[1:]:
            if a["ts"] - current[-1]["ts"] <= CORRELATION_WINDOW:
                current.append(a)
            else:
                clusters.append((ip, current))
                current = [a]
        clusters.append((ip, current))
    return clusters


def fetch_evidence(es, ip, start, end):
    try:
        res = es.search(
            index=EVENTS_INDEX, size=200,
            query={"bool": {"filter": [
                {"range": {"timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}},
                {"exists": {"field": "api_action"}},
                {"match": {"source_ip": ip}},
            ]}},
            sort=[{"timestamp": "asc"}],
        )
    except NotFoundError:
        return []
    keep = ("timestamp", "user", "api_action", "resource", "result",
            "attack_id", "expected_technique")
    return [{k: h["_source"].get(k) for k in keep} for h in res["hits"]["hits"]]


def build_incident(es, ip, alerts):
    first, last = alerts[0]["ts"], alerts[-1]["ts"]
    incident_id = "INC-" + hashlib.sha1(
        f"{ip}|{first.isoformat()}".encode()).hexdigest()[:8].upper()

    tactics = sorted(
        {t for a in alerts for t in a["tactics"]},
        key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99,
    )
    detected = []
    for a in alerts:
        for tid in a["techniques"]:
            if tid not in detected:
                detected.append(tid)
    techniques = [{
        "id": tid,
        "name": TECHNIQUES.get(tid, {}).get("name", "(not in catalog)"),
        "tactics": TECHNIQUES.get(tid, {}).get("tactics", []),
        "summary": TECHNIQUES.get(tid, {}).get("summary", ""),
        "url": TECHNIQUES.get(tid, {}).get("url", ""),
    } for tid in detected]

    severity = max((a["severity"] for a in alerts), key=lambda s: SEVERITY_RANK.get(s, 0))
    risk = max(int(a["risk_score"] or 0) for a in alerts)
    if "Discovery" in tactics and "Collection" in tactics:
        severity, risk = "critical", max(risk, 90)
        title = f"Cloud reconnaissance followed by data collection from {ip}"
    elif "Persistence" in tactics or "Privilege Escalation" in tactics:
        severity, risk = "critical", max(risk, 90)
        title = f"Privilege escalation and persistence through a new cloud account from {ip}"
    else:
        title = f"{alerts[0]['rule_name'].replace('AegisCloud - ', '')} from {ip}"

    evidence = fetch_evidence(es, ip, first - EVIDENCE_BEFORE, last + EVIDENCE_AFTER)
    expected = sorted({e["expected_technique"] for e in evidence if e.get("expected_technique")})
    coverage = {
        "expected": expected,
        "detected": [t for t in expected if t in detected],
        "missed": [t for t in expected if t not in detected],
    }

    return incident_id, {
        "incident_id": incident_id,
        "title": title,
        "severity": severity,
        "risk_score": risk,
        "source_ip": ip,
        "users": sorted({e["user"] for e in evidence if e.get("user")}),
        "first_alert": first.isoformat(),
        "last_alert": last.isoformat(),
        "tactics": tactics,
        "techniques": techniques,
        "alerts": [{"rule": a["rule_name"], "time": a["ts"].isoformat(),
                    "severity": a["severity"], "alert_uuid": a["uuid"]} for a in alerts],
        "evidence": evidence,
        "detection_coverage": coverage,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def save_incident(es, incident_id, fields):
    """Create the incident, or refresh it without resetting its status."""
    now = datetime.now(timezone.utc).isoformat()
    es.update(index=INCIDENTS_INDEX, id=incident_id, doc=fields, retry_on_conflict=5,
            upsert={**fields, "status": "open", "created_at": now})


def run_once(es):
    clusters = cluster_alerts(fetch_alerts(es))
    for ip, alerts in clusters:
        incident_id, fields = build_incident(es, ip, alerts)
        save_incident(es, incident_id, fields)
        cov = fields["detection_coverage"]
        print(f"{incident_id} [{fields['severity'].upper()}] {fields['title']}")
        print(f"    alerts: {len(alerts)} | tactics: {' -> '.join(fields['tactics'])}")
        print(f"    techniques: {', '.join(t['id'] for t in fields['techniques'])}")
        print(f"    evidence events: {len(fields['evidence'])} | "
              f"missed by detection: {', '.join(cov['missed']) or 'none'}")
    if not clusters:
        print("No AegisCloud alerts found yet.")
    return len(clusters)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=15)
    args = parser.parse_args()

    password = os.environ.get("ELASTIC_PASSWORD")
    if not password:
        sys.exit("Set $env:ELASTIC_PASSWORD first.")
    es = Elasticsearch(ES_URL, basic_auth=("elastic", password))

    while True:
        run_once(es)
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()