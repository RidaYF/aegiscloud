"""
AegisCloud AI - automatic pipeline.

Watches the incident index. For every incident that has no AI analysis yet it runs,
in order:   analyst.py --incident ID   ->   graph.py   ->   response.py queue
so the dashboard always shows analysed incidents, their graph and their approval queue.

It only calls the existing scripts (same code, same guardrails). Nothing is executed
against the cloud: actions stay "proposed" until a human approves them.

Usage (from incident-engine, any venv that has the project packages):
    python pipeline.py              # keep watching (Ctrl+C to stop)
    python pipeline.py --once       # one pass, then exit
Secrets are read from the project's .env file if not already in the environment.
"""
import argparse
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from elasticsearch import Elasticsearch, NotFoundError

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
INCIDENTS = "aegiscloud-incidents"
MAX_ATTEMPTS = 2          # per incident, per run of this script


def load_env():
    f = ROOT / ".env"
    if not f.exists():
        return
    for line in f.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env()
es = Elasticsearch("http://localhost:9200",
                   basic_auth=("elastic", os.environ["ELASTIC_PASSWORD"]))
failures = {}


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def run(args, timeout=1500):
    return subprocess.run([sys.executable, *args], cwd=HERE, capture_output=True,
                          text=True, timeout=timeout, env=os.environ)


def tail(text, n=3):
    lines = [x for x in (text or "").strip().splitlines() if x.strip()]
    return " | ".join(lines[-n:]) if lines else "(no output)"


def pending_incidents():
    """Incidents with no stored AI analysis, newest first."""
    try:
        res = es.search(
            index=INCIDENTS, size=200,
            query={"bool": {"must_not": [{"exists": {"field": "ai_analysis"}}]}},
            sort=[{"last_alert": {"order": "desc", "unmapped_type": "date"}}])
    except NotFoundError:
        return []
    return [h["_source"]["incident_id"] for h in res["hits"]["hits"]]


def publish():
    """Refresh the attack graph and the approval queue."""
    for args in (["graph.py"], ["response.py", "queue"]):
        try:
            r = run(args, timeout=300)
        except subprocess.TimeoutExpired:
            log(f"{args[0]} timed out")
            continue
        if r.returncode != 0:
            log(f"{args[0]} did not finish: {tail(r.stderr or r.stdout)}")
        else:
            log(f"{' '.join(args)}: done")


def cycle():
    todo = [i for i in pending_incidents() if failures.get(i, 0) < MAX_ATTEMPTS]
    for iid in todo:
        log(f"Analysing {iid} (about 1-2 minutes)...")
        try:
            r = run(["analyst.py", "--incident", iid])
        except subprocess.TimeoutExpired:
            failures[iid] = failures.get(iid, 0) + 1
            log(f"{iid}: analysis timed out")
            continue
        if r.returncode != 0:
            failures[iid] = failures.get(iid, 0) + 1
            log(f"{iid}: analysis failed: {tail(r.stderr)}")
            continue
        log(f"{iid}: analysis saved")
        publish()
    return len(todo)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=int, default=20, help="seconds between checks")
    args = ap.parse_args()

    log("Pipeline started. Waiting for Elasticsearch...")
    while True:
        try:
            es.info()
            break
        except Exception:
            time.sleep(3)

    publish()                      # make sure graph and queue exist for what is already analysed
    while True:
        try:
            n = cycle()
            if args.once:
                log(f"Pass finished ({n} incident(s) analysed).")
                return
        except Exception as exc:   # keep the watcher alive
            log(f"Cycle error: {exc}")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
