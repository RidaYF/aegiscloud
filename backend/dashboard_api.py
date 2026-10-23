"""
Kestrel dashboard API (port 8001).

Read-only views of incidents, AI analysis, the response queue, the audit log and
the Neo4j attack graph, plus two write endpoints that let a HUMAN approve or
reject a proposed response action (the actual work is done by response.py, which
re-validates everything).

Run from the backend folder, venv active:
    uvicorn dashboard_api:app --reload --port 8001
Secrets are read from the project's .env file if not already in the environment.
"""
import os
import sys
from pathlib import Path

from elasticsearch import Elasticsearch, NotFoundError
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from neo4j import GraphDatabase
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]          # project root


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
sys.path.insert(0, str(ROOT / "incident-engine"))   # to reuse response.py

INCIDENTS = "aegiscloud-incidents"
EVENTS = "aegiscloud-events"
ACTIONS = "aegiscloud-actions"
AUDIT = "aegiscloud-audit"

es = Elasticsearch("http://localhost:9200",
                   basic_auth=("elastic", os.environ["ELASTIC_PASSWORD"]))
neo = GraphDatabase.driver("bolt://localhost:7687",
                           auth=("neo4j", os.environ.get("NEO4J_PASSWORD", "")))

app = FastAPI(title="Kestrel dashboard API")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                   allow_methods=["*"], allow_headers=["*"])


def search_all(index, sort_field):
    try:
        res = es.search(index=index, size=500, query={"match_all": {}},
                        sort=[{sort_field: {"order": "desc", "unmapped_type": "date"}}])
    except NotFoundError:
        return []
    return [h["_source"] for h in res["hits"]["hits"]]


@app.get("/dash/health")
def health():
    return {"status": "ok"}


@app.get("/dash/summary")
def summary():
    incidents = search_all(INCIDENTS, "last_alert")
    actions = search_all(ACTIONS, "created_at")
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for i in incidents:
        by_sev[i.get("severity", "low")] = by_sev.get(i.get("severity", "low"), 0) + 1
    expected = detected = 0
    for i in incidents:
        cov = i.get("detection_coverage") or {}
        expected += len(cov.get("expected", []))
        detected += len(cov.get("detected", []))
    try:
        events = es.count(index=EVENTS)["count"]
    except NotFoundError:
        events = 0
    by_status = {}
    for a in actions:
        by_status[a["status"]] = by_status.get(a["status"], 0) + 1
    return {
        "incidents": len(incidents), "by_severity": by_sev,
        "analysed": sum(1 for i in incidents if i.get("ai_analysis")),
        "events": events, "actions_by_status": by_status,
        "pending_actions": by_status.get("proposed", 0),
        "coverage": {"expected": expected, "detected": detected},
    }


@app.get("/dash/incidents")
def incidents():
    out = []
    for s in search_all(INCIDENTS, "last_alert"):
        cov = s.get("detection_coverage") or {}
        out.append({
            "incident_id": s["incident_id"], "title": s.get("title"),
            "severity": s.get("severity"), "risk_score": s.get("risk_score"),
            "source_ip": s.get("source_ip"), "users": s.get("users", []),
            "tactics": s.get("tactics", []),
            "techniques": [t["id"] for t in s.get("techniques", [])],
            "first_alert": s.get("first_alert"), "last_alert": s.get("last_alert"),
            "status": s.get("status"), "analysed": bool(s.get("ai_analysis")),
            "alerts": len(s.get("alerts", [])), "events": len(s.get("evidence", [])),
            "expected": len(cov.get("expected", [])),
            "detected": len(cov.get("detected", [])),
        })
    return out


@app.get("/dash/incidents/{incident_id}")
def incident(incident_id: str):
    try:
        return es.get(index=INCIDENTS, id=incident_id)["_source"]
    except NotFoundError:
        raise HTTPException(404, "Unknown incident")


@app.get("/dash/actions")
def actions(incident_id: str | None = None):
    try:
        es.indices.refresh(index=ACTIONS)
    except NotFoundError:
        return []
    rows = search_all(ACTIONS, "created_at")
    if incident_id:
        rows = [a for a in rows if a["incident_id"] == incident_id]
    return sorted(rows, key=lambda a: a["action_id"])


class Decision(BaseModel):
    by: str
    reason: str = ""


@app.post("/dash/actions/{action_id}/approve")
def approve(action_id: str, d: Decision):
    import response                                   # lazy: heavy imports
    try:
        response.cmd_approve(es, action_id, d.by, False)
    except SystemExit as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, str(exc))
    return es.get(index=ACTIONS, id=action_id)["_source"]


@app.post("/dash/actions/{action_id}/reject")
def reject(action_id: str, d: Decision):
    import response
    try:
        response.cmd_reject(es, action_id, d.by, d.reason)
    except SystemExit as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, str(exc))
    return es.get(index=ACTIONS, id=action_id)["_source"]


@app.get("/dash/audit")
def audit():
    try:
        es.indices.refresh(index=AUDIT)
    except NotFoundError:
        return []
    return search_all(AUDIT, "time")[:200]


# ---------- attack graph (Neo4j) ----------
LABEL_FIELD = {"Incident": "id", "SourceIP": "address", "Identity": "name",
               "APICall": "action", "Service": "name", "Resource": "name",
               "Technique": "id", "Tactic": "name", "ProposedAction": "action"}


def node_view(n):
    labels = list(n.labels)
    t = labels[0] if labels else "Node"
    props = dict(n)
    return {"id": n.element_id, "type": t,
            "label": props.get(LABEL_FIELD.get(t, "name")), "props": props}


@app.get("/dash/graph/{incident_id}")
def graph(incident_id: str):
    with neo.session() as s:
        rec = s.run("""
            MATCH (i:Incident {id: $id})
            OPTIONAL MATCH (i)-[:CONTAINS|INVOLVES|DETECTED|PROPOSES]->(d)
            RETURN i, collect(DISTINCT d) AS direct
        """, id=incident_id).single()
        if rec is None:
            return {"nodes": [], "edges": []}
        nodes = {rec["i"].element_id: rec["i"]}
        for d in rec["direct"]:
            nodes[d.element_id] = d
        ids = list(nodes)
        for r in s.run("""
            MATCH (d)-[:ON|TARGETED|MAPS_TO|IN_TACTIC|TARGETS|IN]->(b)
            WHERE elementId(d) IN $ids RETURN DISTINCT b
        """, ids=ids):
            nodes[r["b"].element_id] = r["b"]
        ids = list(nodes)
        edges = [{"source": r["s"], "type": r["t"], "target": r["e"]}
                 for r in s.run("""
            MATCH (a)-[r]->(b)
            WHERE elementId(a) IN $ids AND elementId(b) IN $ids
            RETURN elementId(a) AS s, type(r) AS t, elementId(b) AS e
        """, ids=ids)]
    return {"nodes": [node_view(n) for n in nodes.values()], "edges": edges}
