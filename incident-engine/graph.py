"""
AegisCloud AI - Phase 3.3: build the attack-path graph in Neo4j.

Reads incidents from Elasticsearch (index aegiscloud-incidents) and writes them
as a graph:

  (SourceIP)-[:USED]->(Identity)-[:PERFORMED]->(APICall)-[:NEXT]->(APICall)...
  (APICall)-[:ON]->(Service)            which cloud service was called
  (APICall)-[:TARGETED]->(Resource)     bucket / object touched, if any
  (APICall)-[:MAPS_TO]->(Technique)-[:IN_TACTIC]->(Tactic)
  (Incident)-[:INVOLVES|CONTAINS|DETECTED|PROPOSES]->...
  (ProposedAction)-[:TARGETS]->(Identity|Resource)

Call -> technique links come from the AI analyst's validated mapping
(ai_analysis.action_technique_map), NOT from the simulator's ground-truth
labels: a real SOC would not have those labels.

Usage (from incident-engine, venv active):
    $env:ELASTIC_PASSWORD = "..."
    $env:NEO4J_PASSWORD   = "..."
    python graph.py                      # all incidents
    python graph.py --incident INC-XXXX
    python graph.py --reset              # wipe the graph first
"""
import argparse
import os

from elasticsearch import Elasticsearch
from neo4j import GraphDatabase

INCIDENTS_INDEX = "aegiscloud-incidents"
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")

CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Incident) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:SourceIP) REQUIRE n.address IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Identity) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:APICall) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Service) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Resource) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Technique) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Tactic) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:ProposedAction) REQUIRE n.id IS UNIQUE",
]


def clean_resource(raw):
    """'arn:aws:s3:::bucket/key' -> 'bucket/key'. Returns None for '*' or empty."""
    if not raw or raw == "*":
        return None
    return str(raw).replace("arn:aws:s3:::", "")


def write_incident(tx, inc):
    iid = inc["incident_id"]
    users = inc.get("users") or []
    analysis = (inc.get("ai_analysis") or {}).get("analysis") or {}

    tx.run("""
        MERGE (i:Incident {id: $id})
        SET i.title = $title, i.severity = $severity, i.risk_score = $risk,
            i.status = $status, i.first_seen = $first, i.last_seen = $last
    """, id=iid, title=inc.get("title"), severity=inc.get("severity"),
        risk=inc.get("risk_score"), status=inc.get("status"),
        first=inc.get("first_alert"), last=inc.get("last_alert"))

    # source IP
    ip = inc.get("source_ip")
    if ip:
        tx.run("""
            MATCH (i:Incident {id: $id})
            MERGE (ip:SourceIP {address: $ip})
            MERGE (i)-[:INVOLVES]->(ip)
        """, id=iid, ip=ip)

    # identities
    for u in users:
        tx.run("""
            MATCH (i:Incident {id: $id})
            MERGE (u:Identity {name: $u})
            MERGE (i)-[:INVOLVES]->(u)
        """, id=iid, u=u)
        if ip:
            tx.run("""
                MATCH (ip:SourceIP {address: $ip}), (u:Identity {name: $u})
                MERGE (ip)-[:USED]->(u)
            """, ip=ip, u=u)

    # techniques and tactics detected by the rules
    for t in inc.get("techniques") or []:
        tx.run("""
            MATCH (i:Incident {id: $id})
            MERGE (te:Technique {id: $tid})
            SET te.name = $name, te.url = $url, te.summary = $summary
            MERGE (i)-[:DETECTED]->(te)
        """, id=iid, tid=t["id"], name=t.get("name"), url=t.get("url"),
            summary=t.get("summary"))
        for tactic in t.get("tactics") or []:
            tx.run("""
                MATCH (te:Technique {id: $tid})
                MERGE (ta:Tactic {name: $tactic})
                MERGE (te)-[:IN_TACTIC]->(ta)
            """, tid=t["id"], tactic=tactic)

    # call -> technique mapping from the AI analyst (already validated)
    call_to_tech = {}
    for m in analysis.get("action_technique_map") or []:
        if isinstance(m, dict) and m.get("action") and m.get("technique"):
            call_to_tech[m["action"]] = m["technique"]

    # API calls, in time order, chained with NEXT
    evidence = sorted(inc.get("evidence") or [], key=lambda e: e.get("timestamp") or "")
    previous_id = None
    for n, e in enumerate(evidence, start=1):
        action = e.get("api_action")
        if not action:
            continue
        cid = f"{iid}:{n:02d}"
        user = e.get("user") or (users[0] if users else None)
        tx.run("""
            MATCH (i:Incident {id: $iid})
            MERGE (c:APICall {id: $cid})
            SET c.action = $action, c.result = $result, c.time = $time, c.order = $n
            MERGE (i)-[:CONTAINS]->(c)
        """, iid=iid, cid=cid, action=action, result=e.get("result"),
            time=e.get("timestamp"), n=n)

        if user:
            tx.run("""
                MATCH (c:APICall {id: $cid})
                MERGE (u:Identity {name: $user})
                MERGE (u)-[:PERFORMED]->(c)
            """, cid=cid, user=user)

        service = action.split(":")[0]
        tx.run("""
            MATCH (c:APICall {id: $cid})
            MERGE (s:Service {name: $service})
            MERGE (c)-[:ON]->(s)
        """, cid=cid, service=service)

        resource = clean_resource(e.get("resource"))
        if resource:
            kind = "object" if "/" in resource else "bucket"
            tx.run("""
                MATCH (c:APICall {id: $cid})
                MERGE (r:Resource {name: $res})
                SET r.kind = $kind
                MERGE (c)-[:TARGETED]->(r)
            """, cid=cid, res=resource, kind=kind)
            if kind == "object":
                tx.run("""
                    MATCH (r:Resource {name: $res})
                    MERGE (b:Resource {name: $bucket})
                    SET b.kind = 'bucket'
                    MERGE (r)-[:IN]->(b)
                """, res=resource, bucket=resource.split("/")[0])

        tid = call_to_tech.get(action)
        if tid:
            tx.run("""
                MATCH (c:APICall {id: $cid})
                MERGE (te:Technique {id: $tid})
                MERGE (c)-[:MAPS_TO]->(te)
            """, cid=cid, tid=tid)

        if previous_id:
            tx.run("""
                MATCH (a:APICall {id: $a}), (b:APICall {id: $b})
                MERGE (a)-[:NEXT]->(b)
            """, a=previous_id, b=cid)
        previous_id = cid

    # actions proposed by the AI analyst (proposals only, never executed here)
    for k, a in enumerate(analysis.get("recommended_actions") or [], start=1):
        if not isinstance(a, dict) or not a.get("action"):
            continue
        aid = f"{iid}:ACT{k}"
        tx.run("""
            MATCH (i:Incident {id: $iid})
            MERGE (p:ProposedAction {id: $aid})
            SET p.action = $action, p.target = $target, p.reason = $reason,
                p.status = coalesce(p.status, 'proposed')
            MERGE (i)-[:PROPOSES]->(p)
        """, iid=iid, aid=aid, action=a["action"], target=a.get("target"),
            reason=a.get("reason"))
        target = a.get("target")
        if target:
            tx.run("""
                MATCH (p:ProposedAction {id: $aid})
                OPTIONAL MATCH (u:Identity {name: $target})
                OPTIONAL MATCH (r:Resource {name: $target})
                FOREACH (x IN CASE WHEN u IS NULL THEN [] ELSE [u] END |
                         MERGE (p)-[:TARGETS]->(x))
                FOREACH (x IN CASE WHEN r IS NULL THEN [] ELSE [r] END |
                         MERGE (p)-[:TARGETS]->(x))
            """, aid=aid, target=target)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--incident")
    ap.add_argument("--reset", action="store_true", help="delete the whole graph first")
    args = ap.parse_args()

    es = Elasticsearch("http://localhost:9200",
                       basic_auth=("elastic", os.environ["ELASTIC_PASSWORD"]))
    if args.incident:
        incidents = [es.get(index=INCIDENTS_INDEX, id=args.incident)["_source"]]
    else:
        res = es.search(index=INCIDENTS_INDEX, size=200, query={"match_all": {}})
        incidents = [h["_source"] for h in res["hits"]["hits"]]
    if not incidents:
        raise SystemExit("No incidents found. Run: python engine.py --once")

    driver = GraphDatabase.driver(
        NEO4J_URI, auth=("neo4j", os.environ["NEO4J_PASSWORD"]))
    with driver, driver.session() as session:
        if args.reset:
            session.run("MATCH (n) DETACH DELETE n")
            print("Graph wiped.")
        for c in CONSTRAINTS:
            session.run(c)
        for inc in incidents:
            session.execute_write(write_incident, inc)
            analysed = "with AI analysis" if inc.get("ai_analysis") else "no AI analysis yet"
            print(f"Graph updated: {inc['incident_id']} ({analysed})")
        counts = session.run(
            "MATCH (n) RETURN count(n) AS nodes UNION ALL "
            "MATCH ()-[r]->() RETURN count(r) AS nodes").values()
        print(f"Graph now has {counts[0][0]} nodes and {counts[1][0]} relationships.")


if __name__ == "__main__":
    main()
