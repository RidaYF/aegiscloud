"""
AegisCloud AI SOC analyst (Phase 3.2, step 2: with RAG)

Takes one incident from the "aegiscloud-incidents" index, retrieves relevant
playbooks from the knowledge base (rag.py), asks a LOCAL language model (Ollama)
to analyse the incident, then CHECKS the answer before saving it:
  - the model may only use facts from the incident and the retrieved knowledge
  - every MITRE technique ID it mentions must come from the incident or the knowledge
  - API calls it talks about must really appear in the evidence
  - recommended actions must come from a fixed allow-list
The model never executes anything: actions are only proposals for a human.

Usage:
    python analyst.py                         # latest incident, with RAG
    python analyst.py --no-rag                # same, without the knowledge base (baseline)
    python analyst.py --incident INC-5B4875D5
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

from elasticsearch import Elasticsearch, NotFoundError

ES_URL = "http://localhost:9200"
INCIDENTS_INDEX = "aegiscloud-incidents"
OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen2.5:7b"

ALLOWED_ACTIONS = {
    "collect_more_evidence", "notify_team", "disable_access_key",
    "apply_deny_policy", "block_source_ip",
}
LEVELS = {"low", "medium", "high", "critical"}

SYSTEM_PROMPT = """You are a SOC analyst assistant for the AegisCloud platform.
You receive ONE security incident as JSON, and sometimes a KNOWLEDGE BASE with playbooks.

STRICT RULES:
- Use ONLY the facts in the incident JSON and the knowledge base. Do not invent events, users, IPs or times.
- Mention MITRE ATT&CK technique IDs ONLY if they appear in the incident or in the knowledge base.
- Explain techniques using the summaries given, not your own memory.
- Base recommended actions on the playbooks when they are provided, and cite the playbooks you used by their exact title.
- Do not rate the severity lower than the incident's stored severity without a stated reason.
- If something is unknown or not in the data, say so in "uncertainties".
- You only PROPOSE actions. A human will approve them. Never say an action was executed.
- Answer with a single JSON object and nothing else."""

USER_TEMPLATE = """INCIDENT:
{incident}
{knowledge}
Return a JSON object with exactly these keys:
{{
  "summary": "2-3 sentences: what happened, which identity, from where, when",
  "attack_story": ["short step 1", "short step 2", "..."],
  "severity_assessment": {{"level": "low|medium|high|critical", "reason": "..."}},
  "action_technique_map": [{{"action": "one entry for EVERY distinct API call in the evidence, e.g. s3:GetObject", "technique": "T...."}}],
  "mitre_techniques_explained": [{{"id": "T....", "why": "what in the evidence matches it"}}],
  "recommended_actions": [{{"action": "one of: {actions}", "target": "identity, key or IP", "reason": "..."}}],
  "playbooks_used": ["exact playbook title, or empty list"],
  "confidence": "low|medium|high",
  "uncertainties": ["what is missing or unclear"]
}}"""

def _norm(title):
    return re.sub(r"^(playbook|reference|guidance):\s*", "", str(title).strip().lower())
def load_incident(es, incident_id):
    try:
        if incident_id:
            return es.get(index=INCIDENTS_INDEX, id=incident_id)["_source"]
        res = es.search(index=INCIDENTS_INDEX, size=1, query={"match_all": {}},
                        sort=[{"updated_at": "desc"}])
    except NotFoundError:
        sys.exit("No incident found. Run the incident engine first (python engine.py --once).")
    hits = res["hits"]["hits"]
    if not hits:
        sys.exit("No incident found. Run the incident engine first (python engine.py --once).")
    return hits[0]["_source"]


def observed_calls(inc):
    return sorted({e.get("api_action") for e in inc.get("evidence", []) if e.get("api_action")})


def facts_for_model(inc):
    """Compact view of the incident. It deliberately contains NO ground-truth labels."""
    return {
        "incident_id": inc["incident_id"],
        "title": inc["title"],
        "severity": inc["severity"],
        "risk_score": inc["risk_score"],
        "source_ip": inc["source_ip"],
        "users": inc.get("users", []),
        "first_alert": inc["first_alert"],
        "last_alert": inc["last_alert"],
        "tactics_in_order": inc["tactics"],
        "mitre_techniques": [
            {"id": t["id"], "name": t["name"], "tactics": t["tactics"], "summary": t["summary"]}
            for t in inc["techniques"]
        ],
        "alerts": [{"rule": a["rule"], "time": a["time"], "severity": a["severity"]}
                   for a in inc["alerts"]],
        "evidence": [
            {"time": e.get("timestamp"), "user": e.get("user"), "action": e.get("api_action"),
             "resource": e.get("resource"), "result": e.get("result")}
            for e in inc.get("evidence", [])[:30]
        ],
    }


def retrieval_query(inc):
    techs = ", ".join(f"{t['id']} {t['name']}" for t in inc["techniques"])
    return (f"{inc['title']}. Tactics: {', '.join(inc['tactics'])}. Techniques: {techs}. "
            f"Observed API calls: {', '.join(observed_calls(inc))}. How to respond to this incident.")


def knowledge_block(docs):
    if not docs:
        return ""
    parts = ["\nKNOWLEDGE BASE (retrieved playbooks and references):"]
    for d in docs:
        parts.append(f"\n### {d['title']}\n{d['text']}")
    return "\n".join(parts) + "\n"


def ask_ollama(system, user):
    body = json.dumps({
        "model": MODEL, "stream": False, "format": "json",
        "options": {"temperature": 0.2, "num_ctx": 8192},
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
    }).encode()
    req = urllib.request.Request(OLLAMA_URL, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=900) as resp:
            return json.loads(resp.read())["message"]["content"]
    except (urllib.error.URLError, TimeoutError) as exc:
        sys.exit(f"Could not reach Ollama at {OLLAMA_URL}: {exc}\n"
                 "Is Ollama running? Try: curl.exe http://localhost:11434")


def check_answer(raw, inc, docs):
    """Guardrails: parse, then verify the model's answer against the incident and knowledge."""
    problems = []
    try:
        analysis = json.loads(raw)
    except json.JSONDecodeError:
        return {"raw_answer": raw}, ["The model did not return valid JSON."]

    known = {t["id"] for t in inc["techniques"]}
    for d in docs:
        known |= set(d["techniques"])
    known |= {i.split(".")[0] for i in known}          # parent technique IDs are fine

    mentioned = set(re.findall(r"T\d{4}(?:\.\d{3})?", json.dumps(analysis)))
    unknown = sorted(m for m in mentioned if m not in known)
    if unknown:
        problems.append(f"Mentions technique IDs not in the incident or knowledge: {unknown}")

    explained = analysis.get("mitre_techniques_explained") or []
    kept = [e for e in explained if isinstance(e, dict) and e.get("id") in known]
    if len(kept) != len(explained):
        problems.append("Removed technique explanations with unknown IDs.")
    analysis["mitre_techniques_explained"] = kept

    seen_calls = set(observed_calls(inc))
    mapping = analysis.get("action_technique_map") or []
    kept_map = [m for m in mapping if isinstance(m, dict)
                and m.get("action") in seen_calls and m.get("technique") in known]
    if len(kept_map) != len(mapping):
        problems.append("Removed action-to-technique pairs with an unseen call or unknown technique.")
    analysis["action_technique_map"] = kept_map

    actions = analysis.get("recommended_actions") or []
    ok_actions = [a for a in actions if isinstance(a, dict) and a.get("action") in ALLOWED_ACTIONS]
    if len(ok_actions) != len(actions):
        problems.append("Removed proposed actions that are not in the allow-list.")
    analysis["recommended_actions"] = ok_actions

    by_name = {_norm(d["title"]): d["title"] for d in docs}
    used = analysis.get("playbooks_used") or []
    resolved = [by_name[_norm(u)] for u in used if _norm(u) in by_name]
    if len(resolved) != len(used):
        problems.append("Cited playbooks that were not provided.")
    analysis["playbooks_used"] = resolved

    level = (analysis.get("severity_assessment") or {}).get("level")
    if level not in LEVELS:
        problems.append(f"Invalid severity level: {level!r}")

    for key in ("summary", "attack_story", "severity_assessment", "confidence"):
        if key not in analysis:
            problems.append(f"Missing key: {key}")
    # Deterministic calibration: the logs show behaviour, not proof of theft.
    # If the model itself lists open uncertainties, "high" confidence is not allowed.
    if str(analysis.get("confidence", "")).lower() == "high" and analysis.get("uncertainties"):
        analysis["confidence"] = "medium"
        problems.append("Confidence lowered from high to medium: the model reported open uncertainties.")
    return analysis, problems


def analyze(inc, use_rag=True):
    """Run the whole analysis. Returns (analysis, problems, retrieved_docs)."""
    docs = []
    if use_rag:
        import rag
        docs = rag.retrieve(retrieval_query(inc), [t["id"] for t in inc["techniques"]])
    user_prompt = USER_TEMPLATE.format(
        incident=json.dumps(facts_for_model(inc), indent=2),
        knowledge=knowledge_block(docs),
        actions=", ".join(sorted(ALLOWED_ACTIONS)),
    )
    raw = ask_ollama(SYSTEM_PROMPT, user_prompt)
    analysis, problems = check_answer(raw, inc, docs)
    return analysis, problems, docs


def print_analysis(inc, analysis, problems, docs):
    print(f"\n=== {inc['incident_id']}  {inc['title']} ===")
    print(f"Stored severity: {inc['severity']} | risk {inc['risk_score']}")
    print("Knowledge retrieved:", ", ".join(f"{d['title']} [{d['how']}]" for d in docs) or "none (no RAG)")
    print(f"\nSUMMARY:\n  {analysis.get('summary')}")
    print("\nATTACK STORY:")
    for i, step in enumerate(analysis.get("attack_story") or [], 1):
        print(f"  {i}. {step}")
    sev = analysis.get("severity_assessment") or {}
    print(f"\nSEVERITY (AI): {sev.get('level')} - {sev.get('reason')}")
    print("\nCALL -> TECHNIQUE:")
    for m in analysis.get("action_technique_map") or []:
        print(f"  {m.get('action')} -> {m.get('technique')}")
    print("\nMITRE:")
    for t in analysis.get("mitre_techniques_explained") or []:
        print(f"  {t.get('id')}: {t.get('why')}")
    print("\nPROPOSED ACTIONS (need human approval):")
    for a in analysis.get("recommended_actions") or []:
        print(f"  - {a.get('action')} -> {a.get('target')}: {a.get('reason')}")
    print("\nPLAYBOOKS USED:", ", ".join(analysis.get("playbooks_used") or []) or "none")
    print(f"CONFIDENCE: {analysis.get('confidence')}")
    for u in analysis.get("uncertainties") or []:
        print(f"  ? {u}")
    print("\nGUARDRAILS:", "PASSED" if not problems else "ISSUES FOUND")
    for p in problems:
        print(f"  ! {p}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--incident", help="incident id, e.g. INC-5B4875D5")
    parser.add_argument("--no-rag", action="store_true", help="do not use the knowledge base")
    args = parser.parse_args()

    password = os.environ.get("ELASTIC_PASSWORD")
    if not password:
        sys.exit("Set $env:ELASTIC_PASSWORD first.")
    es = Elasticsearch(ES_URL, basic_auth=("elastic", password))

    inc = load_incident(es, args.incident)
    mode = "without RAG" if args.no_rag else "with RAG"
    print(f"Analysing {inc['incident_id']} with {MODEL} {mode} (this can take a minute or two)...")

    analysis, problems, docs = analyze(inc, use_rag=not args.no_rag)
    print_analysis(inc, analysis, problems, docs)

    es.update(index=INCIDENTS_INDEX, id=inc["incident_id"], retry_on_conflict=5, doc={"ai_analysis": {        "model": MODEL,
        "rag": not args.no_rag,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "knowledge_used": [d["title"] for d in docs],
        "analysis": analysis,
        "guardrail_problems": problems,
        "guardrails_passed": not problems,
    }})
    print("\nSaved to the incident as 'ai_analysis'.")


if __name__ == "__main__":
    main()