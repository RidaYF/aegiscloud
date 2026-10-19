"""
AegisCloud AI - Phase 3.2 evaluation: AI analyst WITH vs WITHOUT RAG.

Runs the analyst several times in each mode on the same incident and scores the
answers against the simulator's ground truth (the `expected_technique` labels,
which are never shown to the model).

Usage (from incident-engine, venv active, ELASTIC_PASSWORD set):
    python evaluate.py                      # latest incident, 5 runs per mode
    python evaluate.py --runs 3
    python evaluate.py --incident INC-3171C865
"""
import argparse
import copy
import json
import os
import re
import time
from datetime import datetime, timezone

from elasticsearch import Elasticsearch

import analyst

CALIBRATION_NOTE = "Confidence lowered"


def get_incident(es, incident_id):
    if incident_id:
        return es.get(index=analyst.INCIDENTS_INDEX, id=incident_id)["_source"]
    res = es.search(index=analyst.INCIDENTS_INDEX, size=1,
                    sort=[{"created_at": {"order": "desc", "unmapped_type": "date"}}],
                    query={"match_all": {}})
    hits = res["hits"]["hits"]
    if not hits:
        raise SystemExit("No incident found. Run: python engine.py --once")
    return hits[0]["_source"]


def ground_truth(inc):
    """{api_call: expected_technique} built from the simulator labels in the evidence."""
    truth = {}
    for e in inc.get("evidence", []):
        if e.get("api_action") and e.get("expected_technique"):
            truth[e["api_action"]] = e["expected_technique"]
    return truth


def severity_level(analysis):
    sev = analysis.get("severity_assessment")
    if isinstance(sev, dict):
        sev = sev.get("level") or sev.get("severity") or ""
    m = re.search(r"\b(critical|high|medium|low)\b", str(sev).lower())
    return m.group(1) if m else None


def score_run(analysis, problems, truth, stored_severity):
    valid_json = "raw_answer" not in analysis
    pairs = {}
    for m in analysis.get("action_technique_map") or []:
        if isinstance(m, dict):
            pairs[m.get("action")] = m.get("technique")
    correct = sum(1 for call, tech in truth.items() if pairs.get(call) == tech)
    actions = [a.get("action") for a in (analysis.get("recommended_actions") or [])
               if isinstance(a, dict)]
    real_problems = [p for p in problems if not p.startswith(CALIBRATION_NOTE)]
    return {
        "valid_json": valid_json,
        "technique_correct": correct,
        "technique_total": len(truth),
        "proposes_disable_key": "disable_access_key" in actions,
        "proposes_only_allowed": True,  # the guardrail already strips anything else
        "severity_matches": severity_level(analysis) == stored_severity,
        "confidence": analysis.get("confidence"),
        "calibration_corrected": any(p.startswith(CALIBRATION_NOTE) for p in problems),
        "clean_guardrails": valid_json and not real_problems,
        "guardrail_problems": real_problems,
    }


def mean(values):
    values = list(values)
    return sum(values) / len(values) if values else 0.0


def summarise(rows):
    n = len(rows)
    acc = mean(r["technique_correct"] / r["technique_total"] for r in rows
               if r["technique_total"])
    pct = lambda key: 100.0 * sum(1 for r in rows if r[key]) / n
    return {
        "runs": n,
        "technique_accuracy_%": round(100 * acc, 1),
        "proposes_disable_key_%": round(pct("proposes_disable_key"), 1),
        "severity_matches_%": round(pct("severity_matches"), 1),
        "clean_guardrails_%": round(pct("clean_guardrails"), 1),
        "calibration_corrected_%": round(pct("calibration_corrected"), 1),
        "avg_seconds": round(mean(r["seconds"] for r in rows), 1),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--incident")
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()

    es = Elasticsearch("http://localhost:9200",
                       basic_auth=("elastic", os.environ["ELASTIC_PASSWORD"]))
    inc = get_incident(es, args.incident)
    truth = ground_truth(inc)
    if not truth:
        raise SystemExit("No expected_technique labels in this incident's evidence; "
                         "cannot score. Regenerate data with scenario.py.")
    print(f"Incident {inc['incident_id']} - {len(truth)} labelled API calls: {truth}")
    print(f"Stored severity: {inc.get('severity')}  | {args.runs} runs per mode\n")

    results = {"with_rag": [], "without_rag": []}
    for i in range(1, args.runs + 1):
        for mode, use_rag in (("with_rag", True), ("without_rag", False)):
            t0 = time.time()
            try:
                analysis, problems, _docs = analyst.analyze(copy.deepcopy(inc), use_rag=use_rag)
                row = score_run(analysis, problems, truth, inc.get("severity"))
            except Exception as exc:  # keep going; a crash counts as a failed run
                row = score_run({"raw_answer": str(exc)}, [f"crash: {exc}"], truth,
                                inc.get("severity"))
            row["seconds"] = time.time() - t0
            results[mode].append(row)
            print(f"[run {i}/{args.runs}] {mode:12s} techniques "
                  f"{row['technique_correct']}/{row['technique_total']}  "
                  f"disable_key={row['proposes_disable_key']}  "
                  f"clean={row['clean_guardrails']}  {row['seconds']:.0f}s")

    summary = {mode: summarise(rows) for mode, rows in results.items()}
    print("\n=== RESULTS ===")
    keys = [k for k in summary["with_rag"] if k != "runs"]
    print(f"{'metric':28s}{'WITHOUT RAG':>14s}{'WITH RAG':>12s}")
    for k in keys:
        print(f"{k:28s}{summary['without_rag'][k]:>14}{summary['with_rag'][k]:>12}")

    out = {"incident_id": inc["incident_id"], "model": getattr(analyst, "MODEL", None),
           "ran_at": datetime.now(timezone.utc).isoformat(),
           "summary": summary, "runs": results}
    with open("evaluation-results.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, default=str)
    print("\nSaved: evaluation-results.json")


if __name__ == "__main__":
    main()