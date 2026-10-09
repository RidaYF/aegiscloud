from datetime import datetime, timezone
from typing import Optional, List

from fastapi import FastAPI
from pydantic import BaseModel
import os
from elasticsearch import Elasticsearch

app = FastAPI(title="AegisCloud AI Backend")

# Connect to Elasticsearch. security is disabled in our docker-compose, so no
# auth needed — fine for a local lab, never do this against a public instance.
es_client = Elasticsearch("http://localhost:9200", basic_auth=("elastic", os.environ["ELASTIC_PASSWORD"]))

INDEX_NAME = "aegiscloud-events"


class Event(BaseModel):
    timestamp: datetime
    hostname: str
    event_type: str
    process: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    severity: str
    description: Optional[str] = None
    # cloud API call events
    api_action: Optional[str] = None
    resource: Optional[str] = None
    result: Optional[str] = None
    error_code: Optional[str] = None
    # ground-truth labels set by the attack simulator
    attack_id: Optional[str] = None
    expected_technique: Optional[str] = None
    expected_technique_name: Optional[str] = None
    expected_tactics: Optional[List[str]] = None


@app.on_event("startup")
def ensure_index():
    if not es_client.indices.exists(index=INDEX_NAME):
        es_client.indices.create(index=INDEX_NAME)


@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/api/events")
def receive_events(events: List[Event]):
    for event in events:
        es_client.index(index=INDEX_NAME, document=event.model_dump(mode="json"))
    return {"received": len(events)}


@app.get("/api/events/recent")
def recent_events(limit: int = 20):
    if not es_client.indices.exists(index=INDEX_NAME):
        return []
    try:
        result = es_client.search(
            index=INDEX_NAME,
            size=limit,
            sort=[{"timestamp": "desc"}],
        )
        return [hit["_source"] for hit in result["hits"]["hits"]]
    except Exception:
        return []