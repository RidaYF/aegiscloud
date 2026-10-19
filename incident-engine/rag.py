"""
Knowledge base for the AI SOC analyst (RAG).

RAG = Retrieval-Augmented Generation: before the model answers, we search a small
knowledge base (playbooks + references in knowledge/playbooks.md) and give the
best matches to the model together with the incident.

How it works:
  1. The knowledge file is split into sections ("## ..." headings).
  2. Each section is turned into an "embedding" (a list of numbers that captures its
     meaning) by a small local model in Ollama (nomic-embed-text).
  3. The embeddings are stored in ChromaDB, a local vector database (folder chroma-data/).
  4. To retrieve, the incident is embedded the same way and ChromaDB returns the
     closest sections. We also add any section about the same MITRE technique IDs
     (embeddings are weak at exact IDs like T1530, so we do not rely on them alone).

Usage:
    python rag.py --build                       # (re)build the index from knowledge/playbooks.md
    python rag.py --search "stolen access keys" # try a search
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import chromadb

OLLAMA_EMBED_URL = "http://localhost:11434/api/embed"
EMBED_MODEL = "nomic-embed-text"

HERE = Path(__file__).resolve().parent
KNOWLEDGE_FILE = HERE.parent / "knowledge" / "playbooks.md"
CHROMA_DIR = HERE / "chroma-data"
COLLECTION = "aegis_knowledge"
MAX_DOCS = 8


def embed(texts):
    body = json.dumps({"model": EMBED_MODEL, "input": texts}).encode()
    req = urllib.request.Request(OLLAMA_EMBED_URL, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read())["embeddings"]
    except (urllib.error.URLError, TimeoutError) as exc:
        sys.exit(f"Could not get embeddings from Ollama: {exc}\n"
                 f"Did you run: ollama pull {EMBED_MODEL} ?")


def load_sections():
    text = KNOWLEDGE_FILE.read_text(encoding="utf-8-sig")
    sections = []
    for block in re.split(r"^## ", text, flags=re.M)[1:]:
        title, _, body = block.partition("\n")
        title, body = title.strip(), body.strip()
        match = re.search(r"^Techniques:\s*(.*)$", body, flags=re.M)
        techniques = []
        if match:
            techniques = [t.strip() for t in match.group(1).split(",") if t.strip().startswith("T")]
        sections.append({
            "id": re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-"),
            "title": title, "text": body, "techniques": techniques,
        })
    return sections


def _make_collection(client):
    try:
        return client.get_or_create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})
    except Exception:
        return client.get_or_create_collection(COLLECTION)


def build_index():
    sections = load_sections()
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    try:
        client.delete_collection(COLLECTION)
    except Exception:
        pass
    col = _make_collection(client)
    vectors = embed([f"{s['title']}\n{s['text']}" for s in sections])
    col.add(
        ids=[s["id"] for s in sections],
        documents=[s["text"] for s in sections],
        embeddings=vectors,
        metadatas=[{"title": s["title"], "techniques": ",".join(s["techniques"])} for s in sections],
    )
    print(f"Indexed {len(sections)} sections from {KNOWLEDGE_FILE.name}:")
    for s in sections:
        print(f"  - {s['title']}  {s['techniques'] or ''}")


def retrieve(query_text, technique_ids, k=3):
    """Return the most relevant knowledge sections for an incident."""
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    col = _make_collection(client)
    if col.count() == 0:
        sys.exit("The knowledge base is empty. Run: python rag.py --build")

    res = col.query(query_embeddings=embed([query_text]),
                    n_results=min(k, col.count()),
                    include=["documents", "metadatas"])
    picked = {}
    for id_, doc, meta in zip(res["ids"][0], res["documents"][0], res["metadatas"][0]):
        picked[id_] = {"title": meta["title"], "text": doc, "how": "semantic",
                       "techniques": [t for t in meta.get("techniques", "").split(",") if t]}

    wanted = set(technique_ids)
    rows = col.get(include=["documents", "metadatas"])
    entries = list(zip(rows["ids"], rows["documents"], rows["metadatas"]))

    # Guidance sections (severity, confidence, writing rules) are always included
    for id_, doc, meta in entries:
        if id_ not in picked and meta["title"].startswith("Guidance:"):
            picked[id_] = {"title": meta["title"], "text": doc, "how": "always",
                           "techniques": []}

    # Sections about the same MITRE technique IDs as the incident
    for id_, doc, meta in entries:
        techs = [t for t in meta.get("techniques", "").split(",") if t]
        if id_ not in picked and wanted & set(techs):
            picked[id_] = {"title": meta["title"], "text": doc, "how": "technique-match",
                           "techniques": techs}
    return list(picked.values())[:MAX_DOCS]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--search")
    args = parser.parse_args()
    if args.build:
        build_index()
    elif args.search:
        for d in retrieve(args.search, []):
            print(f"[{d['how']}] {d['title']}")
    else:
        parser.print_help()