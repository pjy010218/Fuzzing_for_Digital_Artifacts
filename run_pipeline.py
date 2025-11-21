import sys
import os
import json
import logging
from core.db.graph_store import ArtifactGraph
from core.llm.classifier import D3FENDMapper

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def process_experiment(json_path, app_name, llm_provider="ollama"):
    if not os.path.exists(json_path):
        print(f"[-] Error: File not found: {json_path}")
        return

    with open(json_path, 'r') as f:
        artifacts = json.load(f)
    
    print(f"[*] Found {len(artifacts)} raw events.")

    try:
        graph = ArtifactGraph("bolt://localhost:7687", "neo4j", "research_password")
    except Exception as e:
        print(f"[-] Neo4j Connection Failed: {e}")
        return

    # Ingest Graph Nodes
    count = graph.ingest_session_data(app_name, artifacts)
    print(f"[+] Ingested {count} artifacts into Graph.")

    # Init LLM
    print(f"[*] Initializing LLM Mapper using provider: {llm_provider.upper()}...")
    mapper = D3FENDMapper(provider=llm_provider)

    print("[*] Starting D3FEND Classification...")
    
    for art in artifacts:
        fp = art['filepath']
        
        # --- AGGRESSIVE FILTERING ---
        # 1. MUST be in user directories or temp
        if not (fp.startswith("/home") or fp.startswith("/root") or fp.startswith("/tmp")):
            continue

        # 2. MUST NOT be your own source code
        if "DAFuzzing" in fp or "venv" in fp or ".vscode" in fp:
            continue
            
        # 3. MUST NOT be hidden cache/config noise
        if any(x in fp for x in ["__pycache__", "/.cache/", "/.config/gtk-3.0", ".Xauthority"]):
            continue
            
        # 4. Skip empty/deleted files
        if art.get('metadata') == "File Deleted or Inaccessible":
            continue
        # -----------------------------

        print(f" -> Analyzing: {fp}")
        
        classification = mapper.classify_artifact(app_name, art)
        print(f"    [AI] {classification.get('d3fend_id')} - {classification.get('d3fend_label')}")
        
        graph.add_d3fend_classification(fp, classification)

    graph.close()
    print("[*] Pipeline Complete.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 run_pipeline.py <json_path> <app_name> [ollama|gemini]")
        exit(1)

    json_file = sys.argv[1]
    target_app = sys.argv[2]
    provider = sys.argv[3] if len(sys.argv) > 3 else "ollama"
    
    process_experiment(json_file, target_app, provider)