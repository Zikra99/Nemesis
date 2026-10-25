import json
import os
from typing import Dict, List

import chromadb
import requests
import yaml
from chromadb.utils import embedding_functions

DATA_DIR = "data"
CHROMA_DIR = os.path.join(DATA_DIR, "chroma_db")
TECHNIQUES_FILE = os.path.join(DATA_DIR, "techniques.json")
ATOMIC_DIR = os.path.join(DATA_DIR, "atomic_tests")

MITRE_URL = ("https://raw.githubusercontent.com/mitre/cti/master/"
             "enterprise-attack/enterprise-attack.json")

ATOMIC_URLS = {
    "T1059": "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/T1059.yaml",
}

OWASP_TOP_10_2025: Dict[str, Dict] = {
    "A01:2025": {"name": "Broken Access Control", "rank": 1},
    "A02:2025": {"name": "Security Misconfiguration", "rank": 2},
    "A03:2025": {"name": "Software Supply Chain Failures", "rank": 3},
    "A04:2025": {"name": "Cryptographic Failures", "rank": 4},
    "A05:2025": {"name": "Injection", "rank": 5},
    "A06:2025": {"name": "Insecure Design", "rank": 6},
    "A07:2025": {"name": "Authentication Failures", "rank": 7},
    "A08:2025": {"name": "Software or Data Integrity Failures", "rank": 8},
    "A09:2025": {"name": "Security Logging and Alerting Failures", "rank": 9},
    "A10:2025": {"name": "Mishandling of Exceptional Conditions", "rank": 10},
}


class RAGRetriever:
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(ATOMIC_DIR, exist_ok=True)
        self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        self.client = chromadb.PersistentClient(path=CHROMA_DIR)
        self.collection = self.client.get_or_create_collection(
            "knowledge_base", embedding_function=self.embedding_fn
        )

    def build_index(self):
        if self.collection.count() > 0:
            print("Knowledge base index already exists -- skipping build.")
            return
        print("Building knowledge base...")
        ids, documents, metadatas = [], [], []
        counter = 0

        for tech in self._load_techniques():
            documents.append(f"{tech['id']} -- {tech['name']}: {tech['description']}")
            ids.append(f"mitre_{counter}")
            metadatas.append({"source_type": "mitre_attack",
                              "ref_id": tech["id"], "name": tech["name"]})
            counter += 1

        for tech_id, data in self._load_atomic_tests().items():
            for test in data.get("atomic_tests", []):
                name = test.get("name", "")
                desc = test.get("description", "")
                if not (name or desc):
                    continue
                documents.append(f"Atomic test for {tech_id} -- {name}: {desc}")
                ids.append(f"atomic_{counter}")
                metadatas.append({"source_type": "atomic_test",
                                  "ref_id": tech_id, "name": name})
                counter += 1

        for oid, info in OWASP_TOP_10_2025.items():
            documents.append(f"{oid} -- {info['name']}: OWASP Top 10:2025 category.")
            ids.append(f"owasp_{counter}")
            metadatas.append({"source_type": "owasp_top10_2025",
                              "ref_id": oid, "name": info["name"]})
            counter += 1

        self.collection.add(ids=ids, documents=documents, metadatas=metadatas)
        print(f"Indexed {len(documents)} documents.")

    def retrieve_grouped(self, query: str, top_k: int = 8) -> Dict[str, List[Dict]]:
        results = self.collection.query(query_texts=[query], n_results=top_k,
                                        include=["metadatas", "documents"])
        grouped = {"mitre_attack": [], "atomic_test": [], "owasp_top10_2025": []}
        if not results["metadatas"] or not results["metadatas"][0]:
            return grouped
        for meta, doc in zip(results["metadatas"][0], results["documents"][0]):
            key = meta.get("source_type")
            if key in grouped:
                grouped[key].append({"ref_id": meta.get("ref_id"),
                                     "name": meta.get("name"), "text": doc})
        return grouped

    def _load_techniques(self) -> List[Dict]:
        if os.path.exists(TECHNIQUES_FILE):
            with open(TECHNIQUES_FILE) as f:
                return json.load(f)
        print("Fetching MITRE ATT&CK techniques...")
        resp = requests.get(MITRE_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        techniques = []
        for obj in data["objects"]:
            if obj["type"] == "attack-pattern":
                ext = obj.get("external_references", [{}])[0]
                tech = {"id": ext.get("external_id", ""), "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                                    if p.get("kill_chain_name") == "mitre-attack"]}
                if tech["id"]:
                    techniques.append(tech)
        with open(TECHNIQUES_FILE, "w") as f:
            json.dump(techniques, f, indent=2)
        print(f"Cached {len(techniques)} techniques.")
        return techniques

    def _load_atomic_tests(self) -> Dict[str, Dict]:
        if not os.listdir(ATOMIC_DIR):
            for tech_id, url in ATOMIC_URLS.items():
                try:
                    r = requests.get(url, timeout=30)
                    r.raise_for_status()
                    with open(os.path.join(ATOMIC_DIR, f"{tech_id}.yaml"), "w") as f:
                        f.write(r.text)
                except Exception as e:
                    print(f"  Failed to download {tech_id}: {e}")
        tests = {}
        for fname in os.listdir(ATOMIC_DIR):
            if not fname.endswith(".yaml"):
                continue
            with open(os.path.join(ATOMIC_DIR, fname)) as f:
                try:
                    data = yaml.safe_load(f)
                except Exception:
                    continue
            if data:
                tests[data.get("attack_technique") or fname.replace(".yaml", "")] = data
        return tests
