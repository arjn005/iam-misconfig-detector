import json
import os
from typing import Any, Dict, List, Tuple


def _extract_documents(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Supports:
    - Raw policy doc: {"Version": "...", "Statement": [...]}
    - Wrapper: {"PolicyDocument": {...}}
    - List wrapper: {"Policies": [{"PolicyDocument": {...}}, ...]}
    """
    docs: List[Dict[str, Any]] = []

    if isinstance(data, dict) and "PolicyDocument" in data and isinstance(data["PolicyDocument"], dict):
        docs.append(data["PolicyDocument"])
        return docs

    if isinstance(data, dict) and "Policies" in data and isinstance(data["Policies"], list):
        for p in data["Policies"]:
            if isinstance(p, dict) and "PolicyDocument" in p and isinstance(p["PolicyDocument"], dict):
                docs.append(p["PolicyDocument"])
        return docs

    if isinstance(data, dict) and "Statement" in data:
        docs.append(data)

    return docs


def load_policy_documents_from_folder(folder_path: str) -> List[Tuple[str, Dict[str, Any]]]:
    results: List[Tuple[str, Dict[str, Any]]] = []

    for name in sorted(os.listdir(folder_path)):
        if not name.lower().endswith(".json"):
            continue

        full_path = os.path.join(folder_path, name)
        with open(full_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        docs = _extract_documents(data)
        for i, d in enumerate(docs):
            src = f"{name}" if len(docs) == 1 else f"{name}#{i}"
            results.append((src, d))

    return results
