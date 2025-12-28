import json
from typing import Any, Dict, List


def write_json_report(findings: List[Dict[str, Any]], out_path: str) -> None:
    report: Dict[str, Any] = {
        "tool": "iam-misconfig-detector",
        "version": "0.1.0",
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
