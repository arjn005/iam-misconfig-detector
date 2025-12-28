from typing import Any, Dict, List


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def check_wildcard_admin(source: str, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    statements = _as_list(policy.get("Statement"))

    for idx, st in enumerate(statements):
        if not isinstance(st, dict):
            continue
        if st.get("Effect") != "Allow":
            continue

        actions = _as_list(st.get("Action"))
        resources = _as_list(st.get("Resource"))

        if ("*" in actions) and ("*" in resources):
            findings.append({
                "id": "IAM_WILDCARD_ADMIN",
                "title": "Wildcard admin permissions (* on Action and Resource)",
                "severity": "CRITICAL",
                "source": source,
                "evidence": {
                    "statement_index": idx,
                    "Action": st.get("Action"),
                    "Resource": st.get("Resource")
                },
                "recommendation": "Replace wildcards with least-privilege actions and scoped resources. Prefer role-based access and limit permissions."
            })

    return findings
