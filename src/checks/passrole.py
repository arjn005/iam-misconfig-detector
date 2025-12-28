from typing import Any, Dict, List


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def check_passrole_broad(source: str, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    statements = _as_list(policy.get("Statement"))

    for idx, st in enumerate(statements):
        if not isinstance(st, dict):
            continue
        if st.get("Effect") != "Allow":
            continue

        actions = [str(a).lower() for a in _as_list(st.get("Action"))]
        resources = _as_list(st.get("Resource"))

        if "iam:passrole" in actions and "*" in resources:
            findings.append({
                "id": "IAM_PASSROLE_BROAD",
                "title": "iam:PassRole allowed on all resources",
                "severity": "CRITICAL",
                "source": source,
                "evidence": {
                    "statement_index": idx,
                    "Action": st.get("Action"),
                    "Resource": st.get("Resource")
                },
                "recommendation": "Restrict PassRole to specific role ARNs and add conditions like iam:PassedToService. Broad PassRole can enable privilege escalation."
            })

    return findings
