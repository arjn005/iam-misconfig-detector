from typing import Any, Dict, List


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def check_public_assume_role(source: str, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    statements = _as_list(policy.get("Statement"))

    for idx, st in enumerate(statements):
        if not isinstance(st, dict):
            continue
        if st.get("Effect") != "Allow":
            continue

        principal = st.get("Principal")
        if principal is None:
            continue

        actions = [str(a).lower() for a in _as_list(st.get("Action"))]

        if "sts:assumerole" in actions and principal == "*":
            findings.append({
                "id": "IAM_TRUST_PUBLIC_ASSUME_ROLE",
                "title": "Public role trust: Principal '*' can assume role",
                "severity": "CRITICAL",
                "source": source,
                "evidence": {
                    "statement_index": idx,
                    "Action": st.get("Action"),
                    "Principal": principal
                },
                "recommendation": "Lock down trust policy to specific AWS accounts/roles or an OIDC provider. Avoid Principal:'*' in trust policies."
            })

    return findings
