from typing import Any, Dict, List


# High-impact actions where MFA is often expected for HUMAN identities.
# (Heuristic, not perfect — but much less noisy.)
SENSITIVE_ACTIONS = {
    "iam:createuser",
    "iam:deleteuser",
    "iam:attachuserpolicy",
    "iam:detachuserpolicy",
    "iam:putuserpolicy",
    "iam:createaccesskey",
    "iam:updateaccesskey",
    "iam:createrole",
    "iam:deleterole",
    "iam:passrole",
    "organizations:*",
}


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _has_mfa_condition(statement: Dict[str, Any]) -> bool:
    cond = statement.get("Condition")
    if not isinstance(cond, dict):
        return False

    for key in ["Bool", "BoolIfExists"]:
        block = cond.get(key)
        if isinstance(block, dict):
            val = block.get("aws:MultiFactorAuthPresent")
            if str(val).lower() == "true":
                return True
    return False


def _is_sensitive_action(action: str) -> bool:
    a = action.lower()
    if a in SENSITIVE_ACTIONS:
        return True
    # also treat wildcards like iam:* as sensitive
    if a.endswith(":*") and (a.startswith("iam:") or a.startswith("organizations:")):
        return True
    return False


def check_missing_mfa_for_sensitive_actions(source: str, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    statements = _as_list(policy.get("Statement"))

    for idx, st in enumerate(statements):
        if not isinstance(st, dict):
            continue
        if st.get("Effect") != "Allow":
            continue

        actions = [str(a) for a in _as_list(st.get("Action"))]
        resources = _as_list(st.get("Resource"))

        if not actions:
            continue

        # Reduce noise: only care when the statement is broad.
        if "*" not in resources:
            continue

        if not any(_is_sensitive_action(a) for a in actions):
            continue

        if _has_mfa_condition(st):
            continue

        findings.append({
            "id": "MFA_MISSING_FOR_SENSITIVE_ACTIONS",
            "title": "High-impact actions allowed without MFA (broad scope)",
            "severity": "MEDIUM",
            "source": source,
            "evidence": {
                "statement_index": idx,
                "Action": st.get("Action"),
                "Resource": st.get("Resource"),
                "Condition": st.get("Condition", None),
            },
            "recommendation": "For human identities, enforce MFA using a Condition like Bool: { aws:MultiFactorAuthPresent: true }. Scope permissions and separate service roles from human admin roles."
        })

    return findings
