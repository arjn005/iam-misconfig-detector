from typing import Any, Dict, List


SENSITIVE_S3_ACTIONS = {
    "s3:*",
    "s3:putobject",
    "s3:deleteobject",
    "s3:getobject",
    "s3:listbucket",
    "s3:putbucketpolicy",
    "s3:deletebucketpolicy",
    "s3:putencryptionconfiguration",
}


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _matches_action(actions: List[str]) -> bool:
    """
    True if any action is overly broad or sensitive.
    """
    for a in actions:
        a = a.lower()
        if a in SENSITIVE_S3_ACTIONS:
            return True
        # match wildcards like s3:Put* or s3:*
        if a.startswith("s3:") and a.endswith("*"):
            return True
    return False


def check_s3_overly_broad(source: str, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    statements = _as_list(policy.get("Statement"))

    for idx, st in enumerate(statements):
        if not isinstance(st, dict):
            continue
        if st.get("Effect") != "Allow":
            continue

        actions_raw = _as_list(st.get("Action"))
        actions = [str(a) for a in actions_raw]
        resources = _as_list(st.get("Resource"))

        if not _matches_action(actions):
            continue

        if "*" in resources:
            findings.append({
                "id": "S3_OVERLY_BROAD",
                "title": "Overly broad S3 permissions on Resource '*'",
                "severity": "HIGH",
                "source": source,
                "evidence": {
                    "statement_index": idx,
                    "Action": st.get("Action"),
                    "Resource": st.get("Resource")
                },
                "recommendation": "Scope S3 permissions to specific bucket ARNs and object ARNs (e.g., arn:aws:s3:::my-bucket and arn:aws:s3:::my-bucket/*). Avoid Resource:'*' for sensitive S3 actions."
            })

    return findings
