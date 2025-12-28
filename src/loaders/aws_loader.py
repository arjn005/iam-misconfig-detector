from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

import boto3
from botocore.exceptions import ClientError


def _decode_policy_document(doc: Any) -> Dict[str, Any]:
    """
    boto3 usually returns a dict for PolicyVersion.Document, but sometimes JSON strings appear in other contexts.
    """
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        return json.loads(doc)
    raise TypeError(f"Unsupported policy document type: {type(doc)}")


def load_iam_policies_from_aws() -> List[Tuple[str, Dict[str, Any]]]:
    """
    Loads:
    - Inline user policies
    - Attached user managed policies (default version)
    - Inline role policies
    - Attached role managed policies (default version)
    - Role trust policies (AssumeRolePolicyDocument)

    Returns list of (source_name, policy_document)
    """
    iam = boto3.client("iam")
    results: List[Tuple[str, Dict[str, Any]]] = []

    # ---- Users ----
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]

            # Inline user policies
            in_p = iam.get_paginator("list_user_policies")
            for ppage in in_p.paginate(UserName=user_name):
                for pol_name in ppage.get("PolicyNames", []):
                    pol = iam.get_user_policy(UserName=user_name, PolicyName=pol_name)
                    doc = _decode_policy_document(pol["PolicyDocument"])
                    results.append((f"aws:user:{user_name}:inline:{pol_name}", doc))

            # Attached user managed policies
            ap = iam.get_paginator("list_attached_user_policies")
            for ppage in ap.paginate(UserName=user_name):
                for pol in ppage.get("AttachedPolicies", []):
                    arn = pol["PolicyArn"]
                    pname = pol["PolicyName"]
                    meta = iam.get_policy(PolicyArn=arn)
                    default_ver = meta["Policy"]["DefaultVersionId"]
                    ver = iam.get_policy_version(PolicyArn=arn, VersionId=default_ver)
                    doc = _decode_policy_document(ver["PolicyVersion"]["Document"])
                    results.append((f"aws:user:{user_name}:attached:{pname}:{default_ver}", doc))

    # ---- Roles ----
    rp = iam.get_paginator("list_roles")
    for page in rp.paginate():
        for role in page.get("Roles", []):
            role_name = role["RoleName"]

            # Trust policy
            trust = _decode_policy_document(role.get("AssumeRolePolicyDocument", {}))
            if trust:
                results.append((f"aws:role:{role_name}:trust", trust))

            # Inline role policies
            in_rp = iam.get_paginator("list_role_policies")
            for ppage in in_rp.paginate(RoleName=role_name):
                for pol_name in ppage.get("PolicyNames", []):
                    pol = iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                    doc = _decode_policy_document(pol["PolicyDocument"])
                    results.append((f"aws:role:{role_name}:inline:{pol_name}", doc))

            # Attached role managed policies
            ar = iam.get_paginator("list_attached_role_policies")
            for ppage in ar.paginate(RoleName=role_name):
                for pol in ppage.get("AttachedPolicies", []):
                    arn = pol["PolicyArn"]
                    pname = pol["PolicyName"]
                    meta = iam.get_policy(PolicyArn=arn)
                    default_ver = meta["Policy"]["DefaultVersionId"]
                    ver = iam.get_policy_version(PolicyArn=arn, VersionId=default_ver)
                    doc = _decode_policy_document(ver["PolicyVersion"]["Document"])
                    results.append((f"aws:role:{role_name}:attached:{pname}:{default_ver}", doc))

    return results
