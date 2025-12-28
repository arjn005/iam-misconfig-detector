import argparse
import os
from typing import Any, Dict, List, Tuple

from loaders.file_loader import load_policy_documents_from_folder
from loaders.aws_loader import load_iam_policies_from_aws

from checks.wildcard_admin import check_wildcard_admin
from checks.passrole import check_passrole_broad
from checks.trust_policy import check_public_assume_role
from checks.s3_risky_permissions import check_s3_overly_broad
from checks.mfa_missing_for_privileged import check_missing_mfa_for_sensitive_actions

from report.json_report import write_json_report
from report.html_report import write_html_report


CHECKS = [
    check_wildcard_admin,
    check_passrole_broad,
    check_public_assume_role,
    check_s3_overly_broad,
    check_missing_mfa_for_sensitive_actions,
]


def run_checks(policies: List[Tuple[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for source, policy in policies:
        for check in CHECKS:
            findings.extend(check(source, policy))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(prog="iam-misconfig-detector")
    parser.add_argument("--mode", choices=["file", "aws"], default="file", help="Scan mode")
    parser.add_argument("--path", help="Folder containing JSON policy files (file mode)")
    parser.add_argument("--out", default="reports/report", help="Output base path without extension")
    args = parser.parse_args()

    if args.mode == "file":
        if not args.path:
            raise SystemExit("ERROR: --path is required when --mode file")
        policies = load_policy_documents_from_folder(args.path)
    else:
        policies = load_iam_policies_from_aws()

    findings = run_checks(policies)

    out_dir = os.path.dirname(args.out) or "."
    os.makedirs(out_dir, exist_ok=True)

    json_path = args.out + ".json"
    html_path = args.out + ".html"

    write_json_report(findings, json_path)
    write_html_report(findings, html_path)

    print(f"Mode: {args.mode}")
    print(f"Scanned {len(policies)} policy document(s)")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"- [{f['severity']}] {f['id']} :: {f['title']} (source: {f['source']})")
    print(f"\nSaved JSON: {json_path}")
    print(f"Saved HTML: {html_path}")


if __name__ == "__main__":
    main()
