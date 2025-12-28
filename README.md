# IAM Misconfiguration Detector (Offline + AWS Read-Only)

A Python CLI tool that scans AWS IAM policies to detect high-risk misconfigurations. It supports:
- **Offline mode**: scan local IAM policy JSON files
- **AWS mode (read-only)**: pull IAM policies and trust policies from a real AWS account using AWS credentials

It generates **HTML + JSON** reports with evidence and remediation guidance.

## Why this matters
IAM misconfigurations are a common cause of cloud security incidents. This tool highlights dangerous permission patterns and encourages **least privilege**, safer trust policies, and MFA enforcement for human identities.

## Checks implemented
- **Wildcard admin**: `Action: "*"` and `Resource: "*"` (CRITICAL)
- **Broad PassRole**: `iam:PassRole` on `Resource: "*"` (CRITICAL)
- **Public trust policy**: `Principal: "*"` with `sts:AssumeRole` (CRITICAL)
- **Overly broad S3 permissions**: sensitive S3 actions with `Resource: "*"` (HIGH)
- **Missing MFA for high-impact actions** (broad scope) (MEDIUM)

## Project structure
- `src/detector.py` - CLI entry point
- `src/loaders/` - file loader + AWS IAM loader
- `src/checks/` - detection rules
- `src/report/` - HTML + JSON reporting
- `examples/policies/` - sample insecure policies for testing
- `reports/` - output folder (generated)

## Quick start

### 1) Setup
```bash
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
