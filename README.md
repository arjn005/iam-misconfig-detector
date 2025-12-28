# IAM Misconfiguration Detector (Offline-First)

A Python CLI tool that scans AWS IAM policy JSON files and detects high-risk misconfigurations
(e.g., wildcard admin permissions, broad `iam:PassRole`, and public assume-role trust policies).
Generates JSON + HTML reports with remediation guidance.

## Why this matters
Misconfigured IAM is a common cause of cloud security incidents. This tool highlights dangerous
permission patterns and provides actionable recommendations aligned with least privilege.

## Features (MVP)
- Offline scanning of IAM policy documents from `.json` files
- Checks:
  - Wildcard admin: `Action: "*"` and `Resource: "*"`
  - Broad `iam:PassRole`
  - Public trust policies (`Principal: "*"` with `sts:AssumeRole`)
- Reports:
  - Console summary
  - JSON report
  - HTML report

## Quick Start

### 1) Setup
```bash
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt

