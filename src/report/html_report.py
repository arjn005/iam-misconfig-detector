from typing import Dict, List
from jinja2 import Template

_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>IAM Misconfiguration Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; }
    h1 { margin-bottom: 0; }
    .meta { color: #555; margin-top: 6px; }
    .card { border: 1px solid #ddd; border-radius: 10px; padding: 14px; margin: 12px 0; }
    .sev { font-weight: bold; }
    .CRITICAL { color: #b00020; }
    .HIGH { color: #d35400; }
    .MEDIUM { color: #b7950b; }
    .LOW { color: #2e86c1; }
    pre { background: #f6f6f6; padding: 10px; border-radius: 8px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>IAM Misconfiguration Report</h1>
  <div class="meta">Total findings: {{ total }}</div>

  {% if total == 0 %}
    <p>No findings detected.</p>
  {% endif %}

  {% for f in findings %}
    <div class="card">
      <div class="sev {{ f.severity }}">[{{ f.severity }}] {{ f.title }}</div>
      <div><b>ID:</b> {{ f.id }}</div>
      <div><b>Source:</b> {{ f.source }}</div>
      <div><b>Recommendation:</b> {{ f.recommendation }}</div>
      <details style="margin-top:8px;">
        <summary>Evidence</summary>
        <pre>{{ f.evidence | tojson(indent=2) }}</pre>
      </details>
    </div>
  {% endfor %}
</body>
</html>
"""

def write_html_report(findings: List[Dict], out_path: str) -> None:
    t = Template(_HTML)
    html = t.render(findings=findings, total=len(findings))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
