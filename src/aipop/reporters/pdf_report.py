"""PDF report generation with executive summary.

Uses WeasyPrint to render HTML templates into professional PDF reports.
Based on ai-llm-red-team-handbook report structure:
- Executive summary (what tested, what went wrong, what to do, how good)
- Finding details with severity, description, evidence, remediation
- Framework coverage section
"""

from __future__ import annotations

import json
from datetime import datetime
from html import escape as h
from pathlib import Path
from typing import Any

from aipop.reporters.cvss_cwe_taxonomy import VULNERABILITY_TAXONOMY

_REPORT_CSS = """
@page {
    size: A4;
    margin: 2.5cm;
    @top-right { content: "AI Purple Ops Security Assessment"; font-size: 8pt; color: #666; }
    @bottom-center { content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color: #666; }
}
body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 10pt; line-height: 1.5; color: #333; }
h1 { color: #7C3AED; border-bottom: 2px solid #7C3AED; padding-bottom: 8px; page-break-before: always; }
h1:first-of-type { page-break-before: avoid; }
h2 { color: #1a1a1a; margin-top: 20px; }
h3 { color: #555; }
.finding { border: 1px solid #ddd; border-left: 4px solid #999; padding: 12px; margin: 12px 0; page-break-inside: avoid; }
.finding.critical { border-left-color: #dc2626; }
.finding.high { border-left-color: #f59e0b; }
.finding.medium { border-left-color: #3b82f6; }
.finding.low { border-left-color: #10b981; }
.severity { font-weight: bold; text-transform: uppercase; }
.severity.critical { color: #dc2626; }
.severity.high { color: #f59e0b; }
.severity.medium { color: #3b82f6; }
.severity.low { color: #10b981; }
.metric { display: inline-block; background: #f3f4f6; padding: 4px 12px; margin: 4px; border-radius: 4px; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; }
th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
th { background: #f9fafb; font-weight: 600; }
.evidence { background: #f9fafb; padding: 8px; font-family: monospace; font-size: 9pt; white-space: pre-wrap; max-height: 200px; overflow: hidden; }
"""


def generate_pdf_report(summary_path: str | Path, output_path: str | Path) -> Path:
    """Generate a professional PDF security assessment report.

    Args:
        summary_path: Path to summary.json from aipop run
        output_path: Path for output PDF

    Returns:
        Path to generated PDF file
    """
    try:
        from weasyprint import HTML
    except ImportError:
        raise ImportError(
            "WeasyPrint is required for PDF generation. "
            "Install with: pip install ai-purple-ops[reports]"
        )

    with Path(summary_path).open() as f:
        data = json.load(f)

    html = _build_report_html(data)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    HTML(string=html).write_pdf(str(output_path))
    return output_path


def _build_report_html(data: dict[str, Any]) -> str:
    """Build HTML report from summary data."""
    total = data.get("total", 0)
    passed = data.get("passed", 0)
    failed = data.get("failed", 0)
    suite = data.get("suite", "unknown")
    model = data.get("model", data.get("adapter", "unknown"))
    version = data.get("version", "unknown")
    started = data.get("utc_started", "unknown")
    finished = data.get("utc_finished", "unknown")
    run_id = data.get("run_id", "unknown")

    # Collect findings by category
    findings_by_category: dict[str, list[dict]] = {}
    for result in data.get("results", []):
        if result.get("passed"):
            continue
        category = result.get("metadata", {}).get("category", "unknown")
        if category not in findings_by_category:
            findings_by_category[category] = []
        findings_by_category[category].append(result)

    # Count by severity
    severity_counts: dict[str, int] = {}
    for result in data.get("results", []):
        if not result.get("passed"):
            risk = result.get("metadata", {}).get("risk", "unknown").upper()
            severity_counts[risk] = severity_counts.get(risk, 0) + 1

    # Build HTML
    html_parts = [f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>{_REPORT_CSS}</style></head><body>

<h1 style="page-break-before: avoid;">AI Security Assessment Report</h1>

<h2>Executive Summary</h2>

<p><strong>What was tested:</strong> {suite} suite against {model} ({total} test cases)</p>
<p><strong>What went wrong:</strong> {failed} of {total} tests identified vulnerabilities across {len(findings_by_category)} categories.</p>
<p><strong>What to do about it:</strong> Review findings below in priority order. Critical and high severity issues should be addressed before production deployment.</p>
<p><strong>Assessment quality:</strong> Run ID {run_id}, AIPOP v{version}, {started} to {finished}.</p>

<h3>Key Metrics</h3>
<div>
    <span class="metric"><strong>Total Tests:</strong> {total}</span>
    <span class="metric"><strong>Passed:</strong> {passed}</span>
    <span class="metric"><strong>Failed:</strong> {failed}</span>
</div>
<div style="margin-top: 8px;">"""]

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            html_parts.append(f'    <span class="metric"><span class="severity {sev.lower()}">{sev}:</span> {count}</span>')

    html_parts.append("</div>")

    # Findings detail
    html_parts.append("<h1>Findings</h1>")

    for category, results in sorted(findings_by_category.items(), key=lambda x: -len(x[1])):
        taxonomy = VULNERABILITY_TAXONOMY.get(category, {})
        risk = results[0].get("metadata", {}).get("risk", "medium")
        cwe = taxonomy.get("cwe_id", "")
        owasp = taxonomy.get("owasp_llm", taxonomy.get("owasp_agentic", ""))
        remediation = taxonomy.get("remediation", "Review and remediate.")
        description = taxonomy.get("description", f"{category} vulnerability detected")

        html_parts.append(f"""
<div class="finding {h(risk)}">
    <h3><span class="severity {h(risk)}">[{h(risk.upper())}]</span> {h(category.replace('_', ' ').title())}</h3>
    <p><strong>Instances:</strong> {len(results)} | <strong>CWE:</strong> {h(cwe)} | <strong>OWASP:</strong> {h(owasp)}</p>
    <p><strong>Description:</strong> {h(description)}</p>
    <p><strong>Remediation:</strong> {h(remediation)}</p>
</div>""")

    # Framework coverage
    html_parts.append("""
<h1>Framework Coverage</h1>
<table>
    <tr><th>Framework</th><th>Coverage</th></tr>
    <tr><td>OWASP LLM Top 10 (2025)</td><td>Mapped via CVSS/CWE taxonomy</td></tr>
    <tr><td>OWASP Agentic Top 10 (2026)</td><td>Mapped via ASI risk IDs</td></tr>
    <tr><td>MITRE ATLAS</td><td>Technique IDs in taxonomy</td></tr>
    <tr><td>CVSS v3.1</td><td>Vector strings per finding category</td></tr>
</table>
""")

    html_parts.append(f"""
<h1>Assessment Metadata</h1>
<table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Run ID</td><td>{run_id}</td></tr>
    <tr><td>Suite</td><td>{suite}</td></tr>
    <tr><td>Model</td><td>{model}</td></tr>
    <tr><td>AIPOP Version</td><td>{version}</td></tr>
    <tr><td>Started</td><td>{started}</td></tr>
    <tr><td>Finished</td><td>{finished}</td></tr>
    <tr><td>Seed</td><td>{data.get('seed', 'N/A')}</td></tr>
    <tr><td>Git Commit</td><td>{data.get('git_commit', 'N/A')}</td></tr>
</table>

<p style="margin-top: 40px; color: #999; font-size: 8pt;">
Generated by AI Purple Ops v{version} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</p>

</body></html>""")

    return "\n".join(html_parts)
