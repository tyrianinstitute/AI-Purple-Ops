"""Legendary HTML reporter with remediation guidance."""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape as h
from pathlib import Path
from typing import Any

from aipop.core.models import RunResult
from aipop.reporters.utils import sanitize_surrogates
from aipop.utils.errors import HarnessError


class HTMLReporterError(HarnessError):
    """Error generating HTML report."""


class HTMLReporter:
    """Generate beautiful, aggregated HTML reports with remediation guidance."""

    def __init__(self) -> None:
        """Initialize HTML reporter."""

    def write_summary(
        self,
        results: list[RunResult],
        output_path: Path | str,
        tool_results: list[dict[str, Any]] | None = None,
    ) -> None:
        """Generate HTML report from test results.

        Args:
            results: List of RunResult objects
            output_path: Path to output HTML file
            tool_results: Optional tool execution results
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Calculate metrics
        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed

        # Count violations
        critical_violations = 0
        high_violations = 0
        medium_violations = 0
        low_violations = 0

        for result in results:
            if result.detector_results:
                for detector_result in result.detector_results:
                    for violation in detector_result.violations:
                        if violation.severity == "critical":
                            critical_violations += 1
                        elif violation.severity == "high":
                            high_violations += 1
                        elif violation.severity == "medium":
                            medium_violations += 1
                        elif violation.severity == "low":
                            low_violations += 1

        # Aggregate tool findings
        tool_findings = []
        if tool_results:
            for tool_result in tool_results:
                tool_findings.extend(tool_result.get("findings", []))

        # Generate HTML
        html_content = self._generate_html(
            total=total,
            passed=passed,
            failed=failed,
            critical_violations=critical_violations,
            high_violations=high_violations,
            medium_violations=medium_violations,
            low_violations=low_violations,
            results=results,
            tool_findings=tool_findings,
        )

        output_path.write_text(sanitize_surrogates(html_content), encoding="utf-8")

    def _generate_html(
        self,
        total: int,
        passed: int,
        failed: int,
        critical_violations: int,
        high_violations: int,
        medium_violations: int,
        low_violations: int,
        results: list[RunResult],
        tool_findings: list[dict[str, Any]],
    ) -> str:
        """Generate HTML content.

        Args:
            total: Total test count
            passed: Passed test count
            failed: Failed test count
            critical_violations: Critical violation count
            high_violations: High violation count
            medium_violations: Medium violation count
            low_violations: Low violation count
            results: Test results
            tool_findings: Tool findings

        Returns:
            HTML content string
        """
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        pass_rate = (passed / total * 100) if total > 0 else 0

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Purple Ops - Redteam Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        .header h1 {{
            color: white;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .subtitle {{
            color: rgba(255,255,255,0.9);
            font-size: 1.2em;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .metric-card.passed {{
            border-color: #238636;
        }}
        .metric-card.failed {{
            border-color: #da3633;
        }}
        .metric-card.critical {{
            border-color: #f85149;
        }}
        .metric-card.high {{
            border-color: #fb8500;
        }}
        .metric-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .metric-label {{
            color: #8b949e;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .passed .metric-value {{ color: #238636; }}
        .failed .metric-value {{ color: #da3633; }}
        .critical .metric-value {{ color: #f85149; }}
        .high .metric-value {{ color: #fb8500; }}
        .section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 30px;
        }}
        .section h2 {{
            color: #58a6ff;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 2px solid #30363d;
            padding-bottom: 10px;
        }}
        .finding {{
            background: #0d1117;
            border-left: 4px solid #f85149;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 4px;
        }}
        .finding.high {{ border-left-color: #fb8500; }}
        .finding.medium {{ border-left-color: #ffb703; }}
        .finding.low {{ border-left-color: #8b949e; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .finding-title {{
            font-size: 1.2em;
            font-weight: bold;
            color: #58a6ff;
        }}
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-critical {{
            background: #f85149;
            color: white;
        }}
        .severity-high {{
            background: #fb8500;
            color: white;
        }}
        .severity-medium {{
            background: #ffb703;
            color: #0d1117;
        }}
        .severity-low {{
            background: #8b949e;
            color: white;
        }}
        .remediation {{
            background: #1c2128;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 15px;
            margin-top: 15px;
        }}
        .remediation h4 {{
            color: #238636;
            margin-bottom: 10px;
            font-size: 1em;
        }}
        .remediation-content {{
            color: #c9d1d9;
            line-height: 1.8;
        }}
        .code-block {{
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .test-result {{
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 10px;
        }}
        .test-result.passed {{
            border-left: 4px solid #238636;
        }}
        .test-result.failed {{
            border-left: 4px solid #da3633;
        }}
        .test-name {{
            font-weight: bold;
            color: #58a6ff;
            margin-bottom: 5px;
        }}
        .timestamp {{
            color: #8b949e;
            font-size: 0.9em;
            text-align: right;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AI Purple Ops Redteam Report</h1>
            <div class="subtitle">Comprehensive AI Security Assessment</div>
        </div>

        <div class="metrics">
            <div class="metric-card passed">
                <div class="metric-value">{passed}/{total}</div>
                <div class="metric-label">Tests Passed</div>
            </div>
            <div class="metric-card failed">
                <div class="metric-value">{failed}</div>
                <div class="metric-label">Tests Failed</div>
            </div>
            <div class="metric-card critical">
                <div class="metric-value">{critical_violations}</div>
                <div class="metric-label">Critical Issues</div>
            </div>
            <div class="metric-card high">
                <div class="metric-value">{high_violations}</div>
                <div class="metric-label">High Severity</div>
            </div>
        </div>

        <div class="section">
            <h2>📊 Executive Summary</h2>
            <p><strong>Pass Rate:</strong> {pass_rate:.1f}% ({passed} of {total} tests passed)</p>
            <p><strong>Total Violations:</strong> {critical_violations + high_violations + medium_violations + low_violations}</p>
            <p><strong>Critical Issues:</strong> {critical_violations} (requires immediate attention)</p>
            <p><strong>High Severity:</strong> {high_violations} (should be addressed promptly)</p>
        </div>
"""

        # Add tool findings section
        if tool_findings:
            html += """
        <div class="section">
            <h2>🔍 Redteam Tool Findings</h2>
"""
            for finding in tool_findings:
                severity = h(finding.get("severity", "medium"))
                remediation = h(finding.get("remediation", "Review and harden model defenses."))
                html += f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">{h(finding.get("attack_vector", "Unknown Attack"))}</div>
                    <span class="severity-badge severity-{severity}">{severity}</span>
                </div>
                <p><strong>Source:</strong> {h(finding.get("source", "unknown"))}</p>
                <p><strong>Category:</strong> {h(finding.get("category", "N/A"))}</p>
                <p><strong>Payload:</strong></p>
                <div class="code-block">{h(finding.get("payload", "N/A")[:200])}...</div>
                <div class="remediation">
                    <h4>💡 Remediation Guidance</h4>
                    <div class="remediation-content">{h(remediation)}</div>
                </div>
            </div>
"""

        # Add test results section
        html += """
        <div class="section">
            <h2>🧪 Test Results</h2>
"""
        for result in results:
            status_class = "passed" if result.passed else "failed"
            # RunResult has test_id, not test_case
            test_name = h(result.test_id)
            test_description = h(result.metadata.get("description", "No description"))
            html += f"""
            <div class="test-result {status_class}">
                <div class="test-name">{test_name}</div>
                <p>{test_description}</p>
"""
            if result.detector_results:
                for detector_result in result.detector_results:
                    if not detector_result.passed:
                        for violation in detector_result.violations:
                            remediation = self._get_remediation_guidance(violation)
                            html += f"""
                <div class="finding {h(violation.severity)}">
                    <div class="finding-header">
                        <div class="finding-title">Policy Violation: {h(violation.rule_id)}</div>
                        <span class="severity-badge severity-{h(violation.severity)}">{h(violation.severity)}</span>
                    </div>
                    <p><strong>Rule ID:</strong> {h(violation.rule_id)}</p>
                    <p><strong>Description:</strong> {h(violation.message)}</p>
                    <div class="remediation">
                        <h4>💡 Remediation Guidance</h4>
                        <div class="remediation-content">{h(remediation)}</div>
                    </div>
                </div>
"""
            html += """
            </div>
"""

        html += f"""
        </div>

        <div class="timestamp">
            Generated: {timestamp}
        </div>
    </div>
</body>
</html>
"""

        return html

    def _get_remediation_guidance(self, violation: Any) -> str:
        """Get remediation guidance for a violation.

        Args:
            violation: PolicyViolation object

        Returns:
            Remediation guidance string
        """
        # PolicyViolation has rule_id, not category - extract category from rule_id if possible
        rule_id = violation.rule_id.lower()
        category = "unknown"
        if "violence" in rule_id:
            category = "violence"
        elif "hate" in rule_id:
            category = "hate_speech"
        elif "sexual" in rule_id:
            category = "sexual_content"
        elif "pii" in rule_id:
            category = "pii"
        elif "injection" in rule_id:
            category = "prompt_injection"
        elif "jailbreak" in rule_id:
            category = "jailbreak"

        severity = violation.severity.lower()

        guidance_map = {
            "violence": "Implement content filtering to detect and block violent content. Use moderation APIs or custom classifiers.",
            "hate_speech": "Enable hate speech detection filters. Review and update content policies regularly.",
            "sexual_content": "Add sexual content detection. Configure appropriate content moderation thresholds.",
            "pii": "Implement PII detection and redaction. Use data loss prevention (DLP) tools. Encrypt sensitive data.",
            "prompt_injection": "Implement input sanitization, output validation, and system prompt hardening. Use prompt injection detection.",
            "jailbreak": "Strengthen system prompts. Add content filtering. Monitor for instruction overrides.",
        }

        # Category-specific guidance
        if category in guidance_map:
            base_guidance = guidance_map[category]
        else:
            base_guidance = (
                "Review the model's content policy and implement appropriate safeguards."
            )

        # Severity-specific additions
        if severity == "critical":
            base_guidance += " **IMMEDIATE ACTION REQUIRED** - This is a critical security issue."
        elif severity == "high":
            base_guidance += " Address this promptly to prevent security incidents."

        return base_guidance
