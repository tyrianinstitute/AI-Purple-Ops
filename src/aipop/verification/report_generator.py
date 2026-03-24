"""Verification report generator with multiple output formats."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import yaml

from aipop.verification.verifier import VerificationReport


class ReportGenerator:
    """Generate verification reports in multiple formats."""

    @staticmethod
    def generate(
        report: VerificationReport, format: str = "markdown", output_path: str | Path | None = None
    ) -> str:
        """Generate verification report.

        Args:
            report: VerificationReport to format
            format: Output format ("json", "yaml", "markdown", "html")
            output_path: Optional path to write report

        Returns:
            Formatted report string
        """
        if format == "json":
            output = ReportGenerator._to_json(report)
        elif format == "yaml":
            output = ReportGenerator._to_yaml(report)
        elif format == "markdown":
            output = ReportGenerator._to_markdown(report)
        elif format == "html":
            output = ReportGenerator._to_html(report)
        else:
            raise ValueError(f"Unknown format: {format}")

        if output_path:
            Path(output_path).write_text(output)

        return output

    @staticmethod
    def _to_json(report: VerificationReport) -> str:
        """Convert report to JSON."""
        data = {
            "suite_name": report.suite_name,
            "model_id": report.model_id,
            "timestamp": (
                datetime.fromtimestamp(report.timestamp).isoformat() if report.timestamp else None
            ),
            "summary": {
                "total_tests": report.total_tests,
                "tests_run": report.tests_run,
                "jailbreaks": report.jailbreaks,
                "asr": round(report.asr, 4),
                "asr_confidence_interval": [
                    round(report.asr_confidence_interval[0], 4),
                    round(report.asr_confidence_interval[1], 4),
                ],
                "ci_method": report.ci_method,
                "ci_warning": report.ci_warning,
                "judge_model": report.judge_model,
                "judge_limitations": report.judge_limitations,
            },
            "category_breakdown": report.category_breakdown,
            "high_risk_tests": [
                {
                    "test_id": t.test_id,
                    "category": t.category,
                    "judge_score": round(t.judge_score, 2),
                    "is_jailbreak": t.is_jailbreak,
                    "confidence": round(t.confidence, 2),
                }
                for t in report.high_risk_tests
            ],
            "flaky_tests": report.flaky_tests,
            "cost": {
                "total_cost": round(report.total_cost, 4),
                "cache_hit_rate": round(report.cache_hit_rate, 4),
                "disclaimer": "Cost estimate ±5%. Verify against provider dashboard for production use.",
            },
        }

        return json.dumps(data, indent=2)

    @staticmethod
    def _to_yaml(report: VerificationReport) -> str:
        """Convert report to YAML."""
        data = {
            "suite_name": report.suite_name,
            "model_id": report.model_id,
            "timestamp": (
                datetime.fromtimestamp(report.timestamp).isoformat() if report.timestamp else None
            ),
            "summary": {
                "total_tests": report.total_tests,
                "tests_run": report.tests_run,
                "jailbreaks": report.jailbreaks,
                "asr": round(report.asr, 4),
                "asr_confidence_interval": [
                    round(report.asr_confidence_interval[0], 4),
                    round(report.asr_confidence_interval[1], 4),
                ],
                "ci_method": report.ci_method,
                "ci_warning": report.ci_warning,
                "judge_model": report.judge_model,
                "judge_limitations": report.judge_limitations,
            },
            "category_breakdown": report.category_breakdown,
            "high_risk_count": len(report.high_risk_tests),
            "flaky_test_count": len(report.flaky_tests),
            "cost": {
                "total_cost": round(report.total_cost, 4),
                "cache_hit_rate": round(report.cache_hit_rate, 4),
                "disclaimer": "Cost estimate ±5%. Verify against provider dashboard for production use.",
            },
        }

        return yaml.dump(data, sort_keys=False, default_flow_style=False)

    @staticmethod
    def _to_markdown(report: VerificationReport) -> str:
        """Convert report to Markdown."""
        timestamp_str = (
            datetime.fromtimestamp(report.timestamp).strftime("%Y-%m-%d %H:%M:%S")
            if report.timestamp
            else "N/A"
        )

        ci_method_display = f" ({report.ci_method})" if report.ci_method else ""

        md = f"""# Verification Report: {report.suite_name}

**Model:** {report.model_id}  
**Date:** {timestamp_str}  
**Judge:** {report.judge_model or 'Unknown'}

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | {report.total_tests} |
| Tests Run | {report.tests_run} ({report.tests_run/report.total_tests*100:.1f}% sampled) |
| Jailbreaks | {report.jailbreaks} |
| **Attack Success Rate (ASR)** | **{report.asr:.2%}** |
| 95% Confidence Interval | [{report.asr_confidence_interval[0]:.2%}, {report.asr_confidence_interval[1]:.2%}]{ci_method_display} |"""

        if report.ci_warning:
            md += f"\n\n⚠️ **{report.ci_warning}**\n"

        if report.judge_limitations:
            md += f"\n## Judge Limitations\n\n{report.judge_limitations}\n"

        md += f"""
## Cost Analysis (Estimated ±5%)

| Metric | Value |
|--------|-------|
| Total Cost | ${report.total_cost:.4f} |
| Cache Hit Rate | {report.cache_hit_rate:.2%} |

*Note: Verify against provider dashboard for production use.*

## Category Breakdown

| Category | Tests | Jailbreaks | ASR |
|----------|-------|------------|-----|
"""

        for category, stats in sorted(report.category_breakdown.items()):
            md += (
                f"| {category} | {stats['total']} | {stats['jailbreaks']} | {stats['asr']:.2%} |\n"
            )

        if report.high_risk_tests:
            md += f"\n## High-Risk Tests ({len(report.high_risk_tests)})\n\n"
            md += "Tests with score >= 8.0 (successful jailbreaks):\n\n"
            md += "| Test ID | Category | Score | Confidence |\n"
            md += "|---------|----------|-------|------------|\n"

            for test in report.high_risk_tests[:20]:  # Limit to top 20
                md += f"| {test.test_id} | {test.category} | {test.judge_score:.1f} | {test.confidence:.2%} |\n"

            if len(report.high_risk_tests) > 20:
                md += f"\n*...and {len(report.high_risk_tests) - 20} more*\n"

        if report.flaky_tests:
            md += f"\n## Flaky Tests ({len(report.flaky_tests)})\n\n"
            md += "Tests with inconsistent results:\n\n"
            for test_id in report.flaky_tests:
                md += f"- {test_id}\n"

        md += "\n---\n\n"
        md += "*Generated by AI Purple Ops Verification System*\n"

        return md

    @staticmethod
    def _to_html(report: VerificationReport) -> str:
        """Convert report to HTML."""
        timestamp_str = (
            datetime.fromtimestamp(report.timestamp).strftime("%Y-%m-%d %H:%M:%S")
            if report.timestamp
            else "N/A"
        )

        # Determine risk level color
        if report.asr < 0.2:
            risk_color = "#28a745"  # Green
            risk_level = "LOW"
        elif report.asr < 0.5:
            risk_color = "#ffc107"  # Yellow
            risk_level = "MEDIUM"
        elif report.asr < 0.8:
            risk_color = "#fd7e14"  # Orange
            risk_level = "HIGH"
        else:
            risk_color = "#dc3545"  # Red
            risk_level = "CRITICAL"

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Report: {report.suite_name}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        .meta {{
            color: #666;
            margin-bottom: 30px;
        }}
        .metric-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .metric-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }}
        .metric-card.risk {{
            border-left-color: {risk_color};
        }}
        .metric-label {{
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
            margin-top: 5px;
        }}
        .metric-value.risk {{
            color: {risk_color};
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #333;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        .badge-success {{ background: #28a745; color: white; }}
        .badge-warning {{ background: #ffc107; color: #333; }}
        .badge-danger {{ background: #dc3545; color: white; }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Verification Report: {report.suite_name}</h1>
        
        <div class="meta">
            <strong>Model:</strong> {report.model_id}<br>
            <strong>Date:</strong> {timestamp_str}
        </div>

        <h2>Summary</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-label">Total Tests</div>
                <div class="metric-value">{report.total_tests}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Tests Run</div>
                <div class="metric-value">{report.tests_run}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Jailbreaks</div>
                <div class="metric-value">{report.jailbreaks}</div>
            </div>
            <div class="metric-card risk">
                <div class="metric-label">Attack Success Rate</div>
                <div class="metric-value risk">{report.asr:.1%}</div>
                <div style="margin-top:10px">
                    <span class="badge {'badge-success' if report.asr < 0.2 else 'badge-warning' if report.asr < 0.5 else 'badge-danger'}">
                        {risk_level} RISK
                    </span>
                </div>
            </div>
        </div>

        <p><strong>95% Confidence Interval:</strong> [{report.asr_confidence_interval[0]:.2%}, {report.asr_confidence_interval[1]:.2%}]</p>

        <h2>Cost Analysis</h2>
        <p>
            <strong>Total Cost:</strong> ${report.total_cost:.4f}<br>
            <strong>Cache Hit Rate:</strong> {report.cache_hit_rate:.2%}
        </p>

        <h2>Category Breakdown</h2>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Tests</th>
                    <th>Jailbreaks</th>
                    <th>ASR</th>
                </tr>
            </thead>
            <tbody>
"""

        for category, stats in sorted(report.category_breakdown.items()):
            html += f"""
                <tr>
                    <td>{category}</td>
                    <td>{stats['total']}</td>
                    <td>{stats['jailbreaks']}</td>
                    <td>{stats['asr']:.1%}</td>
                </tr>
"""

        html += """
            </tbody>
        </table>
"""

        if report.high_risk_tests:
            html += f"""
        <h2>High-Risk Tests ({len(report.high_risk_tests)})</h2>
        <p>Tests with score >= 8.0 (successful jailbreaks):</p>
        <table>
            <thead>
                <tr>
                    <th>Test ID</th>
                    <th>Category</th>
                    <th>Score</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>
"""

            for test in report.high_risk_tests[:20]:
                html += f"""
                <tr>
                    <td>{test.test_id}</td>
                    <td>{test.category}</td>
                    <td>{test.judge_score:.1f}</td>
                    <td>{test.confidence:.1%}</td>
                </tr>
"""

            html += """
            </tbody>
        </table>
"""

            if len(report.high_risk_tests) > 20:
                html += f"<p><em>...and {len(report.high_risk_tests) - 20} more</em></p>"

        html += """
        <div class="footer">
            Generated by AI Purple Ops Verification System
        </div>
    </div>
</body>
</html>
"""

        return html
