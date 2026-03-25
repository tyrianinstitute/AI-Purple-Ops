"""Markdown report generator for bounty submissions and pentest deliverables."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aipop import __version__
from aipop.data import get_finding_info, load_taxonomy
from aipop.utils.errors import HarnessError


class MarkdownReportError(HarnessError):
    """Error generating markdown report."""


class MarkdownReport:
    """Generate a markdown report from scan results."""

    def generate(
        self,
        summary_path: str | Path,
        transcripts_dir: str | Path,
        output_path: str | Path,
        config: dict[str, Any] | None = None,
    ) -> Path:
        summary_path = Path(summary_path)
        output_path = Path(output_path)
        config = config or {}

        if not summary_path.exists():
            raise MarkdownReportError(f"Summary file not found: {summary_path}")

        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        taxonomy = load_taxonomy().get("findings", {})

        md = self._render(summary, taxonomy, config)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(md, encoding="utf-8")
        return output_path

    def _render(
        self,
        summary: dict,
        taxonomy: dict[str, Any],
        config: dict[str, Any],
    ) -> str:
        lines: list[str] = []
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        client = config.get("client_name", "Target")
        assessor = config.get("assessor_name", "Assessor")
        adapter = summary.get("adapter", "unknown")

        lines.append(f"# AI Agent Security Assessment — {client}")
        lines.append("")
        lines.append(f"**Date:** {now}")
        lines.append(f"**Assessor:** {assessor}")
        lines.append(f"**Tool:** AIPOP v{__version__}")
        lines.append(f"**Adapter:** {adapter}")
        lines.append(f"**Mode:** {'LIVE' if adapter != 'mock' else 'MOCK (simulated)'}")
        lines.append("")

        # Summary stats
        total = summary.get("total", 0)
        passed = summary.get("passed", 0)
        failed = summary.get("failed", 0)
        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Tests executed | {total} |")
        lines.append(f"| Passed | {passed} |")
        lines.append(f"| Failed (findings) | {failed} |")
        lines.append(f"| Harmful output rate | {summary.get('harmful_output_rate', 0):.1%} |")
        lines.append(f"| Critical violation rate | {summary.get('critical_violation_rate', 0):.1%} |")
        lines.append("")

        # Findings
        results = summary.get("results", [])
        findings = [r for r in results if not r.get("passed", True)]

        if not findings:
            lines.append("## Findings")
            lines.append("")
            lines.append("No findings detected.")
            lines.append("")
        else:
            lines.append(f"## Findings ({len(findings)})")
            lines.append("")

            for i, f in enumerate(findings, 1):
                test_id = f.get("test_id", f"finding-{i}")
                meta = f.get("metadata", {})
                severity = meta.get("risk", meta.get("severity", "medium")).upper()
                category = meta.get("category", "unknown")

                # Look up taxonomy info
                info = get_finding_info(test_id)
                title = info.get("title", test_id) if info else test_id
                description = info.get("description", "") if info else ""
                remediation = info.get("remediation", "") if info else ""
                owasp_llm = info.get("owasp_llm", []) if info else []
                owasp_agentic = info.get("owasp_agentic", []) if info else []
                cwe = info.get("cwe", []) if info else []
                cvss = info.get("cvss_estimate", "") if info else ""

                lines.append(f"### {i}. {title}")
                lines.append("")
                lines.append(f"**Severity:** {severity}")
                if cvss:
                    lines.append(f"**CVSS:** {cvss}")
                if owasp_llm:
                    items = owasp_llm if isinstance(owasp_llm, list) else [owasp_llm]
                    lines.append(f"**OWASP LLM:** {', '.join(items)}")
                if owasp_agentic:
                    items = owasp_agentic if isinstance(owasp_agentic, list) else [owasp_agentic]
                    lines.append(f"**OWASP Agentic:** {', '.join(items)}")
                if cwe:
                    items = cwe if isinstance(cwe, list) else [cwe]
                    lines.append(f"**CWE:** {', '.join(items)}")
                lines.append(f"**Category:** {category}")
                lines.append(f"**Test ID:** `{test_id}`")
                lines.append("")

                if description:
                    lines.append(f"**Description:** {description}")
                    lines.append("")

                # Evidence — prompt may be in metadata or test_case, response in results
                prompt = f.get("prompt", "") or f.get("metadata", {}).get("prompt", "")
                response = f.get("response", "")
                if prompt:
                    lines.append("**Prompt:**")
                    lines.append(f"```")
                    lines.append(prompt[:500])
                    lines.append(f"```")
                    lines.append("")
                if response:
                    lines.append("**Response:**")
                    lines.append(f"```")
                    lines.append(response[:500])
                    lines.append(f"```")
                    lines.append("")

                if remediation:
                    lines.append(f"**Remediation:** {remediation}")
                    lines.append("")

                lines.append("---")
                lines.append("")

        # Footer
        lines.append("")
        lines.append(f"*Generated by AIPOP v{__version__} on {now}*")

        return "\n".join(lines)
