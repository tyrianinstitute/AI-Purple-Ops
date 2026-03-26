"""Executive-grade HTML report generator for CISO-ready deliverables."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from aipop import __version__
from aipop.data import get_finding_info, load_taxonomy
from aipop.reporters.utils import sanitize_surrogates
from aipop.utils.errors import HarnessError


class ExecutiveReportError(HarnessError):
    """Error generating executive report."""


# ---------------------------------------------------------------------------
# OWASP / compliance reference data
# ---------------------------------------------------------------------------

OWASP_LLM_TOP_10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Insecure Plugin Design",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft",
}

OWASP_AGENTIC_TOP_10 = {
    "ASI-01": "Agent Goal Hijacking",
    "ASI-02": "Agentic Tool Misuse",
    "ASI-03": "Identity & Privilege Abuse",
    "ASI-04": "Agentic Supply Chain",
    "ASI-05": "Uncontrolled Autonomy",
    "ASI-06": "Memory & Context Poisoning",
    "ASI-07": "Agentic Data Leakage",
    "ASI-08": "Insecure Multi-Agent Communication",
    "ASI-09": "Agentic Monitoring Gaps",
    "ASI-10": "Human Oversight Failure",
}

NIST_AI_RMF = [
    ("GOVERN", "GV-1", "Policies and procedures for AI risk management"),
    ("GOVERN", "GV-2", "Roles and responsibilities for AI oversight"),
    ("GOVERN", "GV-3", "Workforce AI risk awareness and training"),
    ("MAP", "MP-1", "Context and intended purpose of AI system"),
    ("MAP", "MP-2", "Classification of AI system by risk tier"),
    ("MAP", "MP-3", "Benefits and costs of AI deployment"),
    ("MEASURE", "MS-1", "AI risk metrics and measurement approaches"),
    ("MEASURE", "MS-2", "AI system performance and security testing"),
    ("MEASURE", "MS-3", "Third-party AI risk evaluation"),
    ("MANAGE", "MG-1", "Risk treatment and response for AI systems"),
    ("MANAGE", "MG-2", "AI risk management in the deployment lifecycle"),
    ("MANAGE", "MG-3", "Post-deployment AI monitoring and incident response"),
]

SOC2_MAPPING = [
    ("CC6.1", "Logical and physical access controls",
     "AI model access controls, prompt injection defenses, input validation"),
    ("CC6.2", "System credentials and authentication",
     "Agent identity management, credential handling in AI contexts"),
    ("CC6.3", "Authorization to access system components",
     "Tool authorization, agentic permission boundaries, privilege escalation prevention"),
    ("CC6.6", "Restrictions on system inputs and outputs",
     "Input filtering, output DLP, prompt injection prevention, content safety"),
    ("CC6.7", "Data transmission protection",
     "Protection of data in AI agent tool calls, exfiltration prevention"),
    ("CC7.1", "Detection of unauthorized changes",
     "RAG poisoning detection, memory integrity, context manipulation monitoring"),
    ("CC7.2", "Monitoring for anomalous activity",
     "Behavioral drift detection, multi-turn attack monitoring, agent activity logging"),
    ("CC7.3", "Evaluation of security events",
     "AI security incident triage, finding severity classification, evidence collection"),
    ("CC8.1", "Authorization of system changes",
     "Agent tool call authorization, human-in-the-loop controls for destructive actions"),
]


# ---------------------------------------------------------------------------
# Risk mapping helpers
# ---------------------------------------------------------------------------

_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CVSS_TO_SEVERITY = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
]


def _cvss_to_severity(score: float) -> str:
    for threshold, label in _CVSS_TO_SEVERITY:
        if score >= threshold:
            return label
    return "info"


def _worst_severity(severities: list[str]) -> str:
    if not severities:
        return "info"
    return min(severities, key=lambda s: _RISK_ORDER.get(s, 99))


# ---------------------------------------------------------------------------
# ExecutiveReport
# ---------------------------------------------------------------------------


class ExecutiveReport:
    """Generate executive HTML report from AIPOP scan results."""

    def generate(
        self,
        summary_path: str | Path,
        transcripts_dir: str | Path,
        output_path: str | Path,
        config: dict[str, Any] | None = None,
    ) -> Path:
        """Generate executive HTML report.

        Args:
            summary_path: Path to summary.json
            transcripts_dir: Path to transcripts directory
            output_path: Output HTML file path
            config: Optional config dict with client_name, assessor_name,
                    engagement_id, scope, date_range

        Returns:
            Path to generated HTML report.
        """
        summary_path = Path(summary_path)
        transcripts_dir = Path(transcripts_dir)
        output_path = Path(output_path)
        config = config or {}

        if not summary_path.exists():
            msg = f"Summary file not found: {summary_path}"
            raise ExecutiveReportError(msg)

        # Load data
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        transcripts = self._load_transcripts(transcripts_dir)
        taxonomy = load_taxonomy().get("findings", {})

        # Build context
        ctx = self._build_context(summary, transcripts, taxonomy, config)

        # Render template
        template_dir = Path(__file__).parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,
        )
        template = env.get_template("executive.html")
        html = template.render(**ctx)

        # Write output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(sanitize_surrogates(html), encoding="utf-8")
        return output_path

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_transcripts(self, transcripts_dir: Path) -> dict[str, dict]:
        """Load all transcript JSON files keyed by test_id."""
        transcripts: dict[str, dict] = {}
        if not transcripts_dir.exists():
            return transcripts
        for path in sorted(transcripts_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                tid = data.get("test_id", path.stem)
                transcripts[tid] = data
            except (json.JSONDecodeError, KeyError):
                continue
        return transcripts

    # ------------------------------------------------------------------
    # Context building
    # ------------------------------------------------------------------

    def _build_context(
        self,
        summary: dict,
        transcripts: dict[str, dict],
        taxonomy: dict[str, Any],
        config: dict[str, Any],
    ) -> dict[str, Any]:
        """Build the full Jinja2 template context."""
        results = summary.get("results", [])
        now = datetime.now(UTC)

        # Merge transcript data into results
        enriched = []
        for r in results:
            tid = r["test_id"]
            transcript = transcripts.get(tid, {})
            info = taxonomy.get(tid, {})
            enriched.append(self._enrich_result(r, transcript, info))

        # Separate findings by confidence level
        # Main report: firm + certain only (no tentative noise)
        # Appendix: tentative findings flagged as "needs manual review"
        min_confidence = config.get("min_confidence", "firm")
        confidence_order = {"certain": 3, "firm": 2, "tentative": 1}
        min_level = confidence_order.get(min_confidence, 2)

        all_findings = [e for e in enriched if not e["passed"] and e["cvss"] > 0]
        findings = [
            f for f in all_findings
            if confidence_order.get(f.get("confidence", "tentative"), 1) >= min_level
        ]
        tentative_findings = [
            f for f in all_findings
            if confidence_order.get(f.get("confidence", "tentative"), 1) < min_level
        ]

        # Sort by CVSS descending
        findings.sort(key=lambda f: (f["cvss"] or 0), reverse=True)
        tentative_findings.sort(key=lambda f: (f["cvss"] or 0), reverse=True)

        # Assign sequential report finding IDs
        for i, f in enumerate(findings, 1):
            f["finding_id"] = f"AI-{now.year}-{i:03d}"
        for i, f in enumerate(tentative_findings, len(findings) + 1):
            f["finding_id"] = f"AI-{now.year}-{i:03d}"

        # Determine severity for each finding
        for f in findings:
            f["severity"] = _cvss_to_severity(f["cvss"])

        severity_counts = Counter(f["severity"] for f in findings)
        all_severities = [f["severity"] for f in findings]
        overall_risk = _worst_severity(all_severities)

        total = summary.get("total", len(results))
        passed = summary.get("passed", 0)
        pass_rate = (passed / total * 100) if total > 0 else 100.0

        return {
            # Cover
            "client_name": config.get("client_name", "AI System Assessment"),
            "assessor_name": config.get("assessor_name", "AI Purple Ops"),
            "engagement_id": config.get("engagement_id", f"AIPOP-{now:%Y%m%d}"),
            "date_range": config.get("date_range", now.strftime("%Y-%m-%d")),
            "scope": config.get("scope", "AI model endpoint security assessment"),
            "report_date": now.strftime("%B %d, %Y"),
            "report_timestamp": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            # Executive summary
            "overall_risk": overall_risk,
            "total_tests": total,
            "severity_counts": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
            },
            "pass_rate": pass_rate,
            "executive_bullets": self._generate_exec_bullets(findings, total, passed),
            "recommendation_summary": self._generate_recommendation(findings),
            # Findings (firm + certain confidence only)
            "findings": findings,
            # Tentative findings (needs manual review — in appendix)
            "tentative_findings": tentative_findings,
            "tentative_count": len(tentative_findings),
            # All results for raw evidence appendix
            "all_results": enriched,
            # Compliance
            "nist_mapping": self._build_nist_mapping(findings),
            "owasp_llm_coverage": self._build_owasp_coverage(
                enriched, OWASP_LLM_TOP_10, "owasp_llm"
            ),
            "owasp_agentic_coverage": self._build_owasp_coverage(
                enriched, OWASP_AGENTIC_TOP_10, "owasp_agentic"
            ),
            "soc2_mapping": self._build_soc2_mapping(findings),
            # Methodology
            "aipop_version": __version__,
            "adapter_name": self._extract_adapter(results),
            "model_name": self._extract_model(results),
            "suites_run": self._extract_suites(results),
            "total_cost": summary.get("cost_usd", 0),
            "p50_latency": summary.get("latency_ms_p50", 0),
        }

    def _enrich_result(
        self,
        result: dict,
        transcript: dict,
        info: dict,
    ) -> dict[str, Any]:
        """Combine summary result, transcript, and taxonomy into a finding dict."""
        tid = result["test_id"]
        meta = result.get("metadata", {})

        # Get prompt from transcript or metadata
        prompt = transcript.get("prompt", meta.get("description", "N/A"))
        response = result.get("response", transcript.get("response", "N/A"))

        # Detector evidence
        detector_evidence = []
        confidence = "tentative"
        for dr in result.get("detector_results", []):
            dr_meta = dr.get("metadata", {})
            if dr_meta.get("evidence"):
                detector_evidence.extend(dr_meta["evidence"])
            if dr_meta.get("confidence"):
                confidence = dr_meta["confidence"]
            if dr_meta.get("verdict"):
                detector_evidence.insert(0, f"Verdict: {dr_meta['verdict']}")

        return {
            "id": tid,
            "title": info.get("title", tid),
            "description": info.get("description", meta.get("description", "")),
            "remediation": info.get("remediation", "Review and address this finding."),
            "category": meta.get("category", "uncategorized"),
            "technique": meta.get("technique", None),
            "risk": meta.get("risk", "medium"),
            "passed": result.get("passed", True),
            "prompt": prompt,
            "response": response,
            "confidence": confidence,
            "detector_evidence": detector_evidence,
            "cvss": info.get("cvss_estimate", 0.0),
            "owasp_llm": info.get("owasp_llm"),
            "owasp_agentic": info.get("owasp_agentic"),
            "atlas": info.get("atlas"),
            "cwe": info.get("cwe"),
            "references": info.get("references", []),
            "severity": _cvss_to_severity(info.get("cvss_estimate", 0.0)),
            "suite_id": meta.get("suite_id", ""),
        }

    # ------------------------------------------------------------------
    # Executive summary generation
    # ------------------------------------------------------------------

    def _generate_exec_bullets(
        self, findings: list[dict], total: int, passed: int
    ) -> list[str]:
        """Generate 3-5 plain-English executive summary bullets."""
        bullets: list[str] = []
        failed = total - passed

        if not findings:
            bullets.append(
                f"All {total} security tests passed. No exploitable vulnerabilities were identified."
            )
            return bullets

        # Top-line stat
        bullets.append(
            f"Of {total} security tests executed, {failed} identified potential vulnerabilities "
            f"in the target AI system."
        )

        # Severity breakdown
        sev = Counter(f["severity"] for f in findings)
        if sev.get("critical"):
            bullets.append(
                f"{sev['critical']} critical-severity finding(s) require immediate remediation "
                f"to prevent exploitation."
            )
        if sev.get("high"):
            bullets.append(
                f"{sev['high']} high-severity finding(s) should be addressed before "
                f"the next production release."
            )

        # Most common category
        cats = Counter(f["category"] for f in findings)
        top_cat, top_count = cats.most_common(1)[0]
        bullets.append(
            f"The most prevalent attack category was {top_cat.replace('_', ' ')} "
            f"({top_count} finding(s)), indicating a systemic weakness in this area."
        )

        # OWASP coverage
        owasp_ids = {f["owasp_llm"] for f in findings if f.get("owasp_llm")}
        if owasp_ids:
            bullets.append(
                f"Findings map to {len(owasp_ids)} OWASP LLM Top 10 categories: "
                f"{', '.join(sorted(owasp_ids))}."
            )

        return bullets[:5]

    def _generate_recommendation(self, findings: list[dict]) -> str:
        """Generate a one-paragraph recommendation summary."""
        if not findings:
            return (
                "The assessed AI system demonstrated strong resistance to the tested attack "
                "patterns. Continue periodic security assessments and expand test coverage "
                "as new attack techniques emerge."
            )

        sev = Counter(f["severity"] for f in findings)
        parts = []
        if sev.get("critical") or sev.get("high"):
            parts.append(
                "Prioritize remediation of critical and high-severity findings before "
                "the system is exposed to untrusted input in production."
            )
        cats = Counter(f["category"] for f in findings)
        top_cat = cats.most_common(1)[0][0].replace("_", " ")
        parts.append(
            f"The concentration of findings in {top_cat} suggests a need for "
            f"defense-in-depth controls in this area, including input classification, "
            f"output filtering, and behavioral monitoring."
        )
        parts.append(
            "A retest is recommended after remediation to validate that fixes are effective "
            "and do not introduce regressions."
        )
        return " ".join(parts)

    # ------------------------------------------------------------------
    # Compliance mappings
    # ------------------------------------------------------------------

    def _build_nist_mapping(self, findings: list[dict]) -> list[dict]:
        """Build NIST AI RMF mapping table."""
        rows = []
        for func, cat, desc in NIST_AI_RMF:
            related: list[str] = []
            # MS-2 (testing) maps to all findings
            if cat == "MS-2" and findings:
                related = [f["id"] for f in findings[:5]]
            # MG-1 (risk treatment) maps to findings with remediation
            elif cat == "MG-1" and findings:
                related = [f["id"] for f in findings[:3]]
            # MG-3 (monitoring) maps to behavioral drift findings
            elif cat == "MG-3":
                related = [
                    f["id"] for f in findings
                    if f.get("category") in ("crescendo", "delayed_payload", "context_confusion")
                ][:3]
            # MS-1 (metrics) — we provide metrics
            elif cat == "MS-1" and findings:
                related = ["Assessment metrics provided"]

            rows.append({
                "function": f"{func} ({cat})",
                "category": desc,
                "findings": related,
            })
        return rows

    def _build_owasp_coverage(
        self,
        all_results: list[dict],
        owasp_map: dict[str, str],
        field: str,
    ) -> list[dict]:
        """Build OWASP coverage matrix."""
        rows = []
        for oid, name in owasp_map.items():
            tested = [r for r in all_results if r.get(field) == oid]
            failed = [r for r in tested if not r["passed"]]
            rows.append({
                "id": oid,
                "name": name,
                "tested": bool(tested),
                "test_count": len(tested),
                "finding_count": len(failed),
            })
        return rows

    def _build_soc2_mapping(self, findings: list[dict]) -> list[dict]:
        """Build SOC 2 relevance table."""
        rows = []
        for criteria, desc, relevance in SOC2_MAPPING:
            # Map findings by category relevance
            related: list[str] = []
            if "injection" in relevance.lower() or "input" in relevance.lower():
                related = [
                    f["id"] for f in findings
                    if f.get("category") in ("prompt_injection", "context_confusion", "encoding_bypass")
                ][:3]
            elif "exfiltration" in relevance.lower() or "output" in relevance.lower():
                related = [
                    f["id"] for f in findings
                    if f.get("category") in ("data_exfiltration", "privacy")
                ][:3]
            elif "poisoning" in relevance.lower() or "integrity" in relevance.lower():
                related = [
                    f["id"] for f in findings
                    if f.get("category") in ("delayed_payload", "memory_poisoning", "rag_poisoning")
                ][:3]
            elif "monitoring" in relevance.lower() or "drift" in relevance.lower():
                related = [
                    f["id"] for f in findings
                    if f.get("category") in ("crescendo", "multi_turn")
                ][:3]
            elif "authorization" in relevance.lower() or "tool" in relevance.lower():
                related = [
                    f["id"] for f in findings
                    if "asi02" in f["id"] or "asi03" in f["id"]
                ][:3]
            elif "credential" in relevance.lower() or "identity" in relevance.lower():
                related = [
                    f["id"] for f in findings
                    if "asi03" in f["id"] or "credential" in f["id"]
                ][:3]

            rows.append({
                "criteria": criteria,
                "description": desc,
                "relevance": relevance,
                "findings": related,
            })
        return rows

    # ------------------------------------------------------------------
    # Metadata extraction
    # ------------------------------------------------------------------

    def _extract_adapter(self, results: list[dict]) -> str:
        for r in results:
            model_meta = r.get("metadata", {}).get("model_meta", {})
            if model_meta.get("model"):
                # Infer adapter from model name
                model = model_meta["model"]
                if "gpt" in model:
                    return "openai"
                if "claude" in model:
                    return "anthropic"
                if "mock" in model:
                    return "mock"
                return model.split("-")[0]
        return "unknown"

    def _extract_model(self, results: list[dict]) -> str:
        for r in results:
            model_meta = r.get("metadata", {}).get("model_meta", {})
            if model_meta.get("model"):
                return model_meta["model"]
        return "unknown"

    def _extract_suites(self, results: list[dict]) -> list[str]:
        suites = set()
        for r in results:
            sid = r.get("metadata", {}).get("suite_id")
            if sid:
                suites.add(sid)
        return sorted(suites)
