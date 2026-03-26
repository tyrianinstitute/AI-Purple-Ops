"""Export findings to engagement platforms (Ghostwriter CE, Dradis CE).

Converts AIPOP summary.json findings into platform-specific import formats.
Ghostwriter: CSV with fixed header schema for bulk findings import.
Dradis: CSV with Issue/Evidence field mapping.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from aipop.reporters.cvss_cwe_taxonomy import VULNERABILITY_TAXONOMY, VulnerabilityClassifier
from aipop.reporters.utils import sanitize_surrogates


def export_ghostwriter_csv(summary_path: str | Path, output_path: str | Path) -> Path:
    """Export findings as Ghostwriter CE bulk import CSV.

    Ghostwriter CSV schema (required headers):
    title, description, severity, impact, mitigation, replication_steps,
    host_detection_techniques, network_detection_techniques, references,
    finding_type, finding_guidance

    Args:
        summary_path: Path to summary.json from aipop run
        output_path: Path for output CSV

    Returns:
        Path to generated CSV file
    """
    with Path(summary_path).open() as f:
        data = json.load(f)

    classifier = VulnerabilityClassifier()
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    headers = [
        "title", "description", "severity", "impact", "mitigation",
        "replication_steps", "host_detection_techniques",
        "network_detection_techniques", "references", "finding_type",
        "finding_guidance",
    ]

    rows = []
    seen_categories: set[str] = set()

    for result in data.get("results", []):
        if result.get("passed"):
            continue

        meta = result.get("metadata", {})
        category = meta.get("category", "unknown")

        # Deduplicate by category -- one finding per vulnerability type
        if category in seen_categories:
            continue
        seen_categories.add(category)

        # Get taxonomy data
        taxonomy = VULNERABILITY_TAXONOMY.get(category, {})
        risk = meta.get("risk", "medium").capitalize()

        # Build finding fields
        description = taxonomy.get("description", meta.get("description", f"{category} vulnerability detected"))
        remediation = taxonomy.get("remediation", "Review and remediate the identified vulnerability.")
        cwe = taxonomy.get("cwe_id", "")
        owasp = taxonomy.get("owasp_llm", taxonomy.get("owasp_agentic", ""))
        mitre = taxonomy.get("mitre_atlas", "")
        cvss = taxonomy.get("cvss")
        cvss_str = cvss.vector_string if cvss else ""

        impact = f"CVSS: {cvss_str}\n{owasp}" if cvss_str else owasp

        # Replication steps from test case
        prompt = result.get("metadata", {}).get("prompt", meta.get("technique", ""))
        response_preview = sanitize_surrogates(result.get("response", ""))[:200]
        replication = f"Prompt: {prompt}\nResponse: {response_preview}" if prompt else ""

        references = "\n".join(filter(None, [cwe, owasp, mitre]))

        rows.append({
            "title": f"[{risk.upper()}] {category.replace('_', ' ').title()}",
            "description": description,
            "severity": risk,
            "impact": impact,
            "mitigation": remediation,
            "replication_steps": replication,
            "host_detection_techniques": "",
            "network_detection_techniques": "",
            "references": references,
            "finding_type": "AI/LLM Security",
            "finding_guidance": "",
        })

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    return output_path


def export_dradis_csv(summary_path: str | Path, output_path: str | Path) -> Path:
    """Export findings as Dradis CE compatible CSV.

    Dradis uses flexible Issue/Evidence fields mapped on import.
    We use standard field names that map naturally.

    Args:
        summary_path: Path to summary.json
        output_path: Path for output CSV

    Returns:
        Path to generated CSV file
    """
    with Path(summary_path).open() as f:
        data = json.load(f)

    classifier = VulnerabilityClassifier()
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    headers = [
        "Title", "Severity", "Category", "Description", "Remediation",
        "CWE", "CVSS", "OWASP", "Evidence", "Node",
    ]

    rows = []
    seen_categories: set[str] = set()

    for result in data.get("results", []):
        if result.get("passed"):
            continue

        meta = result.get("metadata", {})
        category = meta.get("category", "unknown")

        if category in seen_categories:
            continue
        seen_categories.add(category)

        taxonomy = VULNERABILITY_TAXONOMY.get(category, {})
        risk = meta.get("risk", "medium")
        cvss = taxonomy.get("cvss")

        rows.append({
            "Title": category.replace("_", " ").title(),
            "Severity": risk.upper(),
            "Category": category,
            "Description": taxonomy.get("description", f"{category} vulnerability"),
            "Remediation": taxonomy.get("remediation", ""),
            "CWE": taxonomy.get("cwe_id", ""),
            "CVSS": cvss.vector_string if cvss else "",
            "OWASP": taxonomy.get("owasp_llm", taxonomy.get("owasp_agentic", "")),
            "Evidence": sanitize_surrogates(result.get("response", ""))[:300],
            "Node": data.get("model", data.get("adapter", "target")),
        })

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    return output_path
