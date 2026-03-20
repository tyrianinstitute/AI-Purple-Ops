"""OWASP coverage tracking command."""

from __future__ import annotations

import json
import sys
from typing import Any

from rich.console import Console
from rich.table import Table

from aipop.utils.paths import get_package_data_path

# OWASP risk definitions
OWASP_LLM_TOP_10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft",
}

OWASP_AGENTIC_TOP_10 = {
    "ASI01": "Agent Goal Hijacking",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}


def get_coverage(output_json: bool = False) -> dict[str, Any]:
    """Scan all suites and map test cases to OWASP risk IDs."""
    import yaml

    suites_dir = get_package_data_path("suites")
    coverage: dict[str, list[str]] = {
        **{k: [] for k in OWASP_LLM_TOP_10},
        **{k: [] for k in OWASP_AGENTIC_TOP_10},
    }

    # Scan all YAML suite files
    for yaml_file in suites_dir.rglob("*.yaml"):
        try:
            with yaml_file.open() as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict) or "cases" not in data:
                continue
            for case in data.get("cases", []):
                if not isinstance(case, dict):
                    continue
                meta = case.get("metadata", {})
                test_id = case.get("id", "unknown")

                # Check for owasp_agentic mapping
                asi = meta.get("owasp_agentic", "")
                if asi and asi in coverage:
                    coverage[asi].append(test_id)

                # Map categories to LLM Top 10
                category = meta.get("category", "").lower()
                category_to_llm = {
                    "prompt_injection": "LLM01",
                    "adversarial_suffix": "LLM01",
                    "gcg_universal": "LLM01",
                    "encoding_bypass": "LLM01",
                    "context_confusion": "LLM01",
                    "jailbreak": "LLM01",
                    "data_exfiltration": "LLM06",
                    "rag_poisoning": "LLM03",
                    "rag_leakage": "LLM06",
                    "tool_misuse": "LLM08",
                    "multi_turn": "LLM01",
                    "delayed_payload": "LLM01",
                    "agent_goal_hijacking": "LLM01",
                    "agentic_tool_misuse": "LLM08",
                    "identity_privilege_abuse": "LLM08",
                    "agentic_supply_chain": "LLM05",
                    "unexpected_code_execution": "LLM02",
                    "memory_context_poisoning": "LLM03",
                }
                llm_risk = category_to_llm.get(category)
                if llm_risk and llm_risk in coverage:
                    if test_id not in coverage[llm_risk]:
                        coverage[llm_risk].append(test_id)

        except Exception:
            continue

    # Determine coverage depth per ASI risk
    # HARNESS = has a dedicated harness module (not just YAML prompts)
    # TAGGED = has YAML test cases with ASI metadata
    # GAP = no coverage
    asi_harness_support = {
        "ASI01": False,  # No dedicated harness yet, prompt-level only
        "ASI02": False,
        "ASI03": True,   # principal_propagation.py
        "ASI04": True,   # tool_integrity.py gate
        "ASI05": False,
        "ASI06": True,   # memory_poisoning.py
        "ASI07": True,   # a2a_integrity.py
        "ASI08": True,   # a2a_integrity.py (cascading)
        "ASI09": True,   # approval_manipulation.py
        "ASI10": False,
    }

    result = {
        "owasp_llm_top_10": {
            k: {"name": OWASP_LLM_TOP_10[k], "test_count": len(v), "test_ids": v}
            for k, v in coverage.items() if k.startswith("LLM")
        },
        "owasp_agentic_top_10": {
            k: {
                "name": OWASP_AGENTIC_TOP_10[k],
                "test_count": len(v),
                "test_ids": v,
                "has_harness": asi_harness_support.get(k, False),
                "depth": "HARNESS" if asi_harness_support.get(k, False) else ("TAGGED" if len(v) > 0 else "GAP"),
            }
            for k, v in coverage.items() if k.startswith("ASI")
        },
    }

    # Summary stats
    llm_covered = sum(1 for k, v in result["owasp_llm_top_10"].items() if v["test_count"] > 0)
    asi_covered = sum(1 for k, v in result["owasp_agentic_top_10"].items() if v["test_count"] > 0)
    result["summary"] = {
        "llm_top_10_covered": f"{llm_covered}/10",
        "agentic_top_10_covered": f"{asi_covered}/10",
        "total_mapped_tests": sum(v["test_count"] for v in result["owasp_llm_top_10"].values()) + sum(v["test_count"] for v in result["owasp_agentic_top_10"].values()),
    }

    return result


def print_coverage(output_json: bool = False) -> None:
    """Print OWASP coverage report."""
    result = get_coverage()

    if output_json:
        # Strip test_ids for cleaner JSON
        for section in ["owasp_llm_top_10", "owasp_agentic_top_10"]:
            for k in result[section]:
                del result[section][k]["test_ids"]
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
        return

    console = Console()
    console.print("\n[bold]OWASP Coverage Report[/bold]\n")

    # LLM Top 10
    table = Table(title="OWASP LLM Top 10 (2025)")
    table.add_column("Risk ID", style="cyan")
    table.add_column("Name")
    table.add_column("Tests", justify="right")
    table.add_column("Status", justify="center")

    for risk_id in sorted(result["owasp_llm_top_10"]):
        entry = result["owasp_llm_top_10"][risk_id]
        count = entry["test_count"]
        status = "[green]COVERED[/]" if count > 0 else "[red]GAP[/]"
        table.add_row(risk_id, entry["name"], str(count), status)

    console.print(table)
    console.print()

    # Agentic Top 10 with depth indicator
    table2 = Table(title="OWASP Agentic Top 10 (2026)")
    table2.add_column("Risk ID", style="cyan")
    table2.add_column("Name")
    table2.add_column("Tests", justify="right")
    table2.add_column("Depth", justify="center")

    for risk_id in sorted(result["owasp_agentic_top_10"]):
        entry = result["owasp_agentic_top_10"][risk_id]
        count = entry["test_count"]
        depth = entry.get("depth", "GAP")
        depth_display = {
            "HARNESS": "[bold green]HARNESS[/]",
            "TAGGED": "[yellow]TAGGED[/]",
            "GAP": "[red]GAP[/]",
        }.get(depth, f"[dim]{depth}[/]")
        table2.add_row(risk_id, entry["name"], str(count), depth_display)

    console.print(table2)
    console.print()

    summary = result["summary"]
    console.print(f"[bold]LLM Top 10:[/bold] {summary['llm_top_10_covered']} risks covered")
    console.print(f"[bold]Agentic Top 10:[/bold] {summary['agentic_top_10_covered']} risks covered")
    console.print(f"[bold]Total mapped tests:[/bold] {summary['total_mapped_tests']}")
    console.print()
