"""Recon-driven attack planning — select suites from discovered surface."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackPlan:
    """What to test, based on what recon found."""

    suites: list[str] = field(default_factory=list)
    fuzz_config: dict[str, Any] | None = None
    chain_templates: list[str] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    estimated_tests: int = 0
    estimated_duration_sec: int = 0


# Rough test counts per suite — used for estimation only.
# These don't need to be exact; they give the user a ballpark.
_SUITE_TEST_COUNTS: dict[str, int] = {
    "adversarial/context_confusion": 8,
    "adversarial/rag_injection": 10,
    "adversarial/tool_misuse": 12,
    "rag/rag_poisoning": 8,
    "agentic/cve_regression": 6,
    "chains/indirect_upload": 5,
    "chains/indirect_email": 4,
    "chains/memory_poisoning": 6,
}


def plan_attack(recon_report, *, rate_limit: float = 5.0) -> AttackPlan:
    """Generate an attack plan from recon findings.

    Deterministic: same recon input always produces the same plan.

    Logic:
    - Always include: adversarial/context_confusion (basic injection tests)
    - If RAG detected: add adversarial/rag_injection, rag/rag_poisoning
    - If upload endpoint found AND unguarded: add fuzz config targeting upload + indirect chain
    - If upload endpoint found AND guarded: add fuzz config with --morph (need obfuscation to bypass)
    - If tool calling detected: add adversarial/tool_misuse, agentic/cve_regression
    - If email ingestion found: add chain template indirect_email
    - If memory/state detected: add chains/memory_poisoning
    - If no special surfaces: just run the default adversarial suite

    Skip logic:
    - Skip tool_misuse if no tools detected (waste of time and budget)
    - Skip rag_poisoning if no RAG detected
    - Skip email chains if no email ingestion
    """
    plan = AttackPlan()

    # ── Always included ──────────────────────────────────────────
    plan.suites.append("adversarial/context_confusion")
    plan.reasoning.append("adversarial/context_confusion — always included (baseline injection tests)")

    # ── RAG surface ──────────────────────────────────────────────
    if recon_report.has_rag:
        rag_detail = recon_report.rag_evidence[:80] if recon_report.rag_evidence else "behavioral probe"
        plan.suites.append("adversarial/rag_injection")
        plan.reasoning.append(f"adversarial/rag_injection — RAG detected ({rag_detail})")
        plan.suites.append("rag/rag_poisoning")
        plan.reasoning.append(f"rag/rag_poisoning — RAG detected, test document poisoning")
    else:
        plan.skipped.append("adversarial/rag_injection — skipped (no RAG detected)")
        plan.skipped.append("rag/rag_poisoning — skipped (no RAG detected)")

    # ── Upload surface ───────────────────────────────────────────
    if recon_report.upload_endpoints:
        upload_path = recon_report.upload_endpoints[0]
        if recon_report.upload_guarded is False:
            plan.fuzz_config = {
                "target_endpoint": upload_path,
                "mode": "indirect_injection",
                "morph": False,
            }
            plan.chain_templates.append("chains/indirect_upload")
            plan.reasoning.append(
                f"indirect upload fuzz — {upload_path} found, UNGUARDED "
                f"(direct document injection viable)"
            )
        elif recon_report.upload_guarded is True:
            plan.fuzz_config = {
                "target_endpoint": upload_path,
                "mode": "indirect_injection",
                "morph": True,
            }
            plan.chain_templates.append("chains/indirect_upload")
            plan.reasoning.append(
                f"indirect upload fuzz with --morph — {upload_path} found, GUARDED "
                f"(obfuscation needed to bypass content filter)"
            )
        else:
            # upload_guarded is None — unknown guard status
            plan.fuzz_config = {
                "target_endpoint": upload_path,
                "mode": "indirect_injection",
                "morph": False,
            }
            plan.chain_templates.append("chains/indirect_upload")
            plan.reasoning.append(
                f"indirect upload fuzz — {upload_path} found, guard status unknown"
            )

    # ── Tool calling surface ─────────────────────────────────────
    if recon_report.has_tools:
        tool_detail = recon_report.tool_evidence[:80] if recon_report.tool_evidence else "behavioral probe"
        plan.suites.append("adversarial/tool_misuse")
        plan.reasoning.append(f"adversarial/tool_misuse — tool calling detected ({tool_detail})")
        plan.suites.append("agentic/cve_regression")
        plan.reasoning.append("agentic/cve_regression — tool calling detected, test known CVE patterns")
    else:
        plan.skipped.append("adversarial/tool_misuse — skipped (no tools detected)")
        plan.skipped.append("agentic/cve_regression — skipped (no tools detected)")

    # ── Email ingestion surface ──────────────────────────────────
    if recon_report.ingestion_endpoints:
        endpoints = ", ".join(recon_report.ingestion_endpoints)
        plan.chain_templates.append("chains/indirect_email")
        plan.reasoning.append(f"chains/indirect_email — email ingestion found ({endpoints})")
    else:
        plan.skipped.append("chains/indirect_email — skipped (no email ingestion)")

    # ── Memory/state surface ─────────────────────────────────────
    if recon_report.has_memory:
        mem_detail = recon_report.memory_evidence[:80] if recon_report.memory_evidence else "behavioral probe"
        plan.chain_templates.append("chains/memory_poisoning")
        plan.reasoning.append(f"chains/memory_poisoning — stateful memory detected ({mem_detail})")
    else:
        plan.skipped.append("chains/memory_poisoning — skipped (stateless target)")

    # ── Estimation ───────────────────────────────────────────────
    test_count = 0
    for s in plan.suites:
        test_count += _SUITE_TEST_COUNTS.get(s, 8)
    for ct in plan.chain_templates:
        test_count += _SUITE_TEST_COUNTS.get(ct, 5)
    if plan.fuzz_config:
        test_count += 10  # fuzz adds roughly 10 permutations

    plan.estimated_tests = test_count
    plan.estimated_duration_sec = math.ceil(test_count / rate_limit) if rate_limit > 0 else 0

    return plan


def format_plan(plan: AttackPlan) -> str:
    """Format an AttackPlan for terminal display (plain text, no Rich markup)."""
    lines: list[str] = []
    lines.append("  attack plan (based on recon):")

    for reason in plan.reasoning:
        lines.append(f"    \u2713 {reason}")
    for skip in plan.skipped:
        lines.append(f"    \u2717 {skip}")

    rate = plan.estimated_duration_sec
    lines.append("")
    lines.append(
        f"    estimated: {plan.estimated_tests} tests, "
        f"~{rate} seconds"
    )

    return "\n".join(lines)
