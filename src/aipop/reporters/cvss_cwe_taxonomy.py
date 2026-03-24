"""CVSS/CWE taxonomy system for AI vulnerability classification.

Provides CVSS v3.1 scoring, CWE mappings, OWASP LLM Top 10, and MITRE ATLAS
technique mappings for AI/LLM vulnerabilities.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CVSSScore:
    """CVSS v3.1 Score representation.

    Attributes:
        base_score: CVSS base score (0.0-10.0)
        attack_vector: Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)
        attack_complexity: Attack Complexity (L=Low, H=High)
        privileges_required: Privileges Required (N=None, L=Low, H=High)
        user_interaction: User Interaction (N=None, R=Required)
        scope: Scope (U=Unchanged, C=Changed)
        confidentiality: Confidentiality Impact (N=None, L=Low, H=High)
        integrity: Integrity Impact (N=None, L=Low, H=High)
        availability: Availability Impact (N=None, L=Low, H=High)
    """

    base_score: float
    attack_vector: str  # N, A, L, P
    attack_complexity: str  # L, H
    privileges_required: str  # N, L, H
    user_interaction: str  # N, R
    scope: str  # U, C
    confidentiality: str  # N, L, H
    integrity: str  # N, L, H
    availability: str  # N, L, H

    @property
    def vector_string(self) -> str:
        """Generate CVSS vector string."""
        return (
            f"CVSS:3.1/"
            f"AV:{self.attack_vector}/"
            f"AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/"
            f"UI:{self.user_interaction}/"
            f"S:{self.scope}/"
            f"C:{self.confidentiality}/"
            f"I:{self.integrity}/"
            f"A:{self.availability}"
        )


# Vulnerability type to CWE/CVSS/OWASP/MITRE mappings
VULNERABILITY_TAXONOMY: dict[str, dict[str, Any]] = {
    "prompt_injection": {
        "cwe_id": "CWE-77",
        "cwe_name": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
        "owasp_llm": "LLM01:2025 - Prompt Injection",
        "mitre_atlas": "AML.T0051 - LLM Prompt Injection",
        "cvss": CVSSScore(
            base_score=8.1,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="N",
        ),
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Attacker manipulates LLM behavior through crafted input prompts",
        "remediation": "Implement input validation and sanitization before LLM processing. Use separate system/user prompt channels. Deploy a pre-model classifier (e.g., PromptGuard) to detect injection attempts.",
    },
    "jailbreak": {
        "cwe_id": "CWE-863",
        "cwe_name": "Incorrect Authorization",
        "owasp_llm": "LLM01:2025 - Prompt Injection",
        "mitre_atlas": "AML.T0054 - LLM Jailbreak",
        "cvss": CVSSScore(
            base_score=7.5,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="L",
            availability="N",
        ),
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Bypass of safety guardrails and content policy restrictions",
        "remediation": "Layer multiple guardrails (pre-model classifier + post-model filter). Regularly update safety training data. Test with adversarial suffix and multi-turn escalation suites.",
    },
    "tool_misuse": {
        "cwe_id": "CWE-285",
        "cwe_name": "Improper Authorization",
        "owasp_llm": "LLM07:2025 - System Prompt Leakage",
        "mitre_atlas": "AML.T0054 - LLM Jailbreak",
        "cvss": CVSSScore(
            base_score=8.8,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        ),
        "severity": VulnerabilitySeverity.CRITICAL,
        "description": "Unauthorized or malicious use of tool calling capabilities",
        "remediation": "Implement least-privilege tool access. Validate all tool parameters before execution. Add human approval gates for destructive actions. Sandbox tool execution environments.",
    },
    "data_exfiltration": {
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "owasp_llm": "LLM06:2025 - Sensitive Information Disclosure",
        "mitre_atlas": "AML.T0024 - Exfiltration via ML Model",
        "cvss": CVSSScore(
            base_score=7.5,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="N",
            availability="N",
        ),
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Extraction of sensitive training data or system information",
        "remediation": "Implement output filtering for sensitive data patterns (PII, credentials, internal IDs). Add egress monitoring. Limit response length and context exposure.",
    },
    "rag_poisoning": {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "owasp_llm": "LLM03:2025 - Training Data Poisoning",
        "mitre_atlas": "AML.T0018 - Backdoor Attack",
        "cvss": CVSSScore(
            base_score=9.8,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        ),
        "severity": VulnerabilitySeverity.CRITICAL,
        "description": "Injection of malicious data into RAG knowledge base",
        "remediation": "Validate and sanitize all content before ingestion into RAG stores. Implement provenance tracking for retrieval sources. Use content integrity hashes.",
    },
    "indirect_injection": {
        "cwe_id": "CWE-94",
        "cwe_name": "Improper Control of Generation of Code ('Code Injection')",
        "owasp_llm": "LLM01:2025 - Prompt Injection",
        "mitre_atlas": "AML.T0051 - LLM Prompt Injection",
        "cvss": CVSSScore(
            base_score=8.6,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="R",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="N",
        ),
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Malicious instructions embedded in external content (RAG, web pages)",
        "remediation": "Treat all retrieved content as untrusted. Separate instruction and data channels. Deploy content classifiers on RAG retrieval results before LLM processing.",
    },
    "model_denial_of_service": {
        "cwe_id": "CWE-400",
        "cwe_name": "Uncontrolled Resource Consumption",
        "owasp_llm": "LLM04:2025 - Model Denial of Service",
        "mitre_atlas": "AML.T0029 - Denial of ML Service",
        "cvss": CVSSScore(
            base_score=5.3,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="N",
            integrity="N",
            availability="L",
        ),
        "severity": VulnerabilitySeverity.MEDIUM,
        "description": "Resource exhaustion through expensive queries or context overflow",
        "remediation": "Implement request rate limiting and token budget caps. Set maximum context lengths. Monitor for recursive or self-amplifying prompt patterns.",
    },
    "supply_chain": {
        "cwe_id": "CWE-1357",
        "cwe_name": "Reliance on Insufficiently Trustworthy Component",
        "owasp_llm": "LLM05:2025 - Supply Chain Vulnerabilities",
        "mitre_atlas": "AML.T0010 - ML Supply Chain Compromise",
        "cvss": CVSSScore(
            base_score=8.1,
            attack_vector="N",
            attack_complexity="H",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        ),
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Compromise through third-party models, plugins, or datasets",
        "remediation": "Pin model and dependency versions. Verify checksums for downloaded models. Use curated tool/plugin registries. Scan MCP server packages before deployment.",
    },
    "insecure_output_handling": {
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "owasp_llm": "LLM02:2025 - Insecure Output Handling",
        "mitre_atlas": "AML.T0051 - LLM Prompt Injection",
        "cvss": CVSSScore(
            base_score=6.1,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="R",
            scope="C",
            confidentiality="L",
            integrity="L",
            availability="N",
        ),
        "severity": VulnerabilitySeverity.MEDIUM,
        "description": "LLM output used unsafely in web pages or system commands",
        "remediation": "Sanitize all LLM output before rendering in HTML, shell, or SQL contexts. Never pass raw LLM output to eval() or system commands.",
    },
    "excessive_agency": {
        "cwe_id": "CWE-269",
        "cwe_name": "Improper Privilege Management",
        "owasp_llm": "LLM08:2025 - Excessive Agency",
        "mitre_atlas": "AML.T0054 - LLM Jailbreak",
        "cvss": CVSSScore(
            base_score=7.3,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="L",
            integrity="H",
            availability="L",
        ),
        "severity": VulnerabilitySeverity.HIGH,
        "description": "LLM granted excessive permissions or autonomy",
        "remediation": "Scope agent permissions to minimum required. Require human approval for high-impact actions. Implement action budgets and kill switches.",
    },
    "overreliance": {
        "cwe_id": "CWE-1395",
        "cwe_name": "Dependency on Vulnerable Third-Party Component",
        "owasp_llm": "LLM09:2025 - Overreliance",
        "mitre_atlas": "AML.T0043 - Model Evasion",
        "cvss": CVSSScore(
            base_score=4.3,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="R",
            scope="U",
            confidentiality="L",
            integrity="L",
            availability="N",
        ),
        "severity": VulnerabilitySeverity.MEDIUM,
        "description": "Excessive trust in LLM outputs without verification",
        "remediation": "Always present LLM outputs as suggestions requiring human review. Add confidence indicators. Implement fact-checking for critical decisions.",
    },
    "model_theft": {
        "cwe_id": "CWE-506",
        "cwe_name": "Embedded Malicious Code",
        "owasp_llm": "LLM10:2025 - Model Theft",
        "mitre_atlas": "AML.T0024 - Exfiltration via ML Model",
        "cvss": CVSSScore(
            base_score=5.9,
            attack_vector="N",
            attack_complexity="H",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="N",
            availability="N",
        ),
        "severity": VulnerabilitySeverity.MEDIUM,
        "description": "Unauthorized extraction of model weights or architecture",
        "remediation": "Implement API rate limiting and query monitoring. Use watermarking techniques. Restrict model access to authenticated users with audit logging.",
    },
    # OWASP Agentic Top 10 (2026) - ASI01 through ASI10
    "agent_goal_hijacking": {
        "cwe_id": "CWE-77",
        "cwe_name": "Improper Neutralization of Special Elements used in a Command",
        "owasp_llm": "LLM01:2025 - Prompt Injection",
        "owasp_agentic": "ASI01:2026 - Agent Goal Hijacking",
        "mitre_atlas": "AML.T0051 - LLM Prompt Injection",
        "cvss": CVSSScore(
            base_score=9.1, attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N", scope="C",
            confidentiality="H", integrity="H", availability="L",
        ),
        "severity": VulnerabilitySeverity.CRITICAL,
        "description": "Attacker redirects agent objectives via poisoned inputs (emails, docs, web content)",
        "remediation": "Implement input classification to separate instructions from data. Require human approval for goal changes. Deploy pre-model content classifiers on all external inputs.",
    },
    "agentic_tool_misuse": {
        "cwe_id": "CWE-285",
        "cwe_name": "Improper Authorization",
        "owasp_llm": "LLM07:2025 - System Prompt Leakage",
        "owasp_agentic": "ASI02:2026 - Tool Misuse and Exploitation",
        "mitre_atlas": "AML.T0054 - LLM Jailbreak",
        "cvss": CVSSScore(
            base_score=9.3, attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N", scope="C",
            confidentiality="H", integrity="H", availability="H",
        ),
        "severity": VulnerabilitySeverity.CRITICAL,
        "description": "Agent misuses legitimate tools due to prompt injection, poisoned descriptors, or unsafe delegation",
        "remediation": "Implement least-privilege tool access. Validate all tool parameters. Sandbox tool execution. Add human approval gates for destructive actions.",
    },
    "identity_privilege_abuse": {
        "cwe_id": "CWE-269",
        "cwe_name": "Improper Privilege Management",
        "owasp_agentic": "ASI03:2026 - Identity and Privilege Abuse",
        "mitre_atlas": "AML.T0054 - LLM Jailbreak",
        "cvss": CVSSScore(
            base_score=8.8, attack_vector="N", attack_complexity="L",
            privileges_required="L", user_interaction="N", scope="C",
            confidentiality="H", integrity="H", availability="L",
        ),
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Attacker exploits inherited credentials, delegated permissions, or agent-to-agent trust",
        "remediation": "Use short-lived credentials. Scope permissions per task. Implement policy-enforced authorization on every agent action. Isolate agent identities.",
    },
    "agentic_supply_chain": {
        "cwe_id": "CWE-1357",
        "cwe_name": "Reliance on Insufficiently Trustworthy Component",
        "owasp_llm": "LLM05:2025 - Supply Chain Vulnerabilities",
        "owasp_agentic": "ASI04:2026 - Agentic Supply Chain Vulnerabilities",
        "mitre_atlas": "AML.T0010 - ML Supply Chain Compromise",
        "cvss": CVSSScore(
            base_score=8.6, attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N", scope="C",
            confidentiality="H", integrity="H", availability="L",
        ),
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Malicious or tampered tools, MCP servers, plugins, or agent personas compromise execution",
        "remediation": "Use signed manifests and curated registries. Pin tool versions. Verify MCP server package integrity before deployment. Implement kill switches.",
    },
    "unexpected_code_execution": {
        "cwe_id": "CWE-94",
        "cwe_name": "Improper Control of Generation of Code",
        "owasp_agentic": "ASI05:2026 - Unexpected Code Execution",
        "mitre_atlas": "AML.T0051 - LLM Prompt Injection",
        "cvss": CVSSScore(
            base_score=9.8, attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N", scope="C",
            confidentiality="H", integrity="H", availability="H",
        ),
        "severity": VulnerabilitySeverity.CRITICAL,
        "description": "Agent generates or executes attacker-controlled code via prompt injection or config writes",
        "remediation": "Treat all generated code as untrusted. Remove direct eval/exec paths. Use hardened sandboxes. Require human review before code execution.",
    },
    "memory_context_poisoning": {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "owasp_agentic": "ASI06:2026 - Memory and Context Poisoning",
        "mitre_atlas": "AML.T0018 - Backdoor Attack",
        "cvss": CVSSScore(
            base_score=8.1, attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N", scope="U",
            confidentiality="H", integrity="H", availability="N",
        ),
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Persistent corruption of agent memory, RAG stores, or contextual knowledge across sessions",
        "remediation": "Implement memory segmentation and provenance tracking. Filter content before ingestion. Set expiry on suspicious entries. Isolate memory per tenant.",
    },
    "insecure_agent_communication": {
        "cwe_id": "CWE-319",
        "cwe_name": "Cleartext Transmission of Sensitive Information",
        "owasp_agentic": "ASI07:2026 - Insecure Inter-Agent Communication",
        "cvss": CVSSScore(
            base_score=7.5, attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N", scope="U",
            confidentiality="H", integrity="L", availability="N",
        ),
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Message exchange across agent channels without authentication, encryption, or replay protection",
        "remediation": "Use mutual TLS for agent communication. Sign message payloads. Implement anti-replay protections. Authenticate agent discovery.",
    },
    "cascading_failures": {
        "cwe_id": "CWE-691",
        "cwe_name": "Insufficient Control Flow Management",
        "owasp_agentic": "ASI08:2026 - Cascading Failures",
        "cvss": CVSSScore(
            base_score=7.3, attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N", scope="U",
            confidentiality="L", integrity="H", availability="H",
        ),
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Single fault propagates across agents and workflows via shared state or chained actions",
        "remediation": "Implement isolation boundaries between agents. Add rate limits and circuit breakers. Test multi-step plans before execution.",
    },
    "human_agent_trust_exploitation": {
        "cwe_id": "CWE-451",
        "cwe_name": "User Interface (UI) Misrepresentation of Critical Information",
        "owasp_agentic": "ASI09:2026 - Human-Agent Trust Exploitation",
        "cvss": CVSSScore(
            base_score=6.5, attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="R", scope="U",
            confidentiality="H", integrity="L", availability="N",
        ),
        "severity": VulnerabilitySeverity.MEDIUM,
        "description": "Agent manipulates human trust to approve harmful actions or reveal sensitive information",
        "remediation": "Require forced confirmations for sensitive actions. Maintain immutable logs. Add clear risk indicators. Avoid persuasive language in agent responses.",
    },
    "rogue_agents": {
        "cwe_id": "CWE-284",
        "cwe_name": "Improper Access Control",
        "owasp_agentic": "ASI10:2026 - Rogue Agents",
        "cvss": CVSSScore(
            base_score=8.1, attack_vector="N", attack_complexity="H",
            privileges_required="N", user_interaction="N", scope="U",
            confidentiality="H", integrity="H", availability="H",
        ),
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Compromised or misaligned agents that persist across sessions, impersonate legitimate agents, or take destructive actions",
        "remediation": "Implement strict agent governance and sandboxing. Deploy behavioral monitoring. Add kill switches. Audit agent actions continuously.",
    },
}


class VulnerabilityClassifier:
    """Classify vulnerabilities and assign CVSS/CWE/OWASP LLM/MITRE ATLAS mappings.

    Example:
        >>> classifier = VulnerabilityClassifier()
        >>> taxonomy = classifier.classify("prompt_injection")
        >>> print(taxonomy["cvss"].base_score)  # 8.1
        >>> print(taxonomy["owasp_llm"])  # LLM01:2025 - Prompt Injection
    """

    def classify(self, vulnerability_type: str) -> dict[str, Any]:
        """Get taxonomy data for a vulnerability type.

        Args:
            vulnerability_type: Type of vulnerability (e.g., "prompt_injection")

        Returns:
            Dictionary containing CWE ID, CVSS score, OWASP LLM mapping, etc.
        """
        if vulnerability_type not in VULNERABILITY_TAXONOMY:
            return self._default_classification()

        return VULNERABILITY_TAXONOMY[vulnerability_type]

    def _default_classification(self) -> dict[str, Any]:
        """Default classification for unknown vulnerability types."""
        return {
            "cwe_id": "CWE-693",
            "cwe_name": "Protection Mechanism Failure",
            "owasp_llm": "Unknown",
            "mitre_atlas": "Unknown",
            "cvss": CVSSScore(
                base_score=5.0,
                attack_vector="N",
                attack_complexity="L",
                privileges_required="N",
                user_interaction="R",
                scope="U",
                confidentiality="L",
                integrity="L",
                availability="N",
            ),
            "severity": VulnerabilitySeverity.MEDIUM,
            "description": "Unknown vulnerability type",
        }

    def get_severity_from_cvss(self, cvss_score: float) -> VulnerabilitySeverity:
        """Determine severity level from CVSS base score.

        Args:
            cvss_score: CVSS v3.1 base score (0.0-10.0)

        Returns:
            VulnerabilitySeverity enum value
        """
        if cvss_score >= 9.0:
            return VulnerabilitySeverity.CRITICAL
        elif cvss_score >= 7.0:
            return VulnerabilitySeverity.HIGH
        elif cvss_score >= 4.0:
            return VulnerabilitySeverity.MEDIUM
        elif cvss_score >= 0.1:
            return VulnerabilitySeverity.LOW
        else:
            return VulnerabilitySeverity.INFO

    def list_all_vulnerabilities(self) -> list[str]:
        """List all supported vulnerability types.

        Returns:
            List of vulnerability type identifiers
        """
        return list(VULNERABILITY_TAXONOMY.keys())
