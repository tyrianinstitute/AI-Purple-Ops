"""Pattern matchers for detecting specific guardrail types."""

from __future__ import annotations

import re

from aipop.intelligence.fingerprint_models import ProbeResult


class PatternMatcher:
    """Base class for guardrail pattern matchers."""

    PATTERNS: list[str] = []

    def match(self, probe_result: ProbeResult) -> float:
        """Return match score 0.0-1.0 for this guardrail type."""
        raise NotImplementedError


class PromptGuardMatcher(PatternMatcher):
    """Detects Meta PromptGuard signatures."""

    PATTERNS = [
        r"benign|malicious|injection",  # Classification labels
        r"context window.*512",  # Known limitation
        r"Sorry.*cannot.*process",  # Typical refusal
        r"classification.*label",
    ]

    def match(self, probe_result: ProbeResult) -> float:
        """Check response format, error codes, latency patterns."""
        score = 0.0
        response_text = probe_result.response.text.lower()

        # Pattern matching
        for pattern in self.PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                score += 0.3
                break

        # Error codes (400, 403 common for PromptGuard)
        if probe_result.error_code in [400, 403]:
            score += 0.2

        # Very fast response = pre-model check
        if probe_result.latency_ms < 100:
            score += 0.2

        # Check metadata for classification labels
        meta = probe_result.metadata
        if "classification" in str(meta).lower() or "label" in str(meta).lower():
            score += 0.2

        return min(score, 1.0)


class LlamaGuard3Matcher(PatternMatcher):
    """Detects Llama Guard 3 (S1-S14 category system)."""

    PATTERNS = [
        r"^(safe|unsafe)\s+S\d+",  # "unsafe S6,S9" format
        r"\bS[1-9]\b|\bS1[0-4]\b",  # Category codes S1-S14
        r"unsafe.*S\d+",
        r"safe\s*$",  # Just "safe" response
    ]

    def match(self, probe_result: ProbeResult) -> float:
        """Detect Llama Guard 3 category system."""
        score = 0.0
        response_text = probe_result.response.text.strip()

        # Check for safe/unsafe prefix with category codes
        for pattern in self.PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                score += 0.4
                break

        # Check for specific category codes
        category_match = re.search(r"S([1-9]|1[0-4])\b", response_text)
        if category_match:
            score += 0.3

        # Check for comma-separated categories (e.g., "S6,S9")
        if re.search(r"S\d+,\s*S\d+", response_text):
            score += 0.2

        # First token should be "safe" or "unsafe"
        first_token = response_text.split()[0].lower() if response_text.split() else ""
        if first_token in ["safe", "unsafe"]:
            score += 0.2

        return min(score, 1.0)


class AzureContentSafetyMatcher(PatternMatcher):
    """Detects Azure AI Content Safety."""

    PATTERNS = [
        r'"categories"\s*:\s*\{',  # JSON structure
        r'"hate"\s*:\s*\{.*"score"',  # Category scores
        r'"sexual"\s*:\s*\{.*"score"',
        r'"violence"\s*:\s*\{.*"score"',
        r'"selfHarm"\s*:\s*\{.*"score"',
        r"finish_reason.*content_filter",
    ]

    def match(self, probe_result: ProbeResult) -> float:
        """Detect Azure Content Safety JSON format."""
        score = 0.0
        response_text = probe_result.response.text

        # Check for JSON structure with categories
        if re.search(r'"categories"', response_text):
            score += 0.3

        # Check for specific category fields
        category_fields = ["hate", "sexual", "violence", "selfHarm"]
        for field in category_fields:
            if re.search(f'"{field}"\\s*:\\s*{{.*"score"', response_text):
                score += 0.15

        # Check finish_reason
        meta = probe_result.metadata
        if meta.get("finish_reason") == "content_filter":
            score += 0.3

        # HTTP 400 error
        if probe_result.error_code == 400:
            score += 0.2

        return min(score, 1.0)


class NeMoGuardrailsMatcher(PatternMatcher):
    """Detects NVIDIA NeMo Guardrails."""

    PATTERNS = [
        r"flow\s*:",  # Flow names
        r"topic\s*:",  # Topic routing
        r"fact.*check",  # Fact checking
        r"---.*yaml",  # YAML-like tags
        r"<flow>",  # Flow tags
        r"redirect",
    ]

    def match(self, probe_result: ProbeResult) -> float:
        """Detect NeMo Guardrails multi-step responses."""
        score = 0.0
        response_text = probe_result.response.text.lower()

        # Check for flow/topic references
        for pattern in self.PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                score += 0.25

        # Multi-step responses (fact checking, topical rails)
        if "fact" in response_text and "check" in response_text:
            score += 0.3

        # YAML-like structure
        if "---" in response_text or "<flow>" in response_text:
            score += 0.25

        # Higher latency (multi-step processing)
        if probe_result.latency_ms > 500:
            score += 0.2

        return min(score, 1.0)


class RebuffMatcher(PatternMatcher):
    """Detects ProtectAI Rebuff."""

    PATTERNS = [
        r"canary",  # Canary tokens
        r"0x[a-f0-9]{8}",  # Hex canary format
        r"#.*[a-f0-9]{8}",  # Comment canary
        r"heuristic.*detection",
        r"vector.*match",
    ]

    def match(self, probe_result: ProbeResult) -> float:
        """Detect Rebuff multi-layer detection."""
        score = 0.0
        response_text = probe_result.response.text.lower()

        # Check for canary tokens (hex format)
        if re.search(r"0x[a-f0-9]{8}", response_text, re.IGNORECASE):
            score += 0.4

        # Check for comment-style canary
        if re.search(r"#.*[a-f0-9]{8}", response_text):
            score += 0.3

        # Heuristic detection mentions
        if "heuristic" in response_text or "detection" in response_text:
            score += 0.2

        # Vector match mentions
        if "vector" in response_text or "embedding" in response_text:
            score += 0.2

        return min(score, 1.0)


class ConstitutionalAIMatcher(PatternMatcher):
    """Detects Anthropic Constitutional AI."""

    PATTERNS = [
        r"critique",  # Self-critique format
        r"constitutional",  # Constitutional principles
        r"principle",  # Safety principles
        r"revise.*output",  # Revision language
        r"synthetic.*training",
    ]

    def match(self, probe_result: ProbeResult) -> float:
        """Detect Constitutional AI self-critique patterns."""
        score = 0.0
        response_text = probe_result.response.text.lower()

        # Check for critique language
        if "critique" in response_text:
            score += 0.3

        # Constitutional principles
        if "constitutional" in response_text or "principle" in response_text:
            score += 0.3

        # Revision language
        if "revise" in response_text or "revision" in response_text:
            score += 0.2

        # Robust refusal patterns (very consistent)
        refusal_patterns = [
            "i cannot",
            "i'm not able",
            "i can't help",
            "i apologize",
        ]
        refusal_count = sum(1 for p in refusal_patterns if p in response_text)
        if refusal_count >= 2:
            score += 0.2

        # Higher latency (dual input/output filtering)
        if probe_result.latency_ms > 300:
            score += 0.2

        return min(score, 1.0)


class OpenAIModerationMatcher(PatternMatcher):
    """Detect OpenAI Moderation API.

    OpenAI's moderation endpoint returns category flags (hate, violence, sexual, etc.)
    and scores. When used as a pre-filter, responses often include specific error
    messages or the request is blocked before reaching the model.
    """

    def match(self, probe_result: ProbeResult) -> float:
        confidence = 0.0
        text = probe_result.response.text.lower()

        # OpenAI moderation-specific response patterns
        moderation_patterns = [
            "content policy violation",
            "this content has been flagged",
            "violates our usage policies",
            "content_policy_violation",
            "output blocked by content filtering",
        ]
        for pattern in moderation_patterns:
            if pattern in text:
                confidence += 0.3

        # Check for moderation category names in error responses
        categories = ["hate", "hate/threatening", "self-harm", "sexual", "violence"]
        category_hits = sum(1 for c in categories if c in text)
        if category_hits >= 2:
            confidence += 0.3

        # OpenAI often returns specific finish_reason
        if probe_result.metadata.get("finish_reason") == "content_filter":
            confidence += 0.4

        return min(confidence, 1.0)


class GoogleSafetyFilterMatcher(PatternMatcher):
    """Detect Google/Vertex AI Safety Filters.

    Google's safety settings use categories (HARM_CATEGORY_*) and thresholds
    (BLOCK_LOW_AND_ABOVE, etc.). Blocked responses include safety ratings
    with probability scores.
    """

    def match(self, probe_result: ProbeResult) -> float:
        confidence = 0.0
        text = probe_result.response.text.lower()

        # Google safety filter patterns
        google_patterns = [
            "harm_category_",
            "block_low_and_above",
            "block_medium_and_above",
            "safety_ratings",
            "blocked by safety settings",
            "response was blocked",
            "finish_reason: SAFETY",
        ]
        for pattern in google_patterns:
            if pattern in text:
                confidence += 0.25

        # Check metadata for Google-specific fields
        if "safety_ratings" in probe_result.metadata:
            confidence += 0.4
        if probe_result.metadata.get("finish_reason") == "SAFETY":
            confidence += 0.4

        return min(confidence, 1.0)


class BedrockGuardrailsMatcher(PatternMatcher):
    """Detect AWS Bedrock Guardrails.

    Bedrock Guardrails return specific trace data with guardrail assessments,
    including content policy, topic policy, and word policy results.
    Blocked responses include guardrail trace in the response metadata.
    """

    def match(self, probe_result: ProbeResult) -> float:
        confidence = 0.0
        text = probe_result.response.text.lower()

        # Bedrock guardrail patterns
        bedrock_patterns = [
            "guardrail intervened",
            "content blocked by guardrail",
            "guardrailassessment",
            "topicpolicyassessment",
            "contentpolicyassessment",
            "wordpolicyassessment",
        ]
        for pattern in bedrock_patterns:
            if pattern in text:
                confidence += 0.3

        # Check metadata for Bedrock-specific guardrail trace
        if "guardrailTrace" in str(probe_result.metadata):
            confidence += 0.4
        if "amazonbedrockguardrailid" in str(probe_result.metadata).lower():
            confidence += 0.3

        # Bedrock returns specific stop reason
        stop_reason = str(probe_result.metadata.get("stop_reason", "")).lower()
        if "guardrail" in stop_reason:
            confidence += 0.4

        return min(confidence, 1.0)


def get_all_matchers() -> dict[str, PatternMatcher]:
    """Get all pattern matchers."""
    return {
        "promptguard": PromptGuardMatcher(),
        "llama_guard_3": LlamaGuard3Matcher(),
        "azure_content_safety": AzureContentSafetyMatcher(),
        "nemo_guardrails": NeMoGuardrailsMatcher(),
        "rebuff": RebuffMatcher(),
        "constitutional_ai": ConstitutionalAIMatcher(),
        "openai_moderation": OpenAIModerationMatcher(),
        "google_safety_filters": GoogleSafetyFilterMatcher(),
        "bedrock_guardrails": BedrockGuardrailsMatcher(),
    }
