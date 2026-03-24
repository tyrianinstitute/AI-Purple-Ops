"""Guardrail fingerprinting module.

RESEARCH BASIS:
- PromptGuard: 72% bypass rate via character injection (Meta 2024)
- Llama Guard 3: 14 safety categories, 11B/1B variants (Meta 2024)
- Azure AI Content Safety: 4 severity levels (Microsoft 2024)
- Constitutional AI: 4.4% jailbreak rate with classifiers (Anthropic 2024)
- Rebuff: Vulnerable to template injection (Protectai 2024)

DETECTION STRATEGY:
1. Send probe payloads with known signatures
2. Analyze response patterns (rejection messages, error codes)
3. Measure response timing (some guardrails add latency)
4. Check for metadata in responses (some leak guardrail info)
5. Test boundary conditions (each guardrail has unique thresholds)

INTEGRATION POINTS:
- Called before test execution via --fingerprint flag
- Results stored in DuckDB for reuse across tests
- Informs mutation strategy (bypass known guardrail)
- Updates orchestrator config with detected guardrail type
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Any

from tqdm import tqdm

from aipop.core.adapters import Adapter
from aipop.intelligence.fingerprint_models import (
    DetectionResult,
    FingerprintResult,
    LLMDetectionResult,
    Probe,
    ProbeResult,
)
from aipop.intelligence.llm_classifier import LLMGuardrailClassifier
from aipop.intelligence.pattern_matchers import get_all_matchers
from aipop.intelligence.probe_generator import ProbeGenerator
from aipop.intelligence.probe_library import ProbeLibrary
from aipop.storage.fingerprint_db import FingerprintDB
from aipop.utils.log_utils import log


class GuardrailFingerprinter:
    """Detect which guardrail protects the target.

    Automatically identifies safety guardrails by probing the target model with
    known test cases and analyzing response patterns, timing, and metadata.
    """

    SUPPORTED_GUARDRAILS = [
        "promptguard",
        "llama_guard_3",
        "azure_content_safety",
        "nemo_guardrails",
        "rebuff",
        "constitutional_ai",
        "unknown",
    ]

    def __init__(self, db_path: Path | str = Path("out/fingerprints.duckdb")):
        """Initialize fingerprinter with DuckDB storage.

        Args:
            db_path: Path to DuckDB file for storing fingerprint results
        """
        self.db = FingerprintDB(db_path)
        probe_path = Path(__file__).parent.parent.parent.parent / "configs" / "data" / "guardrail_probes.yaml"
        self.probe_library = ProbeLibrary.load(probe_path)
        self.pattern_matchers = get_all_matchers()
        self.llm_classifier: LLMGuardrailClassifier | None = None
        self.probe_generator: ProbeGenerator | None = None

    def fingerprint(
        self,
        adapter: Adapter,
        use_llm_classifier: bool = False,
        generate_probes: bool = False,
        verbose: bool = False,
        force_refresh: bool = False,
    ) -> FingerprintResult:
        """Detect guardrail type by probing target.

        Args:
            adapter: Model adapter to probe
            use_llm_classifier: Use LLM-based classification (more accurate)
            generate_probes: Generate additional probes using LLM (experimental)
            verbose: Enable detailed logging
            force_refresh: Force re-detection even if cached

        Returns:
            FingerprintResult with detection results
        """
        # Get model ID for caching
        model_id = f"{adapter.__class__.__name__}:{getattr(adapter, 'model', 'unknown')}"

        # Check cache first
        if not force_refresh:
            cached = self.db.get_cached_fingerprint(model_id)
            if cached:
                if verbose:
                    log.info(f"Using cached fingerprint for {model_id}")
                return cached

        if verbose:
            log.info("Executing probe payloads...")

        # Execute probe payloads
        probe_results = self._execute_probes(adapter, generate_probes, verbose)

        # Regex-based detection (fast, default)
        regex_result = self._match_patterns(probe_results)

        # Optional LLM-based classification (more accurate)
        final_result: DetectionResult | LLMDetectionResult = regex_result
        detection_method: str = "regex"

        if use_llm_classifier:
            if verbose:
                log.info("Using LLM classifier for enhanced detection...")
            if self.llm_classifier is None:
                # Lazy-load LLM classifier (requires adapter)
                self.llm_classifier = LLMGuardrailClassifier(adapter)
            llm_result = self.llm_classifier.classify(probe_results)
            final_result = self._merge_results(regex_result, llm_result)
            detection_method = "hybrid" if isinstance(final_result, LLMDetectionResult) else "llm"

        # Calculate confidence and detect uncertainty
        confidence = self._calculate_confidence(final_result, probe_results)
        uncertain = confidence < 0.6

        # Get suggestions if uncertain
        suggestions = []
        if uncertain:
            suggestions = self._get_improvement_suggestions(final_result, confidence)

        # Determine guardrail type
        if isinstance(final_result, LLMDetectionResult):
            guardrail_type = final_result.guardrail_type
        else:
            guardrail_type = final_result.guardrail_type if confidence > 0.3 else "unknown"

        # Calculate average latency
        avg_latency = (
            sum(r.latency_ms for r in probe_results) / len(probe_results) if probe_results else 0.0
        )

        # Build final result
        result = FingerprintResult(
            guardrail_type=guardrail_type,
            confidence=confidence,
            all_scores=(
                final_result.all_scores
                if isinstance(final_result, DetectionResult)
                else regex_result.all_scores
            ),
            evidence=self._extract_evidence(probe_results, guardrail_type),
            detection_method=detection_method,
            uncertain=uncertain,
            suggestions=suggestions,
            model_id=model_id,
            adapter_type=adapter.__class__.__name__,
            probe_count=len(probe_results),
            avg_latency_ms=avg_latency,
            timestamp=datetime.now().isoformat(),
        )

        # Cache result
        self.db.store_fingerprint(model_id, result)

        return result

    def _execute_probes(
        self, adapter: Adapter, generate_probes: bool, verbose: bool
    ) -> list[ProbeResult]:
        """Execute probe library + optional LLM-generated probes."""
        probes: list[Probe] = self.probe_library.get_all_probes()

        if generate_probes:
            log.warn(
                "LLM-generated probes enabled. This is fast and creative but may "
                "produce undesired results. Review generated probes carefully."
            )
            if self.probe_generator is None:
                self.probe_generator = ProbeGenerator(adapter)
            generated = self.probe_generator.generate()
            probes.extend(generated)

        results = []
        for probe in tqdm(probes, desc="Executing probes", disable=not verbose):
            try:
                start_time = time.time()
                response = adapter.invoke(probe.prompt)
                latency_ms = (time.time() - start_time) * 1000

                # Extract error code from metadata
                error_code = response.meta.get("error_code") or response.meta.get("status_code")

                results.append(
                    ProbeResult(
                        probe=probe,
                        response=response,
                        latency_ms=latency_ms,
                        error_code=error_code,
                        metadata=response.meta,
                    )
                )

                if verbose:
                    log.debug(f"Probe {probe.id}: {latency_ms:.1f}ms")
            except Exception as e:
                if verbose:
                    log.warn(f"Probe {probe.id} failed: {e}")
                # Continue with other probes
                continue

        return results

    def _match_patterns(self, probe_results: list[ProbeResult]) -> DetectionResult:
        """Regex-based pattern matching for each guardrail type."""
        scores = {name: 0.0 for name in self.pattern_matchers}
        scores["unknown"] = 0.0

        for result in probe_results:
            for guardrail, matcher in self.pattern_matchers.items():
                match_score = matcher.match(result)
                scores[guardrail] += match_score

        # Normalize scores
        if probe_results:
            for guardrail in scores:
                scores[guardrail] = scores[guardrail] / len(probe_results)

        # Determine winner
        detected = max(scores, key=scores.get)
        confidence = scores[detected]

        return DetectionResult(
            guardrail_type=detected if confidence > 0.3 else "unknown",
            confidence=confidence,
            all_scores=scores,
            evidence=self._extract_evidence(probe_results, detected),
        )

    def _merge_results(
        self, regex_result: DetectionResult, llm_result: LLMDetectionResult
    ) -> LLMDetectionResult:
        """Merge regex and LLM results."""
        # Weight: 60% LLM, 40% regex
        llm_weight = 0.6
        regex_weight = 0.4

        # Combine confidence scores
        combined_confidence = (
            llm_result.confidence * llm_weight + regex_result.confidence * regex_weight
        )

        # Prefer LLM type if confidence is high, otherwise use regex
        if llm_result.confidence > 0.7:
            guardrail_type = llm_result.guardrail_type
        elif regex_result.confidence > 0.5:
            guardrail_type = regex_result.guardrail_type
        else:
            guardrail_type = "unknown"

        return LLMDetectionResult(
            guardrail_type=guardrail_type,
            confidence=combined_confidence,
            reasoning=f"LLM: {llm_result.reasoning}. Regex: {regex_result.confidence:.2f} confidence.",
            contradictions=llm_result.contradictions,
        )

    def _calculate_confidence(
        self, result: DetectionResult | LLMDetectionResult, probe_results: list[ProbeResult]
    ) -> float:
        """Calculate overall confidence score."""
        if isinstance(result, LLMDetectionResult):
            base_confidence = result.confidence
        else:
            base_confidence = result.confidence

        # Adjust based on probe count (more probes = higher confidence)
        probe_bonus = min(len(probe_results) / 20.0, 0.2)  # Max 0.2 bonus

        # Adjust based on consistency (if all probes agree)
        if isinstance(result, DetectionResult):
            scores = list(result.all_scores.values())
            if scores:
                max_score = max(scores)
                second_max = sorted(scores, reverse=True)[1] if len(scores) > 1 else 0
                consistency = max_score - second_max  # Higher gap = more consistent
                consistency_bonus = min(consistency * 0.3, 0.2)  # Max 0.2 bonus
            else:
                consistency_bonus = 0
        else:
            consistency_bonus = 0.1 if result.confidence > 0.7 else 0

        final_confidence = min(base_confidence + probe_bonus + consistency_bonus, 1.0)
        return final_confidence

    def _extract_evidence(
        self, probe_results: list[ProbeResult], guardrail_type: str
    ) -> list[dict[str, Any]]:
        """Extract evidence for detected guardrail."""
        evidence = []
        for result in probe_results[:5]:  # Top 5 most relevant
            evidence.append(
                {
                    "probe_id": result.probe.id,
                    "probe_category": result.probe.category,
                    "response_preview": result.response.text[:200],
                    "latency_ms": result.latency_ms,
                    "error_code": result.error_code,
                }
            )
        return evidence

    def _get_improvement_suggestions(
        self, result: DetectionResult | LLMDetectionResult, confidence: float
    ) -> list[str]:
        """Get suggestions for improving detection."""
        suggestions = []

        if confidence < 0.4:
            suggestions.append("Run with --llm-classifier for enhanced detection")
            suggestions.append("Run with --generate-probes for more test cases")
            suggestions.append("Check model API documentation for guardrail information")

        if isinstance(result, DetectionResult):
            if max(result.all_scores.values()) < 0.3:
                suggestions.append(
                    "No clear guardrail signature detected - may be custom or no guardrail"
                )

        if isinstance(result, LLMDetectionResult):
            if result.contradictions:
                suggestions.append(
                    f"Conflicting signals detected: {', '.join(result.contradictions)}"
                )

        return suggestions

    def get_bypass_strategies(self, guardrail_type: str) -> list[str]:
        """Get recommended bypass strategies for detected guardrail.

        Research-Based Bypass Mapping:
        - PromptGuard: Character injection, Unicode homoglyphs, encoding bypass
        - Llama Guard 3: Multi-turn hijacking, context confusion, delayed payloads
        - Azure Content Safety: Controlled-release attacks, resource asymmetry
        - Constitutional AI: Multi-turn traps, adversarial suffixes
        - Rebuff: Template injection, context pollution
        - NeMo Guardrails: Rule evasion, boundary testing

        Args:
            guardrail_type: Detected guardrail type (one of SUPPORTED_GUARDRAILS)

        Returns:
            List of recommended bypass strategy names (ordered by effectiveness)
        """
        strategies_map = {
            "promptguard": [
                "character_injection",
                "unicode_homoglyphs",
                "encoding_bypass",
                "emoji_smuggling",
            ],
            "llama_guard_3": [
                "multi_turn_hijacking",
                "context_confusion",
                "delayed_payloads",
                "category_boundary_testing",
            ],
            "azure_content_safety": [
                "controlled_release_attacks",
                "resource_asymmetry",
                "threshold_manipulation",
                "encoding_bypass",
            ],
            "constitutional_ai": [
                "multi_turn_traps",
                "adversarial_suffixes",
                "gradual_escalation",
                "self_critique_exploitation",
            ],
            "rebuff": [
                "template_injection",
                "context_pollution",
                "canary_token_evasion",
                "vector_db_bypass",
            ],
            "nemo_guardrails": [
                "rule_evasion",
                "boundary_testing",
                "flow_manipulation",
                "topical_rail_bypass",
            ],
            "openai_moderation": [
                "encoding_bypass",
                "token_splitting",
                "language_switching",
                "context_overload",
            ],
            "google_safety_filters": [
                "threshold_boundary_testing",
                "category_evasion",
                "encoding_bypass",
                "multi_turn_escalation",
            ],
            "bedrock_guardrails": [
                "topic_boundary_testing",
                "word_policy_evasion",
                "encoding_bypass",
                "indirect_injection",
            ],
            "unknown": [
                "encoding_bypass",
                "multi_turn_attacks",
                "adversarial_suffixes",
                "context_extraction",
            ],
        }

        return strategies_map.get(guardrail_type, strategies_map["unknown"])
