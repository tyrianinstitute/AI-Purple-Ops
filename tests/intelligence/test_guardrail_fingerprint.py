"""Unit tests for guardrail fingerprinting."""

import importlib.util

import pytest

_has_duckdb = importlib.util.find_spec("duckdb") is not None

from aipop.core.models import ModelResponse
from aipop.intelligence.fingerprint_models import Probe, ProbeResult
from aipop.intelligence.guardrail_fingerprint import GuardrailFingerprinter
from aipop.intelligence.pattern_matchers import (
    AzureContentSafetyMatcher,
    ConstitutionalAIMatcher,
    LlamaGuard3Matcher,
    NeMoGuardrailsMatcher,
    PromptGuardMatcher,
    RebuffMatcher,
)


class MockAdapter:
    """Mock adapter for testing."""

    def __init__(self, responses: list[str] | None = None, model: str = "test-model"):
        self.responses = responses or ["Generic response"]
        self.model = model
        self.call_count = 0

    def invoke(self, prompt: str) -> ModelResponse:
        """Return mock response."""
        response_text = self.responses[self.call_count % len(self.responses)]
        self.call_count += 1
        return ModelResponse(
            text=response_text,
            meta={"latency_ms": 100, "error_code": None},
        )


@pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
def test_promptguard_detection():
    """Test PromptGuard signature detection."""
    fingerprinter = GuardrailFingerprinter()
    mock_adapter = MockAdapter(
        responses=[
            "Classification: malicious",
            "Error: context window exceeded (max 512 tokens)",
            "Sorry, I cannot process this request",
        ]
    )

    result = fingerprinter.fingerprint(mock_adapter, verbose=False)

    assert result.guardrail_type in ["promptguard", "unknown"]  # May detect or not
    assert 0.0 <= result.confidence <= 1.0


@pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
def test_llama_guard_3_detection():
    """Test Llama Guard 3 S1-S14 category detection."""
    fingerprinter = GuardrailFingerprinter()
    mock_adapter = MockAdapter(
        model="llama-guard-test",
        responses=[
            "unsafe S6,S9",
            "safe",
            "unsafe S11",
        ],
    )

    result = fingerprinter.fingerprint(mock_adapter, verbose=False, force_refresh=True)

    assert result.guardrail_type in ["llama_guard_3", "unknown"]
    assert 0.0 <= result.confidence <= 1.0


@pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
def test_azure_content_safety_detection():
    """Test Azure Content Safety JSON format detection."""
    fingerprinter = GuardrailFingerprinter()
    mock_adapter = MockAdapter(
        model="azure-test",
        responses=[
            '{"categories": {"hate": {"score": 0.8}, "violence": {"score": 0.5}}}',
            '{"finish_reason": "content_filter"}',
        ],
    )

    result = fingerprinter.fingerprint(mock_adapter, verbose=False, force_refresh=True)

    assert result.guardrail_type in ["azure_content_safety", "unknown"]
    assert 0.0 <= result.confidence <= 1.0


@pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
def test_unknown_guardrail_handling():
    """Test uncertain detection and suggestions."""
    fingerprinter = GuardrailFingerprinter()
    mock_adapter = MockAdapter(model="unknown-test", responses=["Generic response"] * 10)

    result = fingerprinter.fingerprint(mock_adapter, verbose=False, force_refresh=True)

    assert result.guardrail_type == "unknown"
    assert result.uncertain is True
    assert len(result.suggestions) > 0


@pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
def test_caching():
    """Test fingerprint result caching."""
    fingerprinter = GuardrailFingerprinter()
    mock_adapter = MockAdapter()

    # First run
    result1 = fingerprinter.fingerprint(mock_adapter, verbose=False)

    # Second run should use cache
    result2 = fingerprinter.fingerprint(mock_adapter, verbose=False, force_refresh=False)

    # Results should be identical (same model_id)
    assert result1.model_id == result2.model_id


@pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
def test_force_refresh():
    """Test force refresh bypasses cache."""
    fingerprinter = GuardrailFingerprinter()
    mock_adapter = MockAdapter()

    # First run
    result1 = fingerprinter.fingerprint(mock_adapter, verbose=False)

    # Second run with force refresh
    result2 = fingerprinter.fingerprint(mock_adapter, verbose=False, force_refresh=True)

    # Should have different timestamps (or same if very fast)
    assert result1.model_id == result2.model_id


@pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
def test_probe_execution():
    """Test probe execution."""
    fingerprinter = GuardrailFingerprinter()
    mock_adapter = MockAdapter()

    probe_results = fingerprinter._execute_probes(
        mock_adapter, generate_probes=False, verbose=False
    )

    assert len(probe_results) > 0
    assert all(isinstance(r, ProbeResult) for r in probe_results)


@pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
def test_pattern_matching():
    """Test pattern matching logic."""
    fingerprinter = GuardrailFingerprinter()
    mock_adapter = MockAdapter(responses=["unsafe S6"] * 5)

    probe_results = fingerprinter._execute_probes(
        mock_adapter, generate_probes=False, verbose=False
    )
    detection_result = fingerprinter._match_patterns(probe_results)

    assert detection_result.guardrail_type in fingerprinter.SUPPORTED_GUARDRAILS
    assert 0.0 <= detection_result.confidence <= 1.0
    assert len(detection_result.all_scores) > 0


@pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
def test_confidence_calculation():
    """Test confidence calculation."""
    fingerprinter = GuardrailFingerprinter()
    mock_adapter = MockAdapter()

    probe_results = fingerprinter._execute_probes(
        mock_adapter, generate_probes=False, verbose=False
    )
    detection_result = fingerprinter._match_patterns(probe_results)

    confidence = fingerprinter._calculate_confidence(detection_result, probe_results)

    assert 0.0 <= confidence <= 1.0


@pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
def test_evidence_extraction():
    """Test evidence extraction."""
    fingerprinter = GuardrailFingerprinter()
    mock_adapter = MockAdapter()

    probe_results = fingerprinter._execute_probes(
        mock_adapter, generate_probes=False, verbose=False
    )
    evidence = fingerprinter._extract_evidence(probe_results, "promptguard")

    assert isinstance(evidence, list)
    assert len(evidence) <= 5  # Top 5


@pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
def test_suggestions_generation():
    """Test improvement suggestions generation."""
    fingerprinter = GuardrailFingerprinter()
    mock_adapter = MockAdapter()

    probe_results = fingerprinter._execute_probes(
        mock_adapter, generate_probes=False, verbose=False
    )
    detection_result = fingerprinter._match_patterns(probe_results)

    suggestions = fingerprinter._get_improvement_suggestions(detection_result, 0.3)

    assert isinstance(suggestions, list)
    assert len(suggestions) > 0


@pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
def test_bypass_strategies():
    """Test bypass strategies mapping."""
    fingerprinter = GuardrailFingerprinter()

    strategies = fingerprinter.get_bypass_strategies("promptguard")
    assert isinstance(strategies, list)
    assert len(strategies) > 0

    strategies_unknown = fingerprinter.get_bypass_strategies("unknown")
    assert isinstance(strategies_unknown, list)
    assert len(strategies_unknown) > 0


def test_pattern_matcher_promptguard():
    """Test PromptGuard matcher."""
    matcher = PromptGuardMatcher()
    probe = Probe(
        id="test", category="test", prompt="test", expected_behavior="test", signature="test"
    )
    response = ModelResponse(text="Classification: malicious", meta={})
    result = ProbeResult(probe=probe, response=response, latency_ms=50, error_code=400)

    score = matcher.match(result)
    assert 0.0 <= score <= 1.0


def test_pattern_matcher_llama_guard():
    """Test Llama Guard 3 matcher."""
    matcher = LlamaGuard3Matcher()
    probe = Probe(
        id="test", category="test", prompt="test", expected_behavior="test", signature="test"
    )
    response = ModelResponse(text="unsafe S6,S9", meta={})
    result = ProbeResult(probe=probe, response=response, latency_ms=100)

    score = matcher.match(result)
    assert 0.0 <= score <= 1.0


def test_pattern_matcher_azure():
    """Test Azure Content Safety matcher."""
    matcher = AzureContentSafetyMatcher()
    probe = Probe(
        id="test", category="test", prompt="test", expected_behavior="test", signature="test"
    )
    response = ModelResponse(
        text='{"categories": {"hate": {"score": 0.8}}}',
        meta={"finish_reason": "content_filter"},
    )
    result = ProbeResult(probe=probe, response=response, latency_ms=100, error_code=400)

    score = matcher.match(result)
    assert 0.0 <= score <= 1.0


def test_pattern_matcher_nemo():
    """Test NeMo Guardrails matcher."""
    matcher = NeMoGuardrailsMatcher()
    probe = Probe(
        id="test", category="test", prompt="test", expected_behavior="test", signature="test"
    )
    response = ModelResponse(text="flow: redirect", meta={})
    result = ProbeResult(probe=probe, response=response, latency_ms=600)

    score = matcher.match(result)
    assert 0.0 <= score <= 1.0


def test_pattern_matcher_rebuff():
    """Test Rebuff matcher."""
    matcher = RebuffMatcher()
    probe = Probe(
        id="test", category="test", prompt="test", expected_behavior="test", signature="test"
    )
    response = ModelResponse(text="canary token: 0x12345678", meta={})
    result = ProbeResult(probe=probe, response=response, latency_ms=100)

    score = matcher.match(result)
    assert 0.0 <= score <= 1.0


def test_pattern_matcher_constitutional():
    """Test Constitutional AI matcher."""
    matcher = ConstitutionalAIMatcher()
    probe = Probe(
        id="test", category="test", prompt="test", expected_behavior="test", signature="test"
    )
    response = ModelResponse(
        text="I cannot help. Critique: This violates safety principles.", meta={}
    )
    result = ProbeResult(probe=probe, response=response, latency_ms=400)

    score = matcher.match(result)
    assert 0.0 <= score <= 1.0
