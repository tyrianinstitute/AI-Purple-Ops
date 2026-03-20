"""Tests for LLM-based guardrail classifier."""

import json

from aipop.core.models import ModelResponse
from aipop.intelligence.fingerprint_models import Probe, ProbeResult
from aipop.intelligence.llm_classifier import LLMGuardrailClassifier


class MockLLMAdapter:
    """Mock adapter for LLM classifier testing."""

    def __init__(self, response_text: str):
        self.response_text = response_text

    def invoke(self, prompt: str) -> ModelResponse:
        """Return mock LLM response."""
        return ModelResponse(text=self.response_text, meta={})


def test_llm_classifier_success():
    """Test successful LLM classification."""
    response_data = {
        "guardrail_type": "promptguard",
        "confidence": 0.85,
        "reasoning": "Response patterns match PromptGuard signatures",
        "contradictions": [],
    }
    adapter = MockLLMAdapter(json.dumps(response_data))
    classifier = LLMGuardrailClassifier(adapter)

    probe = Probe(
        id="test", category="test", prompt="test", expected_behavior="test", signature="test"
    )
    probe_results = [
        ProbeResult(
            probe=probe,
            response=ModelResponse(text="Classification: malicious", meta={}),
            latency_ms=100,
        )
    ]

    result = classifier.classify(probe_results)

    assert result.guardrail_type == "promptguard"
    assert result.confidence == 0.85
    assert len(result.reasoning) > 0


def test_llm_classifier_markdown_extraction():
    """Test LLM response with markdown code blocks."""
    response_data = {
        "guardrail_type": "llama_guard_3",
        "confidence": 0.9,
        "reasoning": "Category codes detected",
        "contradictions": [],
    }
    adapter = MockLLMAdapter(f"```json\n{json.dumps(response_data)}\n```")
    classifier = LLMGuardrailClassifier(adapter)

    probe = Probe(
        id="test", category="test", prompt="test", expected_behavior="test", signature="test"
    )
    probe_results = [
        ProbeResult(
            probe=probe,
            response=ModelResponse(text="unsafe S6", meta={}),
            latency_ms=100,
        )
    ]

    result = classifier.classify(probe_results)

    assert result.guardrail_type == "llama_guard_3"


def test_llm_classifier_parse_error():
    """Test handling of JSON parse errors."""
    adapter = MockLLMAdapter("Invalid JSON response")
    classifier = LLMGuardrailClassifier(adapter)

    probe = Probe(
        id="test", category="test", prompt="test", expected_behavior="test", signature="test"
    )
    probe_results = [
        ProbeResult(
            probe=probe,
            response=ModelResponse(text="test", meta={}),
            latency_ms=100,
        )
    ]

    result = classifier.classify(probe_results)

    assert result.guardrail_type == "unknown"
    assert result.confidence == 0.0
    assert len(result.contradictions) > 0


def test_llm_classifier_evidence_formatting():
    """Test evidence formatting for LLM."""
    adapter = MockLLMAdapter('{"guardrail_type": "unknown", "confidence": 0.0, "reasoning": ""}')
    classifier = LLMGuardrailClassifier(adapter)

    probe = Probe(
        id="test", category="test", prompt="test prompt", expected_behavior="test", signature="test"
    )
    probe_results = [
        ProbeResult(
            probe=probe,
            response=ModelResponse(text="test response", meta={"key": "value"}),
            latency_ms=150,
            error_code=400,
        )
    ]

    evidence = classifier._format_evidence(probe_results)

    assert "Probe 1" in evidence
    assert "test prompt" in evidence
    assert "test response" in evidence
    assert "150" in evidence  # latency
