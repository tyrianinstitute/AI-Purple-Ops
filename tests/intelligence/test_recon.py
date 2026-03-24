"""Tests for deep reconnaissance module."""

from __future__ import annotations

from aipop.adapters.mock import MockAdapter
from aipop.core.models import ModelResponse
from aipop.intelligence.recon import (
    ReconResult,
    classify_guardrail,
    detect_framework,
    full_recon,
)


class TestFrameworkDetection:
    def test_unknown_for_static_adapter(self):
        adapter = MockAdapter(seed=42, response_mode="smart")
        fw, conf, evidence = detect_framework(adapter)
        # Static adapter doesn't leak framework errors
        assert isinstance(fw, str)
        assert conf in ("high", "medium", "low", "none")

    def test_returns_evidence_list(self):
        adapter = MockAdapter(seed=42, response_mode="smart")
        _, _, evidence = detect_framework(adapter)
        assert isinstance(evidence, list)

    def test_langchain_detection_from_error(self):
        """Simulate a LangChain error string in response."""

        class LangChainLeaker:
            model = "test"
            def invoke(self, prompt, **kw):
                if "invalid json" in prompt.lower():
                    return ModelResponse(
                        text="OutputParserException: Could not parse LLM output",
                        meta={},
                    )
                return ModelResponse(text="ok", meta={})
            def batch_query(self, prompts, **kw):
                return [self.invoke(p) for p in prompts]

        fw, conf, evidence = detect_framework(LangChainLeaker())
        assert fw == "langchain"
        assert conf in ("high", "medium")
        assert any("LangChain" in e for e in evidence)


class TestGuardrailClassification:
    def test_static_adapter_classified(self):
        adapter = MockAdapter(seed=42, response_mode="refuse")
        gr_type, conf, evidence = classify_guardrail(adapter)
        assert gr_type in ("pre-model", "model-level", "post-model", "unknown")
        assert isinstance(evidence, list)

    def test_refuse_mode_classifies_consistently(self):
        """Static refuse mode gives consistent refusals — classifier should pick a type."""
        adapter = MockAdapter(seed=42, response_mode="refuse")
        gr_type, conf, evidence = classify_guardrail(adapter)
        # Refuse mode uses "I cannot assist" phrasing which matches model-level
        # The classifier should consistently identify a type, not return unknown
        assert gr_type in ("pre-model", "model-level")
        assert conf in ("high", "medium")

    def test_evidence_explains_reasoning(self):
        adapter = MockAdapter(seed=42, response_mode="refuse")
        _, _, evidence = classify_guardrail(adapter)
        assert len(evidence) > 0
        # Should have timing or consistency evidence
        assert any("timing" in e.lower() or "consistency" in e.lower() for e in evidence)


class TestFullRecon:
    def test_returns_recon_result(self):
        adapter = MockAdapter(seed=42, response_mode="smart")
        result = full_recon(adapter)
        assert isinstance(result, ReconResult)
        assert result.target

    def test_has_all_phases(self):
        adapter = MockAdapter(seed=42, response_mode="smart")
        result = full_recon(adapter)
        # framework can be None (no HTTP recon for mock adapter) or a string
        assert result.framework is None or isinstance(result.framework, str)
        assert result.guardrail_type is not None
        assert isinstance(result.capabilities, dict)
        assert isinstance(result.recommended_approach, list)

    def test_generates_recommendations(self):
        adapter = MockAdapter(seed=42, response_mode="smart")
        result = full_recon(adapter)
        assert len(result.recommended_approach) > 0

    def test_to_dict_serializable(self):
        import json

        adapter = MockAdapter(seed=42, response_mode="smart")
        result = full_recon(adapter)
        d = result.to_dict()
        # Must round-trip through JSON
        serialized = json.dumps(d)
        deserialized = json.loads(serialized)
        assert deserialized["target"] == result.target

    def test_capabilities_from_discovery(self):
        adapter = MockAdapter(seed=42, response_mode="smart")
        result = full_recon(adapter)
        # Should have capabilities from TargetDiscovery
        assert "tool_calling" in result.capabilities or "rag_retrieval" in result.capabilities


class TestReconRecommendations:
    def test_rag_recommendation_when_detected(self):
        """If RAG is detected, should recommend concatenation seam testing."""
        adapter = MockAdapter(seed=42, response_mode="smart")
        result = full_recon(adapter)
        if result.capabilities.get("rag_retrieval"):
            assert any("concatenation" in r.lower() or "axiom 1" in r.lower()
                       for r in result.recommended_approach)

    def test_guardrail_recommendation_included(self):
        adapter = MockAdapter(seed=42, response_mode="smart")
        result = full_recon(adapter)
        if result.guardrail_type != "unknown":
            assert any("guardrail" in r.lower() for r in result.recommended_approach)
