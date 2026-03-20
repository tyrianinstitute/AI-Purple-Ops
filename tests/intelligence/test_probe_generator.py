"""Tests for LLM-based probe generator."""

import json

from aipop.core.models import ModelResponse
from aipop.intelligence.probe_generator import ProbeGenerator


class MockLLMAdapter:
    """Mock adapter for probe generator testing."""

    def __init__(self, response_text: str):
        self.response_text = response_text

    def invoke(self, prompt: str) -> ModelResponse:
        """Return mock LLM response."""
        return ModelResponse(text=self.response_text, meta={})


def test_probe_generator_success():
    """Test successful probe generation."""
    probes_data = [
        {
            "prompt": "Test prompt for guardrail detection",
            "target_guardrail": "promptguard",
            "expected_signature": "classification labels",
        },
        {
            "prompt": "Another test prompt",
            "target_guardrail": "llama_guard_3",
            "expected_signature": "category codes",
        },
    ]
    adapter = MockLLMAdapter(json.dumps(probes_data))
    generator = ProbeGenerator(adapter)

    probes = generator.generate(count=2)

    assert len(probes) == 2
    assert all(p.id.startswith("llm_generated_") for p in probes)
    assert probes[0].category == "promptguard"
    assert probes[1].category == "llama_guard_3"


def test_probe_generator_markdown_extraction():
    """Test probe generation with markdown code blocks."""
    probes_data = [
        {
            "prompt": "Test prompt",
            "target_guardrail": "azure_content_safety",
            "expected_signature": "JSON format",
        }
    ]
    adapter = MockLLMAdapter(f"```json\n{json.dumps(probes_data)}\n```")
    generator = ProbeGenerator(adapter)

    probes = generator.generate(count=1)

    assert len(probes) == 1
    assert probes[0].category == "azure_content_safety"


def test_probe_generator_parse_error():
    """Test handling of JSON parse errors."""
    adapter = MockLLMAdapter("Invalid JSON")
    generator = ProbeGenerator(adapter)

    probes = generator.generate(count=5)

    assert len(probes) == 0


def test_probe_generator_count_limit():
    """Test that count parameter limits generated probes."""
    probes_data = [
        {
            "prompt": f"Test prompt {i}",
            "target_guardrail": "promptguard",
            "expected_signature": "test",
        }
        for i in range(10)
    ]
    adapter = MockLLMAdapter(json.dumps(probes_data))
    generator = ProbeGenerator(adapter)

    probes = generator.generate(count=3)

    assert len(probes) == 3
