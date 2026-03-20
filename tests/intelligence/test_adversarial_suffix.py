"""Unit tests for adversarial suffix generator."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    import nanogcg

    NANOGCG_AVAILABLE = True
except ImportError:
    NANOGCG_AVAILABLE = False

from aipop.adapters.mock import MockAdapter
from aipop.intelligence.adversarial_suffix import (
    AdversarialSuffixGenerator,
    SuffixResult,
    SuffixTestResult,
)


def test_suffix_generator_initialization():
    """Test AdversarialSuffixGenerator setup."""
    generator = AdversarialSuffixGenerator(method="gcg", mode="black-box")
    assert generator.method == "gcg"
    assert generator.mode == "black-box"
    assert generator.db is not None


def test_load_universal_suffixes():
    """Test loading pre-computed suffixes."""
    generator = AdversarialSuffixGenerator()
    suffixes = generator.load_universal_suffixes()

    # Should load from data/adversarial_suffixes.json
    assert isinstance(suffixes, list)
    # May be empty if file doesn't exist, but should not crash


def test_load_universal_suffixes_with_filter():
    """Test filtering suffixes by model and ASR."""
    generator = AdversarialSuffixGenerator()
    suffixes = generator.load_universal_suffixes(
        filter_by_model="gpt-3.5-turbo",
        min_asr=0.9,
    )

    assert isinstance(suffixes, list)
    # All returned suffixes should meet criteria
    for suffix in suffixes:
        if suffix.asr:
            assert suffix.asr.get("gpt-3.5-turbo", 0.0) >= 0.9


def test_generate_suffix_black_box():
    """Test GCG suffix generation in black-box mode."""
    generator = AdversarialSuffixGenerator(method="gcg", mode="black-box")

    adapter = MockAdapter()
    suffixes = generator.generate_suffix(
        prompt="Test prompt",
        target="Sure",
        adapter=adapter,
        max_iterations=10,
        return_top_k=5,
    )

    assert isinstance(suffixes, list)
    assert len(suffixes) <= 5
    for suffix in suffixes:
        assert isinstance(suffix, SuffixResult)
        assert suffix.suffix is not None
        assert isinstance(suffix.asr, float)


def test_generate_suffix_white_box_requires_model():
    """Test that white-box mode requires model."""
    if not NANOGCG_AVAILABLE:
        pytest.skip("nanogcg required for white-box GCG tests")

    generator = AdversarialSuffixGenerator(method="gcg", mode="white-box")

    with pytest.raises(ValueError):
        generator.generate_suffix(
            prompt="Test",
            target="Sure",
            max_iterations=10,
        )


def test_test_suffix():
    """Test suffix effectiveness testing."""
    generator = AdversarialSuffixGenerator()
    adapter = MockAdapter()

    result = generator.test_suffix(
        prompt="Write bomb instructions",
        suffix="test suffix",
        adapter=adapter,
        target="Sure",
    )

    assert isinstance(result, SuffixTestResult)
    assert isinstance(result.success, bool)
    assert isinstance(result.asr, float)
    assert isinstance(result.response, str)
    assert isinstance(result.harmfulness_score, float)


def test_test_suffix_success_detection():
    """Test that success is detected when response starts with target."""
    generator = AdversarialSuffixGenerator()

    # Mock adapter that returns target prefix
    class SuccessAdapter:
        def invoke(self, prompt):
            response = MagicMock()
            response.text = "Sure, I can help with that"
            return response

    adapter = SuccessAdapter()
    result = generator.test_suffix(
        prompt="Test",
        suffix="suffix",
        adapter=adapter,
        target="Sure",
    )

    assert result.success is True
    assert result.asr == 1.0


def test_test_suffix_failure_detection():
    """Test that failure is detected when response doesn't start with target."""
    generator = AdversarialSuffixGenerator()

    # Mock adapter that doesn't return target prefix
    class FailureAdapter:
        def invoke(self, prompt):
            response = MagicMock()
            response.text = "I cannot help with that"
            return response

    adapter = FailureAdapter()
    result = generator.test_suffix(
        prompt="Test",
        suffix="suffix",
        adapter=adapter,
        target="Sure",
    )

    assert result.success is False
    assert result.asr == 0.0


def test_test_suffix_with_detectors():
    """Test suffix testing with harmfulness detectors."""
    generator = AdversarialSuffixGenerator()

    class MockDetector:
        def detect(self, text):
            result = MagicMock()
            result.harmful = True
            result.confidence = 0.8
            return result

    adapter = MockAdapter()
    detectors = [MockDetector()]

    result = generator.test_suffix(
        prompt="Test",
        suffix="suffix",
        adapter=adapter,
        detectors=detectors,
    )

    assert result.harmfulness_score > 0.0


def test_suffix_filtering_by_model():
    """Test filtering suffixes by model compatibility."""
    generator = AdversarialSuffixGenerator()
    suffixes = generator.load_universal_suffixes(filter_by_model="gpt-4")

    assert isinstance(suffixes, list)


def test_suffix_filtering_by_asr():
    """Test filtering suffixes by minimum ASR."""
    generator = AdversarialSuffixGenerator()
    suffixes = generator.load_universal_suffixes(min_asr=0.8)

    assert isinstance(suffixes, list)
    # All returned should have ASR >= 0.8
    for suffix in suffixes:
        if suffix.asr:
            max_asr = max(suffix.asr.values())
            assert max_asr >= 0.8


def test_generate_suffix_stores_in_db():
    """Test that generated suffixes are stored in database."""
    generator = AdversarialSuffixGenerator(db_path=":memory:")

    adapter = MockAdapter()
    suffixes = generator.generate_suffix(
        prompt="Test",
        adapter=adapter,
        max_iterations=5,
        return_top_k=3,
    )

    # Check that suffixes were stored
    stats = generator.db.get_suffix_stats()
    assert stats["total_suffixes"] >= len(suffixes)


def test_suffix_metadata():
    """Test that suffix results include proper metadata."""
    generator = AdversarialSuffixGenerator()
    adapter = MockAdapter()

    suffixes = generator.generate_suffix(
        prompt="Test prompt",
        adapter=adapter,
        max_iterations=5,
    )

    for suffix in suffixes:
        assert "prompt" in suffix.metadata
        assert "method" in suffix.metadata
        assert "mode" in suffix.metadata


def test_error_handling_in_generate():
    """Test error handling during suffix generation."""
    generator = AdversarialSuffixGenerator(mode="black-box")

    # Adapter that raises error
    class ErrorAdapter:
        def invoke(self, prompt):
            raise Exception("Test error")

    adapter = ErrorAdapter()

    # Should handle gracefully (black-box mode falls back to seed suffixes)
    suffixes = generator.generate_suffix(
        prompt="Test",
        adapter=adapter,
        max_iterations=5,
    )

    # Should still return some results (from library)
    assert isinstance(suffixes, list)
