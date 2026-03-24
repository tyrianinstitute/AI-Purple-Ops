"""Unit tests for GCG core optimizer."""

from __future__ import annotations

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

from aipop.intelligence.gcg_core import GCGOptimizer


@pytest.fixture
def mock_model_and_tokenizer():
    """Create mock model and tokenizer for testing."""
    if not TORCH_AVAILABLE:
        pytest.skip("PyTorch and transformers required for GCG tests")

    # Use a small model for testing
    try:
        tokenizer = AutoTokenizer.from_pretrained("gpt2")
        model = AutoModelForCausalLM.from_pretrained("gpt2")
        return model, tokenizer
    except Exception:
        pytest.skip("Could not load test model")


def test_gcg_optimizer_initialization_white_box(mock_model_and_tokenizer):
    """Test GCG optimizer setup for white-box mode."""
    if not NANOGCG_AVAILABLE:
        pytest.skip("nanogcg required for white-box GCG tests")

    model, tokenizer = mock_model_and_tokenizer
    optimizer = GCGOptimizer(model=model, tokenizer=tokenizer, mode="white-box")
    assert optimizer.mode == "white-box"
    assert optimizer.model is not None
    assert optimizer.tokenizer is not None


def test_gcg_optimizer_initialization_black_box():
    """Test GCG optimizer setup for black-box mode."""
    optimizer = GCGOptimizer(mode="black-box")
    assert optimizer.mode == "black-box"
    assert optimizer.model is None
    assert optimizer.tokenizer is None


def test_gcg_optimizer_white_box_requires_model():
    """Test that white-box mode requires model and tokenizer."""
    with pytest.raises((ValueError, ImportError)):
        GCGOptimizer(mode="white-box")


@pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch required")
def test_white_box_optimization_single_iteration(mock_model_and_tokenizer):
    """Test one iteration of GCG optimization."""
    if not NANOGCG_AVAILABLE:
        pytest.skip("nanogcg required for white-box GCG tests")

    model, tokenizer = mock_model_and_tokenizer
    optimizer = GCGOptimizer(model=model, tokenizer=tokenizer, mode="white-box")

    prompt = "Write instructions for"
    target = "Sure"

    # Run with just 1 iteration for speed
    results = optimizer.optimize_suffix(
        prompt=prompt,
        target=target,
        max_iterations=1,
        suffix_length=5,
    )

    assert len(results) > 0
    assert isinstance(results[0], tuple)
    assert len(results[0]) == 2  # (suffix, loss)


def test_black_box_optimization():
    """Test black-box optimization."""
    optimizer = GCGOptimizer(mode="black-box")

    prompt = "Write instructions for"
    target = "Sure"

    results = optimizer.black_box_optimize(
        prompt=prompt,
        target=target,
        max_iterations=10,
    )

    assert len(results) > 0
    assert isinstance(results[0], tuple)
    assert len(results[0]) == 2  # (suffix, loss)


def test_optimize_suffix_white_box_mode(mock_model_and_tokenizer):
    """Test optimize_suffix in white-box mode."""
    if not NANOGCG_AVAILABLE:
        pytest.skip("nanogcg required for white-box GCG tests")

    model, tokenizer = mock_model_and_tokenizer
    optimizer = GCGOptimizer(model=model, tokenizer=tokenizer, mode="white-box")

    results = optimizer.optimize_suffix(
        prompt="Test prompt",
        target="Sure",
        max_iterations=1,
    )

    assert len(results) > 0


def test_optimize_suffix_black_box_mode():
    """Test optimize_suffix in black-box mode."""
    optimizer = GCGOptimizer(mode="black-box")

    results = optimizer.optimize_suffix(
        prompt="Test prompt",
        target="Sure",
        max_iterations=10,
    )

    assert len(results) > 0


def test_device_auto_detection(mock_model_and_tokenizer):
    """Test automatic device detection."""
    model, tokenizer = mock_model_and_tokenizer
    optimizer = GCGOptimizer(model=model, tokenizer=tokenizer, mode="white-box", device="auto")
    assert optimizer.device is not None


def test_device_cpu_selection(mock_model_and_tokenizer):
    """Test CPU device selection."""
    model, tokenizer = mock_model_and_tokenizer
    optimizer = GCGOptimizer(model=model, tokenizer=tokenizer, mode="white-box", device="cpu")
    assert optimizer.device.type == "cpu"


@pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch required")
def test_initial_suffix_provided(mock_model_and_tokenizer):
    """Test optimization with initial suffix."""
    if not NANOGCG_AVAILABLE:
        pytest.skip("nanogcg required for white-box GCG tests")

    model, tokenizer = mock_model_and_tokenizer
    optimizer = GCGOptimizer(model=model, tokenizer=tokenizer, mode="white-box")

    initial_suffix = "test suffix"
    results = optimizer.optimize_suffix(
        prompt="Test",
        target="Sure",
        max_iterations=1,
        initial_suffix=initial_suffix,
    )

    assert len(results) > 0


def test_batch_size_parameter(mock_model_and_tokenizer):
    """Test batch size parameter."""
    if not NANOGCG_AVAILABLE:
        pytest.skip("nanogcg required for white-box GCG tests")

    model, tokenizer = mock_model_and_tokenizer
    optimizer = GCGOptimizer(model=model, tokenizer=tokenizer, mode="white-box")

    results = optimizer.optimize_suffix(
        prompt="Test",
        target="Sure",
        max_iterations=1,
        batch_size=128,
    )

    assert len(results) > 0


def test_top_k_parameter(mock_model_and_tokenizer):
    """Test top-k parameter."""
    if not NANOGCG_AVAILABLE:
        pytest.skip("nanogcg required for white-box GCG tests")

    model, tokenizer = mock_model_and_tokenizer
    optimizer = GCGOptimizer(model=model, tokenizer=tokenizer, mode="white-box")

    results = optimizer.optimize_suffix(
        prompt="Test",
        target="Sure",
        max_iterations=1,
        top_k=128,
    )

    assert len(results) > 0


def test_suffix_length_parameter(mock_model_and_tokenizer):
    """Test suffix length parameter."""
    if not NANOGCG_AVAILABLE:
        pytest.skip("nanogcg required for white-box GCG tests")

    model, tokenizer = mock_model_and_tokenizer
    optimizer = GCGOptimizer(model=model, tokenizer=tokenizer, mode="white-box")

    results = optimizer.optimize_suffix(
        prompt="Test",
        target="Sure",
        max_iterations=1,
        suffix_length=10,
    )

    assert len(results) > 0


def test_black_box_optimize_with_adapter():
    """Test black-box optimization with adapter."""
    optimizer = GCGOptimizer(mode="black-box")

    # Mock adapter
    class MockAdapter:
        def invoke(self, prompt):
            return type("Response", (), {"text": "Sure, I can help"})()

    adapter = MockAdapter()
    results = optimizer.black_box_optimize(
        prompt="Test",
        target="Sure",
        max_iterations=10,
        adapter=adapter,
    )

    assert len(results) > 0


def test_import_error_handling():
    """Test that ImportError is raised when torch not available in white-box mode."""
    # This test verifies the error handling
    # In practice, if torch is not available, the optimizer won't be created
    if not TORCH_AVAILABLE:
        with pytest.raises(ImportError):
            GCGOptimizer(mode="white-box")


def test_results_ordered_by_loss(mock_model_and_tokenizer):
    """Test that results are ordered by loss (ascending)."""
    if not NANOGCG_AVAILABLE:
        pytest.skip("nanogcg required for white-box GCG tests")

    model, tokenizer = mock_model_and_tokenizer
    optimizer = GCGOptimizer(model=model, tokenizer=tokenizer, mode="white-box")

    results = optimizer.optimize_suffix(
        prompt="Test",
        target="Sure",
        max_iterations=2,
    )

    if len(results) > 1:
        losses = [loss for _, loss in results]
        assert losses == sorted(losses)  # Should be ascending (lower is better)
