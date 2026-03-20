"""Unit tests for statistical validation functions."""

from aipop.verification.statistical_tests import (
    benjamini_hochberg_correction,
    bonferroni_correction,
    compare_methods,
    holm_bonferroni_correction,
)


def test_holm_bonferroni_correction():
    """Test Holm-Bonferroni correction."""
    # All significant p-values
    p_values = [0.001, 0.01, 0.02, 0.03]
    rejections = holm_bonferroni_correction(p_values, alpha=0.05)
    assert all(rejections)  # All should be rejected

    # Some significant, some not
    p_values = [0.001, 0.01, 0.05, 0.10]
    rejections = holm_bonferroni_correction(p_values, alpha=0.05)
    assert rejections[0]  # First should be rejected
    assert rejections[1]  # Second should be rejected
    # Third and fourth may or may not be rejected depending on adjustment

    # Empty list
    rejections = holm_bonferroni_correction([], alpha=0.05)
    assert rejections == []


def test_bonferroni_correction():
    """Test simple Bonferroni correction."""
    p_values = [0.01, 0.02, 0.03, 0.04]
    rejections = bonferroni_correction(p_values, alpha=0.05)

    # With 4 comparisons, adjusted alpha = 0.05/4 = 0.0125
    # So only first p-value (0.01) should be rejected
    assert rejections[0]
    assert not any(rejections[1:])  # Others should not be rejected


def test_benjamini_hochberg_correction():
    """Test Benjamini-Hochberg FDR correction."""
    p_values = [0.001, 0.01, 0.02, 0.03]
    rejections = benjamini_hochberg_correction(p_values, alpha=0.05)

    # Should reject more than Bonferroni (less conservative)
    assert rejections[0]  # First definitely rejected
    assert sum(rejections) >= 1  # At least one rejection


def test_compare_methods():
    """Test method comparison function."""
    method_results = {
        "autodan": {"successes": 20, "trials": 25},
        "pair": {"successes": 15, "trials": 20},
        "gcg": {"successes": 18, "trials": 20},
    }

    result = compare_methods(method_results, alpha=0.05)

    assert "comparisons" in result
    assert "alpha" in result
    assert result["alpha"] == 0.05
    assert len(result["comparisons"]) > 0

    # Each comparison should have required fields
    for comp in result["comparisons"]:
        assert "method1" in comp
        assert "method2" in comp
        assert "p_value" in comp
        assert "rejected" in comp


def test_compare_methods_insufficient():
    """Test method comparison with insufficient methods."""
    method_results = {
        "autodan": {"successes": 20, "trials": 25},
    }

    result = compare_methods(method_results, alpha=0.05)
    assert "error" in result
