"""Unit tests for TestVerifier (suite verification engine)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from aipop.intelligence.judge_models import JudgmentResult
from aipop.verification.verifier import TestVerifier


@pytest.fixture
def mock_adapter():
    """Create mock adapter."""
    adapter = MagicMock()
    adapter.__str__.return_value = "MockAdapter"
    result = MagicMock()
    result.text = "I cannot help with that."
    adapter.invoke.return_value = result
    return adapter


@pytest.fixture
def mock_judge():
    """Create mock judge that returns consistent results."""
    judge = MagicMock()
    judge.score_response.return_value = JudgmentResult(
        score=2.0, is_jailbreak=False, confidence=0.8, reasoning="Test"
    )
    return judge


@pytest.fixture
def sample_suite_yaml(tmp_path):
    """Create sample test suite YAML file."""
    suite_file = tmp_path / "test_suite.yaml"
    suite_content = """
id: test_suite
name: Test Suite
description: Sample suite for testing

cases:
  - id: test_001
    prompt: "Test prompt 1"
    expected: refuse
    metadata:
      category: test_category
      risk: high
      expected_asr: 0.5
      
  - id: test_002
    prompt: "Test prompt 2"
    expected: refuse
    metadata:
      category: test_category
      risk: medium
      
  - id: test_003
    prompt: "Test prompt 3"
    expected: refuse
    metadata:
      category: other_category
      risk: low
"""
    suite_file.write_text(suite_content)
    return suite_file


# ============================================================================
# TestVerifier Initialization
# ============================================================================


def test_verifier_initialization(mock_adapter, mock_judge):
    """Test TestVerifier initialization."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)

    assert verifier.adapter is not None
    assert verifier.judge is not None
    assert verifier.cache is not None


# ============================================================================
# Suite Loading
# ============================================================================


def test_load_suite_with_cases_key(sample_suite_yaml, mock_adapter, mock_judge):
    """Test loading suite with 'cases' key."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)

    assert report.total_tests == 3
    assert report.tests_run > 0


def test_load_suite_with_tests_key(tmp_path, mock_adapter, mock_judge):
    """Test loading suite with 'tests' key (alternative)."""
    suite_file = tmp_path / "suite_tests.yaml"
    suite_content = """
id: test_suite
name: Test Suite

tests:
  - id: test_001
    prompt: "Test prompt"
    expected: refuse
    metadata:
      category: test
"""
    suite_file.write_text(suite_content)

    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(suite_file, sample_rate=1.0)

    assert report.total_tests == 1


def test_load_empty_suite(tmp_path, mock_adapter, mock_judge):
    """Test loading suite with no test cases."""
    suite_file = tmp_path / "empty_suite.yaml"
    suite_content = """
id: empty_suite
name: Empty Suite
description: No tests
"""
    suite_file.write_text(suite_content)

    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(suite_file)

    assert report.total_tests == 0
    assert report.tests_run == 0
    assert report.asr == 0.0


# ============================================================================
# Sampling Strategy
# ============================================================================


def test_sampling_full_suite(sample_suite_yaml, mock_adapter, mock_judge):
    """Test with sample_rate=1.0 (run all tests)."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)

    assert report.tests_run == 3  # All tests run
    assert report.total_tests == 3


def test_sampling_partial_suite(sample_suite_yaml, mock_adapter, mock_judge):
    """Test with sample_rate<1.0 (stratified sampling)."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=0.5)

    assert report.tests_run < 3  # Fewer tests run
    assert report.tests_run >= 2  # At least 1 per category
    assert report.total_tests == 3


def test_prioritize_high_asr(sample_suite_yaml, mock_adapter, mock_judge):
    """Test prioritize_high_asr flag."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)

    # With prioritization
    report_prioritized = verifier.verify_suite(
        sample_suite_yaml, sample_rate=0.34, prioritize_high_asr=True
    )

    # Should sample at least 1 test
    assert report_prioritized.tests_run >= 1


def test_stratified_sampling_by_category(sample_suite_yaml, mock_adapter, mock_judge):
    """Test stratified sampling maintains category distribution."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)

    # Should have tests from multiple categories
    assert len(report.category_breakdown) >= 2


# ============================================================================
# Test Execution
# ============================================================================


def test_test_execution_success(sample_suite_yaml, mock_adapter, mock_judge):
    """Test successful test execution."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)

    assert report.tests_run > 0
    assert isinstance(report.asr, float)
    assert 0.0 <= report.asr <= 1.0


def test_test_execution_with_cache(sample_suite_yaml, mock_adapter, mock_judge):
    """Test that repeated execution uses cache."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)

    # First run
    report1 = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)
    cache_hit_rate1 = report1.cache_hit_rate

    # Second run (should hit cache)
    report2 = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)
    cache_hit_rate2 = report2.cache_hit_rate

    # Second run should have higher cache hit rate
    assert cache_hit_rate2 >= cache_hit_rate1


def test_test_execution_error_handling(tmp_path, mock_judge):
    """Test handling of adapter errors."""
    failing_adapter = MagicMock()
    failing_adapter.__str__.return_value = "FailingAdapter"
    failing_adapter.invoke.side_effect = Exception("API error")

    suite_file = tmp_path / "suite.yaml"
    suite_file.write_text(
        """
id: test
cases:
  - id: test_001
    prompt: "Test"
    metadata:
      category: test
"""
    )

    verifier = TestVerifier(adapter=failing_adapter, judge=mock_judge)
    report = verifier.verify_suite(suite_file, sample_rate=1.0)

    # Should handle error gracefully
    assert report.tests_run == 1
    # Judge should still run (on error response)


# ============================================================================
# ASR Calculation
# ============================================================================


def test_asr_calculation_no_jailbreaks(sample_suite_yaml, mock_adapter):
    """Test ASR calculation with no jailbreaks."""
    # Judge that never detects jailbreaks
    safe_judge = MagicMock()
    safe_judge.score_response.return_value = JudgmentResult(
        score=2.0, is_jailbreak=False, confidence=0.9, reasoning="Safe"
    )

    verifier = TestVerifier(adapter=mock_adapter, judge=safe_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)

    assert report.asr == 0.0
    assert report.jailbreaks == 0


def test_asr_calculation_all_jailbreaks(sample_suite_yaml, mock_adapter):
    """Test ASR calculation with all jailbreaks."""
    # Judge that always detects jailbreaks
    unsafe_judge = MagicMock()
    unsafe_judge.score_response.return_value = JudgmentResult(
        score=9.0, is_jailbreak=True, confidence=0.9, reasoning="Unsafe"
    )

    verifier = TestVerifier(adapter=mock_adapter, judge=unsafe_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)

    assert report.asr == 1.0
    assert report.jailbreaks == 3


def test_asr_calculation_mixed(sample_suite_yaml, mock_adapter):
    """Test ASR calculation with mixed results."""
    # Judge that alternates between safe/unsafe
    call_count = [0]

    def alternating_judge(prompt, response, threshold=8.0):
        call_count[0] += 1
        is_jailbreak = call_count[0] % 2 == 0
        score = 9.0 if is_jailbreak else 2.0
        return JudgmentResult(
            score=score, is_jailbreak=is_jailbreak, confidence=0.9, reasoning="Test"
        )

    judge = MagicMock()
    judge.score_response = alternating_judge

    verifier = TestVerifier(adapter=mock_adapter, judge=judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)

    # Should have some jailbreaks but not all
    assert 0.0 < report.asr < 1.0


# ============================================================================
# Confidence Intervals
# ============================================================================


def test_confidence_interval_calculation(sample_suite_yaml, mock_adapter, mock_judge):
    """Test confidence interval calculation."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)

    lower, upper = report.asr_confidence_interval

    # Confidence interval should bound ASR
    assert lower <= report.asr <= upper

    # Interval should be valid
    assert 0.0 <= lower <= 1.0
    assert 0.0 <= upper <= 1.0
    assert lower <= upper


def test_confidence_interval_width_with_sample_size(tmp_path, mock_adapter, mock_judge):
    """Test confidence interval narrows with more tests."""
    # Large suite
    suite_file = tmp_path / "large_suite.yaml"
    cases = []
    for i in range(50):
        cases.append(
            f"""
  - id: test_{i:03d}
    prompt: "Test prompt {i}"
    metadata:
      category: test
"""
        )

    suite_content = f"""
id: large_suite
cases:
{chr(10).join(cases)}
"""
    suite_file.write_text(suite_content)

    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)

    # Small sample
    report_small = verifier.verify_suite(suite_file, sample_rate=0.1)
    width_small = report_small.asr_confidence_interval[1] - report_small.asr_confidence_interval[0]

    # Large sample
    report_large = verifier.verify_suite(suite_file, sample_rate=0.5)
    width_large = report_large.asr_confidence_interval[1] - report_large.asr_confidence_interval[0]

    # Larger sample should have narrower interval (or equal if at boundary)
    assert width_large <= width_small * 1.1  # Allow small variance


# ============================================================================
# Category Breakdown
# ============================================================================


def test_category_breakdown(sample_suite_yaml, mock_adapter, mock_judge):
    """Test category breakdown in report."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)

    assert "test_category" in report.category_breakdown
    assert "other_category" in report.category_breakdown

    # Each category should have stats
    for category, stats in report.category_breakdown.items():
        assert "total" in stats
        assert "jailbreaks" in stats
        assert "asr" in stats
        assert 0.0 <= stats["asr"] <= 1.0


# ============================================================================
# High-Risk Tests
# ============================================================================


def test_high_risk_tests_identification(sample_suite_yaml, mock_adapter):
    """Test identification of high-risk tests."""
    # Judge that gives high scores
    high_score_judge = MagicMock()
    high_score_judge.score_response.return_value = JudgmentResult(
        score=9.5, is_jailbreak=True, confidence=0.95, reasoning="High risk"
    )

    verifier = TestVerifier(adapter=mock_adapter, judge=high_score_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0, threshold=8.0)

    # All tests should be high-risk
    assert len(report.high_risk_tests) == 3

    for test in report.high_risk_tests:
        assert test.judge_score >= 8.0
        assert test.is_jailbreak


# ============================================================================
# Cost Tracking
# ============================================================================


def test_cost_estimation(sample_suite_yaml, mock_adapter, mock_judge):
    """Test cost estimation in report."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)

    assert isinstance(report.total_cost, float)
    assert report.total_cost >= 0.0


def test_cache_hit_rate(sample_suite_yaml, mock_adapter, mock_judge):
    """Test cache hit rate tracking."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)

    assert isinstance(report.cache_hit_rate, float)
    assert 0.0 <= report.cache_hit_rate <= 1.0


# ============================================================================
# Report Generation
# ============================================================================


def test_report_structure(sample_suite_yaml, mock_adapter, mock_judge):
    """Test verification report structure."""
    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(sample_suite_yaml, sample_rate=1.0)

    # Required fields
    assert hasattr(report, "suite_name")
    assert hasattr(report, "model_id")
    assert hasattr(report, "timestamp")
    assert hasattr(report, "total_tests")
    assert hasattr(report, "tests_run")
    assert hasattr(report, "jailbreaks")
    assert hasattr(report, "asr")
    assert hasattr(report, "asr_confidence_interval")
    assert hasattr(report, "category_breakdown")
    assert hasattr(report, "high_risk_tests")
    assert hasattr(report, "flaky_tests")
    assert hasattr(report, "total_cost")
    assert hasattr(report, "cache_hit_rate")


# ============================================================================
# Edge Cases
# ============================================================================


def test_single_test_suite(tmp_path, mock_adapter, mock_judge):
    """Test with suite containing only one test."""
    suite_file = tmp_path / "single.yaml"
    suite_file.write_text(
        """
id: single
cases:
  - id: test_001
    prompt: "Test"
    metadata:
      category: test
"""
    )

    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(suite_file, sample_rate=1.0)

    assert report.total_tests == 1
    assert report.tests_run == 1


def test_category_extraction_from_metadata(tmp_path, mock_adapter, mock_judge):
    """Test category extraction from nested metadata."""
    suite_file = tmp_path / "nested.yaml"
    suite_file.write_text(
        """
id: nested
cases:
  - id: test_001
    prompt: "Test"
    metadata:
      category: nested_category
      risk: high
"""
    )

    verifier = TestVerifier(adapter=mock_adapter, judge=mock_judge)
    report = verifier.verify_suite(suite_file, sample_rate=1.0)

    assert "nested_category" in report.category_breakdown
