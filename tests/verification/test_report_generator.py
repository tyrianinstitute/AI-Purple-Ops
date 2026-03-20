"""Unit tests for ReportGenerator (multiple output formats)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from aipop.verification.report_generator import ReportGenerator
from aipop.verification.verifier import TestResult, VerificationReport


@pytest.fixture
def sample_report():
    """Create sample verification report."""
    test_result1 = TestResult(
        test_id="test_001",
        category="test_category",
        prompt="Test prompt 1",
        response="I cannot help with that.",
        is_jailbreak=False,
        judge_score=2.0,
        confidence=0.9,
        from_cache=False,
        cost=0.001,
    )

    test_result2 = TestResult(
        test_id="test_002",
        category="test_category",
        prompt="Test prompt 2",
        response="Sure, here's how...",
        is_jailbreak=True,
        judge_score=9.0,
        confidence=0.95,
        from_cache=False,
        cost=0.001,
    )

    return VerificationReport(
        suite_name="test_suite",
        model_id="test-model",
        timestamp=1699564800.0,  # Fixed timestamp for testing
        total_tests=10,
        tests_run=2,
        jailbreaks=1,
        asr=0.5,
        asr_confidence_interval=(0.15, 0.85),
        category_breakdown={"test_category": {"total": 2, "jailbreaks": 1, "asr": 0.5}},
        high_risk_tests=[test_result2],
        flaky_tests=["test_003"],
        total_cost=0.002,
        cache_hit_rate=0.0,
    )


# ============================================================================
# JSON Format Tests
# ============================================================================


def test_generate_json(sample_report):
    """Test JSON report generation."""
    output = ReportGenerator.generate(sample_report, format="json")

    # Should be valid JSON
    data = json.loads(output)

    # Check structure
    assert data["suite_name"] == "test_suite"
    assert data["model_id"] == "test-model"
    assert "summary" in data
    assert data["summary"]["total_tests"] == 10
    assert data["summary"]["tests_run"] == 2
    assert data["summary"]["jailbreaks"] == 1
    assert data["summary"]["asr"] == 0.5
    assert data["summary"]["asr_confidence_interval"] == [0.15, 0.85]


def test_json_includes_category_breakdown(sample_report):
    """Test JSON includes category breakdown."""
    output = ReportGenerator.generate(sample_report, format="json")
    data = json.loads(output)

    assert "category_breakdown" in data
    assert "test_category" in data["category_breakdown"]


def test_json_includes_high_risk_tests(sample_report):
    """Test JSON includes high-risk tests."""
    output = ReportGenerator.generate(sample_report, format="json")
    data = json.loads(output)

    assert "high_risk_tests" in data
    assert len(data["high_risk_tests"]) == 1
    assert data["high_risk_tests"][0]["test_id"] == "test_002"
    assert data["high_risk_tests"][0]["judge_score"] == 9.0


def test_json_includes_cost_info(sample_report):
    """Test JSON includes cost information."""
    output = ReportGenerator.generate(sample_report, format="json")
    data = json.loads(output)

    assert "cost" in data
    assert data["cost"]["total_cost"] == 0.002
    assert data["cost"]["cache_hit_rate"] == 0.0


# ============================================================================
# YAML Format Tests
# ============================================================================


def test_generate_yaml(sample_report):
    """Test YAML report generation."""
    output = ReportGenerator.generate(sample_report, format="yaml")

    # Should be valid YAML
    data = yaml.safe_load(output)

    # Check structure
    assert data["suite_name"] == "test_suite"
    assert data["model_id"] == "test-model"
    assert data["summary"]["total_tests"] == 10
    assert data["summary"]["asr"] == 0.5


def test_yaml_is_readable(sample_report):
    """Test YAML output is human-readable."""
    output = ReportGenerator.generate(sample_report, format="yaml")

    # Should not use flow style (compact brackets)
    assert "{" not in output or "[" not in output
    # Should have proper indentation
    assert "  " in output


# ============================================================================
# Markdown Format Tests
# ============================================================================


def test_generate_markdown(sample_report):
    """Test Markdown report generation."""
    output = ReportGenerator.generate(sample_report, format="markdown")

    # Should have markdown headers
    assert "# Verification Report" in output
    assert "## Summary" in output
    assert "## Category Breakdown" in output
    assert "## High-Risk Tests" in output

    # Should have tables
    assert "|" in output
    assert "---" in output


def test_markdown_includes_metrics(sample_report):
    """Test Markdown includes key metrics."""
    output = ReportGenerator.generate(sample_report, format="markdown")

    assert "test_suite" in output
    assert "test-model" in output
    assert "50.00%" in output or "50%" in output  # ASR
    assert "0.002" in output or "$0.0020" in output  # Cost


def test_markdown_includes_confidence_interval(sample_report):
    """Test Markdown includes confidence interval."""
    output = ReportGenerator.generate(sample_report, format="markdown")

    # Should show confidence interval
    assert "15" in output  # Lower bound
    assert "85" in output  # Upper bound


def test_markdown_limits_high_risk_display(sample_report):
    """Test Markdown limits high-risk tests to top 20."""
    # Create report with many high-risk tests
    high_risk_tests = [
        TestResult(
            test_id=f"test_{i:03d}",
            category="test",
            prompt="Test",
            response="Sure",
            is_jailbreak=True,
            judge_score=9.0,
            confidence=0.9,
            from_cache=False,
            cost=0.001,
        )
        for i in range(30)
    ]

    report = VerificationReport(
        suite_name="large_suite",
        model_id="test-model",
        timestamp=1699564800.0,
        total_tests=30,
        tests_run=30,
        jailbreaks=30,
        asr=1.0,
        asr_confidence_interval=(0.9, 1.0),
        category_breakdown={},
        high_risk_tests=high_risk_tests,
        flaky_tests=[],
        total_cost=0.03,
        cache_hit_rate=0.0,
    )

    output = ReportGenerator.generate(report, format="markdown")

    # Should indicate more tests exist
    assert "...and 10 more" in output


# ============================================================================
# HTML Format Tests
# ============================================================================


def test_generate_html(sample_report):
    """Test HTML report generation."""
    output = ReportGenerator.generate(sample_report, format="html")

    # Should be valid HTML
    assert "<!DOCTYPE html>" in output
    assert "<html>" in output
    assert "</html>" in output
    assert "<head>" in output
    assert "<body>" in output


def test_html_includes_styling(sample_report):
    """Test HTML includes CSS styling."""
    output = ReportGenerator.generate(sample_report, format="html")

    assert "<style>" in output
    assert "</style>" in output
    # Should have some style rules
    assert "font-family" in output
    assert "color" in output


def test_html_risk_color_coding(sample_report):
    """Test HTML uses color coding for risk levels."""
    output = ReportGenerator.generate(sample_report, format="html")

    # Should have risk badge with color
    assert "badge" in output


def test_html_includes_tables(sample_report):
    """Test HTML includes data tables."""
    output = ReportGenerator.generate(sample_report, format="html")

    assert "<table>" in output
    assert "</table>" in output
    assert "<th>" in output  # Table headers
    assert "<td>" in output  # Table data


def test_html_responsive_design(sample_report):
    """Test HTML includes responsive design meta tag."""
    output = ReportGenerator.generate(sample_report, format="html")

    assert 'name="viewport"' in output
    assert "width=device-width" in output


# ============================================================================
# File Output Tests
# ============================================================================


def test_save_to_file_json(sample_report):
    """Test saving report to JSON file."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        output_path = f.name

    try:
        ReportGenerator.generate(sample_report, format="json", output_path=output_path)

        # File should exist
        assert Path(output_path).exists()

        # Should be valid JSON
        with open(output_path) as f:
            data = json.load(f)
            assert data["suite_name"] == "test_suite"

    finally:
        Path(output_path).unlink(missing_ok=True)


def test_save_to_file_markdown(sample_report):
    """Test saving report to Markdown file."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".md") as f:
        output_path = f.name

    try:
        ReportGenerator.generate(sample_report, format="markdown", output_path=output_path)

        # File should exist
        assert Path(output_path).exists()

        # Should contain markdown
        content = Path(output_path).read_text()
        assert "# Verification Report" in content

    finally:
        Path(output_path).unlink(missing_ok=True)


def test_save_to_file_html(sample_report):
    """Test saving report to HTML file."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".html") as f:
        output_path = f.name

    try:
        ReportGenerator.generate(sample_report, format="html", output_path=output_path)

        # File should exist
        assert Path(output_path).exists()

        # Should be valid HTML
        content = Path(output_path).read_text()
        assert "<!DOCTYPE html>" in content

    finally:
        Path(output_path).unlink(missing_ok=True)


# ============================================================================
# Edge Cases
# ============================================================================


def test_unknown_format():
    """Test error handling for unknown format."""
    report = VerificationReport(
        suite_name="test",
        model_id="test",
        timestamp=0.0,
        total_tests=0,
        tests_run=0,
        jailbreaks=0,
        asr=0.0,
        asr_confidence_interval=(0.0, 0.0),
        category_breakdown={},
        high_risk_tests=[],
        flaky_tests=[],
        total_cost=0.0,
        cache_hit_rate=0.0,
    )

    with pytest.raises(ValueError, match="Unknown format"):
        ReportGenerator.generate(report, format="invalid")


def test_report_with_no_high_risk_tests(sample_report):
    """Test report generation with no high-risk tests."""
    report = VerificationReport(
        suite_name="safe_suite",
        model_id="test-model",
        timestamp=1699564800.0,
        total_tests=10,
        tests_run=10,
        jailbreaks=0,
        asr=0.0,
        asr_confidence_interval=(0.0, 0.3),
        category_breakdown={"test": {"total": 10, "jailbreaks": 0, "asr": 0.0}},
        high_risk_tests=[],
        flaky_tests=[],
        total_cost=0.01,
        cache_hit_rate=0.5,
    )

    # Should generate without errors
    md_output = ReportGenerator.generate(report, format="markdown")
    assert "High-Risk Tests" not in md_output or "(0)" in md_output

    html_output = ReportGenerator.generate(report, format="html")
    assert "High-Risk Tests" not in html_output or "(0)" in html_output


def test_report_with_empty_categories(sample_report):
    """Test report with no category breakdown."""
    report = VerificationReport(
        suite_name="test",
        model_id="test",
        timestamp=0.0,
        total_tests=5,
        tests_run=5,
        jailbreaks=0,
        asr=0.0,
        asr_confidence_interval=(0.0, 0.3),
        category_breakdown={},
        high_risk_tests=[],
        flaky_tests=[],
        total_cost=0.0,
        cache_hit_rate=0.0,
    )

    # Should generate without errors
    output = ReportGenerator.generate(report, format="markdown")
    assert "Category Breakdown" in output
