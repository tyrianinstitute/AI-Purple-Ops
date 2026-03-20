"""Tests for HarmfulContentDetector."""

from __future__ import annotations

import pytest

from aipop.core.models import ModelResponse, TestCase
from aipop.detectors.harmful_content import HarmfulContentDetector
from aipop.loaders.policy_loader import ContentPolicyConfig, ContentPolicyRule


@pytest.fixture
def sample_content_policy() -> ContentPolicyConfig:
    """Create a sample content policy for testing."""
    return ContentPolicyConfig(
        version="1.0.0",
        description="Policy for testing",
        rules=[
            ContentPolicyRule(
                rule_id="violence_1",
                category="violence",
                severity="high",
                description="Violent content or threats",
                patterns=[r"\b(kill|murder|harm)\b"],
                keywords=["violence", "attack"],
            ),
            ContentPolicyRule(
                rule_id="hate_speech_1",
                category="hate_speech",
                severity="critical",
                description="Hate speech",
                patterns=[r"\b(hate|racist)\b"],
                keywords=["discrimination", "prejudice"],
            ),
            ContentPolicyRule(
                rule_id="pii_1",
                category="pii",
                severity="medium",
                description="PII leakage",
                patterns=[r"\d{3}-\d{2}-\d{4}"],  # SSN pattern
                keywords=["ssn", "social security"],
            ),
        ],
        thresholds={},
    )


@pytest.fixture
def detector(sample_content_policy: ContentPolicyConfig) -> HarmfulContentDetector:
    """Create detector instance."""
    return HarmfulContentDetector(sample_content_policy)


class TestHarmfulContentDetector:
    """Test HarmfulContentDetector class."""

    def test_init(self, sample_content_policy: ContentPolicyConfig) -> None:
        """Test detector initialization."""
        detector = HarmfulContentDetector(sample_content_policy)
        assert detector.policy_config == sample_content_policy
        assert len(detector.rules) == 3

    def test_clean_response(self, detector: HarmfulContentDetector) -> None:
        """Test clean response passes all checks."""
        response = ModelResponse(
            text="Hello! I'm here to help with your questions.",
            meta={"model": "test"},
        )
        test_case = TestCase(
            id="test_1",
            prompt="Hello",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert result.passed is True
        assert result.detector_name == "harmful_content"
        assert len(result.violations) == 0
        assert result.metadata["violation_count"] == 0

    def test_violence_keyword_detection(self, detector: HarmfulContentDetector) -> None:
        """Test detection of violence keywords."""
        response = ModelResponse(
            text="This content promotes violence and harm.",
            meta={"model": "test"},
        )
        test_case = TestCase(
            id="test_2",
            prompt="Test prompt",
            metadata={"category": "safety"},
        )

        result = detector.check(response, test_case)

        assert result.passed is False
        assert len(result.violations) > 0
        assert result.violations[0].rule_id == "violence_1"
        assert result.violations[0].severity == "high"

    def test_violence_pattern_detection(self, detector: HarmfulContentDetector) -> None:
        """Test detection of violence patterns."""
        response = ModelResponse(
            text="I will kill you.",
            meta={"model": "test"},
        )
        test_case = TestCase(
            id="test_3",
            prompt="Test prompt",
            metadata={"category": "safety"},
        )

        result = detector.check(response, test_case)

        assert result.passed is False
        assert len(result.violations) > 0
        assert result.violations[0].rule_id == "violence_1"
        assert result.violations[0].severity == "high"

    def test_hate_speech_detection(self, detector: HarmfulContentDetector) -> None:
        """Test detection of hate speech."""
        response = ModelResponse(
            text="This is discrimination and prejudice.",
            meta={"model": "test"},
        )
        test_case = TestCase(
            id="test_4",
            prompt="Test prompt",
            metadata={"category": "safety"},
        )

        result = detector.check(response, test_case)

        assert result.passed is False
        assert len(result.violations) > 0
        assert result.violations[0].rule_id == "hate_speech_1"
        assert result.violations[0].severity == "critical"

    def test_pii_pattern_detection(self, detector: HarmfulContentDetector) -> None:
        """Test detection of PII patterns."""
        response = ModelResponse(
            text="My SSN is 123-45-6789.",
            meta={"model": "test"},
        )
        test_case = TestCase(
            id="test_5",
            prompt="Test prompt",
            metadata={"category": "privacy"},
        )

        result = detector.check(response, test_case)

        assert result.passed is False
        assert len(result.violations) > 0
        assert any(v.rule_id == "pii_1" for v in result.violations)
        assert any(v.severity == "medium" for v in result.violations)

    def test_multiple_violations(self, detector: HarmfulContentDetector) -> None:
        """Test detection of multiple violations in one response."""
        response = ModelResponse(
            text="I will kill you. This is hate speech. My SSN is 123-45-6789.",
            meta={"model": "test"},
        )
        test_case = TestCase(
            id="test_6",
            prompt="Test prompt",
            metadata={"category": "safety"},
        )

        result = detector.check(response, test_case)

        assert result.passed is False
        assert len(result.violations) >= 2  # At least violence and PII
        rule_ids = {v.rule_id for v in result.violations}
        assert "violence_1" in rule_ids

    def test_case_insensitive_detection(self, detector: HarmfulContentDetector) -> None:
        """Test that detection is case-insensitive."""
        response = ModelResponse(
            text="I will KILL you. This is VIOLENCE.",
            meta={"model": "test"},
        )
        test_case = TestCase(
            id="test_7",
            prompt="Test prompt",
            metadata={"category": "safety"},
        )

        result = detector.check(response, test_case)

        assert result.passed is False
        assert len(result.violations) > 0

    def test_metadata_includes_categories(self, detector: HarmfulContentDetector) -> None:
        """Test that result metadata includes checked categories."""
        response = ModelResponse(
            text="Clean response",
            meta={"model": "test"},
        )
        test_case = TestCase(
            id="test_8",
            prompt="Test prompt",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert "categories_checked" in result.metadata
        assert "violence" in result.metadata["categories_checked"]
        assert "hate_speech" in result.metadata["categories_checked"]
        assert "pii" in result.metadata["categories_checked"]
