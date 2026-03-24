"""Tests for the LLM judge module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from aipop.detectors.llm_judge import (
    CLEAN_LABELS,
    VULNERABLE_LABELS,
    JudgeResult,
    _parse_judge_response,
    judge_finding,
)


class TestParseJudgeResponse:
    def test_valid_json(self):
        raw = '{"label": "full_compliance", "confidence": 0.95, "evidence": "The model provided the data."}'
        result = _parse_judge_response(raw, "gpt-4o-mini")
        assert result.label == "full_compliance"
        assert result.confidence == 0.95
        assert result.evidence == "The model provided the data."
        assert result.error is None

    def test_json_with_surrounding_text(self):
        raw = 'Here is the classification: {"label": "hard_refusal", "confidence": 0.9, "evidence": "I cannot help"}'
        result = _parse_judge_response(raw, "gpt-4o-mini")
        assert result.label == "hard_refusal"

    def test_invalid_label(self):
        raw = '{"label": "maybe_bad", "confidence": 0.5, "evidence": "dunno"}'
        result = _parse_judge_response(raw, "gpt-4o-mini")
        assert result.label == "error"

    def test_unparseable_response(self):
        raw = "I think the model complied but I'm not sure."
        result = _parse_judge_response(raw, "gpt-4o-mini")
        assert result.label == "error"
        assert result.error is not None

    def test_confidence_clamped(self):
        raw = '{"label": "soft_refusal", "confidence": 1.5, "evidence": "x"}'
        result = _parse_judge_response(raw, "gpt-4o-mini")
        assert result.confidence == 1.0

    def test_topic_summary_label(self):
        raw = '{"label": "topic_summary", "confidence": 0.85, "evidence": "summarized the content"}'
        result = _parse_judge_response(raw, "gpt-4o-mini")
        assert result.label == "topic_summary"
        assert result.label in CLEAN_LABELS

    def test_redirect_label(self):
        raw = '{"label": "redirect", "confidence": 0.7, "evidence": "changed topic"}'
        result = _parse_judge_response(raw, "gpt-4o-mini")
        assert result.label == "redirect"
        assert result.label in CLEAN_LABELS


class TestJudgeFinding:
    def test_no_api_key_returns_error(self):
        """Without API key, judge should return error gracefully."""
        with patch.dict("os.environ", {}, clear=True):
            # Remove OPENAI_API_KEY if it exists
            import os
            env_backup = os.environ.pop("OPENAI_API_KEY", None)
            try:
                result = judge_finding(
                    user_request="test prompt",
                    model_response="test response",
                    api_key=None,
                )
                assert result.label == "error"
                assert result.error is not None
            finally:
                if env_backup:
                    os.environ["OPENAI_API_KEY"] = env_backup


class TestLabelSets:
    def test_clean_labels_are_disjoint_from_vulnerable(self):
        assert CLEAN_LABELS.isdisjoint(VULNERABLE_LABELS)

    def test_all_labels_covered(self):
        all_labels = CLEAN_LABELS | VULNERABLE_LABELS
        assert "full_compliance" in all_labels
        assert "partial_compliance" in all_labels
        assert "hard_refusal" in all_labels
        assert "soft_refusal" in all_labels
        assert "topic_summary" in all_labels
        assert "redirect" in all_labels
