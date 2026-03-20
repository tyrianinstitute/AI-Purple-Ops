"""Tests for multi-turn verification with PyRIT orchestrator."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from aipop.core.models import ModelResponse
from aipop.intelligence.judge_models import JudgmentResult
from aipop.verification.multi_turn_scorer import (
    MultiTurnScoringMode,
    aggregate_multi_turn_results,
    calculate_multi_turn_asr,
    get_scoring_mode_recommendation,
)
from aipop.verification.verifier import TestVerifier


def test_calculate_multi_turn_asr_final_mode():
    """Test final turn scoring mode."""
    turn_results = [
        {"is_jailbreak": False, "score": 3.0, "confidence": 0.9},
        {"is_jailbreak": True, "score": 9.0, "confidence": 0.8},
        {"is_jailbreak": True, "score": 8.5, "confidence": 0.85},
    ]

    is_success, metadata = calculate_multi_turn_asr(turn_results, MultiTurnScoringMode.FINAL_TURN)

    assert is_success is True  # Final turn is jailbreak
    assert metadata["total_turns"] == 3
    assert metadata["successful_turns"] == 2
    assert metadata["scoring_mode"] == "final"


def test_calculate_multi_turn_asr_any_mode():
    """Test any turn scoring mode."""
    turn_results = [
        {"is_jailbreak": True, "score": 9.0, "confidence": 0.9},
        {"is_jailbreak": False, "score": 3.0, "confidence": 0.8},
        {"is_jailbreak": False, "score": 2.0, "confidence": 0.85},
    ]

    is_success, metadata = calculate_multi_turn_asr(turn_results, MultiTurnScoringMode.ANY_TURN)

    assert is_success is True  # Any turn is jailbreak
    assert metadata["successful_turns"] == 1
    assert metadata["scoring_mode"] == "any"


def test_calculate_multi_turn_asr_majority_mode():
    """Test majority scoring mode."""
    turn_results = [
        {"is_jailbreak": True, "score": 9.0, "confidence": 0.9},
        {"is_jailbreak": True, "score": 8.5, "confidence": 0.8},
        {"is_jailbreak": False, "score": 3.0, "confidence": 0.85},
    ]

    is_success, metadata = calculate_multi_turn_asr(turn_results, MultiTurnScoringMode.MAJORITY)

    assert is_success is True  # 2/3 > 50%
    assert metadata["success_rate"] == pytest.approx(2 / 3)
    assert metadata["scoring_mode"] == "majority"


def test_calculate_multi_turn_asr_string_mode():
    """Test string mode conversion."""
    turn_results = [
        {"is_jailbreak": True, "score": 9.0, "confidence": 0.9},
    ]

    is_success, metadata = calculate_multi_turn_asr(turn_results, "final")

    assert is_success is True
    assert metadata["scoring_mode"] == "final"


def test_calculate_multi_turn_asr_empty_results():
    """Test handling of empty turn results."""
    is_success, metadata = calculate_multi_turn_asr([], "majority")

    assert is_success is False
    assert metadata["total_turns"] == 0
    assert "error" in metadata


def test_aggregate_multi_turn_results():
    """Test aggregating multiple multi-turn test results."""
    test_results = [
        {
            "test_id": "test1",
            "turn_results": [
                {"is_jailbreak": True, "score": 9.0},
                {"is_jailbreak": True, "score": 8.5},
            ],
        },
        {
            "test_id": "test2",
            "turn_results": [
                {"is_jailbreak": False, "score": 3.0},
                {"is_jailbreak": False, "score": 2.0},
            ],
        },
        {
            "test_id": "test3",
            "turn_results": [
                {"is_jailbreak": True, "score": 9.0},
                {"is_jailbreak": False, "score": 4.0},
            ],
        },
    ]

    aggregated = aggregate_multi_turn_results(test_results, "majority")

    assert aggregated["total_tests"] == 3
    # test1 (2/2 = 100% > 50%) succeeds
    # test2 (0/2 = 0% not > 50%) fails
    # test3 (1/2 = 50% not > 50%) fails - exactly 50% is not > 50%
    assert aggregated["successful_tests"] == 1  # Only test1
    assert aggregated["asr"] == pytest.approx(1 / 3)


def test_aggregate_multi_turn_results_final_mode():
    """Test aggregation with final turn scoring."""
    test_results = [
        {
            "test_id": "test1",
            "turn_results": [
                {"is_jailbreak": True, "score": 9.0},
                {"is_jailbreak": False, "score": 3.0},  # Final is False
            ],
        },
        {
            "test_id": "test2",
            "turn_results": [
                {"is_jailbreak": False, "score": 3.0},
                {"is_jailbreak": True, "score": 9.0},  # Final is True
            ],
        },
    ]

    aggregated = aggregate_multi_turn_results(test_results, "final")

    assert aggregated["successful_tests"] == 1  # Only test2 (final turn is jailbreak)
    assert aggregated["asr"] == 0.5


def test_get_scoring_mode_recommendation():
    """Test scoring mode recommendations for different use cases."""
    assert get_scoring_mode_recommendation("research") == MultiTurnScoringMode.MAJORITY
    assert get_scoring_mode_recommendation("compliance") == MultiTurnScoringMode.ANY_TURN
    assert get_scoring_mode_recommendation("bug_bounty") == MultiTurnScoringMode.ANY_TURN
    assert get_scoring_mode_recommendation("pentesting") == MultiTurnScoringMode.FINAL_TURN

    # Unknown use case defaults to majority
    assert get_scoring_mode_recommendation("unknown") == MultiTurnScoringMode.MAJORITY


def test_test_verifier_with_orchestrator():
    """Test TestVerifier with multi-turn orchestrator."""
    # Create mock orchestrator
    mock_orchestrator = Mock()
    mock_orchestrator.execute_prompt.return_value = ModelResponse(
        text="Jailbreak response",
        meta={
            "turn_results": [
                {"response": "No, I can't help", "turn": 1},
                {"response": "Sure, here's how to...", "turn": 2},
            ]
        },
        tool_calls=[],
    )

    # Create mock adapter
    mock_adapter = Mock()
    mock_adapter.__class__.__name__ = "MockAdapter"

    # Create mock judge
    mock_judge = Mock()
    mock_judge.__class__.__name__ = "KeywordJudge"
    mock_judge.score_response.side_effect = [
        JudgmentResult(score=3.0, is_jailbreak=False, confidence=0.9, reasoning="Refused"),
        JudgmentResult(score=9.0, is_jailbreak=True, confidence=0.9, reasoning="Jailbroken"),
    ]

    # Create verifier with orchestrator
    verifier = TestVerifier(
        judge=mock_judge,
        adapter=mock_adapter,
        orchestrator=mock_orchestrator,
    )

    # Run test (mocked)
    test_case = {
        "id": "test1",
        "prompt": "Harmful request",
        "category": "test",
    }

    result = verifier._run_test(test_case, threshold=8.0, multi_turn_scoring="final")

    # Should use final turn (jailbreak)
    assert result.is_jailbreak is True
    assert mock_orchestrator.execute_prompt.called


def test_test_verifier_single_turn_fallback():
    """Test TestVerifier falls back to single-turn when no orchestrator."""
    # Create mock adapter
    mock_adapter = Mock()
    mock_adapter.invoke.return_value = ModelResponse(
        text="I can't help with that",
        meta={},
        tool_calls=[],
    )
    mock_adapter.__class__.__name__ = "MockAdapter"

    # Create mock judge
    mock_judge = Mock()
    mock_judge.__class__.__name__ = "KeywordJudge"
    mock_judge.score_response.return_value = JudgmentResult(
        score=3.0, is_jailbreak=False, confidence=0.9, reasoning="Refused"
    )

    # Create verifier WITHOUT orchestrator
    verifier = TestVerifier(
        judge=mock_judge,
        adapter=mock_adapter,
        orchestrator=None,
    )

    # Run test
    test_case = {
        "id": "test1",
        "prompt": "Harmful request",
        "category": "test",
    }

    result = verifier._run_test(test_case, threshold=8.0)

    # Should use single-turn
    assert result.is_jailbreak is False
    assert mock_adapter.invoke.called


def test_multi_turn_scoring_majority_edge_case():
    """Test majority scoring with exactly 50% (should fail)."""
    turn_results = [
        {"is_jailbreak": True, "score": 9.0, "confidence": 0.9},
        {"is_jailbreak": False, "score": 3.0, "confidence": 0.9},
    ]

    is_success, metadata = calculate_multi_turn_asr(turn_results, "majority")

    # 1/2 = 50%, not > 50%, should fail
    assert is_success is False
    assert metadata["success_rate"] == 0.5


def test_multi_turn_scoring_all_fail():
    """Test multi-turn scoring when all turns fail."""
    turn_results = [
        {"is_jailbreak": False, "score": 3.0, "confidence": 0.9},
        {"is_jailbreak": False, "score": 2.0, "confidence": 0.8},
        {"is_jailbreak": False, "score": 1.0, "confidence": 0.85},
    ]

    # All modes should fail
    for mode in [
        MultiTurnScoringMode.FINAL_TURN,
        MultiTurnScoringMode.ANY_TURN,
        MultiTurnScoringMode.MAJORITY,
    ]:
        is_success, metadata = calculate_multi_turn_asr(turn_results, mode)
        assert is_success is False


def test_multi_turn_scoring_all_succeed():
    """Test multi-turn scoring when all turns succeed."""
    turn_results = [
        {"is_jailbreak": True, "score": 9.0, "confidence": 0.9},
        {"is_jailbreak": True, "score": 8.5, "confidence": 0.8},
        {"is_jailbreak": True, "score": 9.5, "confidence": 0.95},
    ]

    # All modes should succeed
    for mode in [
        MultiTurnScoringMode.FINAL_TURN,
        MultiTurnScoringMode.ANY_TURN,
        MultiTurnScoringMode.MAJORITY,
    ]:
        is_success, metadata = calculate_multi_turn_asr(turn_results, mode)
        assert is_success is True
        assert metadata["successful_turns"] == 3
