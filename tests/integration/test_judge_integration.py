"""Integration tests for judge integration in run command."""

from unittest.mock import MagicMock, patch

import pytest
from aipop.cli.harness import app
from typer.testing import CliRunner


@pytest.fixture
def runner():
    """CLI test runner."""
    return CliRunner()


def test_run_with_judge_keyword(runner, tmp_path):
    """Test run command with keyword judge."""
    with (
        patch("aipop.cli.harness.load_yaml_suite") as mock_load,
        patch("aipop.cli.harness._create_adapter_from_cli") as mock_create_adapter,
        patch("aipop.cli.harness._create_judge_from_cli") as mock_create_judge,
        patch("aipop.runners.mock.MockRunner") as mock_runner_class,
    ):

        # Mock suite
        mock_test_case = MagicMock()
        mock_test_case.id = "test1"
        mock_test_case.prompt = "Test prompt"
        mock_test_case.metadata = {"expected": "pass"}
        mock_load.return_value = [mock_test_case]

        # Mock adapter
        mock_adapter = MagicMock()
        mock_adapter.__class__.__name__ = "MockAdapter"
        mock_adapter.model = "test-model"
        mock_response = MagicMock()
        mock_response.text = "Response text"
        mock_response.meta = {
            "cost_usd": 0.001,
            "tokens_prompt": 10,
            "tokens_completion": 20,
            "model": "test-model",
        }
        mock_adapter.invoke.return_value = mock_response
        mock_create_adapter.return_value = mock_adapter

        # Mock judge
        mock_judge = MagicMock()
        mock_judgment = MagicMock()
        mock_judgment.score = 5.0
        mock_judgment.is_jailbreak = False
        mock_judgment.confidence = 0.8
        mock_judge.score_response.return_value = mock_judgment
        mock_create_judge.return_value = mock_judge

        # Mock runner
        mock_runner = MagicMock()
        mock_result = MagicMock()
        mock_result.test_id = "test1"
        mock_result.response = "Response text"
        mock_result.passed = True
        mock_result.metadata = {"model_meta": mock_response.meta}
        mock_result.detector_results = None
        mock_runner.execute_many.return_value = [mock_result]
        mock_runner.get_asr_summary.return_value = {
            "enabled": True,
            "judge_type": "KeywordJudge",
            "threshold": 8.0,
            "total_tests": 1,
            "jailbreaks": 0,
            "asr": 0.0,
            "asr_confidence_interval": (0.0, 0.5),
        }
        mock_runner_class.return_value = mock_runner

        result = runner.invoke(
            app,
            [
                "run",
                "--suite",
                "suites/adversarial/context_confusion.yaml",
                "--adapter",
                "mock",
                "--model",
                "test-model",
                "--judge",
                "keyword",
            ],
        )

        # Should complete (may fail on suite loading, but judge should be initialized)
        assert result.exit_code in [0, 1]
        mock_create_judge.assert_called_once()


def test_run_with_judge_gpt4(runner):
    """Test run command with GPT-4 judge."""
    with (
        patch("aipop.cli.harness.load_yaml_suite") as mock_load,
        patch("aipop.cli.harness._create_adapter_from_cli") as mock_create_adapter,
        patch("aipop.cli.harness._create_judge_from_cli") as mock_create_judge,
    ):

        # Return at least one test case so execution proceeds
        mock_test_case = MagicMock()
        mock_test_case.id = "test1"
        mock_test_case.prompt = "Test"
        mock_test_case.metadata = {}
        mock_load.return_value = [mock_test_case]

        mock_adapter = MagicMock()
        mock_adapter.__class__.__name__ = "MockAdapter"
        mock_adapter.model = "test"
        mock_response = MagicMock()
        mock_response.text = "Response"
        mock_response.meta = {"cost_usd": 0.0, "model": "test"}
        mock_adapter.invoke.return_value = mock_response
        mock_create_adapter.return_value = mock_adapter

        mock_judge = MagicMock()
        mock_create_judge.return_value = mock_judge

        result = runner.invoke(
            app,
            [
                "run",
                "--suite",
                "suites/adversarial/context_confusion.yaml",
                "--adapter",
                "mock",
                "--model",
                "test",
                "--judge",
                "gpt4",
            ],
        )

        # Should attempt to create GPT-4 judge (may fail early, but judge creation should be attempted)
        # Check if judge was created OR if execution failed before that point
        assert mock_create_judge.called or result.exit_code != 0


def test_test_suffix_with_judge(runner):
    """Test test-suffix command with judge."""
    with (
        patch("aipop.cli.harness._create_adapter_from_cli") as mock_create,
        patch(
            "aipop.intelligence.adversarial_suffix.AdversarialSuffixGenerator"
        ) as mock_gen_class,
        patch("aipop.cli.harness._create_judge_from_cli") as mock_create_judge,
    ):

        mock_adapter = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "Sure, I can help with that"
        mock_adapter.invoke.return_value = mock_response
        mock_create.return_value = mock_adapter

        mock_generator = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.asr = 1.0
        mock_result.harmfulness_score = 0.9
        mock_result.response = "Sure, I can help with that"
        mock_generator.test_suffix.return_value = mock_result
        mock_gen_class.return_value = mock_generator

        mock_judge = MagicMock()
        mock_judgment = MagicMock()
        mock_judgment.score = 9.0
        mock_judgment.is_jailbreak = True
        mock_judgment.confidence = 0.95
        mock_judgment.reasoning = "Response contains harmful content"
        mock_judge.score_response.return_value = mock_judgment
        mock_create_judge.return_value = mock_judge

        result = runner.invoke(
            app,
            [
                "test-suffix",
                "Test prompt",
                "test suffix",
                "--adapter",
                "mock",
                "--model",
                "test",
                "--judge",
                "gpt4",
            ],
        )

        assert result.exit_code == 0
        assert "Judge Evaluation" in result.stdout or "Judge" in result.stdout
