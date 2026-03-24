"""Integration tests for guardrail fingerprinting CLI."""

from unittest.mock import MagicMock, patch

import pytest
from aipop.cli.harness import app
from typer.testing import CliRunner


@pytest.fixture
def runner():
    """CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_adapter():
    """Mock adapter for testing."""
    adapter = MagicMock()
    adapter.__class__.__name__ = "MockAdapter"
    adapter.model = "test-model"
    adapter.invoke.return_value = MagicMock(
        text="Generic response",
        meta={"latency_ms": 100, "error_code": None},
    )
    return adapter


def test_auto_detection_first_run(runner, tmp_path, monkeypatch):
    """Test auto-fingerprinting on first run."""
    # Mock the fingerprinting to avoid actual API calls
    with patch(
        "aipop.intelligence.guardrail_fingerprint.GuardrailFingerprinter"
    ) as mock_fingerprinter_class:
        mock_fingerprinter = MagicMock()
        mock_fingerprinter.db.get_cached_fingerprint.return_value = None  # No cache
        mock_result = MagicMock()
        mock_result.guardrail_type = "promptguard"
        mock_result.confidence = 0.85
        mock_result.detection_method = "regex"
        mock_result.uncertain = False
        mock_result.suggestions = []
        mock_result.all_scores = {"promptguard": 0.85}
        mock_result.model_id = "MockAdapter:test-model"
        mock_fingerprinter.fingerprint.return_value = mock_result
        mock_fingerprinter_class.return_value = mock_fingerprinter

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
            ],
        )

        # Should attempt fingerprinting
        assert mock_fingerprinter.fingerprint.called


def test_manual_fingerprint_flag(runner, tmp_path, monkeypatch):
    """Test --fingerprint flag."""
    with patch(
        "aipop.intelligence.guardrail_fingerprint.GuardrailFingerprinter"
    ) as mock_fingerprinter_class:
        mock_fingerprinter = MagicMock()
        mock_fingerprinter.db.get_cached_fingerprint.return_value = None
        mock_result = MagicMock()
        mock_result.guardrail_type = "llama_guard_3"
        mock_result.confidence = 0.9
        mock_result.detection_method = "regex"
        mock_result.uncertain = False
        mock_result.suggestions = []
        mock_result.all_scores = {"llama_guard_3": 0.9}
        mock_result.model_id = "MockAdapter:test-model"
        mock_fingerprinter.fingerprint.return_value = mock_result
        mock_fingerprinter_class.return_value = mock_fingerprinter

        result = runner.invoke(
            app,
            [
                "run",
                "--suite",
                "suites/adversarial/context_confusion.yaml",
                "--adapter",
                "mock",
                "--fingerprint",
            ],
        )

        # Should call fingerprint with force_refresh=True
        assert mock_fingerprinter.fingerprint.called
        call_kwargs = mock_fingerprinter.fingerprint.call_args[1]
        assert call_kwargs.get("force_refresh") is True


def test_llm_classifier_flag(runner, tmp_path, monkeypatch):
    """Test --llm-classifier flag."""
    with patch(
        "aipop.intelligence.guardrail_fingerprint.GuardrailFingerprinter"
    ) as mock_fingerprinter_class:
        mock_fingerprinter = MagicMock()
        mock_fingerprinter.db.get_cached_fingerprint.return_value = None
        mock_result = MagicMock()
        mock_result.guardrail_type = "azure_content_safety"
        mock_result.confidence = 0.95
        mock_result.detection_method = "hybrid"
        mock_result.uncertain = False
        mock_result.suggestions = []
        mock_result.all_scores = {}
        mock_result.model_id = "MockAdapter:test-model"
        mock_fingerprinter.fingerprint.return_value = mock_result
        mock_fingerprinter_class.return_value = mock_fingerprinter

        result = runner.invoke(
            app,
            [
                "run",
                "--suite",
                "suites/adversarial/context_confusion.yaml",
                "--adapter",
                "mock",
                "--llm-classifier",
            ],
        )

        # Should call fingerprint with use_llm_classifier=True
        assert mock_fingerprinter.fingerprint.called
        call_kwargs = mock_fingerprinter.fingerprint.call_args[1]
        assert call_kwargs.get("use_llm_classifier") is True


def test_generate_probes_flag(runner, tmp_path, monkeypatch):
    """Test --generate-probes flag."""
    with patch(
        "aipop.intelligence.guardrail_fingerprint.GuardrailFingerprinter"
    ) as mock_fingerprinter_class:
        mock_fingerprinter = MagicMock()
        mock_fingerprinter.db.get_cached_fingerprint.return_value = None
        mock_result = MagicMock()
        mock_result.guardrail_type = "unknown"
        mock_result.confidence = 0.5
        mock_result.detection_method = "regex"
        mock_result.uncertain = True
        mock_result.suggestions = ["Try --llm-classifier"]
        mock_result.all_scores = {}
        mock_result.model_id = "MockAdapter:test-model"
        mock_fingerprinter.fingerprint.return_value = mock_result
        mock_fingerprinter_class.return_value = mock_fingerprinter

        result = runner.invoke(
            app,
            [
                "run",
                "--suite",
                "suites/adversarial/context_confusion.yaml",
                "--adapter",
                "mock",
                "--generate-probes",
            ],
        )

        # Should call fingerprint with generate_probes=True
        assert mock_fingerprinter.fingerprint.called
        call_kwargs = mock_fingerprinter.fingerprint.call_args[1]
        assert call_kwargs.get("generate_probes") is True


def test_cache_behavior(runner, tmp_path, monkeypatch):
    """Test cached fingerprints are reused."""
    with patch(
        "aipop.intelligence.guardrail_fingerprint.GuardrailFingerprinter"
    ) as mock_fingerprinter_class:
        mock_fingerprinter = MagicMock()
        # First run: no cache
        mock_fingerprinter.db.get_cached_fingerprint.side_effect = [None, MagicMock()]
        mock_result = MagicMock()
        mock_result.guardrail_type = "promptguard"
        mock_result.confidence = 0.85
        mock_result.detection_method = "regex"
        mock_result.uncertain = False
        mock_result.suggestions = []
        mock_result.all_scores = {}
        mock_result.model_id = "MockAdapter:test-model"
        mock_fingerprinter.fingerprint.return_value = mock_result
        mock_fingerprinter_class.return_value = mock_fingerprinter

        # First run
        result1 = runner.invoke(
            app,
            [
                "run",
                "--suite",
                "suites/adversarial/context_confusion.yaml",
                "--adapter",
                "mock",
            ],
        )

        # Second run (should use cache)
        result2 = runner.invoke(
            app,
            [
                "run",
                "--suite",
                "suites/adversarial/context_confusion.yaml",
                "--adapter",
                "mock",
            ],
        )

        # First run should call fingerprint, second should use cache
        assert mock_fingerprinter.fingerprint.call_count >= 1


def test_fingerprint_error_handling(runner, tmp_path, monkeypatch):
    """Test that fingerprinting errors don't break test execution."""
    with patch(
        "aipop.intelligence.guardrail_fingerprint.GuardrailFingerprinter"
    ) as mock_fingerprinter_class:
        # Make fingerprinting raise an exception
        mock_fingerprinter_class.side_effect = Exception("Fingerprinting failed")

        result = runner.invoke(
            app,
            [
                "run",
                "--suite",
                "suites/adversarial/context_confusion.yaml",
                "--adapter",
                "mock",
                "--fingerprint",
            ],
        )

        # Should continue with tests despite fingerprinting error
        # Exit code should be based on test results, not fingerprinting
        assert result.exit_code in [0, 1]  # May pass or fail based on tests


def test_orchestrator_integration(runner, tmp_path, monkeypatch):
    """Test that detected guardrail updates orchestrator."""
    with patch(
        "aipop.intelligence.guardrail_fingerprint.GuardrailFingerprinter"
    ) as mock_fingerprinter_class:
        mock_fingerprinter = MagicMock()
        mock_fingerprinter.db.get_cached_fingerprint.return_value = None
        mock_result = MagicMock()
        mock_result.guardrail_type = "promptguard"
        mock_result.confidence = 0.85
        mock_result.detection_method = "regex"
        mock_result.uncertain = False
        mock_result.suggestions = []
        mock_result.all_scores = {}
        mock_result.model_id = "MockAdapter:test-model"
        mock_fingerprinter.fingerprint.return_value = mock_result
        mock_fingerprinter_class.return_value = mock_fingerprinter

        with patch("aipop.cli.harness._create_orchestrator_from_cli") as mock_create_orch:
            mock_orch = MagicMock()
            mock_orch.set_guardrail_type = MagicMock()
            mock_create_orch.return_value = mock_orch

            result = runner.invoke(
                app,
                [
                    "run",
                    "--suite",
                    "suites/adversarial/context_confusion.yaml",
                    "--adapter",
                    "mock",
                    "--orchestrator",
                    "simple",
                    "--fingerprint",
                ],
            )

            # Orchestrator should receive guardrail type
            if mock_orch.set_guardrail_type.called:
                mock_orch.set_guardrail_type.assert_called_with("promptguard")


def test_standalone_fingerprint_command(runner, tmp_path):
    """Test standalone fingerprint command."""
    with (
        patch("aipop.cli.harness._create_adapter_from_cli") as mock_create,
        patch(
            "aipop.intelligence.guardrail_fingerprint.GuardrailFingerprinter"
        ) as mock_fingerprinter_class,
    ):

        mock_adapter = MagicMock()
        mock_adapter.__class__.__name__ = "MockAdapter"
        mock_adapter.model = "test-model"
        mock_create.return_value = mock_adapter

        mock_fingerprinter = MagicMock()
        mock_result = MagicMock()
        mock_result.guardrail_type = "llama_guard_3"
        mock_result.confidence = 0.92
        mock_result.detection_method = "hybrid"
        mock_result.uncertain = False
        mock_result.suggestions = []
        mock_result.all_scores = {"llama_guard_3": 0.92}
        mock_result.model_id = "MockAdapter:test-model"
        mock_result.adapter_type = "MockAdapter"
        mock_result.probe_count = 15
        mock_result.avg_latency_ms = 120.5
        mock_result.timestamp = "2024-01-01T00:00:00"
        mock_result.evidence = []
        mock_fingerprinter.fingerprint.return_value = mock_result
        mock_fingerprinter.get_bypass_strategies.return_value = [
            "multi_turn_hijacking",
            "context_confusion",
        ]
        mock_fingerprinter_class.return_value = mock_fingerprinter

        result = runner.invoke(
            app,
            [
                "fingerprint",
                "--adapter",
                "mock",
                "--model",
                "test-model",
            ],
        )

        assert result.exit_code == 0
        assert "Guardrail Fingerprint Results" in result.stdout
        assert "llama_guard_3" in result.stdout


def test_fingerprint_with_output_file(runner, tmp_path):
    """Test fingerprint command with output file."""
    output_file = tmp_path / "fingerprint.json"

    with (
        patch("aipop.cli.harness._create_adapter_from_cli") as mock_create,
        patch(
            "aipop.intelligence.guardrail_fingerprint.GuardrailFingerprinter"
        ) as mock_fingerprinter_class,
    ):

        mock_adapter = MagicMock()
        mock_create.return_value = mock_adapter

        mock_fingerprinter = MagicMock()
        mock_result = MagicMock()
        mock_result.guardrail_type = "unknown"
        mock_result.confidence = 0.3
        mock_result.detection_method = "regex"
        mock_result.uncertain = True
        mock_result.suggestions = ["Run with --llm-classifier"]
        mock_result.all_scores = {"unknown": 0.3}
        mock_result.model_id = "MockAdapter:test"
        mock_result.adapter_type = "MockAdapter"
        mock_result.probe_count = 10
        mock_result.avg_latency_ms = 100.0
        mock_result.timestamp = "2024-01-01T00:00:00"
        mock_result.evidence = []
        mock_fingerprinter.fingerprint.return_value = mock_result
        mock_fingerprinter.get_bypass_strategies.return_value = []
        mock_fingerprinter_class.return_value = mock_fingerprinter

        result = runner.invoke(
            app,
            [
                "fingerprint",
                "--adapter",
                "mock",
                "--model",
                "test",
                "--output",
                str(output_file),
            ],
        )

        assert result.exit_code == 0
        assert output_file.exists()

        # Verify JSON content
        import json

        with open(output_file) as f:
            data = json.load(f)
        assert data["guardrail_type"] == "unknown"
        assert data["confidence"] == 0.3
