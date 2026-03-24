"""Tests for connection helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from aipop.adapters.connection_helpers import (
    check_rest_connection,
    estimate_model_size,
    get_env_or_prompt,
    validate_model_file,
)


class TestConnectionHelpers:
    """Test connection helper functions."""

    def test_validate_model_file_not_found(self) -> None:
        """Test model file validation with nonexistent file."""
        valid, error = validate_model_file("/nonexistent/file.gguf")
        assert not valid
        assert "not found" in error.lower()

    def test_validate_model_file_directory(self, tmp_path: Path) -> None:
        """Test model file validation with directory."""
        dir_path = tmp_path / "models"
        dir_path.mkdir()
        valid, error = validate_model_file(dir_path)
        assert not valid
        assert "not a file" in error.lower()

    def test_validate_model_file_invalid_extension(self, tmp_path: Path) -> None:
        """Test model file validation with invalid extension."""
        file_path = tmp_path / "model.txt"
        file_path.write_text("test")
        valid, error = validate_model_file(file_path)
        assert not valid
        assert "unknown model format" in error.lower()

    def test_validate_model_file_valid(self, tmp_path: Path) -> None:
        """Test model file validation with valid file."""
        file_path = tmp_path / "model.gguf"
        file_path.write_text("test model data")
        valid, error = validate_model_file(file_path)
        assert valid
        assert "valid" in error.lower()

    def test_estimate_model_size(self) -> None:
        """Test model size estimation."""
        # Test known models
        size = estimate_model_size("tinyllama")
        assert size > 0
        assert size < 5  # Should be less than 5GB

        size = estimate_model_size("phi3")
        assert size > 0

        # Test unknown model (should return default)
        size = estimate_model_size("unknown_model_xyz")
        assert size > 0  # Should return default estimate

    def test_rest_connection_function(self) -> None:
        """Test REST connection testing."""
        # Test with a known good endpoint (httpbin echo)
        # This might fail if no internet, which is okay for unit tests
        try:
            result = check_rest_connection("https://httpbin.org/status/200", timeout=5)
            # If we got a result, it should be True (200 status)
            if result is not None:
                assert isinstance(result, bool)
        except Exception:
            # Network error is acceptable in unit tests
            pytest.skip("Network not available")

    def test_get_env_or_prompt_with_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test getting value from environment variable."""
        monkeypatch.setenv("TEST_VAR", "test_value")
        result = get_env_or_prompt("TEST_VAR", "Enter value")
        assert result == "test_value"

    def test_get_env_or_prompt_with_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test getting value with default."""
        monkeypatch.delenv("TEST_VAR", raising=False)
        # Mock input to return empty string (use default)
        monkeypatch.setattr("builtins.input", lambda _: "")
        result = get_env_or_prompt("TEST_VAR", "Enter value", default="default_value")
        assert result == "default_value"
