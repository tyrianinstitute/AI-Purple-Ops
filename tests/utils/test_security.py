"""Tests for security validation utilities."""

from __future__ import annotations

from pathlib import Path

import pytest

from aipop.utils.security import (
    SecurityError,
    sanitize_env_var,
    validate_config_path,
    validate_seed,
    validate_suite_path,
)


class TestValidateSuitePath:
    """Tests for suite path validation."""

    def test_valid_suite_in_suites_dir(self, tmp_path: Path) -> None:
        """Test that valid suite paths in suites/ are accepted."""
        suites_dir = tmp_path / "suites"
        suites_dir.mkdir()
        normal_suite = suites_dir / "normal"
        normal_suite.mkdir()

        # Change to tmp_path for test
        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = validate_suite_path("suites/normal")
            assert result.is_absolute()
            assert "normal" in str(result)
        finally:
            os.chdir(old_cwd)

    def test_valid_suite_in_current_dir(self, tmp_path):
        """Test that suite paths in current directory are accepted."""
        suite_file = tmp_path / "test_suite.yaml"
        suite_file.write_text("id: test\ncases: []")

        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = validate_suite_path("test_suite.yaml")
            assert result.is_absolute()
            assert "test_suite.yaml" in str(result)
        finally:
            os.chdir(old_cwd)

    def test_reject_absolute_path_outside_allowed(self):
        """Test that absolute paths outside allowed directories are rejected."""
        with pytest.raises(SecurityError, match="Suite path outside allowed directories"):
            validate_suite_path("/etc/passwd")

    def test_reject_path_traversal_with_dotdot(self, tmp_path):
        """Test that path traversal with .. is properly validated."""
        import os

        # Create a test directory NOT in /tmp to avoid /tmp being allowed
        import tempfile

        with tempfile.TemporaryDirectory(dir="/var/tmp") as test_dir:
            old_cwd = os.getcwd()
            try:
                os.chdir(test_dir)
                # This should fail as it tries to go outside allowed directories
                with pytest.raises(SecurityError, match="Suite path outside allowed directories"):
                    validate_suite_path("../../../etc/passwd")
            finally:
                os.chdir(old_cwd)


class TestValidateConfigPath:
    """Tests for config path validation."""

    def test_valid_config_in_current_dir(self, tmp_path):
        """Test that config in current directory is accepted."""
        config_file = tmp_path / "aipop.yaml"
        config_file.write_text("run:\n  seed: 42")

        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = validate_config_path("aipop.yaml")
            assert result.is_absolute()
            assert "aipop.yaml" in str(result)
        finally:
            os.chdir(old_cwd)

    def test_reject_config_outside_allowed(self):
        """Test that configs outside allowed directories are rejected."""
        with pytest.raises(SecurityError, match="Config path outside allowed directories"):
            validate_config_path("/etc/passwd")


class TestValidateSeed:
    """Tests for seed validation."""

    def test_valid_seed_as_int(self):
        """Test that valid integer seeds are accepted."""
        assert validate_seed(0) == 0
        assert validate_seed(42) == 42
        assert validate_seed(4294967295) == 4294967295  # 2^32 - 1

    def test_valid_seed_as_string(self):
        """Test that valid string seeds are converted and accepted."""
        assert validate_seed("0") == 0
        assert validate_seed("42") == 42
        assert validate_seed("1000") == 1000

    def test_reject_negative_seed(self):
        """Test that negative seeds are rejected."""
        with pytest.raises(SecurityError, match="Seed value out of bounds"):
            validate_seed(-1)

    def test_reject_seed_too_large(self):
        """Test that seeds larger than 2^32-1 are rejected."""
        with pytest.raises(SecurityError, match="Seed value out of bounds"):
            validate_seed(4294967296)  # 2^32

    def test_reject_invalid_seed_format(self):
        """Test that non-numeric seeds are rejected."""
        with pytest.raises(SecurityError, match="Invalid seed value"):
            validate_seed("not_a_number")

        with pytest.raises(SecurityError, match="Invalid seed value"):
            validate_seed("42.5")


class TestSanitizeEnvVar:
    """Tests for environment variable sanitization."""

    def test_valid_simple_string(self):
        """Test that simple valid strings pass through."""
        assert sanitize_env_var("output", "TEST_VAR") == "output"
        assert sanitize_env_var("reports/dir", "TEST_VAR") == "reports/dir"

    def test_reject_null_bytes(self):
        """Test that strings with null bytes are rejected."""
        with pytest.raises(SecurityError, match="contains null bytes"):
            sanitize_env_var("test\x00bad", "TEST_VAR")

    def test_reject_command_substitution(self):
        """Test that command substitution patterns are rejected."""
        with pytest.raises(SecurityError, match="Command substitution"):
            sanitize_env_var("$(whoami)", "TEST_VAR")

        with pytest.raises(SecurityError, match="Command substitution"):
            sanitize_env_var("`whoami`", "TEST_VAR")

    def test_reject_path_traversal(self):
        """Test that path traversal patterns are rejected."""
        with pytest.raises(SecurityError, match="Path traversal"):
            sanitize_env_var("../../../etc/passwd", "TEST_VAR")

        with pytest.raises(SecurityError, match="Path traversal"):
            sanitize_env_var("..\\..\\windows\\system32", "TEST_VAR")

    def test_reject_too_long(self):
        """Test that overly long strings are rejected."""
        long_string = "a" * 2000
        with pytest.raises(SecurityError, match="exceeds maximum length"):
            sanitize_env_var(long_string, "TEST_VAR")

    def test_reject_non_string(self):
        """Test that non-string values are rejected."""
        with pytest.raises(SecurityError, match="Expected string"):
            sanitize_env_var(123, "TEST_VAR")  # type: ignore


class TestIntegration:
    """Integration tests for security validation."""

    def test_suite_and_config_together(self, tmp_path):
        """Test that both suite and config validation work together."""
        # Create suite
        suites_dir = tmp_path / "suites" / "normal"
        suites_dir.mkdir(parents=True)

        # Create config
        config_file = tmp_path / "aipop.yaml"
        config_file.write_text("run:\n  seed: 42")

        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)

            # Both should validate successfully
            suite_path = validate_suite_path("suites/normal")
            config_path = validate_config_path("aipop.yaml")

            assert suite_path.is_absolute()
            assert config_path.is_absolute()
        finally:
            os.chdir(old_cwd)

    def test_seed_validation_with_env_vars(self):
        """Test that seed validation works with environment variable flow."""
        import os

        # Valid seed
        os.environ["AIPO_SEED"] = "12345"
        assert validate_seed(os.environ["AIPO_SEED"]) == 12345

        # Invalid seed
        os.environ["AIPO_SEED"] = "not_a_number"
        with pytest.raises(SecurityError):
            validate_seed(os.environ["AIPO_SEED"])

        # Clean up
        del os.environ["AIPO_SEED"]
