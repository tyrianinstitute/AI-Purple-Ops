"""Tests for new YAML suite loaders (adapters, adversarial, comparison)."""

from __future__ import annotations

from pathlib import Path

import pytest

from aipop.loaders.yaml_suite import load_yaml_suite


class TestNewYAMLSuites:
    """Test loading new test suites."""

    def test_load_adapter_validation_suite(self) -> None:
        """Test loading adapter validation suite."""
        suite_path = Path("suites/adapters")
        if not suite_path.exists():
            pytest.skip("Adapter validation suite not found")

        test_cases = load_yaml_suite(suite_path)
        assert len(test_cases) > 0
        assert any("invoke" in tc.id or "adapter" in tc.id for tc in test_cases)

    def test_load_adversarial_suite(self) -> None:
        """Test loading adversarial suite."""
        suite_path = Path("suites/adversarial")
        if not suite_path.exists():
            pytest.skip("Adversarial suite not found")

        test_cases = load_yaml_suite(suite_path)
        assert len(test_cases) > 0
        # Should have jailbreak attempts
        assert any("jailbreak" in tc.id or "injection" in tc.id for tc in test_cases)

    def test_load_comparison_suite(self) -> None:
        """Test loading comparison suite."""
        suite_path = Path("suites/comparison")
        if not suite_path.exists():
            pytest.skip("Comparison suite not found")

        test_cases = load_yaml_suite(suite_path)
        assert len(test_cases) > 0
