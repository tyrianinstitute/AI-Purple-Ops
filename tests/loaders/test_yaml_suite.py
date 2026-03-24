"""Tests for YAML suite loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from aipop.loaders.yaml_suite import YAMLSuiteError, load_yaml_suite


class TestYAMLSuiteLoader:
    """Test YAML suite loading functionality."""

    def test_load_valid_suite(self, tmp_path: Path) -> None:
        """Test loading a valid YAML suite file."""
        suite_file = tmp_path / "test_suite.yaml"
        suite_file.write_text(
            """
id: test_suite
name: Test Suite
description: A test suite
cases:
  - id: test_001
    prompt: "Hello"
    expected: pass
    metadata:
      category: utility
"""
        )

        cases = load_yaml_suite(suite_file)

        assert len(cases) == 1
        assert cases[0].id == "test_001"
        assert cases[0].prompt == "Hello"
        assert cases[0].metadata["expected"] == "pass"
        assert cases[0].metadata["category"] == "utility"

    def test_load_directory(self, tmp_path: Path) -> None:
        """Test loading all YAML files from a directory."""
        suite_dir = tmp_path / "suites"
        suite_dir.mkdir()

        (suite_dir / "suite1.yaml").write_text(
            """
id: suite1
cases:
  - id: test_1
    prompt: "Test 1"
"""
        )

        (suite_dir / "suite2.yaml").write_text(
            """
id: suite2
cases:
  - id: test_2
    prompt: "Test 2"
"""
        )

        cases = load_yaml_suite(suite_dir)

        assert len(cases) == 2
        assert {c.id for c in cases} == {"test_1", "test_2"}

    def test_load_multiple_cases(self, tmp_path: Path) -> None:
        """Test loading multiple test cases from one file."""
        suite_file = tmp_path / "multi.yaml"
        suite_file.write_text(
            """
id: multi_suite
cases:
  - id: test_1
    prompt: "Prompt 1"
  - id: test_2
    prompt: "Prompt 2"
  - id: test_3
    prompt: "Prompt 3"
"""
        )

        cases = load_yaml_suite(suite_file)

        assert len(cases) == 3
        assert [c.id for c in cases] == ["test_1", "test_2", "test_3"]

    def test_auto_generate_ids(self, tmp_path: Path) -> None:
        """Test that IDs are auto-generated when missing."""
        suite_file = tmp_path / "auto_ids.yaml"
        suite_file.write_text(
            """
id: auto_suite
cases:
  - prompt: "Test without ID"
"""
        )

        cases = load_yaml_suite(suite_file)

        assert len(cases) == 1
        assert cases[0].id == "auto_suite_case_001"

    def test_suite_id_in_metadata(self, tmp_path: Path) -> None:
        """Test that suite_id is added to test metadata."""
        suite_file = tmp_path / "suite.yaml"
        suite_file.write_text(
            """
id: my_suite
cases:
  - id: test_1
    prompt: "Test"
"""
        )

        cases = load_yaml_suite(suite_file)

        assert cases[0].metadata["suite_id"] == "my_suite"

    def test_path_not_found(self) -> None:
        """Test error when path doesn't exist."""
        with pytest.raises(YAMLSuiteError, match="Suite path not found"):
            load_yaml_suite("/nonexistent/path")

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Test error when directory has no YAML files."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        with pytest.raises(YAMLSuiteError, match="No YAML files found"):
            load_yaml_suite(empty_dir)

    def test_invalid_yaml_syntax(self, tmp_path: Path) -> None:
        """Test error on invalid YAML syntax."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("invalid: yaml: syntax: error:")

        with pytest.raises(YAMLSuiteError, match="Invalid YAML syntax"):
            load_yaml_suite(bad_file)

    def test_missing_cases_field(self, tmp_path: Path) -> None:
        """Test error when 'cases' field is missing."""
        suite_file = tmp_path / "no_cases.yaml"
        suite_file.write_text(
            """
id: suite
name: Suite without cases
"""
        )

        with pytest.raises(YAMLSuiteError, match="Missing 'cases' field"):
            load_yaml_suite(suite_file)

    def test_invalid_cases_type(self, tmp_path: Path) -> None:
        """Test error when 'cases' is not a list."""
        suite_file = tmp_path / "bad_cases.yaml"
        suite_file.write_text(
            """
id: suite
cases: "not a list"
"""
        )

        with pytest.raises(YAMLSuiteError, match="Invalid 'cases' format"):
            load_yaml_suite(suite_file)

    def test_missing_prompt(self, tmp_path: Path) -> None:
        """Test error when prompt field is missing."""
        suite_file = tmp_path / "no_prompt.yaml"
        suite_file.write_text(
            """
id: suite
cases:
  - id: test_1
    metadata:
      category: test
"""
        )

        with pytest.raises(YAMLSuiteError, match="Missing required field 'prompt'"):
            load_yaml_suite(suite_file)

    def test_empty_prompt(self, tmp_path: Path) -> None:
        """Test error when prompt is empty."""
        suite_file = tmp_path / "empty_prompt.yaml"
        suite_file.write_text(
            """
id: suite
cases:
  - id: test_1
    prompt: ""
"""
        )

        with pytest.raises(YAMLSuiteError, match="Invalid prompt"):
            load_yaml_suite(suite_file)

    def test_empty_cases_list(self, tmp_path: Path) -> None:
        """Test error when cases list is empty."""
        suite_file = tmp_path / "empty_cases.yaml"
        suite_file.write_text(
            """
id: suite
cases: []
"""
        )

        with pytest.raises(YAMLSuiteError, match="No test cases found"):
            load_yaml_suite(suite_file)

    def test_metadata_preserved(self, tmp_path: Path) -> None:
        """Test that all metadata fields are preserved."""
        suite_file = tmp_path / "metadata.yaml"
        suite_file.write_text(
            """
id: suite
cases:
  - id: test_1
    prompt: "Test"
    metadata:
      category: safety
      risk: high
      custom_field: custom_value
      nested:
        field: value
"""
        )

        cases = load_yaml_suite(suite_file)

        assert cases[0].metadata["category"] == "safety"
        assert cases[0].metadata["risk"] == "high"
        assert cases[0].metadata["custom_field"] == "custom_value"
        assert cases[0].metadata["nested"]["field"] == "value"

    def test_expected_field_moved_to_metadata(self, tmp_path: Path) -> None:
        """Test that 'expected' field is moved to metadata."""
        suite_file = tmp_path / "expected.yaml"
        suite_file.write_text(
            """
id: suite
cases:
  - id: test_1
    prompt: "Test"
    expected: refuse
"""
        )

        cases = load_yaml_suite(suite_file)

        assert cases[0].metadata["expected"] == "refuse"

    def test_load_yml_extension(self, tmp_path: Path) -> None:
        """Test loading .yml files (not just .yaml)."""
        suite_dir = tmp_path / "suites"
        suite_dir.mkdir()

        (suite_dir / "test.yml").write_text(
            """
id: suite
cases:
  - id: test_1
    prompt: "Test"
"""
        )

        cases = load_yaml_suite(suite_dir)

        assert len(cases) == 1
        assert cases[0].id == "test_1"

    def test_error_includes_file_context(self, tmp_path: Path) -> None:
        """Test that errors include helpful file context."""
        bad_file = tmp_path / "bad_case.yaml"
        bad_file.write_text(
            """
id: suite
cases:
  - prompt: ""
"""
        )

        with pytest.raises(YAMLSuiteError, match="bad_case.yaml"):
            load_yaml_suite(bad_file)
