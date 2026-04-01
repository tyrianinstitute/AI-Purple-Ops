"""YAML test suite loader with schema validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from aipop.core.models import TestCase
from aipop.utils.errors import HarnessError
from aipop.utils.paths import get_package_data_path


class YAMLSuiteError(HarnessError):
    """Error loading or parsing YAML test suite."""


def load_yaml_suite(suite_path: str | Path) -> list[TestCase]:
    """Load test cases from a YAML suite file or directory.

    Supports three formats:
    - Category: 'adversarial' -> loads all in suites/adversarial/
    - Individual: 'basic_jailbreak' -> searches for basic_jailbreak.yaml in all categories
    - Full path: 'adversarial/basic_jailbreak' -> explicit path

    YAML Format:
        id: suite_id
        name: Suite Name
        description: Suite description
        cases:
          - id: test_001
            prompt: "Test prompt"
            expected: pass
            metadata:
              category: utility
              risk: low

    Args:
        suite_path: Suite name, category, or path

    Returns:
        List of TestCase objects loaded from the suite

    Raises:
        YAMLSuiteError: If suite file is invalid or cannot be loaded
    """
    suite_path = Path(suite_path)

    # If it's already an absolute path or exists as-is, handle normally
    if suite_path.is_absolute() or suite_path.exists():
        return _load_suite_path(suite_path)

    # Try to resolve as relative to suites/ directory
    suites_dir = get_package_data_path("suites")

    # Format 1: Full path like "adversarial/basic_jailbreak"
    if "/" in str(suite_path) or "\\" in str(suite_path):
        # Normalize path separators
        parts = str(suite_path).replace("\\", "/").split("/")
        if len(parts) == 2:
            category, suite_name = parts
            full_path = suites_dir / category / f"{suite_name}.yaml"
            if full_path.exists():
                return _load_suite_file(full_path)
            # Try without .yaml extension
            full_path_no_ext = suites_dir / category / suite_name
            if full_path_no_ext.exists() and full_path_no_ext.is_file():
                return _load_suite_file(full_path_no_ext)
            raise YAMLSuiteError(
                f"Suite not found: {suite_path}\n"
                f"Tried: {full_path}\n"
                f"Hint: Check that the suite file exists in suites/{category}/"
            )

    # Format 2: Try as category directory
    category_path = suites_dir / suite_path
    if category_path.is_dir():
        return _load_suite_directory(category_path)

    # Format 3: Search for individual suite file across all categories
    suite_name = suite_path.stem if suite_path.suffix else suite_path
    for category_dir in suites_dir.iterdir():
        if not category_dir.is_dir():
            continue
        suite_file = category_dir / f"{suite_name}.yaml"
        if suite_file.exists():
            return _load_suite_file(suite_file)

    # Nothing found, provide helpful error
    available_categories = []
    if suites_dir.exists():
        available_categories = [d.name for d in suites_dir.iterdir() if d.is_dir()]

    raise YAMLSuiteError(
        f"Suite not found: {suite_path}\n"
        + (
            f"Available categories: {', '.join(sorted(available_categories))}\n"
            if available_categories
            else ""
        )
        + "Hint: Try 'aipop suites list' to see available suites"
    )


def _load_suite_path(suite_path: Path) -> list[TestCase]:
    """Load from a concrete path (file or directory).

    Args:
        suite_path: Path to suite file or directory

    Returns:
        List of TestCase objects

    Raises:
        YAMLSuiteError: If path doesn't exist or is invalid
    """
    if suite_path.is_dir():
        return _load_suite_directory(suite_path)
    if suite_path.is_file():
        return _load_suite_file(suite_path)
    raise YAMLSuiteError(f"Suite path not found: {suite_path}")


def _load_suite_directory(suite_dir: Path) -> list[TestCase]:
    """Load all YAML files from a directory."""
    yaml_files = list(suite_dir.glob("*.yaml")) + list(suite_dir.glob("*.yml"))

    if not yaml_files:
        raise YAMLSuiteError(
            f"No YAML files found in directory: {suite_dir}\n"
            f"Hint: Add .yaml or .yml files to the suite directory."
        )

    all_cases: list[TestCase] = []
    for yaml_file in sorted(yaml_files):
        try:
            cases = _load_suite_file(yaml_file)
            all_cases.extend(cases)
        except YAMLSuiteError as e:
            # Re-raise with file context
            raise YAMLSuiteError(f"Error loading {yaml_file.name}: {e}") from e

    return all_cases


def _load_suite_file(suite_file: Path) -> list[TestCase]:
    """Load test cases from a single YAML file."""
    try:
        with suite_file.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        # Extract line number if available
        line_info = ""
        if hasattr(e, "problem_mark"):
            mark = e.problem_mark
            line_info = f" at line {mark.line + 1}, column {mark.column + 1}"

        raise YAMLSuiteError(
            f"Invalid YAML syntax in {suite_file.name}{line_info}\n"
            f"Error: {e}\n"
            f"Hint: Check YAML syntax with a validator."
        ) from e
    except Exception as e:
        raise YAMLSuiteError(
            f"Failed to read {suite_file.name}: {e}\nHint: Check file permissions and encoding."
        ) from e

    # Validate structure
    if not isinstance(data, dict):
        raise YAMLSuiteError(
            f"Invalid suite format in {suite_file.name}: Expected dict, got {type(data).__name__}\n"
            f"Hint: Suite file should start with 'id:', 'name:', etc."
        )

    if "cases" not in data:
        raise YAMLSuiteError(
            f"Missing 'cases' field in {suite_file.name}\n"
            f"Hint: Add a 'cases:' section with test case definitions."
        )

    if not isinstance(data["cases"], list):
        raise YAMLSuiteError(
            f"Invalid 'cases' format in {suite_file.name}: "
            f"Expected list, got {type(data['cases']).__name__}\n"
            "Hint: 'cases:' should be a list of test case objects."
        )

    # Parse test cases
    test_cases: list[TestCase] = []
    suite_id = data.get("id", suite_file.stem)

    for idx, case_data in enumerate(data["cases"], start=1):
        try:
            test_case = _parse_test_case(case_data, suite_id, idx)
            test_cases.append(test_case)
        except YAMLSuiteError as e:
            raise YAMLSuiteError(f"Error in {suite_file.name}, case #{idx}: {e}") from e

    if not test_cases:
        raise YAMLSuiteError(
            f"No test cases found in {suite_file.name}\n"
            f"Hint: Add at least one test case under 'cases:'."
        )

    return test_cases


def _parse_test_case(case_data: Any, suite_id: str, case_num: int) -> TestCase:  # noqa: ANN401
    """Parse a single test case from YAML data."""
    if not isinstance(case_data, dict):
        raise YAMLSuiteError(
            f"Invalid case format: Expected dict, got {type(case_data).__name__}\n"
            f"Hint: Each test case should be a dict with 'id:', 'prompt:', etc."
        )

    # Multi-step cases (indirect injection chains)
    if case_data.get("type") == "multi_step":
        test_id = case_data.get("id", f"{suite_id}_case_{case_num:03d}")
        metadata = case_data.get("metadata", {})
        metadata["multi_step"] = True
        metadata["steps"] = case_data.get("steps", [])
        metadata["vars"] = case_data.get("vars", {})
        metadata["cleanup"] = case_data.get("cleanup", [])
        metadata["expected"] = "fail"  # multi-step cases test for vulnerabilities
        # Use a placeholder prompt — the chain runner handles execution
        return TestCase(
            id=test_id,
            prompt="[multi-step chain — see steps]",
            metadata=metadata,
        )

    # Validate required fields -- either 'prompt' or 'turns' must be present
    if "prompt" not in case_data and "turns" not in case_data:
        raise YAMLSuiteError(
            "Missing required field 'prompt' or 'turns'\n"
            "Hint: Each test case must have a 'prompt:' field, a 'turns:' list, or 'type: multi_step' with 'steps:'."
        )

    # Extract fields
    test_id = case_data.get("id", f"{suite_id}_case_{case_num:03d}")
    metadata = case_data.get("metadata", {})

    # Handle multi-turn conversations
    if "turns" in case_data:
        turns = case_data["turns"]
        if not isinstance(turns, list) or len(turns) == 0:
            raise YAMLSuiteError(f"'turns' must be a non-empty list for test '{test_id}'")
        # Use first turn's prompt as the primary prompt, store all turns in metadata
        prompt = turns[0].get("prompt", "") if isinstance(turns[0], dict) else str(turns[0])
        metadata["turns"] = turns
        metadata["multi_turn"] = True
    else:
        prompt = case_data["prompt"]

    # Validate and add expected field
    VALID_EXPECTED = {"pass", "refuse", "fail"}
    if "expected" in case_data:
        if case_data["expected"] not in VALID_EXPECTED:
            raise YAMLSuiteError(
                f"Invalid 'expected' value '{case_data['expected']}' in test '{test_id}'. "
                f"Must be one of: {', '.join(sorted(VALID_EXPECTED))}"
            )
        metadata["expected"] = case_data["expected"]

    # Validate risk if present
    VALID_RISKS = {"critical", "high", "medium", "low"}
    risk = case_data.get("metadata", {}).get("risk", "")
    if risk and risk not in VALID_RISKS:
        raise YAMLSuiteError(
            f"Invalid 'risk' value '{risk}' in test '{test_id}'. "
            f"Must be one of: {', '.join(sorted(VALID_RISKS))}"
        )

    # Operator control fields -- preserved in metadata for runner use
    for control_field in ["encoding", "delay_seconds", "mutation", "proxy",
                          "judge", "suffix", "turns", "adapter_override"]:
        if control_field in case_data:
            metadata[control_field] = case_data[control_field]

    # Add suite context to metadata
    metadata["suite_id"] = suite_id

    # Validate prompt is non-empty
    if not isinstance(prompt, str) or not prompt.strip():
        raise YAMLSuiteError(
            f"Invalid prompt for test '{test_id}': prompt must be a non-empty string\n"
            f"Hint: Provide a valid prompt text."
        )

    return TestCase(
        id=test_id,
        prompt=prompt,
        metadata=metadata,
    )
