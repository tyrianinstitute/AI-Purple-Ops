"""Suite registry for discovering and querying test suites."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from aipop.loaders.yaml_suite import YAMLSuiteError
from aipop.utils.errors import HarnessError
from aipop.utils.paths import get_package_data_path

logger = logging.getLogger(__name__)


class SuiteNotFoundError(HarnessError):
    """Error when suite is not found."""


@dataclass
class SuiteMetadata:
    """Metadata for a test suite."""

    id: str
    name: str
    description: str
    path: Path
    category: str
    test_count: int
    metadata: dict[str, Any]


def discover_suites(suites_dir: Path | str | None = None) -> list[SuiteMetadata]:
    """Discover all test suites in the suites directory.

    Args:
        suites_dir: Path to suites directory (defaults to "suites/")

    Returns:
        List of SuiteMetadata objects for all discovered suites

    Raises:
        YAMLSuiteError: If suites directory doesn't exist or is invalid
    """
    if suites_dir is None:
        suites_dir = get_package_data_path("suites")
    else:
        suites_dir = Path(suites_dir)

    if not suites_dir.exists():
        raise YAMLSuiteError(
            f"Suites directory not found: {suites_dir}\n"
            f"Hint: Create a 'suites/' directory with test suite YAML files."
        )

    if not suites_dir.is_dir():
        raise YAMLSuiteError(
            f"Suites path is not a directory: {suites_dir}\n"
            f"Hint: Provide a directory path containing suite YAML files."
        )

    suites: list[SuiteMetadata] = []

    # Scan all subdirectories in suites/
    for category_dir in sorted(suites_dir.iterdir()):
        if not category_dir.is_dir():
            continue

        category = category_dir.name

        # Find all YAML files in category directory
        yaml_files = list(category_dir.glob("*.yaml")) + list(category_dir.glob("*.yml"))

        for suite_file in sorted(yaml_files):
            try:
                metadata = get_suite_metadata(suite_file, category)
                suites.append(metadata)
            except Exception as e:
                # Log warning but continue scanning other suites
                # Don't fail entire discovery for one bad file
                logger.warning(
                    f"Skipping invalid suite {suite_file.name}: {e.__class__.__name__}: {e}"
                )
                continue

    return suites


def get_suite_metadata(suite_file: Path, category: str | None = None) -> SuiteMetadata:
    """Extract metadata from a suite YAML file.

    Args:
        suite_file: Path to suite YAML file
        category: Category name (if None, inferred from parent directory)

    Returns:
        SuiteMetadata object with suite information

    Raises:
        YAMLSuiteError: If suite file is invalid or cannot be loaded
    """
    suite_file = Path(suite_file)

    if not suite_file.exists():
        raise YAMLSuiteError(f"Suite file not found: {suite_file}")

    # Infer category from parent directory if not provided
    if category is None:
        category = suite_file.parent.name

    # Load YAML to get metadata
    try:
        with suite_file.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise YAMLSuiteError(
            f"Invalid YAML syntax in {suite_file.name}: {e}\n"
            f"Hint: Check YAML syntax with a validator."
        ) from e
    except Exception as e:
        raise YAMLSuiteError(
            f"Failed to read {suite_file.name}: {e}\nHint: Check file permissions and encoding."
        ) from e

    if not isinstance(data, dict):
        raise YAMLSuiteError(
            f"Invalid suite format in {suite_file.name}: Expected dict, got {type(data).__name__}"
        )

    # Extract suite metadata
    suite_id = data.get("id", suite_file.stem)
    suite_name = data.get("name", suite_file.stem.replace("_", " ").title())
    description = data.get("description", "")

    # Get test count directly from YAML data (already loaded above)
    # No need to reload the file via load_yaml_suite
    cases = data.get("cases", [])
    test_count = len(cases) if isinstance(cases, list) else 0

    # Extract top-level metadata
    suite_metadata = data.get("metadata", {})

    return SuiteMetadata(
        id=suite_id,
        name=suite_name,
        description=description,
        path=suite_file,
        category=category,
        test_count=test_count,
        metadata=suite_metadata,
    )


def get_suite_info(suite_name: str, suites_dir: Path | str | None = None) -> SuiteMetadata:
    """Get detailed information for a specific suite.

    Args:
        suite_name: Suite name (can be "category/suite" or just "suite")
        suites_dir: Path to suites directory (defaults to "suites/")

    Returns:
        SuiteMetadata object with suite information

    Raises:
        YAMLSuiteError: If suite is not found
    """
    if suites_dir is None:
        suites_dir = get_package_data_path("suites")
    else:
        suites_dir = Path(suites_dir)

    # Try to find the suite
    suite_path = None

    # If suite_name contains "/", treat as "category/suite"
    if "/" in suite_name:
        parts = suite_name.split("/", 1)
        category = parts[0]
        suite_stem = parts[1]
        potential_path = suites_dir / category / f"{suite_stem}.yaml"
        if potential_path.exists():
            suite_path = potential_path
        else:
            potential_path = suites_dir / category / f"{suite_stem}.yml"
            if potential_path.exists():
                suite_path = potential_path
    else:
        # Search all categories for suite with matching name
        for category_dir in suites_dir.iterdir():
            if not category_dir.is_dir():
                continue

            potential_path = category_dir / f"{suite_name}.yaml"
            if potential_path.exists():
                suite_path = potential_path
                break

            potential_path = category_dir / f"{suite_name}.yml"
            if potential_path.exists():
                suite_path = potential_path
                break

    if suite_path is None:
        # Generate helpful error with available suites
        try:
            all_suites = discover_suites(suites_dir)
            available = [f"{s.category}/{s.path.stem}" for s in all_suites]
            available_list = "\n".join(f"  {s}" for s in sorted(available))
        except Exception:
            available_list = "  (unable to list suites)"

        raise SuiteNotFoundError(
            f"Suite '{suite_name}' not found.\n\n"
            f"Available suites:\n{available_list}\n\n"
            f"Run 'aipop suites list' to see all available suites."
        )

    category = suite_path.parent.name
    return get_suite_metadata(suite_path, category)
