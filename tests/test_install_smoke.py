"""Install smoke tests — verify the package is actually installable and functional.

These run in CI to catch pyproject.toml regressions before they hit users.
"""
import importlib
import subprocess
import sys


def test_core_package_imports():
    """The core package imports without optional deps."""
    aipop = importlib.import_module("aipop")
    assert hasattr(aipop, "__file__")


def test_cli_entry_point_exists():
    """aipop CLI entry point is registered and responds to --help."""
    result = subprocess.run(
        [sys.executable, "-m", "aipop.cli.harness", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "Usage" in result.stdout or "usage" in result.stdout.lower()


def test_version_is_set():
    """pyproject.toml version is parseable and not the old 0.1.0 placeholder."""
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as f:
        data = tomllib.load(f)

    version = data["project"]["version"]
    assert version != "0.1.0", "Version still at old placeholder"
    assert "." in version


def test_dependencies_under_project_section():
    """dependencies must be under [project], not [project.urls] or anywhere else."""
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as f:
        data = tomllib.load(f)

    assert "dependencies" in data["project"], "dependencies missing from [project]"
    assert "dependencies" not in data["project"].get("urls", {}), (
        "dependencies still under [project.urls]"
    )


def test_no_conflicting_official_extras():
    """all-official must not exist — pair-official and autodan-official have incompatible pins."""
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as f:
        data = tomllib.load(f)

    extras = data["project"].get("optional-dependencies", {})
    assert "all-official" not in extras, (
        "all-official extra still exists — pair-official and autodan-official "
        "pin incompatible fschat versions"
    )


def test_default_install_is_lean():
    """Default dependencies must not include heavyweight research packages."""
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as f:
        data = tomllib.load(f)

    deps = data["project"]["dependencies"]
    dep_names = [d.split(">")[0].split("<")[0].split("=")[0].split("[")[0].strip().lower()
                 for d in deps]

    forbidden = {"torch", "transformers", "duckdb", "alembic", "weasyprint", "scipy", "pygad"}
    present = forbidden & set(dep_names)
    assert not present, f"Heavyweight packages in default deps: {present}"
