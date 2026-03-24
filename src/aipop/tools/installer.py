"""Tool installation and management module."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml
from rich.progress import Progress, SpinnerColumn, TextColumn

from aipop.utils.log_utils import ConsoleLogger

log = ConsoleLogger()


class ToolInstallError(Exception):
    """Error during tool installation."""


class ToolkitConfigError(Exception):
    """Error loading or parsing toolkit configuration."""


def load_toolkit_config(config_path: Path | str | None = None) -> dict[str, Any]:
    """Load toolkit configuration from YAML file.

    Args:
        config_path: Path to toolkit.yaml config file. Defaults to configs/toolkit.yaml

    Returns:
        Parsed toolkit configuration dictionary

    Raises:
        ToolkitConfigError: If config file cannot be loaded or parsed
    """
    if config_path is None:
        config_path = Path(__file__).parent.parent.parent.parent / "configs" / "toolkit.yaml"
    else:
        config_path = Path(config_path)

    if not config_path.exists():
        raise ToolkitConfigError(f"Toolkit config not found: {config_path}")

    try:
        with config_path.open("r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ToolkitConfigError(f"Invalid YAML in toolkit config: {e}") from e

    if not isinstance(config, dict) or "tools" not in config:
        raise ToolkitConfigError("Invalid toolkit config: missing 'tools' section")

    return config


def verify_sha256(file_path: Path, expected_sha: str | None) -> bool:
    """Verify SHA256 checksum of a file.

    Args:
        file_path: Path to file to verify
        expected_sha: Expected SHA256 hash (hex string)

    Returns:
        True if checksum matches or expected_sha is None, False otherwise
    """
    if expected_sha is None:
        return True  # Skip verification if no checksum provided

    sha256_hash = hashlib.sha256()
    with file_path.open("rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    computed_sha = sha256_hash.hexdigest()
    return computed_sha.lower() == expected_sha.lower()


def download_file(url: str, dest_path: Path, expected_sha: str | None = None) -> Path:
    """Download a file from URL with progress indication.

    Args:
        url: URL to download from
        dest_path: Destination path for downloaded file
        expected_sha: Optional SHA256 checksum to verify

    Returns:
        Path to downloaded file

    Raises:
        ToolInstallError: If download fails or checksum doesn't match
    """
    import requests

    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()

        dest_path.parent.mkdir(parents=True, exist_ok=True)

        total_size = int(response.headers.get("content-length", 0))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=log._console,
        ) as progress:
            task = progress.add_task(f"Downloading {dest_path.name}...", total=total_size)

            with dest_path.open("wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        progress.update(task, advance=len(chunk))

        # Verify checksum if provided
        if expected_sha:
            if not verify_sha256(dest_path, expected_sha):
                dest_path.unlink()
                raise ToolInstallError(
                    f"SHA256 checksum mismatch for {dest_path.name}. "
                    "File may be corrupted or tampered with."
                )

        return dest_path

    except requests.RequestException as e:
        raise ToolInstallError(f"Failed to download {url}: {e}") from e


def install_tool(
    tool_name: str,
    tool_spec: dict[str, Any],
    use_stable: bool = True,
    verify_checksums: bool = True,
) -> bool:
    """Install a single tool based on its specification.

    Args:
        tool_name: Name of the tool to install
        tool_spec: Tool specification from config
        use_stable: If True, use stable version; otherwise use latest
        verify_checksums: If True, verify SHA256 checksums when available

    Returns:
        True if installation succeeded, False otherwise
    """
    version_key = "stable" if use_stable else "latest"
    version_info = tool_spec.get(version_key, {})

    if not version_info:
        log.error(f"No {version_key} version defined for {tool_name}")
        return False

    version = version_info.get("version", "latest")
    tool_type = tool_spec.get("type", "pip")
    install_cmd_template = tool_spec.get("install_cmd", "")

    log.step(f"Installing {tool_name} ({version})...")

    try:
        if tool_type == "npm":
            # npm install -g promptfoo@version
            cmd = install_cmd_template.format(version=version)
            # Convert command string to list for safe execution
            cmd_parts = cmd.split()
            result = subprocess.run(
                cmd_parts,
                shell=False,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                log.error(f"npm install failed: {result.stderr}")
                return False

        elif tool_type == "pip":
            # pip install garak==version
            cmd = install_cmd_template.format(version=version)
            # Convert command string to list for safe execution
            cmd_parts = cmd.split()
            result = subprocess.run(
                cmd_parts,
                shell=False,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                log.error(f"pip install failed: {result.stderr}")
                return False

        elif tool_type == "git":
            # Handle git clone and pip install -e
            url = version_info.get("url", "")
            if not url:
                log.error(f"No URL defined for {tool_name} {version_key} version")
                return False

            # Download and verify if URL is a tarball
            if url.endswith(".tar.gz") or url.endswith(".zip"):
                sha256 = version_info.get("sha256") if verify_checksums else None
                with tempfile.TemporaryDirectory() as tmpdir:
                    archive_path = Path(tmpdir) / f"{tool_name}-{version}.tar.gz"
                    download_file(url, archive_path, sha256)
                    # Extract and install
                    extract_dir = Path(tmpdir) / tool_name
                    extract_dir.mkdir()
                    shutil.unpack_archive(archive_path, extract_dir)
                    # Find setup.py or pyproject.toml
                    setup_dirs = list(extract_dir.rglob("setup.py")) + list(
                        extract_dir.rglob("pyproject.toml")
                    )
                    if setup_dirs:
                        install_dir = setup_dirs[0].parent
                        result = subprocess.run(
                            ["pip", "install", "-e", str(install_dir)],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        if result.returncode != 0:
                            log.error(f"pip install -e failed: {result.stderr}")
                            return False
                    else:
                        log.error(f"No setup.py or pyproject.toml found in {url}")
                        return False
            else:
                # Git clone
                cmd = install_cmd_template.format(url=url, version=version)
                # Convert command string to list for safe execution
                cmd_parts = cmd.split()
                result = subprocess.run(
                    cmd_parts,
                    shell=False,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode != 0:
                    log.error(f"git clone/install failed: {result.stderr}")
                    return False

        else:
            log.error(f"Unknown tool type: {tool_type}")
            return False

        log.ok(f"{tool_name} installed successfully")
        return True

    except Exception as e:
        log.error(f"Installation failed for {tool_name}: {e}")
        return False


def check_tool_available(tool_name: str, tool_spec: dict[str, Any]) -> tuple[bool, str | None]:
    """Check if a tool is installed and available.

    Args:
        tool_name: Name of the tool to check
        tool_spec: Tool specification from config

    Returns:
        Tuple of (is_available, version_string)
    """
    health_check = tool_spec.get("health_check", "")
    timeout = tool_spec.get("health_check_timeout", 5)

    if not health_check:
        return False, None

    try:
        # Replace bare 'python' with the current interpreter so we check
        # the same venv where aipop is installed
        import sys
        import shlex
        if isinstance(health_check, str):
            health_check = health_check.replace("python ", f"{sys.executable} ", 1)
            health_check_parts = shlex.split(health_check)
        else:
            health_check_parts = health_check

        result = subprocess.run(
            health_check_parts,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode == 0:
            version = result.stdout.strip() if result.stdout else "installed"
            return True, version
        return False, None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False, None


def get_tool_version(tool_name: str, tool_spec: dict[str, Any]) -> str | None:
    """Get installed version of a tool.

    Args:
        tool_name: Name of the tool
        tool_spec: Tool specification from config

    Returns:
        Version string if available, None otherwise
    """
    is_available, version = check_tool_available(tool_name, tool_spec)
    return version if is_available else None
