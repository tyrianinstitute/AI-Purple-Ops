"""Plugin installation and management system.

Manages installation of official attack implementations by cloning repositories,
creating isolated virtual environments, and installing dependencies.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from aipop.intelligence.plugins.base import PluginInfo

logger = logging.getLogger(__name__)


@dataclass
class PluginRegistry:
    """Registry entry for an official plugin."""

    name: str
    """Plugin name (gcg, pair, autodan)"""

    repo_url: str
    """GitHub repository URL"""

    install_method: Literal["pip", "pip_editable", "requirements"]
    """Installation method"""

    requirements_file: str | None = None
    """Path to requirements.txt (relative to repo root)"""

    python_version: str = "3.9"
    """Minimum Python version"""

    gpu_required: bool = False
    """Whether GPU is required"""

    known_issues: list[str] | None = None
    """List of known limitations"""


# Official plugin registry
OFFICIAL_PLUGINS: dict[str, PluginRegistry] = {
    "gcg": PluginRegistry(
        name="gcg",
        repo_url="https://github.com/llm-attacks/llm-attacks.git",
        install_method="pip_editable",
        python_version="3.8",
        gpu_required=True,
        known_issues=[
            "Requires local HuggingFace models (Vicuna, LLaMA)",
            "80GB GPU recommended for Vicuna-13B",
            "Only LLaMA-style tokenizers supported",
            "Cannot use API models (OpenAI, Anthropic)",
        ],
    ),
    "pair": PluginRegistry(
        name="pair",
        repo_url="https://github.com/patrickrchao/JailbreakingLLMs.git",
        install_method="requirements",
        requirements_file="requirements.txt",
        python_version="3.8",
        gpu_required=False,
        known_issues=[
            "High API costs (~180 queries per attack)",
            "Requires API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY)",
            "Judge accuracy varies (Llama Guard 76%, GPT-4 88%)",
            "No built-in caching",
        ],
    ),
    "autodan": PluginRegistry(
        name="autodan",
        repo_url="https://github.com/SheltonLiu-N/AutoDAN.git",
        install_method="requirements",
        requirements_file="requirements.txt",
        python_version="3.9",
        gpu_required=True,
        known_issues=[
            "White-box only (needs logits for fitness function)",
            "High GPU memory (256 candidates in VRAM)",
            "~25,600 forward passes per attack",
            "Only HuggingFace models supported",
        ],
    ),
}


class PluginInstaller:
    """Manages plugin installation and venv creation."""

    def __init__(self, plugins_dir: Path | None = None) -> None:
        """Initialize plugin installer.

        Args:
            plugins_dir: Directory for plugin installations (default: ~/.aipop/plugins)
        """
        if plugins_dir is None:
            plugins_dir = Path.home() / ".aipop" / "plugins"

        self.plugins_dir = Path(plugins_dir)
        self.plugins_dir.mkdir(parents=True, exist_ok=True)

    def _show_install_error(
        self, plugin_name: str, error_title: str, error_details: str, recovery_options: list[str]
    ):
        """Show user-friendly install error with recovery options.

        Args:
            plugin_name: Name of plugin that failed
            error_title: Short error description
            error_details: Technical details (truncated)
            recovery_options: List of recovery steps
        """
        from rich.console import Console
        from rich.panel import Panel

        console = Console()

        options_text = "\n".join(f"  {i+1}. {opt}" for i, opt in enumerate(recovery_options))

        console.print("\n")
        console.print(
            Panel.fit(
                f"[red]❌ {error_title}[/red]\n\n"
                f"[bold]Plugin:[/bold] {plugin_name}\n"
                f"[bold]Details:[/bold] {error_details}\n\n"
                f"[bold yellow]Recovery Options:[/bold yellow]\n{options_text}\n\n"
                f"[dim]If issue persists, report at: github.com/tyrianinstitute/AI-Purple-Ops/issues[/dim]",
                border_style="red",
                title="[bold]Installation Failed[/bold]",
            )
        )
        console.print()

        logger.info(f"Plugin installer initialized: {self.plugins_dir}")

    def install_plugin(
        self,
        name: str,
        force: bool = False,
        use_system_python: bool = False,
    ) -> PluginInfo:
        """Install a plugin by cloning repo and setting up venv.

        Args:
            name: Plugin name (gcg, pair, autodan, or "all")
            force: Force reinstall if already installed
            use_system_python: Use system Python instead of creating venv

        Returns:
            PluginInfo for the installed plugin

        Raises:
            ValueError: If plugin name is unknown
            RuntimeError: If installation fails
        """
        if name == "all":
            # Install all plugins
            results = []
            for plugin_name in OFFICIAL_PLUGINS:
                try:
                    info = self.install_plugin(plugin_name, force, use_system_python)
                    results.append(info)
                except Exception as e:
                    logger.error(f"Failed to install {plugin_name}: {e}")
            return results[0] if results else None  # Return first for simplicity

        if name not in OFFICIAL_PLUGINS:
            raise ValueError(
                f"Unknown plugin: {name}. " f"Available: {', '.join(OFFICIAL_PLUGINS.keys())}"
            )

        registry = OFFICIAL_PLUGINS[name]
        install_path = self.plugins_dir / name
        venv_path = install_path / "venv"

        # Check if already installed
        if install_path.exists() and not force:
            logger.info(f"Plugin {name} already installed at {install_path}")
            return self.get_plugin_info(name)

        # Clean up existing installation if forcing
        if install_path.exists() and force:
            logger.info(f"Removing existing installation: {install_path}")
            shutil.rmtree(install_path)

        # Create installation directory
        install_path.mkdir(parents=True, exist_ok=True)

        # Import rich for progress bars
        from rich.console import Console
        from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

        console = Console()

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(f"[cyan]Installing {name}...", total=5)

                # Step 1: Clone repository
                progress.update(task, description=f"[1/5] Cloning {registry.repo_url}...")
                repo_path = install_path / "repo"
                try:
                    result = subprocess.run(
                        ["git", "clone", registry.repo_url, str(repo_path)],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=300,  # 5 minute timeout
                    )
                    progress.advance(task)
                except subprocess.CalledProcessError as e:
                    self._show_install_error(
                        name,
                        "Failed to clone repository",
                        e.stderr[:200] if e.stderr else "Unknown error",
                        recovery_options=[
                            "Check git is installed: git --version",
                            "Check network access: ping github.com",
                            f"Use legacy: --method {name} --implementation legacy",
                            f"Manual install: {registry.repo_url}",
                        ],
                    )
                    raise RuntimeError(f"Failed to clone {name} repository. See options above.")
                except subprocess.TimeoutExpired:
                    self._show_install_error(
                        name,
                        "Git clone timed out (5 minutes)",
                        "Network is too slow or connection interrupted",
                        recovery_options=[
                            "Check internet connection",
                            "Try again with better network",
                            f"Use legacy: --method {name} --implementation legacy",
                        ],
                    )
                    raise RuntimeError("Git clone timeout. See options above.")

                if not use_system_python:
                    # Step 2: Create virtual environment
                    progress.update(task, description="[2/5] Creating virtual environment...")
                    try:
                        subprocess.run(
                            [sys.executable, "-m", "venv", str(venv_path)],
                            check=True,
                            capture_output=True,
                            text=True,
                            timeout=60,
                        )
                        progress.advance(task)
                    except subprocess.CalledProcessError as e:
                        self._show_install_error(
                            name,
                            "Failed to create virtual environment",
                            e.stderr[:200] if e.stderr else "Unknown error",
                            recovery_options=[
                                "Install python3-venv: sudo apt-get install python3-venv",
                                "Use system Python: aipop plugins install --use-system-python",
                                f"Use legacy: --method {name} --implementation legacy",
                            ],
                        )
                        raise RuntimeError(f"Failed to create venv for {name}. See options above.")

                    # Determine Python executable
                    if sys.platform == "win32":
                        python_exe = venv_path / "Scripts" / "python.exe"
                        pip_exe = venv_path / "Scripts" / "pip.exe"
                    else:
                        python_exe = venv_path / "bin" / "python"
                        pip_exe = venv_path / "bin" / "pip"
                else:
                    python_exe = sys.executable
                    pip_exe = "pip"
                    progress.advance(task)  # Skip venv step

                # Step 3: Upgrade pip
                progress.update(task, description="[3/5] Upgrading pip...")
                try:
                    subprocess.run(
                        [str(pip_exe), "install", "--upgrade", "pip"],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    progress.advance(task)
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to upgrade pip: {e.stderr}")
                    progress.advance(task)  # Non-critical, continue

                # Step 4: Install dependencies
                progress.update(task, description="[4/5] Installing dependencies...")
                if registry.install_method == "requirements":
                    requirements_path = repo_path / (
                        registry.requirements_file or "requirements.txt"
                    )
                    if requirements_path.exists():
                        try:
                            subprocess.run(
                                [str(pip_exe), "install", "-r", str(requirements_path)],
                                check=True,
                                capture_output=True,
                                text=True,
                                timeout=600,  # 10 minute timeout for deps
                            )
                        except subprocess.CalledProcessError as e:
                            self._show_install_error(
                                name,
                                "Failed to install dependencies",
                                e.stderr[:200] if e.stderr else "Unknown error",
                                recovery_options=[
                                    "Check requirements compatibility",
                                    "Create clean venv: python -m venv fresh-env",
                                    f"Manual install: cd ~/.aipop/plugins/{name}/repo && pip install -r requirements.txt",
                                    f"Use legacy: --method {name} --implementation legacy",
                                ],
                            )
                            raise RuntimeError(
                                f"Dependency install failed for {name}. See options above."
                            )
                        except subprocess.TimeoutExpired:
                            self._show_install_error(
                                name,
                                "Dependency installation timed out (10 minutes)",
                                "Large packages like PyTorch can take time",
                                recovery_options=[
                                    "Try with better network connection",
                                    "Install manually with pip install -r requirements.txt",
                                    f"Use legacy: --method {name} --implementation legacy",
                                ],
                            )
                            raise RuntimeError(f"Install timeout for {name}. See options above.")
                    else:
                        logger.warning(f"Requirements file not found: {requirements_path}")

                elif registry.install_method == "pip_editable":
                    try:
                        subprocess.run(
                            [str(pip_exe), "install", "-e", str(repo_path)],
                            check=True,
                            capture_output=True,
                            text=True,
                            timeout=600,
                        )
                    except subprocess.CalledProcessError as e:
                        raise RuntimeError(
                            f"Failed to install package: {e.stderr}\n"
                            f"Suggestion: Check setup.py exists and is valid"
                        )

                elif registry.install_method == "pip":
                    try:
                        subprocess.run(
                            [str(pip_exe), "install", str(repo_path)],
                            check=True,
                            capture_output=True,
                            text=True,
                            timeout=600,
                        )
                    except subprocess.CalledProcessError as e:
                        raise RuntimeError(
                            f"Failed to install package: {e.stderr}\n"
                            f"Suggestion: Check setup.py exists and is valid"
                        )

                progress.advance(task)

                # Step 5: Write metadata
                progress.update(task, description="[5/5] Finalizing installation...")
                metadata = {
                    "name": name,
                    "installed": True,
                    "install_date": datetime.now().isoformat(),
                    "repo_url": registry.repo_url,
                    "install_path": str(install_path),
                    "venv_path": str(venv_path) if not use_system_python else None,
                }
                metadata_path = install_path / "metadata.json"
                import json

                with open(metadata_path, "w") as f:
                    json.dump(metadata, f, indent=2)
                progress.advance(task)

                progress.update(
                    task, description=f"[green]✓ {name.upper()} installed successfully!"
                )

            logger.info(f"Successfully installed plugin: {name}")

            return PluginInfo(
                name=name,
                installed=True,
                repo_url=registry.repo_url,
                install_path=install_path,
                venv_path=venv_path if not use_system_python else None,
                last_updated=datetime.now(),
                known_issues=registry.known_issues or [],
            )

        except RuntimeError:
            # Re-raise our enhanced RuntimeErrors
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"Installation failed: {e}")
            if e.stderr:
                logger.error(f"Stderr: {e.stderr}")
            raise RuntimeError(
                f"Failed to install plugin {name}: {e}\n"
                f"Suggestion: Check logs above for details"
            ) from e
        except Exception as e:
            logger.error(f"Unexpected error during installation: {e}")
            raise RuntimeError(
                f"Unexpected error installing {name}: {e}\n"
                f"Suggestion: Check your Python environment and dependencies"
            ) from e

    def list_installed(self) -> list[str]:
        """Return list of installed plugin names.

        Returns:
            List of plugin names (gcg, pair, autodan)
        """
        installed = []
        for name in OFFICIAL_PLUGINS:
            info = self.get_plugin_info(name)
            if info.installed:
                installed.append(name)
        return installed

    def get_plugin_info(self, name: str) -> PluginInfo:
        """Get information about a plugin.

        Args:
            name: Plugin name

        Returns:
            PluginInfo with installation details
        """
        if name not in OFFICIAL_PLUGINS:
            raise ValueError(f"Unknown plugin: {name}")

        registry = OFFICIAL_PLUGINS[name]
        install_path = self.plugins_dir / name
        venv_path = install_path / "venv"
        metadata_path = install_path / "metadata.json"

        # Check if installed
        installed = install_path.exists() and metadata_path.exists()

        # Load metadata if available
        last_updated = None
        if installed and metadata_path.exists():
            import json

            try:
                with open(metadata_path) as f:
                    metadata = json.load(f)
                    install_date_str = metadata.get("install_date")
                    if install_date_str:
                        last_updated = datetime.fromisoformat(install_date_str)
            except Exception as e:
                logger.warning(f"Failed to load metadata: {e}")

        return PluginInfo(
            name=name,
            installed=installed,
            repo_url=registry.repo_url,
            install_path=install_path if installed else None,
            venv_path=venv_path if installed else None,
            last_updated=last_updated,
            dependencies=[],  # Could parse from requirements.txt
            known_issues=registry.known_issues or [],
        )

    def uninstall_plugin(self, name: str) -> None:
        """Remove a plugin installation.

        Args:
            name: Plugin name
        """
        if name not in OFFICIAL_PLUGINS:
            raise ValueError(f"Unknown plugin: {name}")

        install_path = self.plugins_dir / name
        if install_path.exists():
            logger.info(f"Removing {install_path}...")
            shutil.rmtree(install_path)
            logger.info(f"Successfully uninstalled plugin: {name}")
        else:
            logger.warning(f"Plugin {name} not installed")

    def update_plugin(self, name: str) -> PluginInfo:
        """Update a plugin by pulling latest from repo.

        Args:
            name: Plugin name

        Returns:
            Updated PluginInfo
        """
        if name not in OFFICIAL_PLUGINS:
            raise ValueError(f"Unknown plugin: {name}")

        install_path = self.plugins_dir / name
        repo_path = install_path / "repo"

        if not repo_path.exists():
            raise RuntimeError(f"Plugin {name} not installed")

        try:
            logger.info(f"Updating {name}...")
            subprocess.run(
                ["git", "pull"],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True,
            )
            logger.info(f"Successfully updated plugin: {name}")

            # Update metadata
            metadata_path = install_path / "metadata.json"
            if metadata_path.exists():
                import json

                with open(metadata_path) as f:
                    metadata = json.load(f)
                metadata["last_updated"] = datetime.now().isoformat()
                with open(metadata_path, "w") as f:
                    json.dump(metadata, f, indent=2)

            return self.get_plugin_info(name)

        except subprocess.CalledProcessError as e:
            logger.error(f"Update failed: {e}")
            raise RuntimeError(f"Failed to update plugin {name}") from e
