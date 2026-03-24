"""Dependency installer for AI Purple Ops profiles."""

import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from aipop.setup.profiles import InstallProfile

console = Console()


class InstallationError(Exception):
    """Raised when installation fails."""


class DependencyInstaller:
    """Handles installation of dependencies for different profiles."""

    def __init__(self, profile: InstallProfile, verbose: bool = False) -> None:
        """Initialize installer.

        Args:
            profile: Installation profile to install
            verbose: Show detailed output
        """
        self.profile = profile
        self.verbose = verbose
        self.console = Console()

    def install(self) -> bool:
        """Install all dependencies for the profile.

        Returns:
            True if installation succeeded, False otherwise
        """
        if not self.profile.dependencies:
            self.console.print(
                f"[green]✓[/green] Profile '{self.profile.display_name}' has no additional dependencies"
            )
            return True

        self.console.print(
            Panel.fit(
                f"[bold]Installing {self.profile.display_name} Profile[/bold]\n\n"
                f"Dependencies: {len(self.profile.dependencies)}\n"
                f"Disk space required: ~{self.profile.disk_size_mb}MB",
                border_style="cyan",
            )
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            for dep in self.profile.dependencies:
                task = progress.add_task(f"Installing {dep}...", total=None)

                try:
                    self._install_package(dep)
                    progress.update(task, description=f"✓ Installed {dep}")
                except InstallationError as e:
                    progress.update(task, description=f"✗ Failed: {dep}")
                    self.console.print(f"[red]Error installing {dep}: {e}[/red]")
                    return False

        self.console.print("\n[green]✓ Installation complete![/green]")
        return True

    def _install_package(self, package: str) -> None:
        """Install a single package via pip.

        Args:
            package: Package spec (e.g., "promptfoo>=0.90.0")

        Raises:
            InstallationError: If installation fails
        """
        cmd = [sys.executable, "-m", "pip", "install", package]

        if not self.verbose:
            cmd.append("--quiet")

        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )

            if self.verbose and result.stdout:
                self.console.print(result.stdout)

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            raise InstallationError(f"pip install failed: {error_msg}") from e
        except FileNotFoundError as e:
            raise InstallationError("pip not found - is Python installed correctly?") from e

    def validate_installation(self) -> dict[str, bool]:
        """Validate that all dependencies are installed correctly.

        Returns:
            Dict mapping package names to installation status
        """
        results = {}

        for dep in self.profile.dependencies:
            # Extract package name (remove version specifiers)
            pkg_name = dep.split(">=")[0].split("==")[0].split("<")[0]

            try:
                __import__(pkg_name.replace("-", "_"))
                results[pkg_name] = True
            except ImportError:
                results[pkg_name] = False

        return results


def create_ctf_config(config_dir: Path | None = None) -> Path:
    """Create default CTF configuration file.

    Args:
        config_dir: Directory to create config in (default: ~/.aipop)

    Returns:
        Path to created config file
    """
    if config_dir is None:
        config_dir = Path.home() / ".aipop"

    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "ctf_config.yaml"

    default_config = """# AI Purple Ops CTF Configuration
# This file configures the CTF attack orchestration system

attacker:
  # Attacker model (GPT-4/Claude) used to plan attacks
  model: gpt-4  # or: gpt-4-turbo, claude-3-5-sonnet-20241022, etc.
  provider: openai  # or: anthropic, ollama, etc.
  api_key_env: OPENAI_API_KEY  # Environment variable with API key
  fallback_to_primary: true  # Use primary adapter if attacker model unavailable

orchestration:
  max_turns: 20  # Maximum conversation turns per attack
  timeout_seconds: 300  # 5 minutes
  enable_caching: true  # Cache conversation states in DuckDB
  cost_warning_threshold: 5.0  # Warn if attack cost exceeds $5

strategies:
  # Strategy-specific settings
  mcp_injection:
    max_tool_attempts: 10
    detect_tools_first: true
    
  prompt_extraction:
    use_gradual_extraction: true
    max_characters_per_turn: 50
    
  indirect_injection:
    max_rag_documents: 5
    test_citations: true

output:
  export_conversations: true  # Save all conversations to JSON
  export_dir: ~/.aipop/ctf_sessions
  show_cost_breakdown: true
  show_state_transitions: true
"""

    if not config_path.exists():
        config_path.write_text(default_config)
        console.print(f"[green]✓[/green] Created CTF config: {config_path}")
    else:
        console.print(f"[yellow]![/yellow] CTF config already exists: {config_path}")

    return config_path


def show_installation_summary(profile: InstallProfile, success: bool) -> None:
    """Show installation summary with next steps.

    Args:
        profile: Installed profile
        success: Whether installation succeeded
    """
    if success:
        console.print(
            Panel.fit(
                f"[bold green]✓ {profile.display_name} Profile Installed Successfully![/bold green]\n\n"
                f"[bold]What's included:[/bold]\n"
                + "\n".join(f"  • {uc}" for uc in profile.use_cases)
                + "\n\n[bold]Next steps:[/bold]\n"
                + (
                    "  • Try: [cyan]aipop ctf mcp-inject --adapter openai[/cyan]\n"
                    "  • See: [cyan]aipop ctf --help[/cyan]\n"
                    "  • Docs: [cyan]docs/CTF_MCP_INJECTION.md[/cyan]"
                    if profile.includes_ctf
                    else "  • Try: [cyan]aipop run --suite adversarial --adapter openai[/cyan]\n"
                    "  • See: [cyan]aipop --help[/cyan]\n"
                    "  • Docs: [cyan]README.md[/cyan]"
                ),
                border_style="green",
                title="[bold]Installation Complete[/bold]",
            )
        )
    else:
        console.print(
            Panel.fit(
                f"[bold red]✗ {profile.display_name} Profile Installation Failed[/bold red]\n\n"
                "[bold]Troubleshooting:[/bold]\n"
                "  • Check internet connection\n"
                "  • Ensure pip is up to date: [cyan]pip install --upgrade pip[/cyan]\n"
                "  • Try manual install: [cyan]pip install -e .[pro][/cyan]\n"
                "  • Check logs above for specific errors\n\n"
                "[bold]Get help:[/bold]\n"
                "  • GitHub Issues: https://github.com/tyrianinstitute/AI-Purple-Ops/issues\n"
                "  • Documentation: docs/SETUP_GUIDE.md",
                border_style="red",
                title="[bold]Installation Failed[/bold]",
            )
        )
