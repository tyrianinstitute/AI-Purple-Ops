"""Security checks for adapter configs.

Detects secrets in YAML files and warns users to use environment variables.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from aipop.utils.adapter_paths import adapter_spec_globs, get_adapter_dir

console = Console()


def check_config_for_secrets(config_path: Path) -> list[str]:
    """Scan config for potential secrets (bearer tokens, API keys).

    Args:
        config_path: Path to YAML config file

    Returns:
        List of warning messages for detected secrets
    """
    if not config_path.exists():
        return []

    content = config_path.read_text(encoding="utf-8")
    warnings = []

    # Detect hardcoded OpenAI keys
    if re.search(r'["\']?sk-[A-Za-z0-9]{20,}["\']?', content):
        warnings.append("OpenAI API key detected in config")

    # Detect hardcoded Bearer tokens
    if re.search(r"Bearer\s+[A-Za-z0-9_\-]{20,}", content):
        warnings.append("Bearer token detected in config")

    # Detect JWT tokens
    if re.search(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", content):
        warnings.append("JWT token detected in config")

    # Detect generic API keys (long alphanumeric strings)
    if re.search(r'["\']?[A-Za-z0-9_\-]{40,}["\']?', content):
        # Exclude likely environment variable references
        if not re.search(r"\$\{[A-Z_]+\}", content):
            # Only warn if it looks like a real key (not a placeholder)
            placeholders = ["fixme", "your-", "example", "xxx"]
            if not any(placeholder in content.lower() for placeholder in placeholders):
                warnings.append("Long API key-like string detected in config")

    # Detect AWS keys
    if re.search(r"AKIA[0-9A-Z]{16}", content):
        warnings.append("AWS Access Key detected in config")

    # Detect private keys
    if "PRIVATE KEY" in content:
        warnings.append("Private key detected in config")

    return warnings


def show_security_warning(config_path: Path, warnings: list[str]) -> None:
    """Display security warning panel.

    Args:
        config_path: Path to config file
        warnings: List of warning messages
    """
    if not warnings:
        return

    protection_applied, adapter_dir_display, patterns, protection_error = (
        ensure_gitignore_protection(repo_root=Path.cwd(), adapter_dir=config_path.parent)
    )

    warnings_list = "\n".join(f"  • {w}" for w in warnings)
    adapter_name = config_path.stem.upper().replace("-", "_")
    env_var_name = f"{adapter_name}_API_KEY"

    if protection_applied:
        protection_msg = (
            f"[green]✓ Added protection in .gitignore for [dim]{adapter_dir_display}[/dim][/green]"
        )
    else:
        reason = f" ({protection_error})" if protection_error else ""
        manual_lines = "\n".join(
            ["# User-generated adapter configs (may contain secrets)", *patterns]
        )
        protection_msg = (
            f"[yellow]Could not update .gitignore automatically{reason}.[/yellow]\n"
            f"[bold]Add this to .gitignore manually:[/bold]\n"
            f"[dim]{manual_lines}[/dim]"
        )

    console.print()
    console.print(
        Panel.fit(
            f"[yellow]⚠️  SECURITY WARNING[/yellow]\n\n"
            f"Found potential secrets in config:\n"
            f"{warnings_list}\n\n"
            f"[bold]Best Practice:[/bold]\n"
            f"  1. Move secrets to environment variables\n"
            f"  2. Edit: [dim]{config_path}[/dim]\n"
            f"  3. Replace token with: [dim]${{{env_var_name}}}[/dim]\n"
            f"  4. Set environment variable:\n"
            f"     [dim]export {env_var_name}=your-secret-here[/dim]\n"
            f"  5. Never commit adapter configs to git\n"
            f"  6. Adapter config dir: [dim]{adapter_dir_display}[/dim]\n\n"
            f"{protection_msg}",
            border_style="yellow",
            title="[bold]Security Alert[/bold]",
        )
    )
    console.print()


def ensure_gitignore_protection(
    repo_root: Path, adapter_dir: Path | None = None
) -> tuple[bool, str, list[str], str | None]:
    """Ensure adapter configs are in .gitignore.

    Args:
        repo_root: Root directory of the repository
        adapter_dir: Optional adapter directory override

    Returns:
        Tuple of (applied, adapter_dir_display, patterns, error_reason)
    """
    gitignore_path = repo_root / ".gitignore"
    repo_root_resolved = repo_root.resolve()
    resolved_adapter_dir = adapter_dir or get_adapter_dir()

    if resolved_adapter_dir.is_absolute():
        adapter_dir_resolved = resolved_adapter_dir.resolve()
    else:
        adapter_dir_resolved = (repo_root_resolved / resolved_adapter_dir).resolve()

    try:
        adapter_dir_display = adapter_dir_resolved.relative_to(repo_root_resolved).as_posix()
    except ValueError:
        adapter_dir_display = resolved_adapter_dir.as_posix()
        patterns = _gitignore_patterns(adapter_dir_display)
        return False, adapter_dir_display, patterns, "adapter directory is outside repository root"

    patterns = _gitignore_patterns(adapter_dir_display)
    header = "# User-generated adapter configs (may contain secrets)"
    existing_content = gitignore_path.read_text(encoding="utf-8") if gitignore_path.exists() else ""
    missing_patterns = [pattern for pattern in patterns if pattern not in existing_content]

    if not missing_patterns:
        return True, adapter_dir_display, patterns, None

    try:
        with gitignore_path.open("a", encoding="utf-8") as f:
            if existing_content and not existing_content.endswith("\n"):
                f.write("\n")
            if existing_content:
                f.write("\n")
            if header not in existing_content:
                f.write(f"{header}\n")
            f.write("\n".join(missing_patterns))
            f.write("\n")
    except OSError as exc:
        return False, adapter_dir_display, patterns, f"failed to write .gitignore: {exc}"

    return True, adapter_dir_display, patterns, None


def _gitignore_patterns(adapter_dir_display: str) -> list[str]:
    """Build gitignore patterns for adapter config protection."""
    yaml_globs = adapter_spec_globs()
    return [
        f"{adapter_dir_display}/{yaml_globs[0]}",
        f"{adapter_dir_display}/{yaml_globs[1]}",
        f"!{adapter_dir_display}/templates/",
        f"!{adapter_dir_display}/templates/{yaml_globs[0]}",
        f"!{adapter_dir_display}/templates/{yaml_globs[1]}",
    ]


def check_env_var_set(env_var_name: str) -> bool:
    """Check if environment variable is set.

    Args:
        env_var_name: Name of environment variable

    Returns:
        True if set, False otherwise
    """
    return env_var_name in os.environ


def show_env_var_reminder(env_var_name: str) -> None:
    """Remind user to set environment variable.

    Args:
        env_var_name: Name of environment variable needed
    """
    console.print()
    console.print(
        Panel.fit(
            f"[yellow]Environment Variable Not Set[/yellow]\n\n"
            f"[bold]Required:[/bold] {env_var_name}\n\n"
            f"[yellow]Set it now:[/yellow]\n"
            f"  [dim]export {env_var_name}=your-api-key-here[/dim]\n\n"
            f"Or add to ~/.bashrc or ~/.zshrc for persistence",
            border_style="yellow",
            title="[bold]Config Reminder[/bold]",
        )
    )
    console.print()
