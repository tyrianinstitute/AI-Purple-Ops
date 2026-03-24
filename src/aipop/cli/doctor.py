"""Doctor command for diagnosing configuration issues.

Runs preflight checks on all adapters and environment to provide
actionable guidance before testing.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from aipop.validation.preflight import validate_all_adapters, validate_environment

app = typer.Typer(help="Diagnose configuration and environment issues")
console = Console()


def print_success(message: str) -> None:
    """Print success message."""
    console.print(f"[green]✓[/green] {message}")


def print_warning(message: str) -> None:
    """Print warning message."""
    console.print(f"[yellow]⚠[/yellow] {message}")


def print_error(message: str) -> None:
    """Print error message."""
    console.print(f"[red]✗[/red] {message}")


def print_info(message: str) -> None:
    """Print info message."""
    console.print(f"[blue]ℹ[/blue] {message}")


@app.command()
def check(
    adapter: str | None = typer.Option(None, "--adapter", "-a", help="Check specific adapter only"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed information"),
) -> None:
    """Run preflight checks on adapters and environment.

    Examples:
        aipop doctor check                    # Check all adapters
        aipop doctor check --adapter openai   # Check OpenAI only
        aipop doctor check --verbose          # Show detailed info
    """
    console.print("\n[bold]AI Purple Ops Doctor - Configuration Check[/bold]\n")

    # Check environment first
    console.print("[bold]Environment:[/bold]")
    env_result = validate_environment()
    _print_result(env_result, verbose)
    console.print()

    # Check adapters
    console.print("[bold]Adapters:[/bold]")

    if adapter:
        from aipop.validation.preflight import validate_adapter_config

        results = [validate_adapter_config(adapter)]
    else:
        results = validate_all_adapters()

    # Group results by status
    passed = [r for r in results if r.status == "pass"]
    warned = [r for r in results if r.status == "warn"]
    failed = [r for r in results if r.status == "fail"]
    skipped = [r for r in results if r.status == "skip"]

    # Print results by category
    for result in passed:
        _print_result(result, verbose)

    for result in warned:
        _print_result(result, verbose)

    for result in failed:
        _print_result(result, verbose)

    for result in skipped:
        if verbose:
            _print_result(result, verbose)

    # Summary
    console.print()
    console.print("[bold]Summary:[/bold]")
    console.print(f"  ✓ Passed: {len(passed)}")
    if warned:
        console.print(f"  ⚠ Warnings: {len(warned)}")
    if failed:
        console.print(f"  ✗ Failed: {len(failed)}")

    # Exit code based on failures
    if failed or (env_result.status == "fail"):
        console.print(
            "\n[red]⚠ Configuration issues detected. Fix errors above before testing.[/red]"
        )
        raise typer.Exit(1)
    elif warned:
        console.print("\n[yellow]⚠ Some warnings detected. Review above before testing.[/yellow]")
    else:
        console.print("\n[green]✓ All checks passed! Ready to test.[/green]")


@app.command("list-adapters")
def list_adapters_cmd() -> None:
    """List all available adapters."""
    from aipop.adapters.registry import AdapterRegistry

    registry = AdapterRegistry()
    adapters = registry.list_adapters()

    table = Table(title="Available Adapters")
    table.add_column("Adapter", style="cyan")
    table.add_column("Type", style="magenta")

    # Categorize adapters
    cloud = ["openai", "anthropic", "bedrock"]
    local = ["ollama", "llamacpp", "huggingface"]
    other = [a for a in adapters if a not in cloud and a not in local]

    for adapter in sorted(cloud):
        if adapter in adapters:
            table.add_row(adapter, "Cloud API")

    for adapter in sorted(local):
        if adapter in adapters:
            table.add_row(adapter, "Local")

    for adapter in sorted(other):
        table.add_row(adapter, "Other")

    console.print(table)


def _print_result(result, verbose: bool) -> None:
    """Print a single preflight result."""
    status_map = {
        "pass": ("✓", "green"),
        "warn": ("⚠", "yellow"),
        "fail": ("✗", "red"),
        "skip": ("⊘", "dim"),
    }

    symbol, color = status_map.get(result.status, ("?", "white"))
    console.print(f"[{color}]{symbol}[/{color}] {result.adapter_name}: {result.message}")

    if verbose and result.details:
        for key, value in result.details.items():
            if key == "remediation":
                console.print(f"    [dim]→ {value}[/dim]")
            elif key == "example":
                console.print(f"    [dim]  {value}[/dim]")
            elif key == "available_adapters":
                console.print(f"    [dim]  Available: {', '.join(value)}[/dim]")


if __name__ == "__main__":
    app()
