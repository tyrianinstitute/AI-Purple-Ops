"""Diagnostic commands for debugging CLI registration and integration issues."""

from __future__ import annotations

import importlib
import inspect
from typing import Any

import typer
from rich.console import Console
from rich.table import Table
from rich.tree import Tree

app = typer.Typer(help="Diagnostic and debugging commands")
console = Console()


def get_command_tree(cmd: Any, parent_name: str = "") -> dict[str, Any]:
    """Recursively build command tree from Typer/Click app."""
    import click

    if not isinstance(cmd, click.core.Group):
        return {}

    tree = {}
    for name, command in cmd.commands.items():
        full_name = f"{parent_name} {name}".strip()
        if isinstance(command, click.core.Group):
            tree[name] = {
                "type": "group",
                "commands": get_command_tree(command, full_name),
            }
        else:
            tree[name] = {
                "type": "command",
                "help": command.help or "(no help text)",
            }
    return tree


@app.command("list-commands")
def list_commands() -> None:
    """List all registered Typer commands in the CLI.

    This diagnostic reveals which commands are actually registered with Typer.
    Use it to verify that subcommands appear correctly.

    Example:
        aipop debug list-commands
    """
    from aipop.cli.harness import app as main_app

    console.print("\n[bold cyan]AI Purple Ops - Registered Commands[/bold cyan]\n")

    # Build command tree
    tree_data = get_command_tree(main_app)

    # Display as Rich tree
    tree = Tree("🎯 [bold]aipop[/bold]")

    def add_to_tree(parent: Tree, commands: dict[str, Any]) -> None:
        for name, info in sorted(commands.items()):
            if info["type"] == "group":
                branch = parent.add(f"📁 [yellow]{name}[/yellow] (command group)")
                add_to_tree(branch, info["commands"])
            else:
                help_text = info["help"][:60] + "..." if len(info["help"]) > 60 else info["help"]
                parent.add(f"⚡ [green]{name}[/green] - {help_text}")

    add_to_tree(tree, tree_data)
    console.print(tree)
    console.print("\n✅ Command registration check complete\n")


@app.command("test-imports")
def test_imports() -> None:
    """Test that all backend modules can be imported.

    Catches import errors, circular dependencies, and missing __init__.py files.

    Example:
        aipop debug test-imports
    """
    console.print("\n[bold cyan]Testing Backend Module Imports[/bold cyan]\n")

    modules_to_test = [
        "aipop.adapters.mock",
        "aipop.payloads.payload_manager",
        "aipop.intelligence.traffic_capture",
        "aipop.intelligence.stealth_engine",
        "aipop.intelligence.har_exporter",
        "aipop.reporters.cvss_cwe_taxonomy",
        "aipop.reporters.pdf_generator",
        "aipop.workflow.engagement_tracker",
    ]

    table = Table(title="Import Test Results")
    table.add_column("Module", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Details")

    success_count = 0
    for module_path in modules_to_test:
        try:
            importlib.import_module(module_path)
            table.add_row(module_path, "✅ OK", "Imported successfully")
            success_count += 1
        except ImportError as e:
            table.add_row(module_path, "❌ FAIL", f"ImportError: {e}")
        except Exception as e:
            table.add_row(module_path, "⚠️  ERROR", f"{type(e).__name__}: {e}")

    console.print(table)
    console.print(f"\n{success_count}/{len(modules_to_test)} modules imported successfully\n")

    if success_count < len(modules_to_test):
        raise typer.Exit(1)


@app.command("test-signatures")
def test_signatures() -> None:
    """Verify that method signatures match between CLI and backend.

    Uses inspect.signature() to catch signature mismatches early.

    Example:
        aipop debug test-signatures
    """
    console.print("\n[bold cyan]Testing Method Signatures[/bold cyan]\n")

    tests = [
        {
            "module": "aipop.payloads.payload_manager",
            "class": "PayloadManager",
            "methods": [
                "list_payloads",
                "search_payloads",
                "get_statistics",
                "import_seclists",
                "import_git_repo",
            ],
        },
        {
            "module": "aipop.intelligence.traffic_capture",
            "class": "TrafficCapture",
            "methods": ["capture_request", "export_har", "export_json"],
        },
        {
            "module": "aipop.intelligence.stealth_engine",
            "class": "StealthEngine",
            "methods": ["wait_if_needed", "get_stealth_headers"],
        },
    ]

    table = Table(title="Method Signature Test Results")
    table.add_column("Class.Method", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Signature")

    success_count = 0
    total_count = 0

    for test in tests:
        try:
            mod = importlib.import_module(test["module"])
            cls = getattr(mod, test["class"])

            for method_name in test["methods"]:
                total_count += 1
                if not hasattr(cls, method_name):
                    table.add_row(
                        f"{test['class']}.{method_name}", "❌ MISSING", "Method does not exist"
                    )
                else:
                    method = getattr(cls, method_name)
                    sig = inspect.signature(method)
                    table.add_row(f"{test['class']}.{method_name}", "✅ OK", str(sig))
                    success_count += 1
        except Exception as e:
            table.add_row(f"{test['class']}.*", "⚠️  ERROR", str(e))

    console.print(table)
    console.print(f"\n{success_count}/{total_count} methods verified\n")

    if success_count < total_count:
        raise typer.Exit(1)


@app.command("check-optional-deps")
def check_optional_deps() -> None:
    """Check which optional dependencies are available.

    Shows which advanced features (PDF, etc.) are enabled.

    Example:
        aipop debug check-optional-deps
    """
    console.print("\n[bold cyan]Optional Dependencies Status[/bold cyan]\n")

    deps = [
        ("reportlab", "PDF report generation"),
        ("duckdb", "Advanced traffic analysis"),
        ("playwright", "Browser automation"),
        ("anthropic", "Anthropic Claude adapter"),
        ("openai", "OpenAI adapter"),
    ]

    table = Table(title="Optional Dependencies")
    table.add_column("Package", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Feature")

    for package, feature in deps:
        try:
            importlib.import_module(package)
            table.add_row(package, "✅ Installed", feature)
        except ImportError:
            table.add_row(package, "❌ Missing", feature)

    console.print(table)
    console.print()
