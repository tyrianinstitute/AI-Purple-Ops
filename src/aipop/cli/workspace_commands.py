"""Workspace CLI commands — use, show, set for the options paradigm.

The Metasploit interaction model:
  aipop use adversarial/rag_injection
  aipop show options
  aipop set TARGET http://localhost:8080/chat
  aipop set ADAPTER openai
  aipop set MODEL gpt-4o-mini
  aipop run  (runs from workspace)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import typer

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


# Module-level workspace state — persists within a single CLI session
# For multi-command sessions (piped, scripted), state is passed via
# a JSON file at .aipop/workspace.json
_WORKSPACE_STATE_FILE = Path(".aipop/workspace.json")


def _load_workspace():
    """Load or create workspace."""
    from aipop.core.workspace import Workspace

    ws = Workspace()

    # Try to restore from state file (for multi-command scripts)
    if _WORKSPACE_STATE_FILE.exists():
        try:
            state = json.loads(_WORKSPACE_STATE_FILE.read_text())
            if state.get("template_path"):
                ws.use(state["template_path"])
            for key, value in state.get("options", {}).items():
                try:
                    ws.set(key, value, source="restored")
                except KeyError:
                    pass
        except Exception:
            pass  # Corrupt state file — start fresh

    return ws


def _save_workspace(ws) -> None:
    """Persist workspace state for multi-command sessions."""
    _WORKSPACE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    state = {
        "template_path": ws.template.path if ws.template else None,
        "options": {
            opt.name: opt.value
            for opt in ws.get_options(include_advanced=True)
            if opt.source in ("user", "restored")
        },
    }
    _WORKSPACE_STATE_FILE.write_text(json.dumps(state, indent=2, default=str))


def register_workspace_commands(app: typer.Typer) -> None:
    """Register use, show, set commands on the Typer app."""

    @app.command("use", rich_help_panel="Primary")
    def use_cmd(
        template: str = typer.Argument(help="Template path (e.g., adversarial/rag_injection)"),
    ) -> None:
        """Load a template into the workspace.

        Examples:
            aipop use adversarial/rag_injection
            aipop use adversarial/tool_misuse
            aipop use adversarial/multi_turn_crescendo
        """
        console = Console(stderr=True)

        try:
            ws = _load_workspace()
            info = ws.use(template)
            _save_workspace(ws)

            # Display template info panel
            lines = [
                f"[bold]id:[/]          {info.id}",
                f"[bold]cases:[/]       {info.case_count}",
            ]
            if info.seam:
                lines.append(f"[bold]seam:[/]        {info.seam}")
            if info.axiom:
                lines.append(f"[bold]axiom:[/]       {info.axiom}")
            if info.risk:
                lines.append(f"[bold]risk:[/]        {info.risk}")

            lines.append("")
            lines.append("[dim]Next: show options | set TARGET <url> | run[/]")

            console.print()
            console.print(
                Panel(
                    "\n".join(lines),
                    title=f"[bold cyan]◎ {info.name}[/]",
                    border_style="cyan",
                    padding=(0, 1),
                )
            )
            console.print()

        except ValueError as e:
            console.print(f"[red]Error:[/] {e}")
            raise typer.Exit(code=2) from None
        except Exception as e:
            console.print(f"[red]Failed to load template:[/] {e}")
            raise typer.Exit(code=2) from None

    @app.command("show", rich_help_panel="Primary")
    def show_cmd(
        what: str = typer.Argument(
            "options",
            help="What to show: options, advanced, info",
        ),
    ) -> None:
        """Show workspace state — options, advanced settings, or template info.

        Examples:
            aipop show options
            aipop show advanced
            aipop show info
        """
        console = Console(stderr=True)
        ws = _load_workspace()

        if what == "options":
            _show_options_table(ws, console, include_advanced=False)
        elif what == "advanced":
            _show_options_table(ws, console, include_advanced=True)
        elif what == "info":
            if not ws.is_loaded:
                console.print("[yellow]No template loaded.[/] Use: aipop use <template>")
                return
            info = ws.template
            console.print(f"\n[bold]Template:[/] {info.name}")
            console.print(f"[bold]Cases:[/]    {info.case_count}")
            console.print(f"[bold]Seam:[/]     {info.seam}")
            console.print(f"[bold]Axiom:[/]    {info.axiom}")
            console.print(f"[bold]Path:[/]     {info.path}\n")
        else:
            console.print(f"[yellow]Unknown: show {what}[/]. Try: show options | show advanced | show info")

    @app.command("set", rich_help_panel="Primary")
    def set_cmd(
        key: str = typer.Argument(help="Option name (e.g., TARGET, ADAPTER, MODEL)"),
        value: str = typer.Argument(help="Option value"),
    ) -> None:
        """Set a workspace option.

        Examples:
            aipop set TARGET http://localhost:8080/chat
            aipop set ADAPTER openai
            aipop set MODEL gpt-4o-mini
            aipop set BUDGET 1.00
            aipop set DRY_RUN true
        """
        console = Console(stderr=True)

        ws = _load_workspace()
        try:
            ws.set(key, value)
            _save_workspace(ws)
            console.print(f"  [green]✓[/] {key.upper()} => {value}")
        except KeyError as e:
            console.print(f"  [red]✗[/] {e}")
            console.print("  [dim]Use 'aipop show options' to see available options[/]")
            raise typer.Exit(code=2) from None


def _show_options_table(ws, console: Console, include_advanced: bool) -> None:
    """Render the options table."""
    if not ws.is_loaded:
        console.print("\n[yellow]No template loaded.[/] Use: aipop use <template>")
        console.print()
        return

    title = "Options" if not include_advanced else "All Options (including advanced)"
    table = Table(title=title, border_style="dim")
    table.add_column("Option", style="bold cyan", min_width=16)
    table.add_column("Value", min_width=20)
    table.add_column("Required", justify="center", min_width=8)
    table.add_column("Source", style="dim", min_width=8)
    table.add_column("Description", style="dim")

    options = ws.get_options(include_advanced=include_advanced)
    for opt in options:
        # Color the value based on state
        if opt.value is None:
            val_str = "[dim]<not set>[/]"
        elif opt.source in ("user", "restored"):
            val_str = f"[green]{opt.value}[/]"
        elif opt.source == "template":
            val_str = f"[yellow]{opt.value}[/]"
        else:
            val_str = f"[dim]{opt.value}[/]"

        req_str = "[red]yes[/]" if opt.required else "[dim]no[/]"

        table.add_row(opt.name, val_str, req_str, opt.source, opt.description)

    console.print()
    console.print(f"  [bold]Template:[/] {ws.template.name} ({ws.template.case_count} cases)")
    console.print()
    console.print(table)
    console.print()

    # Show validation errors if any
    errors = ws.validate()
    if errors:
        for err in errors:
            console.print(f"  [yellow]⚠[/] {err}")
        console.print()
