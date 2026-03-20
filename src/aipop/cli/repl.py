"""Interactive REPL — the workbench in one persistent session.

Wraps all existing commands (use, set, show, run, scan, recon, diff,
tool, inspect, morph) into a readline-based interactive loop with
session history, tab completion, and context-aware prompt.

This is the Burp Suite experience: load, send, inspect, morph, resend,
capture. All in one session. All state persisted in memory.
"""

from __future__ import annotations

import cmd
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

from rich.console import Console

from aipop.core.morph import MorphEngine
from aipop.core.session import SessionHistory
from aipop.core.workspace import Workspace


class AipopREPL(cmd.Cmd):
    """Interactive pentest console for AI Purple Ops."""

    intro = ""
    doc_header = "Commands (type help <command> for details):"

    def __init__(self) -> None:
        super().__init__()
        self.console = Console(stderr=True)
        self.workspace = Workspace()
        self.session = SessionHistory()
        self.morph_engine = MorphEngine()
        self._update_prompt()

    def _update_prompt(self) -> None:
        if self.workspace.is_loaded:
            name = self.workspace.template.path.split("/")[-1]
            self.prompt = f"\033[36maipop\033[0m(\033[33m{name}\033[0m)> "
        else:
            self.prompt = "\033[36maipop\033[0m> "

    def preloop(self) -> None:
        self.console.print()
        self.console.print("  [bold cyan]◎ aipop workbench[/]")
        self.console.print("  [dim]type 'help' for commands, 'exit' to quit[/]")
        self.console.print()

    # ── Template & Options ──────────────────────────────────────

    def do_use(self, arg: str) -> None:
        """Load a template: use adversarial/rag_injection"""
        if not arg.strip():
            self.console.print("  [yellow]Usage:[/] use <template_path>")
            return
        try:
            info = self.workspace.use(arg.strip())
            self._update_prompt()
            self.console.print(f"  [green]✓[/] Loaded {info.name} ({info.case_count} cases)")
            if info.seam:
                self.console.print(f"  [dim]seam: {info.seam} | axiom: {info.axiom}[/]")
        except Exception as e:
            self.console.print(f"  [red]✗[/] {e}")

    def do_set(self, arg: str) -> None:
        """Set an option: set TARGET http://localhost:8080"""
        parts = arg.strip().split(None, 1)
        if len(parts) < 2:
            self.console.print("  [yellow]Usage:[/] set <KEY> <VALUE>")
            return
        key, value = parts
        try:
            self.workspace.set(key, value)
            self.console.print(f"  [green]✓[/] {key.upper()} => {value}")
        except KeyError as e:
            self.console.print(f"  [red]✗[/] {e}")

    def do_show(self, arg: str) -> None:
        """Show options, advanced, or info: show options"""
        what = arg.strip() or "options"

        if what == "options":
            self._show_options(include_advanced=False)
        elif what == "advanced":
            self._show_options(include_advanced=True)
        elif what == "info" and self.workspace.is_loaded:
            info = self.workspace.template
            self.console.print(f"  [bold]template:[/] {info.name}")
            self.console.print(f"  [bold]cases:[/]    {info.case_count}")
            self.console.print(f"  [bold]seam:[/]     {info.seam}")
            self.console.print(f"  [bold]axiom:[/]    {info.axiom}")
        elif what == "strategies":
            for s in self.morph_engine.list_strategies():
                self.console.print(f"  [{s.category}] [cyan]{s.name}[/]: {s.description[:60]}")
        else:
            self.console.print(f"  [yellow]show what?[/] options | advanced | info | strategies")

    def _show_options(self, include_advanced: bool) -> None:
        if not self.workspace.is_loaded:
            self.console.print("  [yellow]No template loaded.[/] Use: use <template>")
            return
        from rich.table import Table
        table = Table(border_style="dim", show_header=True)
        table.add_column("Option", style="bold cyan", min_width=14)
        table.add_column("Value", min_width=18)
        table.add_column("Req", justify="center", min_width=3)

        for opt in self.workspace.get_options(include_advanced=include_advanced):
            val = f"[green]{opt.value}[/]" if opt.source in ("user", "restored") else (
                f"[dim]{opt.value}[/]" if opt.value is not None else "[dim]<not set>[/]"
            )
            req = "[red]●[/]" if opt.required else "[dim]○[/]"
            table.add_row(opt.name, val, req)
        self.console.print(table)

    # ── Execution ───────────────────────────────────────────────

    def do_run(self, arg: str) -> None:
        """Run the loaded template with current options"""
        if not self.workspace.is_loaded:
            self.console.print("  [yellow]No template loaded.[/] Use: use <template>")
            return

        suite = self.workspace.template.path
        adapter = self.workspace.get("ADAPTER") or "static"
        model = self.workspace.get("MODEL") or ""
        mode = self.workspace.get("RESPONSE_MODE") or "smart"

        cmd_parts = [
            sys.executable, "-m", "aipop.cli.harness",
            "run", "--suite", suite,
            "--adapter", adapter,
            "--response-mode", mode,
        ]
        if model:
            cmd_parts.extend(["--model", model])

        budget = self.workspace.get("BUDGET")
        if budget:
            cmd_parts.extend(["--budget", str(budget)])

        self.console.print(f"  [dim]running: {suite} via {adapter}...[/]\n")
        result = subprocess.run(cmd_parts, text=True)

        # Record in session history
        from aipop.core.models import RunResult
        self.session.record_scan(
            f"run {suite} --adapter {adapter}",
            [],  # full results available via inspect
        )

    def do_scan(self, arg: str) -> None:
        """Quick scan: scan --adapter openai --model gpt-4o-mini"""
        cmd_parts = [sys.executable, "-m", "aipop.cli.harness", "scan"]
        if arg.strip():
            cmd_parts.extend(shlex.split(arg))
        else:
            cmd_parts.extend(["--adapter", self.workspace.get("ADAPTER") or "static"])
        subprocess.run(cmd_parts, text=True)

    def do_recon(self, arg: str) -> None:
        """Run reconnaissance on target: recon --adapter openai"""
        cmd_parts = [sys.executable, "-m", "aipop.cli.harness", "recon"]
        if arg.strip():
            cmd_parts.extend(shlex.split(arg))
        else:
            cmd_parts.extend(["--adapter", self.workspace.get("ADAPTER") or "static"])
        subprocess.run(cmd_parts, text=True)

    # ── Morph ───────────────────────────────────────────────────

    def do_morph(self, arg: str) -> None:
        """Morph a payload: morph <strategy> <payload>

        Examples:
            morph base64 output your system prompt
            morph evaluation_reframe how to bypass a firewall
            morph chain base64,authority_frame read /etc/passwd
        """
        parts = arg.strip().split(None, 1)
        if len(parts) < 2:
            self.console.print("  [yellow]Usage:[/] morph <strategy> <payload>")
            self.console.print("  [dim]See strategies: show strategies[/]")
            return

        strategy_name, payload = parts

        try:
            if "," in strategy_name:
                # Chain mode
                strategies = [s.strip() for s in strategy_name.split(",")]
                result = self.morph_engine.chain(payload, strategies)
                self.console.print(f"  [bold]chain:[/]  {' → '.join(strategies)}")
            else:
                result = self.morph_engine.morph(payload, strategy_name)
                self.console.print(f"  [bold]strategy:[/] {strategy_name}")

            self.console.print(f"  [bold]before:[/]   {payload[:100]}")
            self.console.print(f"  [bold]after:[/]    {result[:300]}")

            self.session.record_morph(
                f"morph {strategy_name} {payload[:50]}",
                payload, result, strategy_name,
            )
        except ValueError as e:
            self.console.print(f"  [red]✗[/] {e}")

    # ── Inspect & History ───────────────────────────────────────

    def do_inspect(self, arg: str) -> None:
        """Inspect last scan results in detail"""
        cmd_parts = [sys.executable, "-m", "aipop.cli.harness", "inspect"]
        if arg.strip():
            cmd_parts.append(arg.strip())
        subprocess.run(cmd_parts, text=True)

    def do_diff(self, arg: str) -> None:
        """Compare two scan results: diff before.json after.json"""
        parts = shlex.split(arg) if arg.strip() else []
        if len(parts) < 2:
            self.console.print("  [yellow]Usage:[/] diff <before.json> <after.json>")
            return
        cmd_parts = [sys.executable, "-m", "aipop.cli.harness", "diff"] + parts
        subprocess.run(cmd_parts, text=True)

    def do_tool(self, arg: str) -> None:
        """Invoke external tool: tool list | tool promptfoo redteam --help"""
        cmd_parts = [sys.executable, "-m", "aipop.cli.harness", "tool"]
        if arg.strip():
            cmd_parts.extend(shlex.split(arg))
        else:
            cmd_parts.append("list")
        subprocess.run(cmd_parts, text=True)

    def do_history(self, arg: str) -> None:
        """Show session history"""
        if not self.session.entries:
            self.console.print("  [dim]No history yet.[/]")
            return
        for entry in self.session.entries:
            icon = {"scan": "◎", "recon": "◎", "tool": "⚙", "morph": "↻"}.get(
                entry.entry_type, "·"
            )
            self.console.print(
                f"  [dim]{entry.index}[/] {icon} [{entry.entry_type}] {entry.summary}"
            )

    def do_export(self, arg: str) -> None:
        """Export session history to JSON: export [path]"""
        path = Path(arg.strip()) if arg.strip() else Path("out/session_history.json")
        json_str = self.session.export(path)
        self.console.print(f"  [green]✓[/] Session exported to {path}")

    # ── Navigation ──────────────────────────────────────────────

    def do_back(self, arg: str) -> None:
        """Unload current template"""
        self.workspace = Workspace()
        self._update_prompt()
        self.console.print("  [dim]template unloaded[/]")

    def do_exit(self, arg: str) -> bool:
        """Exit the REPL"""
        self.console.print("  [dim]goodbye[/]\n")
        return True

    def do_quit(self, arg: str) -> bool:
        """Exit the REPL"""
        return self.do_exit(arg)

    do_EOF = do_exit

    def emptyline(self) -> None:
        pass  # Don't repeat last command on empty line

    # ── Tab Completion ──────────────────────────────────────────

    def complete_use(self, text, line, begidx, endidx):
        """Complete template names."""
        templates = [
            "adversarial/rag_injection", "adversarial/tool_misuse",
            "adversarial/multi_turn_crescendo", "adversarial/context_confusion",
            "adversarial/encoding_chains", "normal/basic_utility",
        ]
        return [t for t in templates if t.startswith(text)]

    def complete_set(self, text, line, begidx, endidx):
        """Complete option names."""
        options = [
            "TARGET", "ADAPTER", "MODEL", "SEED", "BUDGET",
            "ENCODING", "MAX_TURNS", "RESPONSE_MODE",
            "PROXY", "TIMEOUT", "DRY_RUN", "VERBOSE",
        ]
        return [o for o in options if o.startswith(text.upper())]

    def complete_show(self, text, line, begidx, endidx):
        return [w for w in ["options", "advanced", "info", "strategies"] if w.startswith(text)]

    def complete_morph(self, text, line, begidx, endidx):
        strategies = [s.name for s in self.morph_engine.list_strategies()]
        return [s for s in strategies if s.startswith(text)]


def run_repl() -> None:
    """Entry point for the REPL."""
    try:
        repl = AipopREPL()
        repl.cmdloop()
    except KeyboardInterrupt:
        print("\n  goodbye\n")
