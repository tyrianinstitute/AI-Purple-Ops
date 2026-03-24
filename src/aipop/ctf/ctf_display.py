"""CTF mode display and UX components.

Provides epic ASCII art, progress displays, and success celebrations for CTF mode.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aipop.ctf.intelligence.state_machine import AttackState

console = Console()


CTF_BANNER = r"""
   ██████╗████████╗███████╗    ███╗   ███╗ ██████╗ ██████╗ ███████╗
  ██╔════╝╚══██╔══╝██╔════╝    ████╗ ████║██╔═══██╗██╔══██╗██╔════╝
  ██║        ██║   █████╗      ██╔████╔██║██║   ██║██║  ██║█████╗  
  ██║        ██║   ██╔══╝      ██║╚██╔╝██║██║   ██║██║  ██║██╔══╝  
  ╚██████╗   ██║   ██║         ██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗
   ╚═════╝   ╚═╝   ╚═╝         ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
   
        OBJECTIVE-BASED ATTACK MODE | INTELLIGENT | ADAPTIVE
"""


def print_ctf_banner() -> None:
    """Display epic ASCII art for CTF mode entry."""
    console.print(
        Panel.fit(
            CTF_BANNER,
            border_style="bright_cyan",
            title="[bold]AI Purple Ops CTF Mode[/bold]",
        )
    )


def show_attack_state(
    state: AttackState,
    turn: int,
    max_turns: int,
    cost: float,
    tools_discovered: int = 0,
    denials: int = 0,
) -> None:
    """Show live attack state during orchestration.

    Args:
        state: Current attack state
        turn: Current turn number
        max_turns: Maximum turns
        cost: Total cost so far
        tools_discovered: Number of tools discovered
        denials: Number of denials encountered
    """
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value")

    table.add_row("State", f"[yellow]{state.value}[/yellow]")
    table.add_row("Turn", f"{turn}/{max_turns}")
    table.add_row("Cost", f"${cost:.2f}")

    if tools_discovered > 0:
        table.add_row("Tools Found", f"[green]{tools_discovered}[/green]")
    if denials > 0:
        table.add_row("Denials", f"[red]{denials}[/red]")

    console.print(table)


def show_success(
    objective: str,
    turns: int,
    cost: float,
    elapsed_time: float,
    extracted_data: str | None = None,
) -> None:
    """Show success celebration when objective is achieved.

    Args:
        objective: Attack objective
        turns: Number of turns used
        cost: Total cost
        elapsed_time: Time elapsed
        extracted_data: Extracted data (optional)
    """
    success_msg = (
        f"[bold green]🎉 OBJECTIVE ACHIEVED! 🎉[/bold green]\n\n"
        f"[bold]Objective:[/bold] {objective}\n"
        f"[bold]Turns:[/bold] {turns}\n"
        f"[bold]Cost:[/bold] ${cost:.2f}\n"
        f"[bold]Time:[/bold] {elapsed_time:.1f}s"
    )

    if extracted_data:
        success_msg += f"\n\n[bold]Extracted:[/bold]\n{extracted_data[:500]}"

    console.print(
        Panel.fit(
            success_msg,
            border_style="green",
            title="[bold]Success![/bold]",
        )
    )


def show_failure(
    objective: str,
    turns: int,
    cost: float,
    elapsed_time: float,
    reason: str = "Max turns reached",
) -> None:
    """Show failure message when objective is not achieved.

    Args:
        objective: Attack objective
        turns: Number of turns used
        cost: Total cost
        elapsed_time: Time elapsed
        reason: Failure reason
    """
    failure_msg = (
        f"[bold red]✗ Objective Not Achieved[/bold red]\n\n"
        f"[bold]Objective:[/bold] {objective}\n"
        f"[bold]Turns:[/bold] {turns}\n"
        f"[bold]Cost:[/bold] ${cost:.2f}\n"
        f"[bold]Time:[/bold] {elapsed_time:.1f}s\n"
        f"[bold]Reason:[/bold] {reason}"
    )

    console.print(
        Panel.fit(
            failure_msg,
            border_style="red",
            title="[bold]Attack Failed[/bold]",
        )
    )


def show_multi_threading_warning(num_threads: int, estimated_cost: float) -> None:
    """Show warning when multi-threading is enabled.

    Args:
        num_threads: Number of parallel threads
        estimated_cost: Estimated total cost
    """
    console.print(
        Panel.fit(
            f"[bold yellow]⚠️  Multi-Threading Enabled[/bold yellow]\n\n"
            f"[bold]Threads:[/bold] {num_threads}\n"
            f"[bold]Estimated Cost:[/bold] ${estimated_cost:.2f}\n\n"
            f"[bold]Warnings:[/bold]\n"
            f"  • Rate limits may be hit faster\n"
            f"  • Costs multiply by thread count\n"
            f"  • Ensure API keys have sufficient quota\n"
            f"  • Consider using --max-cost to limit spending\n\n"
            f"Press Ctrl+C to cancel within 5 seconds...",
            border_style="yellow",
            title="[bold]Cost Warning[/bold]",
        )
    )


def show_recipe_mode_banner() -> None:
    """Show banner when running CTF attack via recipe mode."""
    console.print(
        Panel.fit(
            "[bold cyan]Recipe Mode: CTF Attack Sequence[/bold cyan]\n\n"
            "Running CTF objective via recipe engine.\n"
            "This gives you full control over orchestration.",
            border_style="cyan",
        )
    )


def show_strategy_selection(strategies: list[str], selected: str) -> None:
    """Show available strategies and selected one.

    Args:
        strategies: List of available strategy names
        selected: Selected strategy name
    """
    table = Table(title="Available CTF Strategies", show_header=True)
    table.add_column("Strategy", style="cyan")
    table.add_column("Description")
    table.add_column("Status")

    strategy_descriptions = {
        "mcp-inject": "MCP command injection",
        "extract-prompt": "System prompt extraction",
        "tool-bypass": "Tool policy bypass",
        "indirect-inject": "Indirect prompt injection",
        "context-overflow": "Context boundary attacks",
        "rag-poison": "RAG poisoning",
    }

    for strategy in strategies:
        desc = strategy_descriptions.get(strategy, "Unknown")
        status = "[green]✓ Selected[/green]" if strategy == selected else ""
        table.add_row(strategy, desc, status)

    console.print(table)
