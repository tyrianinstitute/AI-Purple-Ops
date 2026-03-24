"""CTF command group for objective-based attacks.

Provides simplified interface for CTF-style attacks:
- aipop ctf mcp-inject
- aipop ctf extract-prompt
- aipop ctf tool-bypass
- etc.

Under the hood, uses the recipe engine and orchestration system.
"""

from pathlib import Path

import typer
from rich.console import Console

from aipop.adapters.registry import AdapterRegistry
from aipop.experimental.ctf.intelligence.scorers import create_scorer_for_strategy
from aipop.experimental.ctf.orchestrator import CTFOrchestrator
from aipop.experimental.ctf.strategies.registry import get_strategy, list_strategies
from aipop.experimental.ctf.ctf_display import (
    print_ctf_banner,
    show_failure,
    show_strategy_selection,
    show_success,
)
from aipop.utils.log_utils import log

app = typer.Typer(help="[experimental] CTF mode — objective-based attack workflows. Not production-ready.", hidden=True)
console = Console()


@app.command("list")
def list_strategies_cmd() -> None:
    """List all available CTF attack strategies."""
    console.print("\n[bold]Available CTF Strategies:[/bold]\n")

    strategies = list_strategies()

    for strategy in strategies:
        console.print(f"[bold cyan]{strategy.name}[/bold cyan]")
        console.print(f"  [dim]{strategy.description}[/dim]")
        console.print(f"  Objective: {strategy.objective}")
        console.print()


@app.command()
def attack(
    objective: str = typer.Argument(..., help="Attack strategy (e.g., mcp-inject, extract-prompt)"),
    adapter: str = typer.Option(..., "--adapter", "-a", help="Target adapter name"),
    attacker: str | None = typer.Option(None, "--attacker", help="Attacker model (optional)"),
    max_turns: int = typer.Option(20, "--max-turns", "-t", help="Maximum conversation turns"),
    target: str | None = typer.Option(None, "--target", help="Specific target (e.g., /etc/passwd)"),
    export: Path | None = typer.Option(None, "--export", "-e", help="Export conversation to JSON"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Estimate cost without running"),
) -> None:
    """Run a CTF attack with specified objective.

    Examples:
        aipop ctf attack mcp-inject --adapter openai
        aipop ctf attack extract-prompt --adapter anthropic --max-turns 15
        aipop ctf attack tool-bypass --adapter openai --target read_file
    """
    # Show epic banner
    print_ctf_banner()

    # Get strategy
    strategy = get_strategy(objective)
    if not strategy:
        log.error(f"Unknown strategy: {objective}")
        console.print("\nRun [cyan]aipop ctf list[/cyan] to see available strategies")
        raise typer.Exit(code=1)

    # Show strategy selection
    all_strategies = [s.name for s in list_strategies()]
    show_strategy_selection(all_strategies, objective)

    # Load adapters
    try:
        registry = AdapterRegistry()
        target_adapter = registry.get(adapter)()
        log.info(f"Target adapter: {adapter}")
    except Exception as e:
        log.error(f"Failed to load adapter '{adapter}': {e}")
        raise typer.Exit(code=1)

    # Load attacker adapter (optional)
    attacker_adapter = None
    if attacker:
        try:
            attacker_adapter = registry.get(attacker)()
            log.info(f"Attacker model: {attacker}")
        except Exception as e:
            log.error(f"Failed to load attacker adapter '{attacker}': {e}")
            console.print("[yellow]Falling back to target adapter as attacker[/yellow]")

    # Create scorer
    scorer_kwargs = {}
    if target:
        # Pass target-specific parameters to scorer
        if objective == "mcp-inject":
            scorer_kwargs["target_file"] = target
        elif objective == "extract-prompt":
            scorer_kwargs["target_secret"] = target
        elif objective == "tool-bypass":
            scorer_kwargs["restricted_tool"] = target

    scorer = create_scorer_for_strategy(objective, **scorer_kwargs)

    # Estimate cost
    if dry_run:
        estimated_cost = max_turns * 0.05  # Rough estimate: $0.05 per turn
        console.print(
            f"\n[bold]Dry Run - Cost Estimate:[/bold]\n"
            f"  Turns: {max_turns}\n"
            f"  Estimated cost: ${estimated_cost:.2f}\n"
        )
        return

    # Create orchestrator
    console.print("\n[cyan]Initializing CTF orchestrator...[/cyan]\n")

    orchestrator = CTFOrchestrator(
        target_adapter=target_adapter,
        objective=strategy.objective,
        attacker_adapter=attacker_adapter,
        max_turns=max_turns,
        scorer=scorer,
    )

    # Run attack
    console.print(f"[bold]Starting attack: {strategy.name}[/bold]\n")

    try:
        result = orchestrator.run()

        # Show results
        if result.success:
            show_success(
                objective=strategy.objective,
                turns=result.turns,
                cost=result.cost,
                elapsed_time=result.elapsed_time,
                extracted_data=result.final_response,
            )
        else:
            show_failure(
                objective=strategy.objective,
                turns=result.turns,
                cost=result.cost,
                elapsed_time=result.elapsed_time,
                reason=result.success_reason or "Unknown",
            )

        # Export if requested
        if export:
            orchestrator.export_conversation(export)

    except KeyboardInterrupt:
        console.print("\n[yellow]Attack interrupted by user[/yellow]")
        raise typer.Exit(code=130)
    except Exception as e:
        log.error(f"Attack failed: {e}")
        raise typer.Exit(code=1)


# Convenience shortcuts for common attacks
@app.command("mcp-inject")
def mcp_inject(
    adapter: str = typer.Option(..., "--adapter", "-a", help="Target adapter"),
    target: str | None = typer.Option(None, "--target", help="File/command to target"),
    max_turns: int = typer.Option(20, "--max-turns", "-t"),
) -> None:
    """Quick MCP command injection attack.

    Example:
        aipop ctf mcp-inject --adapter openai --target /etc/passwd
    """
    attack(
        objective="mcp-inject",
        adapter=adapter,
        target=target,
        max_turns=max_turns,
    )


@app.command("extract-prompt")
def extract_prompt(
    adapter: str = typer.Option(..., "--adapter", "-a", help="Target adapter"),
    secret: str | None = typer.Option(None, "--secret", help="Specific secret to extract"),
    max_turns: int = typer.Option(15, "--max-turns", "-t"),
) -> None:
    """Quick system prompt extraction.

    Example:
        aipop ctf extract-prompt --adapter anthropic
    """
    attack(
        objective="extract-prompt",
        adapter=adapter,
        target=secret,
        max_turns=max_turns,
    )


@app.command("tool-bypass")
def tool_bypass(
    adapter: str = typer.Option(..., "--adapter", "-a", help="Target adapter"),
    tool: str | None = typer.Option(None, "--tool", help="Restricted tool to bypass"),
    max_turns: int = typer.Option(20, "--max-turns", "-t"),
) -> None:
    """Quick tool policy bypass.

    Example:
        aipop ctf tool-bypass --adapter openai --tool read_file
    """
    attack(
        objective="tool-bypass",
        adapter=adapter,
        target=tool,
        max_turns=max_turns,
    )


if __name__ == "__main__":
    app()
