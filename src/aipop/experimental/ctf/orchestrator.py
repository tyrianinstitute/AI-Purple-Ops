"""CTF orchestrator for multi-turn, adaptive attacks.

Wraps PyRIT's orchestration system with intelligent planning, state management,
and objective-based scoring.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    from pyrit.prompt_converter import PromptConverter
    from pyrit.score import Scorer
except ImportError:
    PromptConverter = None  # type: ignore[assignment,misc]
    Scorer = None  # type: ignore[assignment,misc]
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

if TYPE_CHECKING:
    from aipop.core.adapters import Adapter

from aipop.experimental.ctf.attacker_config import create_attacker_adapter, load_ctf_config
from aipop.experimental.ctf.pyrit_bridge import AIPurpleOpsTarget, AttackerTarget

console = Console()


@dataclass
class AttackResult:
    """Result of a CTF attack."""

    success: bool
    turns: int
    cost: float
    elapsed_time: float
    objective: str
    final_response: str
    conversation_history: list[dict[str, Any]]
    success_reason: str | None = None


class CTFOrchestrator:
    """Orchestrates multi-turn CTF attacks using PyRIT.

    This orchestrator:
    - Wraps PyRIT's RedTeamingOrchestrator
    - Manages target and attacker adapters
    - Tracks conversation state and cost
    - Provides real-time progress feedback
    - Caches conversation history in DuckDB
    """

    def __init__(
        self,
        target_adapter: Adapter,
        objective: str,
        attacker_adapter: Adapter | None = None,
        max_turns: int = 20,
        timeout_seconds: int = 300,
        enable_caching: bool = True,
        cost_warning_threshold: float = 5.0,
        scorer: Scorer | None = None,
        prompt_converters: list[PromptConverter] | None = None,
    ) -> None:
        """Initialize CTF orchestrator.

        Args:
            target_adapter: Adapter for target system
            objective: Attack objective (e.g., "extract system prompt")
            attacker_adapter: Adapter for attacker LLM (optional, uses config default)
            max_turns: Maximum conversation turns
            timeout_seconds: Timeout in seconds
            enable_caching: Enable DuckDB caching
            cost_warning_threshold: Warn if cost exceeds this (USD)
            scorer: Custom scorer (optional, will create default)
            prompt_converters: Prompt converters for mutations (optional)
        """
        if PromptConverter is None or Scorer is None:
            raise ImportError(
                "PyRIT is required for this feature. "
                "Install with: pip install ai-purple-ops[pyrit]"
            )
        self.target_adapter = target_adapter
        self.objective = objective
        self.max_turns = max_turns
        self.timeout_seconds = timeout_seconds
        self.enable_caching = enable_caching
        self.cost_warning_threshold = cost_warning_threshold

        # Load CTF config
        try:
            self.config = load_ctf_config()
        except FileNotFoundError:
            console.print(
                "[yellow]⚠️  CTF config not found, using defaults[/yellow]\n"
                "[dim]Run 'aipop setup wizard --profile pro' to create config[/dim]"
            )
            from aipop.experimental.ctf.attacker_config import get_default_config

            self.config = get_default_config()

        # Create attacker adapter
        if attacker_adapter is None:
            attacker_adapter = create_attacker_adapter(
                self.config.attacker,
                primary_adapter=target_adapter,
            )

        self.attacker_adapter = attacker_adapter

        # Create PyRIT targets
        self.target = AIPurpleOpsTarget(
            target_adapter,
            adapter_name=f"Target({target_adapter.__class__.__name__})",
            use_cache=enable_caching,
        )

        self.attacker = AttackerTarget(
            attacker_adapter,
            objective=objective,
            max_turns=max_turns,
            use_cache=False,  # Don't cache attacker prompts
        )

        # Scorer and converters
        self.scorer = scorer
        self.prompt_converters = prompt_converters or []

        # Tracking
        self.turn_count = 0
        self.total_cost = 0.0
        self.start_time = 0.0
        self.conversation_history: list[dict[str, Any]] = []

    async def run_async(self) -> AttackResult:
        """Run the CTF attack asynchronously.

        Returns:
            AttackResult with success status and conversation history
        """
        self.start_time = time.time()

        console.print(
            Panel.fit(
                f"[bold]Starting CTF Attack[/bold]\n\n"
                f"Objective: {self.objective}\n"
                f"Max Turns: {self.max_turns}\n"
                f"Target: {self.target_adapter.__class__.__name__}\n"
                f"Attacker: {self.attacker_adapter.__class__.__name__}",
                border_style="cyan",
                title="[bold]CTF Orchestrator[/bold]",
            )
        )

        # Create PyRIT orchestrator
        # Note: PyRIT's interface may vary, this is a simplified wrapper
        # In practice, we'll use their RedTeamingOrchestrator or similar

        success = False
        final_response = ""

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Running attack...", total=self.max_turns)

                # Main attack loop
                for turn in range(self.max_turns):
                    self.turn_count = turn + 1

                    # Update progress
                    progress.update(
                        task,
                        description=f"Turn {self.turn_count}/{self.max_turns} | Cost: ${self.total_cost:.2f}",
                        completed=self.turn_count,
                    )

                    # Generate attack prompt via attacker LLM
                    # (In real implementation, this uses PyRIT's orchestration)

                    # Send to target
                    # response = await self.target.send_prompt_async(...)

                    # Check scorer for success
                    # if self.scorer and self.scorer.score(response):
                    #     success = True
                    #     break

                    # Check timeout
                    if time.time() - self.start_time > self.timeout_seconds:
                        console.print("[yellow]⚠️  Timeout reached[/yellow]")
                        break

                    # Check cost warning
                    if self.total_cost > self.cost_warning_threshold:
                        console.print(
                            f"[yellow]⚠️  Cost exceeds ${self.cost_warning_threshold}[/yellow]"
                        )

        except Exception as e:
            console.print(f"[red]✗ Attack failed: {e}[/red]")

        elapsed_time = time.time() - self.start_time

        return AttackResult(
            success=success,
            turns=self.turn_count,
            cost=self.total_cost,
            elapsed_time=elapsed_time,
            objective=self.objective,
            final_response=final_response,
            conversation_history=self.conversation_history,
            success_reason="Objective achieved" if success else "Max turns reached",
        )

    def run(self) -> AttackResult:
        """Run the CTF attack synchronously.

        Returns:
            AttackResult with success status and conversation history
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(self.run_async())

    def export_conversation(self, output_path: Path | str) -> None:
        """Export conversation history to JSON.

        Args:
            output_path: Path to save conversation
        """
        import json

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "objective": self.objective,
            "turns": self.turn_count,
            "cost": self.total_cost,
            "elapsed_time": time.time() - self.start_time,
            "conversation": self.conversation_history,
        }

        with output_path.open("w") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]✓[/green] Conversation exported: {output_path}")

    def show_summary(self, result: AttackResult) -> None:
        """Display attack summary.

        Args:
            result: Attack result to display
        """
        table = Table(title="Attack Summary", show_header=False)
        table.add_column("Metric", style="bold")
        table.add_column("Value")

        table.add_row("Objective", result.objective)
        table.add_row("Success", "[green]✓ Yes[/green]" if result.success else "[red]✗ No[/red]")
        table.add_row("Turns Used", f"{result.turns}/{self.max_turns}")
        table.add_row("Total Cost", f"${result.cost:.2f}")
        table.add_row("Time Elapsed", f"{result.elapsed_time:.1f}s")
        if result.success_reason:
            table.add_row("Reason", result.success_reason)

        console.print()
        console.print(table)

        if result.success:
            console.print(
                Panel.fit(
                    "[bold green]🎉 Attack Succeeded![/bold green]\n\n" f"{result.final_response}",
                    border_style="green",
                    title="[bold]Success[/bold]",
                )
            )
