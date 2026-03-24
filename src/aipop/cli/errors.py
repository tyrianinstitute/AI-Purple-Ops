"""Smart error handling — every error tells you what to do next.

Wraps common error types with actionable guidance. No stack traces
for known errors. No dead ends. The pentester always knows the next step.

Usage:
    from aipop.cli.errors import handle_error, SmartError

    try:
        do_something()
    except Exception as e:
        handle_error(e, console)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.panel import Panel


@dataclass
class SmartError:
    """An error with guidance attached."""

    title: str
    message: str
    suggestions: list[str]
    exit_code: int = 2


# Known error patterns → smart responses
ERROR_PATTERNS: list[tuple[type | str, SmartError]] = []


def _match_error(error: Exception) -> SmartError | None:
    """Match an exception to a known pattern with guidance."""
    error_str = str(error).lower()
    error_type = type(error).__name__

    # Adapter errors
    if "api key not found" in error_str or "api_key" in error_str:
        provider = "unknown"
        if "openai" in error_str:
            provider = "OpenAI"
            env_var = "OPENAI_API_KEY"
        elif "anthropic" in error_str:
            provider = "Anthropic"
            env_var = "ANTHROPIC_API_KEY"
        else:
            env_var = "<PROVIDER>_API_KEY"

        return SmartError(
            title=f"{provider} API Key Missing",
            message=str(error),
            suggestions=[
                f"Set the environment variable: export {env_var}=<your-key>",
                "Or use the static adapter for pipeline validation: --adapter static",
                "Or use a local model: --adapter ollama --model llama3",
            ],
            exit_code=2,
        )

    if "unknown adapter" in error_str:
        return SmartError(
            title="Unknown Adapter",
            message=str(error),
            suggestions=[
                "Available adapters: static, openai, anthropic, ollama, huggingface, bedrock",
                "Use --adapter static for pipeline validation (no API key needed)",
                "See all adapters: aipop adapter list",
            ],
            exit_code=2,
        )

    # Suite/template errors
    if "no test cases found" in error_str or "failed to load suite" in error_str:
        return SmartError(
            title="Suite Not Found",
            message=str(error),
            suggestions=[
                "List available suites: aipop suites list",
                "Try a built-in suite: aipop scan --suite adversarial",
                "Check the path: suites are in suites/ (e.g., adversarial/rag_injection)",
            ],
            exit_code=2,
        )

    if "yamlsuiteerror" in error_type.lower() or "yaml" in error_str and "error" in error_str:
        return SmartError(
            title="Invalid Suite YAML",
            message=str(error),
            suggestions=[
                "Check YAML syntax: each case needs id, prompt, and metadata",
                "Validate with: python -c \"import yaml; yaml.safe_load(open('your_suite.yaml'))\"",
                "See examples in suites/adversarial/ for the expected format",
            ],
            exit_code=2,
        )

    # Connection errors
    if "connection" in error_str and ("refused" in error_str or "error" in error_str):
        return SmartError(
            title="Connection Failed",
            message=str(error),
            suggestions=[
                "Check if the target is running and accessible",
                "If using Ollama: is `ollama serve` running?",
                "If using a proxy: verify proxy is running (--proxy http://127.0.0.1:8080)",
                "Try the static adapter first: --adapter static",
            ],
            exit_code=4,
        )

    if "timeout" in error_str:
        return SmartError(
            title="Request Timeout",
            message=str(error),
            suggestions=[
                "The target took too long to respond",
                "Increase timeout: aipop set TIMEOUT 60",
                "Check target health independently before scanning",
                "If rate-limited: reduce request rate or add --budget cap",
            ],
            exit_code=4,
        )

    # Import/dependency errors
    if "import" in error_type.lower() or "no module named" in error_str:
        module = str(error).split("'")[1] if "'" in str(error) else "unknown"
        return SmartError(
            title="Missing Dependency",
            message=str(error),
            suggestions=[
                f"Install the required extra: pip install ai-purple-ops[all]",
                "Or install specifically:",
                "  pip install ai-purple-ops[pyrit]        # for multi-turn attacks",
                "  pip install ai-purple-ops[intelligence] # for fingerprinting",
                "  pip install ai-purple-ops[reports]      # for PDF generation",
            ],
            exit_code=3,
        )

    # Budget exceeded
    if "budget" in error_str and "exceeded" in error_str:
        return SmartError(
            title="Budget Exceeded",
            message=str(error),
            suggestions=[
                "The scan stopped because the budget cap was reached",
                "Increase budget: --budget 5.00",
                "Or use a cheaper model: --model gpt-4o-mini",
                "Review partial results in out/reports/summary.json",
            ],
            exit_code=1,
        )

    # Permission errors
    if "permission" in error_str and ("denied" in error_str or "error" in error_str):
        return SmartError(
            title="Permission Denied",
            message=str(error),
            suggestions=[
                "Check file/directory permissions on the output path",
                "Default output: out/reports/ — ensure it's writable",
                "Override with: --output-dir /tmp/aipop_output",
            ],
            exit_code=4,
        )

    return None


def handle_error(
    error: Exception,
    console: Console | None = None,
    context: str = "",
) -> int:
    """Handle an error with smart guidance. Returns exit code.

    Args:
        error: The exception to handle
        console: Rich console for output (defaults to stderr)
        context: Optional context string (e.g., "during scan", "loading suite")

    Returns:
        Appropriate exit code (2=config, 3=dependency, 4=runtime)
    """
    console = console or Console(stderr=True)
    smart = _match_error(error)

    if smart:
        # Known error — show guidance panel
        lines = [f"[bold]{smart.message}[/]", ""]
        for i, suggestion in enumerate(smart.suggestions, 1):
            if suggestion.startswith("  "):
                lines.append(f"[dim]{suggestion}[/]")
            else:
                lines.append(f"  [cyan]{i}.[/] {suggestion}")

        console.print()
        console.print(
            Panel(
                "\n".join(lines),
                title=f"[bold red]✗ {smart.title}[/]",
                border_style="red",
                padding=(0, 1),
            )
        )
        console.print()
        return smart.exit_code
    else:
        # Unknown error — show error with generic guidance
        console.print()
        console.print(
            Panel(
                f"[bold]{error}[/]\n\n"
                f"  [cyan]1.[/] Run with --trace for full debug output\n"
                f"  [cyan]2.[/] Check: aipop doctor\n"
                f"  [cyan]3.[/] Report: https://github.com/tyrianinstitute/AI-Purple-Ops/issues",
                title=f"[bold red]✗ {type(error).__name__}[/]",
                border_style="red",
                padding=(0, 1),
            )
        )
        console.print()
        return 4
