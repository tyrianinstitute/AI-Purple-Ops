"""Utility for downloading and managing small local models for testing."""

from __future__ import annotations

import subprocess

from rich.console import Console

console = Console()


def download_tinyllama() -> bool:
    """Download TinyLlama model via Ollama for local testing.

    TinyLlama is a 1.1B parameter model that's fast and small (~637MB).
    Perfect for testing mutation engine without API keys.

    Returns:
        True if successful, False otherwise
    """
    try:
        # Check if Ollama is installed
        result = subprocess.run(
            ["ollama", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            console.print("[red]Ollama not found. Install from: https://ollama.com[/red]")
            return False

        console.print("[cyan]Checking if tinyllama is already downloaded...[/cyan]")

        # Check if model exists
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            check=False,
        )

        if "tinyllama" in result.stdout:
            console.print("[green]✓ tinyllama already downloaded[/green]")
            return True

        # Download the model
        console.print("[cyan]Downloading tinyllama (~637MB)...[/cyan]")
        console.print("[dim]This is a one-time download for local testing[/dim]")

        result = subprocess.run(
            ["ollama", "pull", "tinyllama"],
            check=False,
        )

        if result.returncode == 0:
            console.print("[green]✓ tinyllama downloaded successfully[/green]")
            console.print("\n[cyan]Test it with:[/cyan]")
            console.print("  aipop mutate 'test' --strategies paraphrase --provider ollama")
            return True
        else:
            console.print("[red]Failed to download tinyllama[/red]")
            return False

    except FileNotFoundError:
        console.print("[red]Ollama not found. Install from: https://ollama.com[/red]")
        return False
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return False


def list_local_models() -> list[str]:
    """List all locally available Ollama models.

    Returns:
        List of model names
    """
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            return []

        # Parse output (skip header)
        models = []
        for line in result.stdout.strip().split("\n")[1:]:
            if line.strip():
                model_name = line.split()[0]
                models.append(model_name)

        return models

    except FileNotFoundError:
        return []


def test_local_model(model: str = "tinyllama") -> bool:
    """Test a local model with a simple prompt.

    Args:
        model: Model name to test (default: tinyllama)

    Returns:
        True if test successful, False otherwise
    """
    try:
        from aipop.mutators.paraphrasing import ParaphrasingMutator

        console.print(f"[cyan]Testing {model}...[/cyan]")

        mutator = ParaphrasingMutator(provider="ollama", model=model)
        mutations = mutator.mutate("Hello world")

        if mutations:
            console.print(f"[green]✓ {model} working![/green]")
            console.print(f"Generated {len(mutations)} mutations")
            return True
        else:
            console.print(f"[yellow]Warning: {model} returned no mutations[/yellow]")
            return False

    except Exception as e:
        console.print(f"[red]Error testing {model}: {e}[/red]")
        return False


if __name__ == "__main__":
    console.print("[bold]Local Model Setup for Testing[/bold]\n")

    models = list_local_models()
    if models:
        console.print(f"[green]Found {len(models)} local model(s):[/green]")
        for model in models:
            console.print(f"  • {model}")
        console.print()

    if "tinyllama" not in models:
        console.print("[yellow]Recommended: Download tinyllama for fast local testing[/yellow]")
        download_tinyllama()
    else:
        console.print("[green]✓ tinyllama ready for use[/green]")
        test_local_model("tinyllama")
