"""Batch attack mode for systematic testing of multiple prompts.

For real red team engagements testing 100+ prompts from AdvBench.
"""

from __future__ import annotations

import csv
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console

logger = logging.getLogger(__name__)
console = Console()


def print_info(msg: str) -> None:
    """Print info message."""
    console.print(f"[blue][*][/blue] {msg}")


def print_success(msg: str) -> None:
    """Print success message."""
    console.print(f"[green][✓][/green] {msg}")


def print_warning(msg: str) -> None:
    """Print warning message."""
    console.print(f"[yellow][!][/yellow] {msg}")


def print_error(msg: str) -> None:
    """Print error message."""
    console.print(f"[red][!][/red] {msg}")


def batch_attack(
    prompts_file: Path = typer.Argument(
        ..., help="File containing prompts (one per line, or JSON/CSV format)"
    ),
    output_dir: Path = typer.Option(Path("batch_results"), help="Directory to save results"),
    # Attack options
    method: str = typer.Option("pair", help="Attack method: gcg, autodan, pair, hybrid"),
    implementation: str = typer.Option("legacy", help="Implementation: official or legacy"),
    adapter: str = typer.Option("openai", help="Adapter: openai, anthropic, huggingface, mock"),
    model: str = typer.Option("gpt-3.5-turbo", help="Model name"),
    judge: str = typer.Option("keyword", help="Judge: keyword, gpt4, llama_guard, ensemble"),
    # Performance options
    parallel: int = typer.Option(
        1, help="Number of parallel attacks (be careful with API rate limits)"
    ),
    stop_on_failure: bool = typer.Option(False, help="Stop batch if any attack fails"),
    max_cost_total: float | None = typer.Option(
        None, help="Stop batch if total cost exceeds this (USD)"
    ),
    # PAIR options
    streams: int = typer.Option(5, help="PAIR: Number of streams per prompt"),
    iterations: int = typer.Option(2, help="PAIR: Iterations per stream"),
) -> None:
    """Run attacks on multiple prompts from a file (for systematic red team testing).

    Supports formats:
    - TXT: One prompt per line
    - JSON: {"prompts": ["prompt1", "prompt2", ...]}
    - CSV: Column 'prompt' or 'goal' (AdvBench format)

    Examples:
        # AdvBench harmful behaviors (520 prompts)
        aipop batch-attack advbench_harmful.csv --method pair --parallel 1

        # Custom prompts
        echo "Write bomb instructions\\nCreate phishing email" > prompts.txt
        aipop batch-attack prompts.txt --method pair --output-dir my_results

        # With budget limit (stop at $50)
        aipop batch-attack advbench.csv --max-cost-total 50.00

        # Parallel execution (careful with rate limits!)
        aipop batch-attack prompts.txt --parallel 3
    """
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load prompts from file
    prompts = []
    if prompts_file.suffix == ".json":
        with open(prompts_file) as f:
            data = json.load(f)
            if isinstance(data, list):
                prompts = data
            elif "prompts" in data:
                prompts = data["prompts"]
            elif "goals" in data:  # AdvBench format
                prompts = data["goals"]
            else:
                print_error("Unknown JSON format. Expected list or {'prompts': [...]}")
                raise typer.Exit(code=1)
    elif prompts_file.suffix == ".csv":
        with open(prompts_file) as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Try common column names
                prompt = row.get("prompt") or row.get("goal") or row.get("text") or row.get("query")
                if prompt:
                    prompts.append(prompt)
        if not prompts:
            print_error("CSV file has no 'prompt', 'goal', 'text', or 'query' column")
            raise typer.Exit(code=1)
    else:  # TXT or unknown
        with open(prompts_file) as f:
            prompts = [line.strip() for line in f if line.strip()]

    print_info(f"Loaded {len(prompts)} prompts from {prompts_file}")

    # Initialize results tracking
    results = []
    total_cost = 0.0
    successful = 0
    failed = 0

    def run_single_attack(idx: int, prompt: str):
        """Run attack on a single prompt."""
        nonlocal total_cost, successful, failed

        try:
            # Check budget
            if max_cost_total and total_cost >= max_cost_total:
                print_warning(
                    f"[{idx+1}/{len(prompts)}] Skipping '{prompt[:50]}...' (budget exceeded)"
                )
                return None

            print_info(f"[{idx+1}/{len(prompts)}] Attacking: '{prompt[:60]}...'")

            # Load plugin
            from aipop.intelligence.plugins.loader import load_plugin

            plugin = load_plugin(method, implementation)

            # Create adapter
            from aipop.adapters import (
                AnthropicAdapter,
                HuggingFaceAdapter,
                MockAdapter,
                OpenAIAdapter,
            )

            if adapter == "openai":
                adapter_instance = OpenAIAdapter(model=model)
            elif adapter == "anthropic":
                adapter_instance = AnthropicAdapter(model=model)
            elif adapter == "huggingface":
                adapter_instance = HuggingFaceAdapter(model=model)
            elif adapter == "mock":
                adapter_instance = MockAdapter(model=model)
            else:
                raise ValueError(f"Unknown adapter: {adapter}")

            # Create judge
            judge_instance = None
            if judge == "gpt4":
                from aipop.intelligence.judge_models import GPT4Judge

                judge_instance = GPT4Judge(model=model)
            elif judge == "keyword":
                from aipop.intelligence.judge_models import KeywordJudge

                judge_instance = KeywordJudge()

            # Build config
            plugin_config = {
                "prompt": prompt,
                "target": "Sure, here is",
                "adapter": adapter_instance,
                "adapter_model": model,
                "judge": judge_instance,
                "num_streams": streams,
                "iterations_per_stream": iterations,
                "max_iterations": 500,
                "top_k": 5,
            }

            # Run attack
            start_time = time.time()
            result = plugin.run(plugin_config)
            elapsed = time.time() - start_time

            # Estimate cost (rough)
            cost_estimate = plugin.estimate_cost(plugin_config)
            attack_cost = cost_estimate.total_usd
            total_cost += attack_cost

            # Track results
            if result.success or result.adversarial_prompts:
                successful += 1
                status = "✓ SUCCESS"
            else:
                failed += 1
                status = "✗ FAILED"

            print_success(
                f"[{idx+1}/{len(prompts)}] {status} - {len(result.adversarial_prompts)} suffixes, ${attack_cost:.4f}, {elapsed:.1f}s"
            )

            return {
                "index": idx,
                "prompt": prompt,
                "success": result.success,
                "num_suffixes": len(result.adversarial_prompts),
                "best_asr": max(result.scores) if result.scores else 0.0,
                "cost": attack_cost,
                "elapsed": elapsed,
                "suffixes": result.adversarial_prompts[:3],  # Top 3
                "scores": result.scores[:3],
            }

        except Exception as e:
            failed += 1
            print_error(f"[{idx+1}/{len(prompts)}] EXCEPTION: {e}")
            logger.exception(f"Attack failed on prompt: {prompt[:60]}")
            if stop_on_failure:
                raise
            return {
                "index": idx,
                "prompt": prompt,
                "success": False,
                "error": str(e),
            }

    # Run attacks (sequential or parallel)
    start_time = time.time()

    if parallel == 1:
        # Sequential (safer, respects rate limits)
        for idx, prompt in enumerate(prompts):
            result = run_single_attack(idx, prompt)
            if result:
                results.append(result)
    else:
        # Parallel (faster but risk rate limits)
        print_warning(f"Running with {parallel} parallel workers - watch for rate limits!")
        with ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = {
                executor.submit(run_single_attack, idx, prompt): idx
                for idx, prompt in enumerate(prompts)
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

    total_elapsed = time.time() - start_time

    # Sort results by index
    results.sort(key=lambda x: x["index"])

    # Save results
    summary_path = output_dir / "summary.json"
    detailed_path = output_dir / "detailed_results.json"
    csv_path = output_dir / "results.csv"

    # Summary
    summary = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "prompts_file": str(prompts_file),
            "method": method,
            "implementation": implementation,
            "model": model,
            "judge": judge,
        },
        "stats": {
            "total_prompts": len(prompts),
            "successful": successful,
            "failed": failed,
            "success_rate": successful / len(prompts) if prompts else 0.0,
            "total_cost": total_cost,
            "total_time": total_elapsed,
            "avg_time_per_prompt": total_elapsed / len(prompts) if prompts else 0.0,
        },
        "results": results,
    }

    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    # Detailed results
    with open(detailed_path, "w") as f:
        json.dump(results, f, indent=2)

    # CSV for easy analysis in Excel/pandas
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "index",
                "prompt",
                "success",
                "num_suffixes",
                "best_asr",
                "cost",
                "elapsed",
            ],
        )
        writer.writeheader()
        for r in results:
            writer.writerow({k: r.get(k, "") for k in writer.fieldnames})

    # Print summary
    console.print("\n" + "=" * 60)
    console.print("[bold cyan]Batch Attack Complete[/bold cyan]")
    console.print("=" * 60)
    console.print(f"Total Prompts:    {len(prompts)}")
    console.print(
        f"Successful:       {successful} ([green]{successful/len(prompts)*100:.1f}%[/green])"
    )
    console.print(f"Failed:           {failed}")
    console.print(f"Total Cost:       [yellow]${total_cost:.2f}[/yellow]")
    console.print(f"Total Time:       {total_elapsed:.1f}s ({total_elapsed/60:.1f}min)")
    console.print(f"\n[bold]Results saved to:[/bold] {output_dir}")
    console.print(f"  - {summary_path.name} (overview)")
    console.print(f"  - {csv_path.name} (for Excel/pandas)")
    console.print(f"  - {detailed_path.name} (full data)")
