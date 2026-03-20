"""Payload management CLI commands."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from aipop.payloads.payload_manager import PayloadManager
from aipop.utils.progress import print_error, print_success

app = typer.Typer(help="Payload management commands")
console = Console()


@app.command("list")
def list_payloads(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category"),
    tool: str | None = typer.Option(None, "--tool", "-t", help="Filter by tool name"),
    top: int | None = typer.Option(None, "--top", "-n", help="Limit number of results"),
) -> None:
    """List available payloads.

    Examples:
        aipop payloads list
        aipop payloads list --category injection
        aipop payloads list --tool read_file --top 10
    """
    try:
        manager = PayloadManager()
        payloads = manager.list_payloads(category=category, tool=tool, top=top)

        if not payloads:
            print_error("No payloads found. Try importing from SecLists first.")
            raise typer.Exit(1)

        table = Table(title=f"Payloads ({len(payloads)} found)")
        table.add_column("Category", style="cyan")
        table.add_column("Tool", style="magenta")
        table.add_column("Payload Preview", style="green")

        for p in payloads[:20]:  # Show max 20
            # Handle tuple/list results from DuckDB
            category_val = str(p[2]) if len(p) > 2 else "unknown"
            tool_val = str(p[4]) if len(p) > 4 else "N/A"
            payload_text = str(p[1]) if len(p) > 1 else "N/A"
            preview = payload_text[:50] + "..." if len(payload_text) > 50 else payload_text
            table.add_row(category_val, tool_val, preview)

        console.print(table)

        if len(payloads) > 20:
            console.print(
                f"\n[dim]Showing 20 of {len(payloads)} payloads. Use --top to see more.[/dim]"
            )

        manager.close()
    except Exception as e:
        print_error(f"Failed to list payloads: {e}")
        raise typer.Exit(1) from None


@app.command("search")
def search_payloads(
    query: str = typer.Argument(..., help="Search query"),
) -> None:
    """Search payloads by keyword.

    Examples:
        aipop payloads search "path traversal"
        aipop payloads search injection
    """
    try:
        manager = PayloadManager()
        results = manager.search_payloads(query)

        if not results:
            print_error(f"No payloads found matching: {query}")
            raise typer.Exit(1)

        print_success(f"Found {len(results)} matching payloads")
        console.print()

        for i, result in enumerate(results[:20], 1):  # Show max 20
            console.print(f"  {i}. {result}")

        if len(results) > 20:
            console.print(f"\n[dim]Showing 20 of {len(results)} results[/dim]")

        manager.close()
    except Exception as e:
        print_error(f"Failed to search payloads: {e}")
        raise typer.Exit(1) from None


@app.command("stats")
def show_stats() -> None:
    """Show payload database statistics.

    Examples:
        aipop payloads stats
    """
    try:
        manager = PayloadManager()
        stats = manager.get_statistics()

        table = Table(title="Payload Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Total Payloads", str(stats.get("total_payloads", 0)))
        table.add_row("Total Attempts", str(stats.get("total_attempts", 0)))

        # Show categories breakdown
        categories = stats.get("categories", {})
        if categories:
            console.print(table)
            console.print()

            cat_table = Table(title="Categories")
            cat_table.add_column("Category", style="cyan")
            cat_table.add_column("Count", style="green")

            for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                cat_table.add_row(cat, str(count))

            console.print(cat_table)
        else:
            console.print(table)

        manager.close()
    except Exception as e:
        print_error(f"Failed to get statistics: {e}")
        raise typer.Exit(1) from None


@app.command("import-seclists")
def import_seclists(
    path: str = typer.Argument(..., help="Path to SecLists directory"),
    categories: str | None = typer.Option(
        None, "--categories", "-c", help="Comma-separated categories to import"
    ),
) -> None:
    """Import payloads from SecLists repository.

    Examples:
        aipop payloads import-seclists /opt/SecLists
        aipop payloads import-seclists /opt/SecLists --categories "Fuzzing,Injection"
    """
    try:
        manager = PayloadManager()

        cats = categories.split(",") if categories else None
        print_success(f"Importing from SecLists at: {path}")
        if cats:
            console.print(f"  Categories: {', '.join(cats)}")

        count = manager.import_seclists(path, cats)

        print_success(f"Successfully imported {count} payloads from SecLists")
        manager.close()
    except Exception as e:
        print_error(f"Failed to import SecLists: {e}")
        raise typer.Exit(1) from None


@app.command("import-git")
def import_git(
    repo_url: str = typer.Argument(..., help="Git repository URL"),
) -> None:
    """Import payloads from Git repository.

    Examples:
        aipop payloads import-git https://github.com/user/custom-payloads
    """
    try:
        manager = PayloadManager()

        print_success(f"Importing from Git repository: {repo_url}")
        manager.import_git_repo(repo_url)

        print_success("Successfully imported payloads from Git repository")
        manager.close()
    except Exception as e:
        print_error(f"Failed to import from Git: {e}")
        raise typer.Exit(1) from None
