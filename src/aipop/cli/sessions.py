"""Session management CLI commands.

Provides commands to list, view, export, and prune captured traffic sessions.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Manage captured traffic sessions")
console = Console()


def print_success(message: str) -> None:
    """Print success message."""
    console.print(f"[green]✓[/green] {message}")


def print_error(message: str) -> None:
    """Print error message."""
    console.print(f"[red]✗[/red] {message}")


def print_info(message: str) -> None:
    """Print info message."""
    console.print(f"[blue]ℹ[/blue] {message}")


@app.command("list")
def list_sessions(
    data_dir: str | None = typer.Option(None, "--data-dir", help="Override data directory"),
) -> None:
    """List all captured traffic sessions.

    Examples:
        aipop sessions list
        aipop sessions list --data-dir /custom/path
    """
    from datetime import datetime

    import duckdb

    from aipop.utils.paths import get_session_db_path, list_session_ids

    try:
        session_ids = list_session_ids(data_dir)

        if not session_ids:
            print_info("No sessions found")
            return

        # Create table
        table = Table(title="Captured Traffic Sessions")
        table.add_column("Session ID", style="cyan")
        table.add_column("Requests", style="magenta")
        table.add_column("Size", style="yellow")
        table.add_column("Modified", style="green")

        for session_id in session_ids:
            db_path = get_session_db_path(session_id, data_dir)

            # Get request count and file size
            request_count = 0
            try:
                conn = duckdb.connect(str(db_path), read_only=True)
                result = conn.execute("SELECT COUNT(*) FROM captured_requests").fetchone()
                if result:
                    request_count = result[0]
                conn.close()
            except Exception:
                pass

            # Get file size
            size_mb = db_path.stat().st_size / (1024 * 1024)
            size_str = f"{size_mb:.2f} MB"

            # Get modification time
            mtime = datetime.fromtimestamp(db_path.stat().st_mtime)
            time_str = mtime.strftime("%Y-%m-%d %H:%M")

            table.add_row(session_id, str(request_count), size_str, time_str)

        console.print(table)
        print_info(f"Total sessions: {len(session_ids)}")

    except Exception as e:
        print_error(f"Failed to list sessions: {e}")
        raise typer.Exit(1) from None


@app.command("show")
def show_session(
    session_id: str = typer.Argument(..., help="Session ID to display"),
    data_dir: str | None = typer.Option(None, "--data-dir", help="Override data directory"),
) -> None:
    """Show details of a specific session.

    Examples:
        aipop sessions show abc123-456
    """
    import duckdb

    from aipop.utils.paths import get_session_db_path

    try:
        db_path = get_session_db_path(session_id, data_dir)

        if not db_path.exists():
            print_error(f"Session not found: {session_id}")
            raise typer.Exit(1)

        # Connect to database
        conn = duckdb.connect(str(db_path), read_only=True)

        # Get summary stats
        result = conn.execute(
            """
            SELECT 
                COUNT(*) as total_requests,
                COUNT(DISTINCT method) as unique_methods,
                MIN(ts) as first_request,
                MAX(ts) as last_request,
                SUM(response_time_ms) as total_time_ms
            FROM captured_requests
        """
        ).fetchone()

        if not result or result[0] == 0:
            print_info(f"Session {session_id} has no captured requests")
            conn.close()
            return

        total, methods, first, last, total_time = result

        # Display info
        console.print(f"\n[bold]Session: {session_id}[/bold]")
        console.print(f"Total Requests: {total}")
        console.print(f"Unique Methods: {methods}")
        console.print(f"First Request: {first}")
        console.print(f"Last Request: {last}")
        console.print(f"Total Time: {total_time or 0}ms")

        # Get method breakdown
        methods_result = conn.execute(
            """
            SELECT method, COUNT(*) as count
            FROM captured_requests
            GROUP BY method
            ORDER BY count DESC
        """
        ).fetchall()

        if methods_result:
            console.print("\n[bold]Methods:[/bold]")
            for method, count in methods_result:
                console.print(f"  {method}: {count}")

        # Get status code breakdown
        status_result = conn.execute(
            """
            SELECT status, COUNT(*) as count
            FROM captured_requests
            WHERE status IS NOT NULL
            GROUP BY status
            ORDER BY status
        """
        ).fetchall()

        if status_result:
            console.print("\n[bold]Status Codes:[/bold]")
            for status, count in status_result:
                console.print(f"  {status}: {count}")

        conn.close()

    except Exception as e:
        print_error(f"Failed to show session: {e}")
        raise typer.Exit(1) from None


@app.command("export")
def export_session(
    session_id: str = typer.Argument(..., help="Session ID to export"),
    format: str = typer.Option("json", "--format", "-f", help="Export format (json/har/csv)"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
    data_dir: str | None = typer.Option(None, "--data-dir", help="Override data directory"),
) -> None:
    """Export a session to HAR, JSON, or CSV format.

    Examples:
        aipop sessions export abc123 --format har --output traffic.har
        aipop sessions export abc123 --format json
    """
    import json

    import duckdb

    from aipop.intelligence.har_exporter import build_har, save_har
    from aipop.utils.paths import get_session_db_path

    try:
        db_path = get_session_db_path(session_id, data_dir)

        if not db_path.exists():
            print_error(f"Session not found: {session_id}")
            raise typer.Exit(1)

        # Load captured requests
        conn = duckdb.connect(str(db_path), read_only=True)
        rows = conn.execute("SELECT * FROM captured_requests ORDER BY ts").fetchall()
        columns = [desc[0] for desc in conn.description]
        conn.close()

        if not rows:
            print_info(f"Session {session_id} has no captured requests")
            return

        # Convert to dicts
        requests = [dict(zip(columns, row)) for row in rows]

        # Determine output path
        if not output:
            output = f"{session_id}.{format}"

        # Export based on format
        if format == "har":
            har = build_har(requests, {"session_id": session_id})
            save_har(har, output)
            print_success(f"Exported {len(requests)} requests to HAR: {output}")

        elif format == "json":
            with open(output, "w") as f:
                json.dump(
                    {
                        "session_id": session_id,
                        "requests": requests,
                    },
                    f,
                    indent=2,
                    default=str,
                )
            print_success(f"Exported {len(requests)} requests to JSON: {output}")

        elif format == "csv":
            import csv

            with open(output, "w", newline="") as f:
                if requests:
                    writer = csv.DictWriter(f, fieldnames=requests[0].keys())
                    writer.writeheader()
                    writer.writerows(requests)
            print_success(f"Exported {len(requests)} requests to CSV: {output}")

        else:
            print_error(f"Unknown format: {format}. Use json, har, or csv")
            raise typer.Exit(1)

    except Exception as e:
        print_error(f"Failed to export session: {e}")
        raise typer.Exit(1) from None


@app.command("delete")
def delete_session(
    session_id: str = typer.Argument(..., help="Session ID to delete"),
    data_dir: str | None = typer.Option(None, "--data-dir", help="Override data directory"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
) -> None:
    """Delete a session database.

    Examples:
        aipop sessions delete abc123
        aipop sessions delete abc123 --yes
    """
    from aipop.utils.paths import get_session_db_path

    try:
        db_path = get_session_db_path(session_id, data_dir)

        if not db_path.exists():
            print_error(f"Session not found: {session_id}")
            raise typer.Exit(1)

        # Confirm deletion
        if not yes:
            confirm = typer.confirm(f"Delete session {session_id}?")
            if not confirm:
                print_info("Cancelled")
                return

        # Delete file
        db_path.unlink()
        print_success(f"Deleted session: {session_id}")

    except Exception as e:
        print_error(f"Failed to delete session: {e}")
        raise typer.Exit(1) from None


@app.command("prune")
def prune_sessions(
    older_than: int = typer.Option(14, "--older-than", help="Delete sessions older than N days"),
    data_dir: str | None = typer.Option(None, "--data-dir", help="Override data directory"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
) -> None:
    """Delete sessions older than specified days.

    Examples:
        aipop sessions prune --older-than 30
        aipop sessions prune --older-than 7 --yes
    """
    from aipop.utils.paths import cleanup_old_sessions

    try:
        if not yes:
            confirm = typer.confirm(f"Delete sessions older than {older_than} days?")
            if not confirm:
                print_info("Cancelled")
                return

        deleted = cleanup_old_sessions(older_than, data_dir)

        if deleted > 0:
            print_success(f"Deleted {deleted} old session(s)")
        else:
            print_info("No old sessions found")

    except Exception as e:
        print_error(f"Failed to prune sessions: {e}")
        raise typer.Exit(1) from None


if __name__ == "__main__":
    app()
