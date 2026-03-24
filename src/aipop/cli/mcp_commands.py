"""MCP adapter commands for fast pentester workflow.

Provides CLI commands for MCP server interaction and exploitation:
- discover: Auto-discover MCP endpoints
- enumerate: List available tools
- call: Invoke a specific tool
- exploit: Auto-exploitation mode
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from aipop.utils.adapter_paths import get_adapter_templates_dir

app = typer.Typer(name="mcp", help="MCP adapter commands for CTF and pentesting")
console = Console()


@app.command()
def enumerate(
    config: str = typer.Argument(..., help="Path to MCP adapter config YAML"),
    output: str | None = typer.Option(None, "--output", "-o", help="Save output to file (JSON)"),
) -> None:
    """Enumerate available MCP tools from a server.

    Quickly lists all tools, their descriptions, and schemas for reconnaissance.

    Example:
        aipop mcp enumerate adapters/ctf-target.yaml
        aipop mcp enumerate adapters/ctf-target.yaml --output tools.json
    """
    try:
        from aipop.adapters.mcp_adapter import MCPAdapter
    except ImportError:
        console.print("[red]Error:[/red] MCP adapter not available")
        raise typer.Exit(1) from None

    console.print(f"\n[cyan]🔍 Enumerating MCP tools from:[/cyan] {config}")

    try:
        # Load adapter
        adapter = MCPAdapter.from_config(config)
        adapter.connect()

        # Enumerate tools
        tools = adapter.enumerate_tools()

        if not tools:
            console.print("[yellow]No tools available on this server[/yellow]")
            raise typer.Exit(0)

        # Display table
        table = Table(title=f"MCP Tools ({len(tools)} found)", show_header=True)
        table.add_column("Tool Name", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")
        table.add_column("Parameters", style="dim")

        tools_data = []
        for tool in tools:
            # Extract required params
            schema = tool.input_schema or {}
            required = schema.get("required", [])
            params_str = ", ".join(required) if required else "none"

            table.add_row(
                tool.name,
                tool.description[:60] + "..." if len(tool.description) > 60 else tool.description,
                params_str,
            )

            # Collect for JSON output
            tools_data.append(
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                }
            )

        console.print(table)

        # Save to file if requested
        if output:
            output_path = Path(output)
            with open(output_path, "w") as f:
                json.dump(tools_data, f, indent=2)
            console.print(f"\n[green]✓[/green] Saved to {output}")

        console.print(f"\n[green]✓ Enumerated {len(tools)} tools[/green]")

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1) from None


@app.command()
def call(
    config: str = typer.Argument(..., help="Path to MCP adapter config YAML"),
    tool: str = typer.Argument(..., help="Tool name to call"),
    params: str | None = typer.Option(None, "--params", "-p", help="Tool parameters (JSON string)"),
    params_file: str | None = typer.Option(
        None, "--params-file", "-f", help="Tool parameters (JSON file)"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
) -> None:
    """Call a specific MCP tool with parameters.

    Examples:
        # Simple call
        aipop mcp call target.yaml read_file --params '{"path": "/flag.txt"}'

        # From file
        aipop mcp call target.yaml search --params-file params.json

        # Verbose mode
        aipop mcp call target.yaml get_secret -v
    """
    try:
        from aipop.adapters.mcp_adapter import MCPAdapter
    except ImportError:
        console.print("[red]Error:[/red] MCP adapter not available")
        raise typer.Exit(1) from None

    console.print(f"\n[cyan]🔧 Calling MCP tool:[/cyan] {tool}")

    try:
        # Parse parameters
        if params_file:
            with open(params_file) as f:
                tool_params = json.load(f)
        elif params:
            tool_params = json.loads(params)
        else:
            tool_params = {}

        if verbose:
            console.print(f"[dim]Parameters:[/dim] {json.dumps(tool_params, indent=2)}")

        # Load adapter and call tool
        adapter = MCPAdapter.from_config(config)
        adapter.connect()

        result = adapter.call_tool(tool, tool_params)

        # Display result
        if result.is_error:
            console.print(
                Panel(
                    f"[red]{result.error_message}[/red]",
                    title="❌ Error",
                    border_style="red",
                )
            )
            raise typer.Exit(1)
        else:
            # Check for flags
            content_str = str(result.content)

            # Highlight flags if found
            if any(pattern in content_str.lower() for pattern in ["flag{", "ctf{", "secret"]):
                console.print(
                    Panel(
                        Syntax(content_str, "text", theme="monokai"),
                        title="🚩 Result (FLAG DETECTED!)",
                        border_style="green",
                    )
                )
            else:
                console.print(
                    Panel(
                        Syntax(content_str[:1000], "text", theme="monokai"),  # Limit output
                        title="✓ Result",
                        border_style="cyan",
                    )
                )

            if verbose:
                console.print("\n[dim]Metadata:[/dim]")
                console.print(f"  Is Error: {result.is_error}")
                if hasattr(result, "metadata"):
                    console.print(f"  Metadata: {result.metadata}")

    except json.JSONDecodeError as e:
        console.print(f"[red]Error:[/red] Invalid JSON in parameters: {e}")
        raise typer.Exit(1) from None
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1) from None


@app.command()
def exploit(
    config: str = typer.Argument(..., help="Path to MCP adapter config YAML"),
    objective: str = typer.Argument(..., help="Attack objective (e.g., 'Extract the flag')"),
    max_iterations: int = typer.Option(
        10, "--max-iterations", "-n", help="Maximum attack iterations"
    ),
    output: str | None = typer.Option(None, "--output", "-o", help="Save attack log to file"),
) -> None:
    """Auto-exploitation mode: Let AI Purple Ops automatically solve the CTF.

    This command uses intelligent strategies to:
    - Enumerate available tools
    - Try common payloads (path traversal, SQLi, etc.)
    - Parse responses for hints
    - Chain tool calls
    - Detect flags automatically

    Examples:
        # Basic auto-exploit
        aipop mcp exploit target.yaml "Extract the secret flag"

        # With custom iteration limit
        aipop mcp exploit target.yaml "Get the password" --max-iterations 20

        # Save attack log
        aipop mcp exploit target.yaml "Find the flag" --output attack.log
    """
    try:
        from aipop.adapters.mcp_adapter import MCPAdapter
    except ImportError:
        console.print("[red]Error:[/red] MCP adapter not available")
        raise typer.Exit(1) from None

    console.print(
        Panel(
            f"[cyan]Objective:[/cyan] {objective}\n"
            f"[cyan]Max Iterations:[/cyan] {max_iterations}",
            title="🎯 Auto-Exploitation Mode",
            border_style="cyan",
        )
    )

    try:
        # Load adapter
        adapter = MCPAdapter.from_config(config)

        # Run auto-exploitation
        console.print("\n[yellow]Starting automated exploitation...[/yellow]\n")

        result = adapter.invoke(
            objective,
            mode="auto",
            max_iterations=max_iterations,
        )

        # Display results
        if result.meta.get("flags_found"):
            flags = result.meta["flags_found"]
            console.print(
                Panel(
                    "[green bold]🎉 SUCCESS![/green bold]\n\n"
                    "[cyan]Flags Captured:[/cyan]\n" + "\n".join(f"  🚩 {flag}" for flag in flags),
                    title="CTF Solved",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    f"[yellow]Auto-exploitation completed without finding flags.[/yellow]\n\n"
                    f"[dim]{result.text[:500]}[/dim]",
                    title="⚠️ No Flags Found",
                    border_style="yellow",
                )
            )

        # Show stats
        console.print("\n[cyan]Attack Statistics:[/cyan]")
        console.print(f"  Tools Called: {result.meta.get('tools_called', 0)}")
        console.print(f"  Secrets Found: {len(result.meta.get('secrets_found', []))}")
        console.print(f"  Latency: {result.meta.get('latency_ms', 0):.2f}ms")

        # Save log if requested
        if output:
            log_data = {
                "objective": objective,
                "success": bool(result.meta.get("flags_found")),
                "flags": result.meta.get("flags_found", []),
                "secrets": result.meta.get("secrets_found", []),
                "tools_called": result.meta.get("tools_called", 0),
                "output": result.text,
                "meta": result.meta,
            }

            with open(output, "w") as f:
                json.dump(log_data, f, indent=2)

            console.print(f"\n[green]✓[/green] Attack log saved to {output}")

    except Exception as e:
        console.print(f"\n[red]Error during exploitation:[/red] {e}")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            import traceback

            console.print(traceback.format_exc())
        raise typer.Exit(1) from None


@app.command()
def test_connection(
    config: str = typer.Argument(..., help="Path to MCP adapter config YAML"),
) -> None:
    """Test connection to an MCP server.

    Verifies:
    - Transport connectivity
    - Authentication
    - Protocol handshake
    - Server capabilities

    Example:
        aipop mcp test-connection adapters/target.yaml
    """
    try:
        from aipop.adapters.mcp_adapter import MCPAdapter
    except ImportError:
        console.print("[red]Error:[/red] MCP adapter not available")
        raise typer.Exit(1) from None

    console.print(f"\n[cyan]🔌 Testing MCP connection:[/cyan] {config}\n")

    try:
        # Load and connect
        console.print("[dim]Loading adapter...[/dim]")
        adapter = MCPAdapter.from_config(config)

        console.print("[dim]Connecting to server...[/dim]")
        adapter.connect()

        # Get capabilities
        caps = adapter._capabilities

        console.print(
            Panel(
                f"[green]✓ Connection successful![/green]\n\n"
                f"[cyan]Server Info:[/cyan]\n"
                f"  Name: {caps.server_info.get('name', 'Unknown') if caps else 'Unknown'}\n"
                f"  Version: {caps.server_info.get('version', 'Unknown') if caps else 'Unknown'}\n\n"
                f"[cyan]Capabilities:[/cyan]\n"
                f"{caps.summary() if caps else 'None'}",
                title="✓ MCP Connection Test",
                border_style="green",
            )
        )

        console.print("[green]✓ All checks passed[/green]")

    except Exception as e:
        console.print(
            Panel(
                f"[red]{e}[/red]",
                title="❌ Connection Failed",
                border_style="red",
            )
        )
        raise typer.Exit(1) from None


@app.command()
def info() -> None:
    """Display MCP adapter information and usage examples."""
    example_template = (get_adapter_templates_dir() / "mcp.yaml").as_posix()
    help_text = f"""
[cyan bold]MCP (Model Context Protocol) Adapter[/cyan bold]

The MCP adapter enables AI Purple Ops to interact with and exploit MCP servers.

[yellow]Quick Start:[/yellow]

1. Create an adapter config (use `aipop adapter quick` from cURL)
2. Test connection: `aipop mcp test-connection config.yaml`
3. Enumerate tools: `aipop mcp enumerate config.yaml`
4. Auto-exploit: `aipop mcp exploit config.yaml "Extract the flag"`

[yellow]Commands:[/yellow]

• enumerate    - List available MCP tools
• call         - Call a specific tool
• exploit      - Auto-exploitation mode (AI-driven)
• test-connection - Verify MCP server connectivity

[yellow]Supported Transports:[/yellow]

• HTTP (POST + SSE)
• WebSocket  
• stdio (local process)

[yellow]CTF Workflow:[/yellow]

```bash
# 1. Enumerate recon
aipop mcp enumerate target.yaml

# 2. Manual tool call
aipop mcp call target.yaml read_file -p '{{"path": "/flag.txt"}}'

# 3. Auto-exploitation (let AI solve it)
aipop mcp exploit target.yaml "Find and extract the CTF flag"
```

[yellow]For full documentation:[/yellow]
See {example_template} for configuration examples
"""

    console.print(Panel(help_text, title="MCP Adapter Info", border_style="cyan"))


if __name__ == "__main__":
    app()
