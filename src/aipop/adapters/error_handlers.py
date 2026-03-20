"""Rich error handling for adapter failures.

Provides pentester-friendly error messages with troubleshooting guidance.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel

if TYPE_CHECKING:
    from requests import Response

console = Console()


def handle_connection_error(url: str, error: Exception) -> None:
    """Display connection error with troubleshooting.

    Args:
        url: Target URL that failed
        error: Exception that occurred
    """
    console.print()
    console.print(
        Panel.fit(
            f"[red]Connection Failed[/red]\n\n"
            f"[bold]URL:[/bold] {url}\n"
            f"[bold]Error:[/bold] {error!s}\n\n"
            f"[yellow]Troubleshooting:[/yellow]\n"
            f"  1. Check if API endpoint is correct\n"
            f"  2. Verify network connectivity: curl {url}\n"
            f"  3. Check for firewall/proxy blocking\n"
            f"  4. Try with --timeout 120 for slow APIs\n"
            f"  5. Verify the target is online and accepting connections",
            border_style="red",
            title="[bold]Connection Error[/bold]",
        )
    )
    console.print()


def handle_auth_error(status_code: int, auth_type: str, config_path: str) -> None:
    """Display auth error with specific guidance.

    Args:
        status_code: HTTP status code (401, 403)
        auth_type: Type of auth (bearer, api_key, etc.)
        config_path: Path to adapter config file
    """
    console.print()
    console.print(
        Panel.fit(
            f"[red]Authentication Failed ({status_code})[/red]\n\n"
            f"[bold]Auth Type:[/bold] {auth_type}\n\n"
            f"[yellow]Quick Fixes:[/yellow]\n"
            f"  1. Check API key/token is valid\n"
            f"  2. Set environment variable:\n"
            f"     [dim]export YOUR_API_KEY=your-key-here[/dim]\n"
            f"  3. Verify token hasn't expired\n"
            f"  4. Check API permissions/rate limits\n"
            f"  5. Verify auth header format in Burp\n\n"
            f"[dim]Edit config: {config_path}[/dim]",
            border_style="red",
            title="[bold]Auth Error[/bold]",
        )
    )
    console.print()


def handle_parse_error(response_text: str, error: Exception) -> None:
    """Display JSON parse error.

    Args:
        response_text: Response text that failed to parse
        error: Parse exception
    """
    preview = response_text[:200] + "..." if len(response_text) > 200 else response_text

    console.print()
    console.print(
        Panel.fit(
            f"[red]Response Parse Error[/red]\n\n"
            f"[bold]Error:[/bold] {error!s}\n\n"
            f"[bold]Response Preview:[/bold]\n"
            f"[dim]{preview}[/dim]\n\n"
            f"[yellow]Possible Issues:[/yellow]\n"
            f"  1. API returned HTML error page (check HTTP status)\n"
            f"  2. Response is not JSON (check Content-Type header)\n"
            f"  3. API endpoint is incorrect\n"
            f"  4. Server error occurred (check status code)",
            border_style="red",
            title="[bold]Parse Error[/bold]",
        )
    )
    console.print()


def handle_field_not_found(field_path: str, available_fields: list[str], config_path: str) -> None:
    """Display field not found error with suggestions.

    Args:
        field_path: Field path that wasn't found
        available_fields: List of available fields in response
        config_path: Path to adapter config file
    """
    # Show first 10 fields
    fields_preview = available_fields[:10]
    if len(available_fields) > 10:
        fields_preview.append(f"... and {len(available_fields) - 10} more")

    fields_list = "\n".join(f"  • {f}" for f in fields_preview)

    console.print()
    console.print(
        Panel.fit(
            f"[red]Field Not Found[/red]\n\n"
            f"[bold]Looking for:[/bold] {field_path}\n\n"
            f"[bold]Available fields:[/bold]\n"
            f"{fields_list}\n\n"
            f"[yellow]Fix:[/yellow]\n"
            f"  1. Edit config: {config_path}\n"
            f"  2. Update 'response.text_field' to correct path\n"
            f"  3. Use dot notation for nested fields: data.response\n"
            f"  4. Re-test: aipop adapter test [adapter-name]",
            border_style="red",
            title="[bold]Field Error[/bold]",
        )
    )
    console.print()


def handle_rate_limit(response: Response, retry_after: int | None = None) -> None:
    """Display rate limit error.

    Args:
        response: HTTP response object
        retry_after: Seconds to wait before retry (from Retry-After header)
    """
    wait_time = retry_after or "unknown"

    console.print()
    console.print(
        Panel.fit(
            f"[yellow]Rate Limit Exceeded (429)[/yellow]\n\n"
            f"[bold]Retry After:[/bold] {wait_time} seconds\n\n"
            f"[yellow]Options:[/yellow]\n"
            f"  1. Wait and retry manually\n"
            f"  2. Reduce request rate (use --delay between requests)\n"
            f"  3. Check API rate limits for your tier\n"
            f"  4. Consider upgrading API plan\n"
            f"  5. Use batch mode with delays",
            border_style="yellow",
            title="[bold]Rate Limit[/bold]",
        )
    )
    console.print()


def handle_timeout(url: str, timeout: int) -> None:
    """Display timeout error.

    Args:
        url: Target URL
        timeout: Timeout value that was exceeded
    """
    console.print()
    console.print(
        Panel.fit(
            f"[red]Request Timeout[/red]\n\n"
            f"[bold]URL:[/bold] {url}\n"
            f"[bold]Timeout:[/bold] {timeout} seconds\n\n"
            f"[yellow]Solutions:[/yellow]\n"
            f"  1. Increase timeout: Edit config → connection.timeout: 120\n"
            f"  2. Check if API is slow/overloaded\n"
            f"  3. Verify network latency to target\n"
            f"  4. Try smaller prompts (some models slower with long inputs)\n"
            f"  5. Check API status page for incidents",
            border_style="red",
            title="[bold]Timeout Error[/bold]",
        )
    )
    console.print()


def handle_server_error(status_code: int, response_text: str) -> None:
    """Display server error (5xx).

    Args:
        status_code: HTTP status code (500-599)
        response_text: Response body
    """
    preview = response_text[:200] + "..." if len(response_text) > 200 else response_text

    console.print()
    console.print(
        Panel.fit(
            f"[red]Server Error ({status_code})[/red]\n\n"
            f"[bold]Response:[/bold]\n"
            f"[dim]{preview}[/dim]\n\n"
            f"[yellow]This is a server-side issue:[/yellow]\n"
            f"  1. Check API status page\n"
            f"  2. Retry in a few moments\n"
            f"  3. Contact API support if persistent\n"
            f"  4. Check API docs for known issues\n"
            f"  5. Verify request format is correct",
            border_style="red",
            title="[bold]Server Error[/bold]",
        )
    )
    console.print()


def handle_bad_request(status_code: int, response_text: str, config_path: str) -> None:
    """Display bad request error (4xx excluding 401/403/429).

    Args:
        status_code: HTTP status code (400, 404, etc.)
        response_text: Response body
        config_path: Path to adapter config file
    """
    preview = response_text[:200] + "..." if len(response_text) > 200 else response_text

    console.print()
    console.print(
        Panel.fit(
            f"[red]Bad Request ({status_code})[/red]\n\n"
            f"[bold]Response:[/bold]\n"
            f"[dim]{preview}[/dim]\n\n"
            f"[yellow]Common Issues:[/yellow]\n"
            f"  1. [bold]400:[/bold] Invalid request format or missing required fields\n"
            f"  2. [bold]404:[/bold] Wrong endpoint URL\n"
            f"  3. [bold]405:[/bold] Wrong HTTP method (GET vs POST)\n"
            f"  4. [bold]422:[/bold] Validation error - check required fields\n\n"
            f"[yellow]Fix:[/yellow]\n"
            f"  1. Compare request with working Burp request\n"
            f"  2. Check extra_fields in config\n"
            f"  3. Verify endpoint URL and method\n"
            f"  4. Edit: {config_path}",
            border_style="red",
            title="[bold]Request Error[/bold]",
        )
    )
    console.print()


def show_test_success(
    adapter_name: str, prompt: str, response_text: str, latency_ms: float
) -> None:
    """Display successful test result.

    Args:
        adapter_name: Name of the adapter
        prompt: Test prompt used
        response_text: Response received
        latency_ms: Response time in milliseconds
    """
    preview = response_text[:200] + "..." if len(response_text) > 200 else response_text

    console.print()
    console.print(
        Panel.fit(
            f"[green]✓ Test Successful[/green]\n\n"
            f"[bold]Prompt:[/bold] {prompt}\n"
            f"[bold]Response:[/bold] {preview}\n"
            f"[bold]Latency:[/bold] {latency_ms:.0f}ms\n\n"
            f"[dim]Ready to use:[/dim]\n"
            f"  aipop run --suite quick_test --adapter {adapter_name}",
            border_style="green",
            title="[bold]Adapter Test[/bold]",
        )
    )
    console.print()


def show_config_location(config_path: str, adapter_name: str) -> None:
    """Show where config was saved and next steps.

    Args:
        config_path: Path where config was saved
        adapter_name: Name of the adapter
    """
    console.print()
    console.print(
        Panel.fit(
            f"[green]✓ Adapter Config Generated[/green]\n\n"
            f"[bold]Location:[/bold] {config_path}\n\n"
            f"[yellow]Next Steps:[/yellow]\n"
            f"  1. Review config for any FIXME fields\n"
            f"  2. Test adapter: [dim]aipop adapter test {adapter_name}[/dim]\n"
            f"  3. Use in scans: [dim]aipop run --suite quick_test --adapter {adapter_name}[/dim]\n\n"
            f"[dim]Edit config if auto-detection was incorrect[/dim]",
            border_style="green",
            title="[bold]Config Saved[/bold]",
        )
    )
    console.print()
