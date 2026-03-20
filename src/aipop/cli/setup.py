"""Setup wizard and profile installation for AI Purple Ops."""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from aipop.setup.installer import (
    DependencyInstaller,
    create_ctf_config,
    show_installation_summary,
)
from aipop.setup.profiles import ProfileType, get_profile, list_profiles

app = typer.Typer(help="Setup and configure AI Purple Ops")
console = Console()


ASCII_BANNER = r"""
   █████╗ ██╗    ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ███████╗     ██████╗ ██████╗ ███████╗
  ██╔══██╗██║    ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝    ██╔═══██╗██╔══██╗██╔════╝
  ███████║██║    ██████╔╝██║   ██║██████╔╝██████╔╝██║     █████╗      ██║   ██║██████╔╝███████╗
  ██╔══██║██║    ██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ██╔══╝      ██║   ██║██╔═══╝ ╚════██║
  ██║  ██║██║    ██║     ╚██████╔╝██║  ██║██║     ███████╗███████╗    ╚██████╔╝██║     ███████║
  ╚═╝  ╚═╝╚═╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝     ╚═════╝ ╚═╝     ╚══════╝
                                                                                                  
                        SETUP WIZARD | INSTALLATION PROFILES
"""


def show_welcome_banner() -> None:
    """Display welcome banner."""
    console.print(
        Panel.fit(
            ASCII_BANNER,
            border_style="bright_cyan",
            title="[bold]Welcome to AI Purple Ops[/bold]",
        )
    )


def show_profile_comparison() -> None:
    """Display comparison table of installation profiles."""
    table = Table(title="Installation Profiles", show_header=True, header_style="bold cyan")
    table.add_column("Feature", style="dim")
    table.add_column("Basic", justify="center")
    table.add_column("Pro (CTF-Ready)", justify="center", style="green")

    # Feature comparison
    features = [
        ("Adversarial Suffix Generation", "✓", "✓"),
        ("7 Production Adapters", "✓", "✓"),
        ("Batch Vulnerability Scanning", "✓", "✓"),
        ("Evidence Reports", "✓", "✓"),
        ("Guardrail Fingerprinting", "✓", "✓"),
        ("", "", ""),  # Separator
        ("CTF Objective-Based Attacks", "✗", "✓"),
        ("Multi-Turn Orchestration", "✗", "✓"),
        ("Context-Aware Probing", "✗", "✓"),
        ("State Machine Strategies", "✗", "✓"),
        ("PyRIT Integration", "✗", "✓"),
        ("Promptfoo Plugins", "✗", "✓"),
        ("", "", ""),  # Separator
        ("Disk Space", "~500MB", "~700MB"),
        ("Installation Time", "< 1 min", "2-3 mins"),
    ]

    for feature, basic, pro in features:
        table.add_row(feature, basic, pro)

    console.print(table)


def show_profile_details(profile_type: ProfileType) -> None:
    """Show detailed information about a profile.

    Args:
        profile_type: Profile to display
    """
    profile = get_profile(profile_type)

    console.print(
        Panel.fit(
            f"[bold]{profile.display_name} Profile[/bold]\n\n"
            f"{profile.description}\n\n"
            f"[bold]Use Cases:[/bold]\n"
            + "\n".join(f"  • {uc}" for uc in profile.use_cases)
            + f"\n\n[bold]Requirements:[/bold]\n"
            f"  • Disk Space: ~{profile.disk_size_mb}MB\n"
            f"  • Python: 3.11+\n"
            + (
                f"  • Additional Dependencies: {len(profile.dependencies)}\n"
                if profile.dependencies
                else ""
            ),
            border_style="cyan",
            title=f"[bold]{profile.display_name}[/bold]",
        )
    )


@app.command("wizard")
def setup_wizard(
    non_interactive: bool = typer.Option(
        False, "--non-interactive", "-y", help="Skip prompts, install Pro profile"
    ),
    profile: str | None = typer.Option(None, "--profile", "-p", help="Profile to install"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
) -> None:
    """Interactive setup wizard for AI Purple Ops.

    Guides you through selecting and installing an installation profile.
    """
    show_welcome_banner()

    # Non-interactive mode: install Pro
    if non_interactive:
        console.print("[cyan]Running in non-interactive mode, installing Pro profile...[/cyan]\n")
        selected_profile = ProfileType.PRO
    elif profile:
        # Profile specified via CLI
        try:
            selected_profile = ProfileType(profile.lower())
            console.print(f"[cyan]Installing {profile} profile...[/cyan]\n")
        except ValueError:
            console.print(f"[red]Error: Invalid profile '{profile}'[/red]")
            console.print("Valid profiles: basic, pro")
            raise typer.Exit(code=1)
    else:
        # Interactive mode
        console.print(
            "\n[bold]AI Purple Ops[/bold] offers different installation profiles based on your needs.\n"
        )

        show_profile_comparison()

        console.print(
            "\n[bold cyan]Which profile would you like to install?[/bold cyan]\n\n"
            "  [bold]basic[/bold]  - Core adversarial testing (recommended for beginners)\n"
            "  [bold]pro[/bold]    - Full CTF capabilities (recommended for security professionals)\n"
            "  [bold]custom[/bold] - Select individual components (advanced users)\n"
        )

        choice = Prompt.ask(
            "\nSelect profile",
            choices=["basic", "pro", "custom"],
            default="pro",
        )

        selected_profile = ProfileType(choice)

        if selected_profile == ProfileType.CUSTOM:
            console.print(
                "\n[yellow]Custom installation not yet implemented.[/yellow]\n"
                "For now, please use: [cyan]pip install -e .[pro][/cyan] or [cyan]pip install -e .[/cyan]\n"
            )
            raise typer.Exit(code=0)

    # Show profile details
    console.print()
    show_profile_details(selected_profile)
    console.print()

    # Confirm installation
    if not non_interactive:
        if not Confirm.ask(f"Install {get_profile(selected_profile).display_name} profile?"):
            console.print("[yellow]Installation cancelled.[/yellow]")
            raise typer.Exit(code=0)

    # Install profile
    profile_obj = get_profile(selected_profile)
    installer = DependencyInstaller(profile_obj, verbose=verbose)

    console.print()
    success = installer.install()

    # Create CTF config if Pro profile
    if success and selected_profile == ProfileType.PRO:
        console.print()
        create_ctf_config()

    # Show summary
    console.print()
    show_installation_summary(profile_obj, success)

    if not success:
        raise typer.Exit(code=1)


@app.command("validate")
def validate_installation(
    profile: str = typer.Option("basic", "--profile", "-p", help="Profile to validate"),
) -> None:
    """Validate that a profile is installed correctly.

    Checks that all required dependencies are available.
    """
    try:
        profile_type = ProfileType(profile.lower())
    except ValueError:
        console.print(f"[red]Error: Invalid profile '{profile}'[/red]")
        console.print("Valid profiles: basic, pro")
        raise typer.Exit(code=1)

    profile_obj = get_profile(profile_type)
    installer = DependencyInstaller(profile_obj)

    console.print(f"\n[bold]Validating {profile_obj.display_name} Profile...[/bold]\n")

    if not profile_obj.dependencies:
        console.print("[green]✓ No additional dependencies required[/green]")
        return

    results = installer.validate_installation()

    table = Table(show_header=True, header_style="bold")
    table.add_column("Package", style="dim")
    table.add_column("Status", justify="center")

    all_installed = True
    for pkg, installed in results.items():
        if installed:
            table.add_row(pkg, "[green]✓ Installed[/green]")
        else:
            table.add_row(pkg, "[red]✗ Missing[/red]")
            all_installed = False

    console.print(table)
    console.print()

    if all_installed:
        console.print(
            f"[green]✓ All {profile_obj.display_name} dependencies are installed![/green]"
        )
    else:
        console.print(
            f"[red]✗ Some dependencies are missing[/red]\n\n"
            f"Run [cyan]aipop setup wizard --profile {profile}[/cyan] to reinstall"
        )
        raise typer.Exit(code=1)


@app.command("profiles")
def list_available_profiles() -> None:
    """List all available installation profiles."""
    console.print("\n[bold]Available Installation Profiles:[/bold]\n")

    for profile in list_profiles():
        console.print(f"[bold cyan]{profile.display_name}[/bold cyan] ({profile.name})")
        console.print(f"  {profile.description}")
        console.print(
            f"  Disk: ~{profile.disk_size_mb}MB | Dependencies: {len(profile.dependencies)}"
        )
        console.print()


if __name__ == "__main__":
    app()
