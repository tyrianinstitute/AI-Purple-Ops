"""Attacker LLM configuration for CTF orchestration.

Manages configuration for the attacker model that plans and generates attacks.
Supports both dedicated attacker models and fallback to primary adapter.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from rich.console import Console

if TYPE_CHECKING:
    from aipop.core.adapters import Adapter

console = Console()


@dataclass
class AttackerConfig:
    """Configuration for attacker LLM."""

    model: str
    provider: str
    api_key_env: str
    fallback_to_primary: bool = True
    max_turns: int = 20
    timeout_seconds: int = 300
    enable_caching: bool = True
    cost_warning_threshold: float = 5.0


@dataclass
class OrchestrationConfig:
    """Configuration for CTF orchestration."""

    max_turns: int = 20
    timeout_seconds: int = 300
    enable_caching: bool = True
    cost_warning_threshold: float = 5.0


@dataclass
class CTFConfig:
    """Complete CTF configuration."""

    attacker: AttackerConfig
    orchestration: OrchestrationConfig
    strategies: dict[str, Any]
    output: dict[str, Any]


def load_ctf_config(config_path: Path | str | None = None) -> CTFConfig:
    """Load CTF configuration from YAML file.

    Args:
        config_path: Path to config file (default: ~/.aipop/ctf_config.yaml)

    Returns:
        CTFConfig instance

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid
    """
    if config_path is None:
        config_path = Path.home() / ".aipop" / "ctf_config.yaml"
    else:
        config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(
            f"CTF config not found: {config_path}\n"
            f"Run 'aipop setup wizard --profile pro' to create it"
        )

    with config_path.open() as f:
        data = yaml.safe_load(f)

    # Parse attacker config
    attacker_data = data.get("attacker", {})
    attacker = AttackerConfig(
        model=attacker_data.get("model", "gpt-4"),
        provider=attacker_data.get("provider", "openai"),
        api_key_env=attacker_data.get("api_key_env", "OPENAI_API_KEY"),
        fallback_to_primary=attacker_data.get("fallback_to_primary", True),
    )

    # Parse orchestration config
    orch_data = data.get("orchestration", {})
    orchestration = OrchestrationConfig(
        max_turns=orch_data.get("max_turns", 20),
        timeout_seconds=orch_data.get("timeout_seconds", 300),
        enable_caching=orch_data.get("enable_caching", True),
        cost_warning_threshold=orch_data.get("cost_warning_threshold", 5.0),
    )

    # Parse strategies and output
    strategies = data.get("strategies", {})
    output = data.get("output", {})

    return CTFConfig(
        attacker=attacker,
        orchestration=orchestration,
        strategies=strategies,
        output=output,
    )


def create_attacker_adapter(
    config: AttackerConfig,
    primary_adapter: Adapter | None = None,
) -> Adapter:
    """Create attacker adapter from configuration.

    Args:
        config: Attacker configuration
        primary_adapter: Primary adapter to fallback to if attacker unavailable

    Returns:
        Adapter instance for attacker LLM

    Raises:
        ValueError: If attacker cannot be created and no fallback available
    """
    from aipop.adapters.registry import AdapterRegistry

    # Check if API key is available
    api_key = os.getenv(config.api_key_env)

    if not api_key:
        if config.fallback_to_primary and primary_adapter:
            console.print(
                f"[yellow]⚠️  {config.api_key_env} not set, using primary adapter as attacker[/yellow]"
            )
            return primary_adapter
        raise ValueError(
            f"Attacker API key not found: {config.api_key_env}\n"
            f"Set it with: export {config.api_key_env}=your_key_here"
        )

    # Create adapter based on provider
    try:
        registry = AdapterRegistry()

        # Map provider to adapter name
        provider_map = {
            "openai": "openai",
            "anthropic": "anthropic",
            "ollama": "ollama",
            "huggingface": "huggingface",
        }

        adapter_name = provider_map.get(config.provider)
        if not adapter_name:
            raise ValueError(f"Unsupported attacker provider: {config.provider}")

        # Get adapter class
        adapter_class = registry.get(adapter_name)

        # Create instance with model
        adapter = adapter_class(model_name=config.model)

        console.print(f"[green]✓[/green] Attacker LLM: {config.provider}/{config.model}")

        return adapter

    except Exception as e:
        if config.fallback_to_primary and primary_adapter:
            console.print(
                f"[yellow]⚠️  Failed to create attacker adapter: {e}[/yellow]\n"
                f"[yellow]   Using primary adapter as fallback[/yellow]"
            )
            return primary_adapter
        raise ValueError(f"Failed to create attacker adapter: {e}") from e


def get_default_config() -> CTFConfig:
    """Get default CTF configuration.

    Returns:
        Default CTFConfig instance
    """
    return CTFConfig(
        attacker=AttackerConfig(
            model="gpt-4",
            provider="openai",
            api_key_env="OPENAI_API_KEY",
            fallback_to_primary=True,
        ),
        orchestration=OrchestrationConfig(
            max_turns=20,
            timeout_seconds=300,
            enable_caching=True,
            cost_warning_threshold=5.0,
        ),
        strategies={
            "mcp_injection": {
                "max_tool_attempts": 10,
                "detect_tools_first": True,
            },
            "prompt_extraction": {
                "use_gradual_extraction": True,
                "max_characters_per_turn": 50,
            },
            "indirect_injection": {
                "max_rag_documents": 5,
                "test_citations": True,
            },
        },
        output={
            "export_conversations": True,
            "export_dir": str(Path.home() / ".aipop" / "ctf_sessions"),
            "show_cost_breakdown": True,
            "show_state_transitions": True,
        },
    )
