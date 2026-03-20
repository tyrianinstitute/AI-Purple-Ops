"""Base classes for attack plugins.

All official attack wrappers inherit from AttackPlugin and implement
the standardized interface for execution, cost estimation, and availability checking.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class CostEstimate:
    """Estimated cost for running an attack."""

    total_usd: float
    """Total estimated cost in USD"""

    breakdown: dict[str, float] = field(default_factory=dict)
    """Cost breakdown by component (e.g., attacker_llm, target_llm, judge)"""

    num_queries: int = 0
    """Estimated number of API queries"""

    confidence: str = "medium"
    """Confidence level: low, medium, high"""

    notes: list[str] = field(default_factory=list)
    """Additional notes about cost estimation"""


@dataclass
class AttackResult:
    """Result from running an attack plugin."""

    success: bool
    """Whether the attack succeeded"""

    adversarial_prompts: list[str]
    """Generated adversarial prompts/suffixes"""

    scores: list[float]
    """Score for each prompt (e.g., fitness, loss, ASR)"""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Additional metadata (iterations, convergence, etc.)"""

    cost: float = 0.0
    """Actual cost incurred in USD"""

    num_queries: int = 0
    """Actual number of API queries made"""

    execution_time: float = 0.0
    """Execution time in seconds"""

    error: str | None = None
    """Error message if attack failed"""


@dataclass
class PluginInfo:
    """Information about an installed plugin."""

    name: str
    """Plugin name (gcg, pair, autodan)"""

    installed: bool
    """Whether plugin is installed"""

    version: str | None = None
    """Version of the official implementation"""

    repo_url: str | None = None
    """URL of the official repository"""

    install_path: Path | None = None
    """Path to plugin installation"""

    venv_path: Path | None = None
    """Path to plugin's virtual environment"""

    last_updated: datetime | None = None
    """Last update timestamp"""

    dependencies: list[str] = field(default_factory=list)
    """List of major dependencies"""

    known_issues: list[str] = field(default_factory=list)
    """Known limitations or issues"""


class AttackPlugin(ABC):
    """Base class for attack plugins.

    All official attack implementations (GCG, PAIR, AutoDAN) must inherit
    from this class and implement the abstract methods.
    """

    @abstractmethod
    def name(self) -> str:
        """Return plugin name (gcg, pair, autodan)."""

    @abstractmethod
    def check_available(self) -> tuple[bool, str]:
        """Check if plugin dependencies are available.

        Returns:
            Tuple of (is_available, error_message).
            If available, error_message is empty string.
        """

    @abstractmethod
    def run(self, config: dict[str, Any]) -> AttackResult:
        """Execute the attack with given configuration.

        Args:
            config: Attack configuration dictionary containing:
                - prompt: Target prompt to attack
                - target: Desired model response
                - model: Model identifier
                - adapter: Adapter type (openai, anthropic, etc.)
                - method-specific parameters

        Returns:
            AttackResult containing generated adversarial content and metrics.
        """

    @abstractmethod
    def estimate_cost(self, config: dict[str, Any]) -> CostEstimate:
        """Estimate API costs before running the attack.

        Args:
            config: Same config dict that would be passed to run()

        Returns:
            CostEstimate with projected costs and query counts.
        """

    def get_info(self) -> PluginInfo:
        """Get information about this plugin.

        Default implementation returns basic info. Override for more details.
        """
        is_available, error_msg = self.check_available()
        return PluginInfo(
            name=self.name(),
            installed=is_available,
            known_issues=[error_msg] if error_msg else [],
        )
