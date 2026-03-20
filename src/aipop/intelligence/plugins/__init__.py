"""Plugin system for wrapping official attack implementations.

This module provides a plugin architecture for integrating battle-tested
adversarial attack implementations (GCG, PAIR, AutoDAN) while maintaining
dependency isolation through subprocess execution.
"""

from aipop.intelligence.plugins.base import (
    AttackPlugin,
    AttackResult,
    CostEstimate,
    PluginInfo,
)

__all__ = [
    "AttackPlugin",
    "AttackResult",
    "CostEstimate",
    "PluginInfo",
]
