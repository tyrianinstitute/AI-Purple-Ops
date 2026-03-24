"""CTF attack strategies.

Maps objectives to specific attack implementations, payloads, and scorers.
"""

from aipop.experimental.ctf.strategies.registry import StrategyRegistry, get_strategy

__all__ = ["StrategyRegistry", "get_strategy"]
