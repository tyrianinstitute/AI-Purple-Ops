"""CTF attack orchestration system for AI Purple Ops.

This module provides intelligent, context-aware attack capabilities for CTF challenges,
including multi-turn orchestration, state machine planning, and objective-based scoring.
"""

from aipop.experimental.ctf.orchestrator import CTFOrchestrator
from aipop.experimental.ctf.pyrit_bridge import AIPurpleOpsTarget

__all__ = ["AIPurpleOpsTarget", "CTFOrchestrator"]
