"""Intelligence layer for context-aware CTF attacks.

Provides:
- Response parsing (detect tools, hints, partial success)
- State machine (traverse attack strategies)
- Scorers (objective-based success detection)
- Planner (attacker LLM orchestration)
"""

from aipop.ctf.intelligence.planner import AttackerPlanner
from aipop.ctf.intelligence.response_parser import ResponseParser
from aipop.ctf.intelligence.scorers import CTFScorer, MCPInjectionScorer, PromptExtractionScorer
from aipop.ctf.intelligence.state_machine import AttackState, AttackStateMachine

__all__ = [
    "AttackState",
    "AttackStateMachine",
    "AttackerPlanner",
    "CTFScorer",
    "MCPInjectionScorer",
    "PromptExtractionScorer",
    "ResponseParser",
]
