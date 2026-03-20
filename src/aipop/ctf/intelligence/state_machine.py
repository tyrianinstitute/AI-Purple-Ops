"""Attack state machine for CTF orchestration.

Manages state transitions during multi-turn attacks, tracking:
- Current state (RECONNAISSANCE, DIRECT_ATTACK, etc.)
- Knowledge base (what we've learned)
- Visited states (avoid loops)
- Transition logic (when to pivot)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AttackState(str, Enum):
    """Attack states during CTF orchestration."""

    # Universal states
    RECONNAISSANCE = "RECONNAISSANCE"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"

    # Prompt extraction states
    DIRECT_EXTRACTION = "DIRECT_EXTRACTION"
    INDIRECT_EXTRACTION = "INDIRECT_EXTRACTION"
    GRADUAL_EXTRACTION = "GRADUAL_EXTRACTION"
    META_QUESTIONS = "META_QUESTIONS"

    # MCP/Tool abuse states
    TOOL_DISCOVERY = "TOOL_DISCOVERY"
    PARAMETER_INJECTION = "PARAMETER_INJECTION"
    DIRECT_INJECTION = "DIRECT_INJECTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"

    # Encoding/Bypass states
    ENCODING_BYPASS = "ENCODING_BYPASS"

    # Indirect/RAG states
    CONTEXT_INJECTION = "CONTEXT_INJECTION"
    CITATION_MANIPULATION = "CITATION_MANIPULATION"
    MULTI_TURN_POISONING = "MULTI_TURN_POISONING"

    # Tool policy bypass
    PERMISSION_BYPASS = "PERMISSION_BYPASS"
    PARAMETER_MANIPULATION = "PARAMETER_MANIPULATION"
    FUNCTION_CALLING_ABUSE = "FUNCTION_CALLING_ABUSE"

    # Context attacks
    CONTEXT_OVERFLOW = "CONTEXT_OVERFLOW"
    DELIMITER_CONFUSION = "DELIMITER_CONFUSION"
    MEMORY_CORRUPTION = "MEMORY_CORRUPTION"

    # RAG poisoning
    VECTOR_POISONING = "VECTOR_POISONING"
    RETRIEVAL_MANIPULATION = "RETRIEVAL_MANIPULATION"
    METADATA_INJECTION = "METADATA_INJECTION"


@dataclass
class KnowledgeBase:
    """Knowledge accumulated during attack."""

    tools_discovered: list[str] = field(default_factory=list)
    secrets_partial: list[str] = field(default_factory=list)
    encoding_hints: list[str] = field(default_factory=list)
    denial_count: int = 0
    partial_success_count: int = 0
    capitalized_words: list[str] = field(default_factory=list)
    custom_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class StateTransition:
    """Represents a state transition."""

    from_state: AttackState
    to_state: AttackState
    condition: str
    priority: int = 0


class AttackStateMachine:
    """State machine for adaptive CTF attacks.

    Manages state transitions based on response analysis and knowledge base.
    """

    def __init__(
        self,
        strategy_name: str,
        state_transitions: dict[str, list[str]] | None = None,
        initial_state: AttackState = AttackState.RECONNAISSANCE,
    ) -> None:
        """Initialize state machine.

        Args:
            strategy_name: Name of the attack strategy
            state_transitions: Dict mapping states to possible next states
            initial_state: Starting state
        """
        self.strategy_name = strategy_name
        self.current_state = initial_state
        self.state_history: list[AttackState] = [initial_state]
        self.knowledge_base = KnowledgeBase()

        # Parse state transitions
        self.transitions: dict[AttackState, list[AttackState]] = {}
        if state_transitions:
            for state_str, next_states_str in state_transitions.items():
                try:
                    state = AttackState(state_str)
                    next_states = [AttackState(ns) for ns in next_states_str]
                    self.transitions[state] = next_states
                except ValueError:
                    # Skip invalid states
                    pass

    def transition_to(self, new_state: AttackState, reason: str = "") -> bool:
        """Transition to a new state.

        Args:
            new_state: State to transition to
            reason: Reason for transition (for logging)

        Returns:
            True if transition was successful, False if invalid
        """
        # Check if transition is valid
        valid_next_states = self.transitions.get(self.current_state, [])

        # Always allow transition to SUCCESS or FAILED
        if new_state in (AttackState.SUCCESS, AttackState.FAILED):
            self.current_state = new_state
            self.state_history.append(new_state)
            return True

        # Check if new_state is in valid transitions
        if valid_next_states and new_state not in valid_next_states:
            # Invalid transition
            return False

        # Transition
        self.current_state = new_state
        self.state_history.append(new_state)

        return True

    def get_next_state_suggestions(
        self,
        parsed_response: Any,
    ) -> list[tuple[AttackState, float]]:
        """Get suggested next states based on parsed response.

        Args:
            parsed_response: Parsed response from ResponseParser

        Returns:
            List of (state, confidence) tuples sorted by confidence
        """
        suggestions: list[tuple[AttackState, float]] = []

        # Get valid next states
        valid_next = self.transitions.get(self.current_state, [])
        if not valid_next:
            return suggestions

        # Analyze response to determine best next state
        if hasattr(parsed_response, "success_indicators") and parsed_response.success_indicators:
            # Success!
            suggestions.append((AttackState.SUCCESS, 1.0))
            return suggestions

        if hasattr(parsed_response, "tools_detected") and parsed_response.tools_detected:
            # Tools found, prioritize tool-related states
            if AttackState.TOOL_DISCOVERY in valid_next:
                suggestions.append((AttackState.TOOL_DISCOVERY, 0.9))
            if AttackState.PARAMETER_INJECTION in valid_next:
                suggestions.append((AttackState.PARAMETER_INJECTION, 0.8))

        if hasattr(parsed_response, "denial_detected") and parsed_response.denial_detected:
            # Denied, try alternative approaches
            self.knowledge_base.denial_count += 1

            if AttackState.ENCODING_BYPASS in valid_next:
                suggestions.append((AttackState.ENCODING_BYPASS, 0.7))
            if AttackState.INDIRECT_EXTRACTION in valid_next:
                suggestions.append((AttackState.INDIRECT_EXTRACTION, 0.7))

        if hasattr(parsed_response, "partial_success") and parsed_response.partial_success:
            # Partial success, continue current approach
            self.knowledge_base.partial_success_count += 1

            if AttackState.GRADUAL_EXTRACTION in valid_next:
                suggestions.append((AttackState.GRADUAL_EXTRACTION, 0.8))

        # If no strong signals, try all valid next states with equal priority
        if not suggestions:
            for state in valid_next:
                if state not in (AttackState.SUCCESS, AttackState.FAILED):
                    suggestions.append((state, 0.5))

        # Sort by confidence
        suggestions.sort(key=lambda x: x[1], reverse=True)

        return suggestions

    def update_knowledge(self, parsed_response: Any) -> None:
        """Update knowledge base from parsed response.

        Args:
            parsed_response: Parsed response from ResponseParser
        """
        if hasattr(parsed_response, "tools_detected"):
            for tool in parsed_response.tools_detected:
                if tool not in self.knowledge_base.tools_discovered:
                    self.knowledge_base.tools_discovered.append(tool)

        if hasattr(parsed_response, "capitalized_words"):
            for word in parsed_response.capitalized_words:
                if word not in self.knowledge_base.capitalized_words:
                    self.knowledge_base.capitalized_words.append(word)

        if hasattr(parsed_response, "hints"):
            for hint in parsed_response.hints:
                if hint.startswith("encoding:"):
                    enc = hint.split(":")[1]
                    if enc not in self.knowledge_base.encoding_hints:
                        self.knowledge_base.encoding_hints.append(enc)

    def is_terminal_state(self) -> bool:
        """Check if current state is terminal.

        Returns:
            True if in SUCCESS or FAILED state
        """
        return self.current_state in (AttackState.SUCCESS, AttackState.FAILED)

    def has_visited_state(self, state: AttackState) -> bool:
        """Check if a state has been visited.

        Args:
            state: State to check

        Returns:
            True if state has been visited
        """
        return state in self.state_history

    def get_state_loop_count(self, state: AttackState) -> int:
        """Get how many times a state has been visited.

        Args:
            state: State to count

        Returns:
            Number of times state was visited
        """
        return self.state_history.count(state)

    def should_give_up(self, max_denials: int = 5, max_same_state: int = 3) -> bool:
        """Check if attack should be abandoned.

        Args:
            max_denials: Maximum number of denials before giving up
            max_same_state: Maximum times to visit same state

        Returns:
            True if attack should be abandoned
        """
        # Too many denials
        if self.knowledge_base.denial_count >= max_denials:
            return True

        # Stuck in loop
        if self.get_state_loop_count(self.current_state) >= max_same_state:
            return True

        return False

    def get_summary(self) -> dict[str, Any]:
        """Get summary of state machine status.

        Returns:
            Dict with state machine summary
        """
        return {
            "strategy": self.strategy_name,
            "current_state": self.current_state.value,
            "states_visited": len(set(self.state_history)),
            "total_transitions": len(self.state_history) - 1,
            "tools_discovered": len(self.knowledge_base.tools_discovered),
            "denial_count": self.knowledge_base.denial_count,
            "partial_success_count": self.knowledge_base.partial_success_count,
            "is_terminal": self.is_terminal_state(),
        }
