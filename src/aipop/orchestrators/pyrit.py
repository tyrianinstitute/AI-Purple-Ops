"""PyRIT-based orchestrator for multi-turn conversations with DuckDB memory."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

try:
    from pyrit.memory import DuckDBMemory
    from pyrit.memory.memory_models import PromptMemoryEntry
except ImportError:
    DuckDBMemory = None  # type: ignore[assignment,misc]
    PromptMemoryEntry = None  # type: ignore[assignment,misc]

from aipop.core.adapters import Adapter
from aipop.core.models import ModelResponse, TestCase
from aipop.core.orchestrator_config import OrchestratorConfig


class PyRITOrchestrator:
    """Multi-turn orchestrator using PyRIT's proven memory architecture.

    Features:
    - Multi-turn conversation state tracking (5+ turns)
    - DuckDB-backed memory persistence (PyRIT schema)
    - Conversation reset and branching
    - Integration with mutation engine
    - Debug/verbose logging
    - Config hierarchy support

    Configuration:
    - max_turns: Maximum conversation turns (default: 10)
    - db_path: DuckDB file path (default: out/conversations.duckdb)
    - enable_mutations: Enable mutation injection (default: false)
    """

    def __init__(self, config: OrchestratorConfig | None = None) -> None:
        """Initialize PyRIT orchestrator with optional config.

        Args:
            config: Orchestrator configuration (defaults used if None)
        """
        if DuckDBMemory is None:
            raise ImportError(
                "PyRIT is required for this feature. "
                "Install with: pip install ai-purple-ops[pyrit]"
            )
        self.config = config or OrchestratorConfig()

        # Load custom params from config
        self.max_turns = self.config.custom_params.get("max_turns", 10)
        self.context_window = self.config.custom_params.get("context_window", 5)
        self.enable_branching = self.config.custom_params.get("enable_branching", True)
        self.persist_history = self.config.custom_params.get("persist_history", True)
        self.strategy = self.config.custom_params.get("strategy", "multi_turn")

        # Initialize DuckDB memory for conversation persistence
        db_path = self.config.custom_params.get("db_path", "out/conversations.duckdb")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            self.memory = DuckDBMemory(db_path=db_path)
        except Exception as e:
            # Fallback to in-memory if DuckDB fails
            if self.config.debug or self.config.verbose:
                print(f"Warning: Could not initialize DuckDB at {db_path}: {e}")
                print("Falling back to in-memory conversation storage")
            self.memory = None

        # Conversation state
        self._current_conversation_id: str | None = None
        self._conversation_history: list[dict[str, Any]] = []
        self._turn_counter: int = 0
        self._execution_history: list[dict[str, Any]] = []
        self._state: dict[str, Any] = {}

        # Initialize mutation engine if enabled
        self.mutation_engine = None
        self.guardrail_type: str | None = None
        if self.config.custom_params.get("enable_mutations"):
            from aipop.core.mutation_config import MutationConfig
            from aipop.mutators.mutation_engine import MutationEngine

            mutation_config_path = self.config.custom_params.get(
                "mutation_config", "configs/mutation/default.yaml"
            )
            mut_config = MutationConfig.from_file(Path(mutation_config_path))
            try:
                self.mutation_engine = MutationEngine(mut_config)
            except ValueError:
                # Mutation engine disabled if config invalid
                pass

    def execute_prompt(
        self,
        prompt: str,
        test_case: TestCase,
        adapter: Adapter,
        config_override: dict[str, Any] | None = None,
    ) -> ModelResponse:
        """Execute prompt with multi-turn conversation support.

        Args:
            prompt: The prompt text to send
            test_case: Original test case (for metadata/context)
            adapter: Model adapter to invoke
            config_override: Per-call config override (from test metadata)

        Returns:
            ModelResponse with conversation history and orchestration metadata
        """
        # Resolve configuration hierarchy
        effective_config = self._resolve_config(test_case, config_override)

        # Initialize conversation if needed
        if self._current_conversation_id is None:
            self._current_conversation_id = str(uuid.uuid4())
            self._turn_counter = 0
            if effective_config.debug or effective_config.verbose:
                print(f"Started new conversation: {self._current_conversation_id}")

        # Increment turn counter
        self._turn_counter += 1

        # Debug logging
        if effective_config.debug or effective_config.verbose:
            self._log_execution(
                "execute_prompt",
                {
                    "conversation_id": self._current_conversation_id,
                    "turn": self._turn_counter,
                    "prompt_preview": prompt[:100],
                    "test_id": test_case.id,
                    "config": effective_config.__dict__,
                },
            )

        # Build conversation context from history
        context = self._build_context()

        # Apply mutations if enabled
        final_prompt = prompt
        mutation_metadata = {}
        if self.mutation_engine and effective_config.custom_params.get("enable_mutations"):
            mutations = self.mutation_engine.mutate_with_feedback(
                prompt,
                {
                    "test_case": test_case,
                    "optimization_target": test_case.metadata.get("optimization_target", "asr"),
                    "conversation_context": context,
                },
            )

            # Try mutations in order (best first based on RL)
            for mutation in mutations:
                try:
                    mutated_prompt = mutation.mutated
                    adapter_response = adapter.invoke(mutated_prompt)

                    # Record result
                    self.mutation_engine.record_result(
                        {
                            "original": prompt,
                            "mutated": mutation.mutated,
                            "type": mutation.mutation_type,
                            "metadata": mutation.metadata,
                            "test_case_id": test_case.id,
                            "conversation_id": self._current_conversation_id,
                            "turn": self._turn_counter,
                            "success": True,
                            "response": adapter_response.text,
                        }
                    )

                    final_prompt = mutated_prompt
                    mutation_metadata = {
                        "mutation_applied": True,
                        "mutation_type": mutation.mutation_type,
                        "original_prompt": prompt,
                    }
                    break
                except Exception:
                    continue
            else:
                # No mutations succeeded, fall back to original
                adapter_response = adapter.invoke(prompt)
        else:
            # No mutations, use original prompt
            adapter_response = adapter.invoke(prompt)

        response_text = adapter_response.text

        # Store turn in conversation history
        turn_data = {
            "turn": self._turn_counter,
            "prompt": final_prompt,
            "response": response_text,
            "timestamp": time.time(),
            "test_case_id": test_case.id,
            **mutation_metadata,
        }
        self._conversation_history.append(turn_data)

        # Persist to DuckDB if enabled
        if self.memory and self.persist_history:
            try:
                # Create prompt memory entry for PyRIT
                prompt_entry = PromptMemoryEntry(
                    conversation_id=self._current_conversation_id,
                    role="user",
                    content=final_prompt,
                )
                self.memory.add_request_pieces_to_memory([prompt_entry])

                # Create response memory entry
                response_entry = PromptMemoryEntry(
                    conversation_id=self._current_conversation_id,
                    role="assistant",
                    content=response_text,
                )
                self.memory.add_request_pieces_to_memory([response_entry])
            except Exception as e:
                if effective_config.debug or effective_config.verbose:
                    print(f"Warning: Failed to persist to DuckDB: {e}")

        # Build response metadata
        meta = {
            "orchestrator": "pyrit",
            "conversation_id": self._current_conversation_id,
            "turn": self._turn_counter,
            "max_turns": self.max_turns,
            "context_window": self.context_window,
            "config_used": effective_config.__dict__,
            **adapter_response.meta,
            **mutation_metadata,
        }

        if effective_config.debug:
            meta["conversation_history"] = self._conversation_history[-self.context_window :]
            meta["execution_history"] = self._execution_history[-5:]

        return ModelResponse(text=response_text, meta=meta, tool_calls=adapter_response.tool_calls)

    def _build_context(self) -> str:
        """Build conversation context from history for next turn.

        Returns:
            Context string with recent conversation turns
        """
        if not self._conversation_history:
            return ""

        # Get last N turns based on context_window
        recent_turns = self._conversation_history[-self.context_window :]

        context_lines = []
        for turn in recent_turns:
            context_lines.append(f"Turn {turn['turn']}:")
            context_lines.append(f"  User: {turn['prompt'][:200]}")
            context_lines.append(f"  Assistant: {turn['response'][:200]}")

        return "\n".join(context_lines)

    def reset_conversation(self) -> None:
        """Reset current conversation state (start new conversation)."""
        if self.config.debug or self.config.verbose:
            print(f"Resetting conversation: {self._current_conversation_id}")

        self._current_conversation_id = None
        self._conversation_history = []
        self._turn_counter = 0

    def get_conversation_history(self) -> list[dict[str, Any]]:
        """Retrieve all turns for current conversation.

        Returns:
            List of turn data dictionaries with prompts and responses
        """
        return self._conversation_history.copy()

    def branch_conversation(self, turn_id: int) -> None:
        """Create new conversation branch from specific turn.

        Args:
            turn_id: Turn number to branch from (1-indexed)
        """
        if not self.enable_branching:
            raise ValueError("Conversation branching is disabled in config")

        if turn_id < 1 or turn_id > len(self._conversation_history):
            raise ValueError(f"Invalid turn_id: {turn_id}")

        # Create new conversation ID for branch
        old_conversation_id = self._current_conversation_id
        self._current_conversation_id = str(uuid.uuid4())

        # Keep history up to branch point
        self._conversation_history = self._conversation_history[:turn_id]
        self._turn_counter = turn_id

        if self.config.debug or self.config.verbose:
            print(
                f"Branched conversation {old_conversation_id} -> {self._current_conversation_id} at turn {turn_id}"
            )

    def set_conversation_id(self, conversation_id: str) -> None:
        """Continue a previous conversation by ID.

        Args:
            conversation_id: Conversation ID to resume
        """
        if not self.memory or not self.persist_history:
            raise ValueError("Cannot resume conversations without persistent memory")

        # Load conversation history from DuckDB
        try:
            # Query PyRIT memory for conversation
            entries = self.memory.get_prompt_request_pieces(conversation_id=conversation_id)

            # Rebuild conversation history
            self._conversation_history = []
            self._turn_counter = 0
            current_turn_data: dict[str, Any] = {}

            for entry in entries:
                if entry.role == "user":
                    self._turn_counter += 1
                    current_turn_data = {
                        "turn": self._turn_counter,
                        "prompt": entry.content,
                        "test_case_id": None,  # Not stored in PyRIT
                    }
                elif entry.role == "assistant":
                    current_turn_data["response"] = entry.content
                    current_turn_data["timestamp"] = time.time()  # Approximate
                    self._conversation_history.append(current_turn_data)
                    current_turn_data = {}

            self._current_conversation_id = conversation_id

            if self.config.debug or self.config.verbose:
                print(f"Resumed conversation {conversation_id} with {self._turn_counter} turns")

        except Exception as e:
            raise ValueError(f"Failed to load conversation {conversation_id}: {e}") from e

    def _resolve_config(
        self,
        test_case: TestCase,
        override: dict[str, Any] | None,
    ) -> OrchestratorConfig:
        """Resolve configuration using hierarchy.

        Args:
            test_case: Test case with metadata
            override: Per-call config override

        Returns:
            Effective OrchestratorConfig after applying hierarchy
        """
        config = self.config

        # Apply test case metadata override (highest priority)
        test_config = OrchestratorConfig.from_test_metadata(test_case.metadata)
        if test_config:
            config = config.merge(test_config)

        # Apply per-call override
        if override:
            override_config = OrchestratorConfig(**override)
            config = config.merge(override_config)

        return config

    def _log_execution(self, event: str, data: dict[str, Any]) -> None:
        """Log execution event for debugging.

        Args:
            event: Event name
            data: Event data dictionary
        """
        entry = {
            "event": event,
            "timestamp": time.time(),
            **data,
        }
        self._execution_history.append(entry)

        if self.config.verbose:
            print(f"[PyRIT Orchestrator] {event}: {data}")

    def set_guardrail_type(self, guardrail_type: str) -> None:
        """Update orchestration strategy based on detected guardrail.

        Args:
            guardrail_type: Detected guardrail type (promptguard, llama_guard_3, etc.)
        """
        self.guardrail_type = guardrail_type

        # Configure mutation engine with guardrail-specific optimization
        if self.mutation_engine:
            self.mutation_engine.set_guardrail_optimization(guardrail_type)

            if self.config.debug or self.config.verbose:
                strategy_info = self.mutation_engine.get_strategy_info()
                print(f"[PyRIT Orchestrator] Optimized for {guardrail_type}")
                print(
                    f"[PyRIT Orchestrator] Priority mutators: {', '.join(strategy_info['priority_mutators'])}"
                )

        # Adjust max_turns for guardrails that require multi-turn attacks
        if guardrail_type == "llama_guard_3":
            self.max_turns = max(self.max_turns, 5)  # Category-based requires more turns
        elif guardrail_type == "constitutional_ai":
            self.max_turns = max(self.max_turns, 7)  # Gradual escalation needs many turns

    def reset_state(self) -> None:
        """Reset conversation state between test cases."""
        self.reset_conversation()
        self._state.clear()
        if self.config.debug:
            self._execution_history.clear()

    def get_debug_info(self) -> dict[str, Any]:
        """Return current orchestrator state for debugging.

        Returns:
            Dictionary with state, config, and execution history
        """
        return {
            "orchestrator_type": "pyrit",
            "config": self.config.__dict__,
            "conversation_id": self._current_conversation_id,
            "turn_counter": self._turn_counter,
            "conversation_history": self._conversation_history,
            "state": self._state,
            "execution_history": self._execution_history,
            "total_executions": len(self._execution_history),
            "context_window": self.context_window,
            "max_turns": self.max_turns,
        }

    def get_raw_memory(self):
        """Get raw PyRIT memory for bleeding-edge features and advanced use cases.

        This escape hatch allows direct access to PyRIT internals, enabling
        use of bleeding-edge PyRIT features without waiting for AI Purple Ops updates.

        Returns:
            DuckDBMemory: Raw PyRIT memory object (or None if memory initialization failed)

        Example:
            >>> orchestrator = PyRITOrchestrator(config=config)
            >>> raw_memory = orchestrator.get_raw_memory()
            >>>
            >>> # Use brand new PyRIT feature directly
            >>> from pyrit.scorer import BrandNewScorer  # PyRIT v0.10+ feature
            >>> scorer = BrandNewScorer()
            >>> raw_memory.add_scorer(scorer)  # Works immediately, no AI Purple Ops update needed
        """
        return self.memory

    def __getattr__(self, name: str):
        """Auto-passthrough for PyRIT methods not explicitly wrapped.

        This ensures bleeding-edge PyRIT features work immediately without
        AI Purple Ops updates. If a method/attribute isn't found on
        PyRITOrchestrator, it's forwarded to the underlying PyRIT memory.

        Args:
            name: Attribute/method name to look up

        Returns:
            Attribute from PyRIT memory if found

        Raises:
            AttributeError: If attribute not found on PyRITOrchestrator or PyRIT memory

        Example:
            >>> orchestrator = PyRITOrchestrator(config=config)
            >>>
            >>> # PyRIT v0.10 adds new method tomorrow
            >>> orchestrator.brand_new_pyrit_method()  # Auto-forwards to memory.brand_new_pyrit_method()
        """
        # Avoid infinite recursion for private attributes
        if name.startswith("_"):
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

        # Try forwarding to PyRIT memory
        if self.memory is not None and hasattr(self.memory, name):
            attr = getattr(self.memory, name)
            # If callable, wrap to maintain context
            if callable(attr):

                def wrapper(*args, **kwargs):
                    return attr(*args, **kwargs)

                return wrapper
            return attr

        raise AttributeError(
            f"'{type(self).__name__}' object has no attribute '{name}'. "
            f"Not found in PyRIT memory either. "
            f"For bleeding-edge PyRIT features, use orchestrator.get_raw_memory() for direct access."
        )
