"""Simple orchestrator implementation for single-turn conversations."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from aipop.core.adapters import Adapter
from aipop.core.models import ModelResponse, TestCase
from aipop.core.orchestrator_config import OrchestratorConfig


class SimpleOrchestrator:
    """Basic single-turn orchestrator with configuration support.

    This is the simplest orchestrator - it just passes prompts directly
    to the adapter. Useful for backward compatibility and baseline testing.

    Supports:
    - Configuration hierarchy (test metadata > instance config > defaults)
    - Debug mode (logs all decisions)
    - Per-test overrides via metadata
    - Programmatic API for scripting
    """

    def __init__(self, config: OrchestratorConfig | None = None) -> None:
        """Initialize simple orchestrator with optional config.

        Args:
            config: Orchestrator configuration (defaults used if None)
        """
        self.config = config or OrchestratorConfig()
        self._execution_history: list[dict[str, Any]] = []
        self._state: dict[str, Any] = {}
        self.mutation_engine = None
        self.guardrail_type: str | None = None

        # Initialize mutation engine if enabled
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
                # Mutation engine disabled if config invalid (e.g., missing API key)
                pass

    def execute_prompt(
        self,
        prompt: str,
        test_case: TestCase,
        adapter: Adapter,
        config_override: dict[str, Any] | None = None,
    ) -> ModelResponse:
        """Execute prompt with config support and debug logging.

        Args:
            prompt: The prompt text to send
            test_case: Original test case (for metadata/context)
            adapter: Model adapter to invoke
            config_override: Per-call config override (from test metadata)

        Returns:
            ModelResponse with orchestration metadata
        """
        # Resolve configuration hierarchy
        effective_config = self._resolve_config(test_case, config_override)

        # Debug logging
        if effective_config.debug or effective_config.verbose:
            self._log_execution(
                "execute_prompt",
                {
                    "prompt_preview": prompt[:100],
                    "test_id": test_case.id,
                    "config": effective_config.__dict__,
                },
            )

        # Execute prompt (simple orchestrator just passes through)
        try:
            # Apply mutations if enabled
            if self.mutation_engine and effective_config.custom_params.get("enable_mutations"):
                mutations = self.mutation_engine.mutate_with_feedback(
                    prompt,
                    {
                        "test_case": test_case,
                        "optimization_target": test_case.metadata.get("optimization_target", "asr"),
                    },
                )

                # Try mutations in order (best first based on RL)
                for mutation in mutations:
                    try:
                        mutated_response = adapter.invoke(mutation.mutated)
                        # Record result
                        self.mutation_engine.record_result(
                            {
                                "original": prompt,
                                "mutated": mutation.mutated,
                                "type": mutation.mutation_type,
                                "metadata": mutation.metadata,
                                "test_case_id": test_case.id,
                                "success": True,  # Determine based on response
                                "response": mutated_response.text,
                            }
                        )
                        # Return first successful mutation response
                        response_text = mutated_response.text
                        adapter_response = mutated_response
                        break
                    except Exception:
                        continue
                else:
                    # No mutations succeeded, fall back to original
                    adapter_response = adapter.invoke(prompt)
                    response_text = adapter_response.text
            else:
                # No mutations, use original prompt
                adapter_response = adapter.invoke(prompt)
                response_text = adapter_response.text

            # Build response with orchestration metadata
            meta = {
                "orchestrator": "simple",
                "config_used": effective_config.__dict__,
                **adapter_response.meta,  # Include adapter metadata
            }

            if effective_config.debug:
                meta["execution_history"] = self._execution_history[-5:]  # Last 5 entries

            return ModelResponse(
                text=response_text, meta=meta, tool_calls=adapter_response.tool_calls
            )

        except Exception as e:
            if effective_config.debug:
                self._log_execution("error", {"error": str(e), "test_id": test_case.id})
            raise

    def _resolve_config(
        self,
        test_case: TestCase,
        override: dict[str, Any] | None,
    ) -> OrchestratorConfig:
        """Resolve configuration using hierarchy: test metadata > override > instance > defaults.

        Args:
            test_case: Test case with metadata
            override: Per-call config override

        Returns:
            Effective OrchestratorConfig after applying hierarchy
        """
        # Start with instance config
        config = self.config

        # Apply test case metadata override (highest priority)
        test_config = OrchestratorConfig.from_test_metadata(test_case.metadata)
        if test_config:
            config = config.merge(test_config)

        # Apply per-call override (if provided)
        if override:
            override_config = OrchestratorConfig(**override)
            config = config.merge(override_config)

        return config

    def _log_execution(self, event: str, data: dict[str, Any]) -> None:
        """Log execution event for debugging.

        Args:
            event: Event name (e.g., "execute_prompt", "error")
            data: Event data dictionary
        """
        entry = {
            "event": event,
            "timestamp": time.time(),
            **data,
        }
        self._execution_history.append(entry)

    def reset_state(self) -> None:
        """Reset conversation state between test cases."""
        self._state.clear()
        if self.config.debug:
            self._execution_history.clear()

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
                print(f"[Orchestrator] Optimized for {guardrail_type}")
                print(
                    f"[Orchestrator] Priority mutators: {', '.join(strategy_info['priority_mutators'])}"
                )
                print(f"[Orchestrator] Mutator order: {strategy_info['mutator_order']}")

    def get_debug_info(self) -> dict[str, Any]:
        """Return current orchestrator state for debugging.

        Returns:
            Dictionary with state, config, and execution history
        """
        return {
            "orchestrator_type": "simple",
            "config": self.config.__dict__,
            "state": self._state,
            "execution_history": self._execution_history,
            "total_executions": len(self._execution_history),
        }
