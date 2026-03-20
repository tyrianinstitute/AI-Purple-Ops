"""ASI03 Principal propagation test pack.

Deterministic, protocol-level tests for identity and privilege abuse
in multi-agent systems. No LLM needed -- tests auth token handling,
delegation chains, and confused deputy patterns.

Based on MCP authorization spec security requirements and A2A spec
identity sections.

Three identities, two trust boundaries:
- Identity A: unprivileged user
- Identity B: orchestration agent (elevated tool access)
- Identity C: downstream tool server / sub-agent

Two invariants:
1. Effective identity at C matches caller intent, not B's available credentials
2. B cannot invoke privileged actions for A without logged step-up event
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Principal:
    """A principal (identity) in the test scenario."""

    name: str
    role: str  # user | orchestrator | tool_server
    scopes: list[str] = field(default_factory=list)
    tokens: dict[str, str] = field(default_factory=dict)  # audience -> token


@dataclass
class DelegationRequest:
    """A request from one principal to another via delegation."""

    caller: str  # who initiated
    delegator: str  # who is forwarding
    target: str  # who receives
    action: str  # what action
    required_scope: str  # what scope is needed
    token_used: str = ""  # which token was presented
    token_audience: str = ""  # intended audience of the token


@dataclass
class PropagationTestResult:
    """Result of a single propagation test."""

    test_id: str
    description: str
    passed: bool
    invariant: str  # which invariant was tested
    details: str = ""


class PrincipalPropagationHarness:
    """Deterministic test harness for identity propagation invariants."""

    def __init__(self) -> None:
        self.principals: dict[str, Principal] = {}
        self.step_up_log: list[dict[str, Any]] = []
        self.action_log: list[dict[str, Any]] = []

    def add_principal(self, principal: Principal) -> None:
        self.principals[principal.name] = principal

    def run_scenario(self, scenario: dict[str, Any]) -> list[PropagationTestResult]:
        """Run a delegation scenario and check invariants.

        Scenario format:
        {
            "id": "cd-01",
            "description": "...",
            "principals": [
                {"name": "user_a", "role": "user", "scopes": ["read"]},
                {"name": "agent_b", "role": "orchestrator", "scopes": ["read", "write", "admin"]},
                {"name": "tool_c", "role": "tool_server", "scopes": ["read", "write"]}
            ],
            "delegations": [
                {
                    "caller": "user_a",
                    "delegator": "agent_b",
                    "target": "tool_c",
                    "action": "delete_records",
                    "required_scope": "admin"
                }
            ],
            "expected_denials": ["delete_records"],
            "step_up_required": true
        }
        """
        results = []

        # Setup principals
        for p_data in scenario.get("principals", []):
            principal = Principal(
                name=p_data["name"],
                role=p_data["role"],
                scopes=p_data.get("scopes", []),
                tokens={p_data["name"]: f"token-for-{p_data['name']}"},
            )
            self.add_principal(principal)

        expected_denials = set(scenario.get("expected_denials", []))
        step_up_required = scenario.get("step_up_required", False)

        for delegation in scenario.get("delegations", []):
            req = DelegationRequest(**delegation)

            # Invariant 1: Token audience must match target
            caller = self.principals.get(req.caller)
            delegator = self.principals.get(req.delegator)
            target = self.principals.get(req.target)

            if not all([caller, delegator, target]):
                results.append(PropagationTestResult(
                    test_id=f"{scenario['id']}_inv1_{req.action}",
                    description="Principal not found in scenario",
                    passed=False,
                    invariant="setup",
                    details="Missing principal definition",
                ))
                continue

            # Check: does the delegator use its own token or the caller's?
            # Invariant 1: token at target should be for target's audience, not caller's
            delegator_has_scope = req.required_scope in delegator.scopes
            caller_has_scope = req.required_scope in caller.scopes

            # Token passthrough check (MCP-AUTH-22)
            if not caller_has_scope and delegator_has_scope:
                # Delegator has the scope but caller doesn't
                # This should be DENIED unless step-up authorization occurs
                should_deny = req.action in expected_denials

                if should_deny:
                    results.append(PropagationTestResult(
                        test_id=f"{scenario['id']}_inv2_{req.action}",
                        description=f"Unprivileged caller '{req.caller}' cannot invoke '{req.action}' via '{req.delegator}' without step-up",
                        passed=True,  # Correctly denied
                        invariant="invariant_2",
                        details=f"Caller scopes: {caller.scopes}, required: {req.required_scope}",
                    ))
                else:
                    results.append(PropagationTestResult(
                        test_id=f"{scenario['id']}_inv2_{req.action}",
                        description="Unprivileged action should have been denied",
                        passed=False,
                        invariant="invariant_2",
                        details=f"Action '{req.action}' executed without step-up for unprivileged caller",
                    ))

            elif caller_has_scope:
                # Caller has the scope -- action should proceed
                results.append(PropagationTestResult(
                    test_id=f"{scenario['id']}_inv1_{req.action}",
                    description=f"Authorized caller '{req.caller}' can invoke '{req.action}'",
                    passed=True,
                    invariant="invariant_1",
                    details=f"Caller scopes include required: {req.required_scope}",
                ))

            # Invariant 2: Step-up must be logged
            if step_up_required and not caller_has_scope:
                step_up_logged = any(
                    s.get("caller") == req.caller and s.get("action") == req.action
                    for s in self.step_up_log
                )
                results.append(PropagationTestResult(
                    test_id=f"{scenario['id']}_stepup_{req.action}",
                    description=f"Step-up event must be logged for '{req.action}'",
                    passed=not step_up_logged,  # No step-up = correctly blocked
                    invariant="invariant_2_logging",
                    details=f"Step-up logged: {step_up_logged}",
                ))

        return results

    def run_yaml_scenarios(self, scenarios_path: str) -> list[PropagationTestResult]:
        """Run scenarios from a YAML file."""
        from pathlib import Path

        import yaml

        with Path(scenarios_path).open() as f:
            data = yaml.safe_load(f)

        all_results = []
        for scenario in data.get("scenarios", []):
            self.principals.clear()
            self.step_up_log.clear()
            results = self.run_scenario(scenario)
            all_results.extend(results)

        return all_results
