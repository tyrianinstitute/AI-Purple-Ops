"""Multi-agent scenario runner for ASI03/ASI07 testing.

Lightweight runner with 2-3 mock agents passing messages via JSON-RPC.
ASI03 scenarios test delegation with real identity propagation.
ASI07 scenarios test message tampering injection points.
Evidence captures the full message trace with identity/scope at each boundary.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentIdentity:
    """Identity of an agent in the topology."""
    name: str
    role: str  # orchestrator | worker | tool_server
    scopes: list[str] = field(default_factory=list)
    token: str = ""

    def __post_init__(self) -> None:
        if not self.token:
            self.token = f"token-{self.name}-{uuid.uuid4().hex[:8]}"


@dataclass
class AgentMessage:
    """A message between agents."""
    id: str
    sender: str
    receiver: str
    method: str
    params: dict[str, Any] = field(default_factory=dict)
    auth_token: str = ""
    sender_scopes: list[str] = field(default_factory=list)


@dataclass
class MessageTraceEntry:
    """A single entry in the message trace."""
    message: AgentMessage
    boundary: str  # Which trust boundary was crossed
    identity_at_boundary: str  # Who the receiver thinks sent it
    scopes_at_boundary: list[str]  # What scopes the receiver sees
    tampered: bool = False
    tampering_type: str = ""


@dataclass
class ScenarioResult:
    """Result of running a multi-agent scenario."""
    scenario_id: str
    passed: bool
    trace: list[MessageTraceEntry] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    details: str = ""


class MockAgent:
    """A mock agent that processes messages and enforces identity rules."""

    def __init__(self, identity: AgentIdentity) -> None:
        self.identity = identity
        self.received_messages: list[AgentMessage] = []

    def receive(self, message: AgentMessage) -> dict[str, Any]:
        """Process an incoming message and validate identity/scope."""
        self.received_messages.append(message)

        # Validate the auth token is for THIS agent (audience binding)
        if message.auth_token and not message.auth_token.startswith(f"token-{self.identity.name}"):
            return {"status": "rejected", "reason": "token audience mismatch"}

        # Check if sender has required scopes for the requested method
        method_scope_requirements = {
            "read_data": ["read"],
            "write_data": ["write"],
            "delete_data": ["admin"],
            "execute_tool": ["execute"],
            "admin_action": ["admin"],
        }

        required = method_scope_requirements.get(message.method, [])
        if required and not any(s in message.sender_scopes for s in required):
            return {"status": "denied", "reason": f"insufficient scope for {message.method}"}

        return {"status": "accepted", "method": message.method}


class MultiAgentRunner:
    """Runs multi-agent scenarios with identity tracking at every boundary."""

    def __init__(self) -> None:
        self.agents: dict[str, MockAgent] = {}
        self.trace: list[MessageTraceEntry] = []

    def add_agent(self, identity: AgentIdentity) -> None:
        self.agents[identity.name] = MockAgent(identity)

    def send_message(
        self,
        sender_name: str,
        receiver_name: str,
        method: str,
        params: dict[str, Any] | None = None,
        use_sender_token: bool = True,
        tamper_identity: str | None = None,
        tamper_scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        """Send a message between agents with full identity tracking.

        Args:
            sender_name: Who is sending
            receiver_name: Who receives
            method: The action requested
            params: Message parameters
            use_sender_token: If True, uses sender's token (correct). If False, uses receiver's (passthrough bug)
            tamper_identity: If set, overrides the identity seen by receiver (ASI07)
            tamper_scopes: If set, overrides the scopes seen by receiver (ASI07)
        """
        sender = self.agents.get(sender_name)
        receiver = self.agents.get(receiver_name)

        if not sender or not receiver:
            return {"status": "error", "reason": "agent not found"}

        # Build the message
        actual_scopes = sender.identity.scopes
        actual_identity = sender_name

        # Apply tampering if specified (ASI07 simulation)
        tampered = False
        tampering_type = ""
        if tamper_identity:
            actual_identity = tamper_identity
            tampered = True
            tampering_type = "identity_spoof"
        if tamper_scopes:
            actual_scopes = tamper_scopes
            tampered = True
            tampering_type = tampering_type or "scope_escalation"

        # Token selection: correct = sender's token scoped to receiver
        # Bug = forwarding sender's own token (passthrough)
        token = f"token-{receiver_name}-delegated-{sender_name}" if use_sender_token else sender.identity.token

        message = AgentMessage(
            id=f"msg-{uuid.uuid4().hex[:8]}",
            sender=actual_identity,
            receiver=receiver_name,
            method=method,
            params=params or {},
            auth_token=token,
            sender_scopes=actual_scopes,
        )

        # Record trace entry
        self.trace.append(MessageTraceEntry(
            message=message,
            boundary=f"{sender_name}->{receiver_name}",
            identity_at_boundary=actual_identity,
            scopes_at_boundary=actual_scopes,
            tampered=tampered,
            tampering_type=tampering_type,
        ))

        # Deliver to receiver
        return receiver.receive(message)

    def run_scenario(self, scenario: dict[str, Any]) -> ScenarioResult:
        """Run a complete multi-agent scenario."""
        self.agents.clear()
        self.trace.clear()
        violations = []

        # Setup agents
        for agent_def in scenario.get("agents", []):
            self.add_agent(AgentIdentity(
                name=agent_def["name"],
                role=agent_def["role"],
                scopes=agent_def.get("scopes", []),
            ))

        # Execute message sequence
        for step in scenario.get("steps", []):
            result = self.send_message(
                sender_name=step["from"],
                receiver_name=step["to"],
                method=step["method"],
                params=step.get("params"),
                use_sender_token=step.get("use_sender_token", True),
                tamper_identity=step.get("tamper_identity"),
                tamper_scopes=step.get("tamper_scopes"),
            )

            expected = step.get("expected_status", "accepted")
            if result["status"] != expected:
                if expected == "denied" and result["status"] == "accepted":
                    violations.append(
                        f"Step {step['from']}->{step['to']}: {step['method']} was accepted but should have been denied"
                    )
                elif expected == "accepted" and result["status"] == "denied":
                    violations.append(
                        f"Step {step['from']}->{step['to']}: {step['method']} was denied but should have been accepted"
                    )

        return ScenarioResult(
            scenario_id=scenario.get("id", "unknown"),
            passed=len(violations) == 0,
            trace=self.trace,
            violations=violations,
            details=f"{len(self.trace)} messages, {len(violations)} violations",
        )
