"""Workspace — the in-memory state for the options paradigm.

Holds the loaded template, user option overrides, and resolved config.
CLI commands (use, show, set, run) operate on this workspace.

This is the Metasploit 'module context' — load a template, see its
options, set values, run. The workspace is session-scoped and stateless
across CLI invocations (no hidden files, no database).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aipop.loaders.yaml_suite import load_yaml_suite


@dataclass
class Option:
    """Single configurable option in the workspace."""

    name: str
    value: Any
    default: Any
    required: bool
    description: str
    source: str = "default"  # default | template | user | env

    @property
    def is_set(self) -> bool:
        return self.value is not None


@dataclass
class TemplateInfo:
    """Metadata about the loaded template."""

    id: str
    name: str
    description: str
    path: str
    case_count: int
    seam: str = ""
    axiom: str = ""
    risk: str = ""


class Workspace:
    """Session workspace for the options paradigm.

    Usage:
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        ws.set("TARGET", "http://localhost:8080/chat")
        ws.set("ADAPTER", "openai")
        ws.set("MODEL", "gpt-4o-mini")
        ws.show_options()
        result = ws.run()
    """

    # Core options every template supports
    CORE_OPTIONS = {
        "TARGET": Option(
            name="TARGET",
            value=None,
            default=None,
            required=False,
            description="Target URL or endpoint",
        ),
        "ADAPTER": Option(
            name="ADAPTER",
            value="static",
            default="static",
            required=True,
            description="Adapter: static, openai, anthropic, ollama, huggingface",
        ),
        "MODEL": Option(
            name="MODEL",
            value=None,
            default=None,
            required=False,
            description="Model name (gpt-4o-mini, claude-sonnet-4, llama3)",
        ),
        "SEED": Option(
            name="SEED",
            value=42,
            default=42,
            required=False,
            description="Random seed for reproducible results",
        ),
        "BUDGET": Option(
            name="BUDGET",
            value=None,
            default=None,
            required=False,
            description="Budget cap in USD (stops scan when exceeded)",
        ),
        "ENCODING": Option(
            name="ENCODING",
            value=None,
            default=None,
            required=False,
            description="Apply encoding to payloads: base64, rot13, hex",
        ),
        "MAX_TURNS": Option(
            name="MAX_TURNS",
            value=1,
            default=1,
            required=False,
            description="Maximum conversation turns for multi-turn templates",
        ),
        "RESPONSE_MODE": Option(
            name="RESPONSE_MODE",
            value="smart",
            default="smart",
            required=False,
            description="Static adapter response mode: smart, refuse, echo, random",
        ),
    }

    ADVANCED_OPTIONS = {
        "PROXY": Option(
            name="PROXY",
            value=None,
            default=None,
            required=False,
            description="HTTP/SOCKS5 proxy (e.g., http://127.0.0.1:8080)",
        ),
        "TIMEOUT": Option(
            name="TIMEOUT",
            value=30,
            default=30,
            required=False,
            description="Per-request timeout in seconds",
        ),
        "DRY_RUN": Option(
            name="DRY_RUN",
            value=False,
            default=False,
            required=False,
            description="Show payloads without sending (no network calls)",
        ),
        "VERBOSE": Option(
            name="VERBOSE",
            value=False,
            default=False,
            required=False,
            description="Show detailed output including detector verdicts",
        ),
        "CAPTURE_TRAFFIC": Option(
            name="CAPTURE_TRAFFIC",
            value=False,
            default=False,
            required=False,
            description="Capture HTTP request/response for evidence",
        ),
    }

    def __init__(self) -> None:
        self._options: dict[str, Option] = {}
        self._template: TemplateInfo | None = None
        self._test_cases: list = []
        self._reset_options()

    def _reset_options(self) -> None:
        """Reset all options to defaults."""
        self._options = {}
        for name, opt in self.CORE_OPTIONS.items():
            self._options[name] = Option(
                name=opt.name,
                value=opt.default,
                default=opt.default,
                required=opt.required,
                description=opt.description,
                source="default",
            )
        for name, opt in self.ADVANCED_OPTIONS.items():
            self._options[name] = Option(
                name=opt.name,
                value=opt.default,
                default=opt.default,
                required=opt.required,
                description=opt.description,
                source="default",
            )

    def use(self, template_path: str) -> TemplateInfo:
        """Load a template into the workspace.

        Args:
            template_path: Suite path (e.g., "adversarial/rag_injection")

        Returns:
            TemplateInfo about the loaded template
        """
        self._reset_options()
        cases = load_yaml_suite(template_path)

        if not cases:
            raise ValueError(f"No test cases found in template: {template_path}")

        # Extract template metadata from first case
        first_meta = cases[0].metadata if cases else {}
        seam = first_meta.get("seam", "")
        axiom = first_meta.get("axiom", "")
        risk = first_meta.get("risk", "")

        # Try to read suite header info from the YAML
        suite_id = template_path.replace("/", "_")
        suite_name = template_path

        # Check if cases have a common suite_id
        common_suite_id = first_meta.get("suite_id", "")
        if common_suite_id:
            suite_id = common_suite_id

        self._template = TemplateInfo(
            id=suite_id,
            name=suite_name,
            description=f"{len(cases)} test cases | seam: {seam}" if seam else f"{len(cases)} test cases",
            path=template_path,
            case_count=len(cases),
            seam=seam,
            axiom=axiom,
            risk=risk,
        )
        self._test_cases = cases

        # Apply template-level overrides from metadata
        if first_meta.get("encoding"):
            self.set("ENCODING", first_meta["encoding"], source="template")

        return self._template

    def set(self, key: str, value: Any, source: str = "user") -> None:
        """Set an option value.

        Args:
            key: Option name (case-insensitive)
            value: New value
            source: Where the value came from (user, template, env)
        """
        key_upper = key.upper()
        if key_upper not in self._options:
            raise KeyError(
                f"Unknown option: {key}. Use 'show options' to see available options."
            )

        opt = self._options[key_upper]

        # Type coercion
        if isinstance(opt.default, bool) and not isinstance(value, bool):
            value = str(value).lower() in ("true", "1", "yes")
        elif isinstance(opt.default, int) and not isinstance(value, (int, type(None))):
            try:
                value = int(value)
            except (ValueError, TypeError):
                pass
        elif isinstance(opt.default, float) and not isinstance(value, (float, type(None))):
            try:
                value = float(value)
            except (ValueError, TypeError):
                pass

        opt.value = value
        opt.source = source

    def get(self, key: str) -> Any:
        """Get an option value."""
        key_upper = key.upper()
        if key_upper not in self._options:
            return None
        return self._options[key_upper].value

    def get_options(self, include_advanced: bool = False) -> list[Option]:
        """Get all options for display.

        Args:
            include_advanced: Include advanced options
        """
        core_names = set(self.CORE_OPTIONS.keys())
        result = []
        for name, opt in self._options.items():
            if name in core_names:
                result.append(opt)
            elif include_advanced:
                result.append(opt)
        return result

    @property
    def template(self) -> TemplateInfo | None:
        return self._template

    @property
    def test_cases(self) -> list:
        return self._test_cases

    @property
    def is_loaded(self) -> bool:
        return self._template is not None

    def validate(self) -> list[str]:
        """Check if all required options are set. Returns list of errors."""
        errors = []
        for opt in self._options.values():
            if opt.required and not opt.is_set:
                errors.append(f"Required option not set: {opt.name} — {opt.description}")
        if not self.is_loaded:
            errors.append("No template loaded. Use 'aipop use <template>' first.")
        return errors
