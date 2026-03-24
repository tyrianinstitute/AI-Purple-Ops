"""Tool orchestrator for running multiple redteam tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aipop.core.adapters import Adapter
from aipop.integrations.base import ToolResult, ToolWrapper
from aipop.integrations.exceptions import ToolNotAvailableError
from aipop.integrations.garak import GarakWrapper
from aipop.integrations.promptfoo import PromptfooWrapper
from aipop.integrations.promptinject import PromptInjectWrapper
from aipop.integrations.pyrit import PyRITWrapper
from aipop.redteam.indirect_injection import IndirectInjectionBaseline


@dataclass
class ToolExecutionStatus:
    """Status of tool execution."""

    tool_name: str
    available: bool
    executed: bool
    success: bool
    error: str | None = None
    findings_count: int = 0


def get_tool_wrapper(tool_name: str) -> ToolWrapper:
    """Get tool wrapper by name.

    Args:
        tool_name: Tool name (promptfoo, garak, pyrit, promptinject, indirect_injection)

    Returns:
        ToolWrapper instance

    Raises:
        ValueError: If tool name is unknown
    """
    wrappers = {
        "promptfoo": PromptfooWrapper(),
        "garak": GarakWrapper(),
        "pyrit": PyRITWrapper(),
        "promptinject": PromptInjectWrapper(),
        "indirect_injection": IndirectInjectionBaseline(),
    }

    if tool_name not in wrappers:
        raise ValueError(f"Unknown tool: {tool_name}. Available: {list(wrappers.keys())}")

    return wrappers[tool_name]


def orchestrate_tools(
    tools: list[dict[str, Any]],
    adapter: Adapter | None = None,
    skip_missing: bool = False,
) -> tuple[list[ToolResult], list[ToolExecutionStatus]]:
    """Orchestrate multiple tools with configuration.

    Args:
        tools: List of tool specifications from recipe
        adapter: Optional model adapter for tools to use
        skip_missing: If True, skip missing tools without error

    Returns:
        Tuple of (tool_results, tool_statuses) for reporting
    """
    results = []
    statuses = []
    missing_tools = []
    failed_tools = []

    for tool_spec in tools:
        if not tool_spec.get("enabled", True):
            continue

        tool_name = tool_spec.get("tool")
        if not tool_name:
            continue

        status = ToolExecutionStatus(
            tool_name=tool_name, available=False, executed=False, success=False
        )

        try:
            wrapper = get_tool_wrapper(tool_name)

            if not wrapper.is_available():
                status.available = False
                status.error = f"Tool '{tool_name}' is not installed"
                missing_tools.append(tool_name)

                from aipop.utils.log_utils import log

                if skip_missing:
                    log.warning(
                        f"Tool '{tool_name}' is not installed (skipping). "
                        f"Install with: 'make toolkit' or 'aipop tools install --tool {tool_name}'"
                    )
                else:
                    log.warning(
                        f"Tool '{tool_name}' is not installed. "
                        f"Install with: 'make toolkit' or 'aipop tools install --tool {tool_name}'"
                    )

                statuses.append(status)
                if skip_missing:
                    continue
                else:
                    # Continue but mark as unavailable
                    continue

            status.available = True

            config = tool_spec.get("config", {})
            result = wrapper.execute(config, adapter)

            status.executed = True
            status.success = result.success
            status.findings_count = len(result.findings)
            if result.error:
                status.error = result.error
                failed_tools.append(tool_name)

            results.append(result)
            statuses.append(status)

        except ToolNotAvailableError as e:
            status.available = False
            status.error = str(e)
            missing_tools.append(tool_name)

            import logging; log = logging.getLogger(__name__)

            if skip_missing:
                log.warning(
                    f"Tool '{tool_name}' is not available: {e} (skipping). "
                    f"Install with: 'make toolkit' or 'aipop tools install --tool {tool_name}'"
                )
            else:
                log.warning(
                    f"Tool '{tool_name}' is not available: {e}. "
                    f"Install with: 'make toolkit' or 'aipop tools install --tool {tool_name}'"
                )

            statuses.append(status)
            if skip_missing:
                continue
            else:
                continue
        except Exception as e:
            status.available = True
            status.executed = True
            status.success = False
            status.error = str(e)
            failed_tools.append(tool_name)

            import logging; log = logging.getLogger(__name__)

            log.error(f"Tool '{tool_name}' execution failed: {e}")
            statuses.append(status)
            continue

    # Log summary if there were issues
    if missing_tools or failed_tools:
        import logging; log = logging.getLogger(__name__)

        if missing_tools:
            log.warning(
                f"Missing tools ({len(missing_tools)}): {', '.join(missing_tools)}. "
                f"Run 'aipop tools install --tool <name>' to install."
            )
        if failed_tools:
            log.error(
                f"Failed tools ({len(failed_tools)}): {', '.join(failed_tools)}. "
                f"Check logs for details."
            )

    return results, statuses
