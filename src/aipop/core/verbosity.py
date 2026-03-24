"""Verbosity ladder — centralized output level control.

Four levels, each showing progressively more information:

  quiet    → JSON only to stdout, nothing to stderr. For CI/CD pipelines.
  default  → Cinematic output: recon panel, findings, summary. For humans.
  verbose  → Default + detector verdicts, tool call details, timing per test.
  trace    → Verbose + raw prompts/responses, full adapter metadata, debug info.

Usage:
    from aipop.core.verbosity import Verbosity, get_verbosity, set_verbosity

    v = get_verbosity()
    if v >= Verbosity.VERBOSE:
        console.print(f"Detector: {result.detector_name} → {result.passed}")
    if v >= Verbosity.TRACE:
        console.print(f"Raw response: {response.text[:500]}")
"""

from __future__ import annotations

import logging
from enum import IntEnum

log = logging.getLogger(__name__)


class Verbosity(IntEnum):
    """Output verbosity levels. Higher = more detail."""

    QUIET = 0    # JSON only, no Rich, no stderr
    DEFAULT = 1  # Cinematic output: panels, findings, summaries
    VERBOSE = 2  # + detector verdicts, tool call details, timing
    TRACE = 3    # + raw prompts/responses, full metadata, debug


# Module-level state — set once at CLI startup, read everywhere
_current: Verbosity = Verbosity.DEFAULT


def set_verbosity(level: Verbosity | int | str) -> None:
    """Set the global verbosity level.

    Args:
        level: Verbosity enum, int (0-3), or string name (quiet/default/verbose/trace)
    """
    global _current

    if isinstance(level, str):
        level = level.lower().strip()
        name_map = {
            "quiet": Verbosity.QUIET,
            "default": Verbosity.DEFAULT,
            "verbose": Verbosity.VERBOSE,
            "trace": Verbosity.TRACE,
            # Aliases
            "q": Verbosity.QUIET,
            "v": Verbosity.VERBOSE,
            "vv": Verbosity.TRACE,
            "debug": Verbosity.TRACE,
        }
        if level in name_map:
            _current = name_map[level]
        else:
            log.warning(f"Unknown verbosity level: {level}. Using default.")
            _current = Verbosity.DEFAULT
    elif isinstance(level, int):
        try:
            _current = Verbosity(min(max(level, 0), 3))
        except ValueError:
            _current = Verbosity.DEFAULT
    else:
        _current = level

    # Sync Python logging level
    if _current >= Verbosity.TRACE:
        logging.getLogger("aipop").setLevel(logging.DEBUG)
    elif _current >= Verbosity.VERBOSE:
        logging.getLogger("aipop").setLevel(logging.INFO)
    else:
        logging.getLogger("aipop").setLevel(logging.WARNING)


def get_verbosity() -> Verbosity:
    """Get the current global verbosity level."""
    return _current


def is_quiet() -> bool:
    """Check if output should be JSON-only (no Rich, no stderr)."""
    return _current <= Verbosity.QUIET


def is_verbose() -> bool:
    """Check if verbose details should be shown."""
    return _current >= Verbosity.VERBOSE


def is_trace() -> bool:
    """Check if full trace output should be shown."""
    return _current >= Verbosity.TRACE
