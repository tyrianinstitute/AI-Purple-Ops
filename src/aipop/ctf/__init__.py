"""CTF attack orchestration — EXPERIMENTAL, moved to aipop.experimental.ctf.

This package is a backwards-compatibility shim. All real code now lives
under aipop.experimental.ctf. Direct imports still work but emit a
deprecation warning.
"""

import warnings as _warnings

_warnings.warn(
    "aipop.ctf is experimental and has been relocated to aipop.experimental.ctf. "
    "Update your imports to avoid breakage in a future release.",
    DeprecationWarning,
    stacklevel=2,
)

from aipop.experimental.ctf.orchestrator import CTFOrchestrator
from aipop.experimental.ctf.pyrit_bridge import AIPurpleOpsTarget

__all__ = ["AIPurpleOpsTarget", "CTFOrchestrator"]
