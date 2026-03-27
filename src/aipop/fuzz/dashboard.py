"""Live fuzz dashboard — AFL-style status screen for AI fuzzing."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text


# NATO phonetic decoder
_NATO = {
    "alpha": "a", "bravo": "b", "charlie": "c", "delta": "d",
    "echo": "e", "foxtrot": "f", "golf": "g", "hotel": "h",
    "india": "i", "juliet": "j", "kilo": "k", "lima": "l",
    "mike": "m", "november": "n", "oscar": "o", "papa": "p",
    "quebec": "q", "romeo": "r", "sierra": "s", "tango": "t",
    "uniform": "u", "victor": "v", "whiskey": "w", "xray": "x",
    "yankee": "y", "zulu": "z", "zero": "0", "one": "1",
    "two": "2", "three": "3", "four": "4", "five": "5",
    "six": "6", "seven": "7", "eight": "8", "nine": "9",
    "exclamation": "!", "hash": "#", "hashtag": "#", "dash": "-",
    "underscore": "_", "period": ".", "dot": ".", "at": "@",
    "colon": ":", "slash": "/", "mark": "",
}


def _decode_nato(text: str) -> str | None:
    """Attempt to decode NATO phonetic alphabet from a leaked string."""
    words = text.lower().replace("-", " ").replace(",", " ").split()
    chars = []
    hits = 0
    for w in words:
        w_clean = w.strip("[](){}|`'\"")
        if w_clean in _NATO:
            chars.append(_NATO[w_clean])
            hits += 1
    if hits >= 3 and len(chars) >= 4:
        return "".join(chars)
    return None


@dataclass
class FuzzStats:
    """Accumulated stats for the live dashboard."""

    total_planned: int = 0
    tested: int = 0
    bypassed: int = 0
    blocked: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)

    strategy_bypasses: Counter = field(default_factory=Counter)
    strategy_attempts: Counter = field(default_factory=Counter)

    leaked_items: list[str] = field(default_factory=list)
    decoded_items: list[str] = field(default_factory=list)
    latest_leak: str = ""

    callback_url: str = ""
    target: str = ""

    @property
    def runtime(self) -> str:
        elapsed = time.time() - self.start_time
        m, s = divmod(int(elapsed), 60)
        return f"{m:02d}:{s:02d}"

    @property
    def rate(self) -> float:
        elapsed = time.time() - self.start_time
        if elapsed < 0.1:
            return 0.0
        return self.tested / elapsed

    @property
    def bypass_rate(self) -> float:
        if self.tested == 0:
            return 0.0
        return 100 * self.bypassed / self.tested

    def record_attempt(self, attempt) -> None:
        """Record a single fuzz attempt result."""
        self.tested += 1
        strategy = getattr(attempt, "strategy", "unknown")
        self.strategy_attempts[strategy] += 1

        if getattr(attempt, "error", None):
            self.errors += 1
        elif getattr(attempt, "vulnerable", False):
            self.bypassed += 1
            self.strategy_bypasses[strategy] += 1
            for marker in getattr(attempt, "leaked_markers", []):
                if marker not in self.leaked_items:
                    self.leaked_items.append(marker)
                    self.latest_leak = marker
                    decoded = _decode_nato(marker)
                    if decoded and decoded not in self.decoded_items:
                        # Only keep if not a substring of an existing decoded
                        if not any(decoded in existing for existing in self.decoded_items):
                            self.decoded_items.append(decoded)
        else:
            self.blocked += 1


def build_dashboard(stats: FuzzStats) -> Panel:
    """Build the Rich panel for the live dashboard."""
    lines = []

    # Header
    lines.append(f"[bold]target:[/]    {stats.target}")
    lines.append(f"[bold]runtime:[/]   {stats.runtime}          [bold]attempts/sec:[/] {stats.rate:.1f}")
    lines.append("")

    # Progress bars
    tested_pct = stats.tested / max(stats.total_planned, 1)
    bypass_pct = stats.bypassed / max(stats.tested, 1)
    blocked_pct = stats.blocked / max(stats.tested, 1)

    tested_bar = _bar(tested_pct, "cyan")
    bypass_bar = _bar(bypass_pct, "red")
    blocked_bar = _bar(blocked_pct, "green")

    lines.append(f"  TESTED    {tested_bar}  {stats.tested} / {stats.total_planned}")
    lines.append(f"  BYPASSED  {bypass_bar}  {stats.bypassed} ({stats.bypass_rate:.1f}%)")
    lines.append(f"  BLOCKED   {blocked_bar}  {stats.blocked}")
    if stats.errors:
        lines.append(f"  ERRORS    {stats.errors}")
    lines.append("")

    # Strategy effectiveness
    if stats.strategy_attempts:
        lines.append("[bold]MUTATION EFFECTIVENESS[/]")
        for strat in sorted(stats.strategy_attempts.keys()):
            total = stats.strategy_attempts[strat]
            bypasses = stats.strategy_bypasses.get(strat, 0)
            pct = 100 * bypasses / total if total > 0 else 0
            eff_bar = _bar(pct / 100, "red" if pct > 50 else "yellow" if pct > 10 else "dim")
            lines.append(f"  {strat:24s} {eff_bar}  {pct:.0f}% bypass ({bypasses}/{total})")
        lines.append("")

    # Decoded leaks
    if stats.decoded_items:
        lines.append("[bold yellow]DECODED EXFILTRATION[/]")
        for d in stats.decoded_items[-6:]:
            lines.append(f"  [yellow]→ {d}[/]")
        lines.append("")
    elif stats.leaked_items:
        lines.append("[bold red]LATEST LEAK[/]")
        lines.append(f"  [red]▸ {stats.latest_leak[:80]}[/]")
        lines.append("")

    # Callback
    if stats.callback_url:
        lines.append(f"[bold]Callback:[/] {stats.callback_url}")

    return Panel(
        "\n".join(lines),
        title="[bold cyan]aipop fuzz — LIVE[/]",
        border_style="cyan",
    )


def _bar(pct: float, color: str, width: int = 24) -> str:
    """Build a text progress bar."""
    filled = int(pct * width)
    empty = width - filled
    return f"[{color}]{'█' * filled}{'░' * empty}[/{color}]"


class LiveDashboard:
    """Context manager for the live fuzz dashboard."""

    def __init__(self, stats: FuzzStats, console: Console | None = None):
        self.stats = stats
        self.console = console or Console(stderr=True)
        self._live: Live | None = None

    def __enter__(self):
        self._live = Live(
            build_dashboard(self.stats),
            console=self.console,
            refresh_per_second=4,
        )
        self._live.__enter__()
        return self

    def __exit__(self, *args):
        if self._live:
            self._live.__exit__(*args)

    def update(self):
        """Refresh the dashboard."""
        if self._live:
            self._live.update(build_dashboard(self.stats))
