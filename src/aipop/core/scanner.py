"""Shared scan engine — interface-agnostic, never prints."""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from aipop import __version__
from aipop.core.adapters import Adapter
from aipop.core.detectors import Detector
from aipop.core.models import RunResult, TestCase


@dataclass
class ScanOptions:
    """Everything Scanner needs that isn't adapter/detectors."""

    suite: str
    seed: int = 42
    response_mode: str = "smart"
    orchestrator: Any | None = None
    judge: Any | None = None
    judge_threshold: float = 8.0
    budget: float | None = None
    transcripts_dir: str | None = None


@dataclass
class ScanResult:
    """Complete scan output. JSON-serializable."""

    run_id: str
    suite: str
    adapter_name: str
    model_name: str
    results: list[RunResult]
    total: int
    passed: int
    failed: int
    started_at: str
    finished_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the JSON contract that --output json produces.

        Keys: status, total, passed, failed, run_id, suite, suite_hash,
        version, utc_started, utc_finished, seed, response_mode, adapter,
        model, git_commit, python_version, platform.
        """
        d: dict[str, Any] = {
            "status": "completed",
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "run_id": self.run_id,
            "suite": self.suite,
            "adapter": self.adapter_name,
            "model": self.model_name,
        }
        d.update(self.metadata)
        return d


class Scanner:
    """Interface-agnostic scan engine.

    Two public methods: __init__ and scan.
    Returns structured data, never prints.
    """

    def __init__(
        self,
        adapter: Adapter,
        detectors: list[Detector] | None = None,
    ) -> None:
        self.adapter = adapter
        self.detectors = detectors or []

    def scan(
        self,
        test_cases: list[RunResult] | list[TestCase],
        options: ScanOptions,
        on_result: Callable[[RunResult], None] | None = None,
    ) -> ScanResult:
        """Execute test suite and return structured results.

        Args:
            test_cases: TestCase list to execute, or pre-computed RunResult
                list from harness-backed suites.
            options: Scan configuration.
            on_result: Optional callback fired after each test completes.
                Use for progress bars or streaming — Scanner never prints.

        Returns:
            ScanResult with all results and metadata.
        """
        started_at = datetime.now(UTC)
        run_id = f"run-{started_at.strftime('%Y%m%dT%H%M%S')}-{os.getpid()}-{uuid.uuid4().hex[:6]}"

        # If caller passed pre-computed results (harness suites), skip execution
        if test_cases and isinstance(test_cases[0], RunResult):
            results = list(test_cases)
        else:
            results = self._execute_tests(
                test_cases,  # type: ignore[arg-type]
                options,
                on_result,
            )

        finished_at = datetime.now(UTC)

        total = len(results)
        failed = sum(1 for r in results if not r.passed)
        passed = total - failed

        metadata = self._build_metadata(
            options,
            run_id,
            started_at,
            finished_at,
        )

        return ScanResult(
            run_id=run_id,
            suite=options.suite,
            adapter_name=self._adapter_name(),
            model_name=self._model_name(),
            results=results,
            total=total,
            passed=passed,
            failed=failed,
            started_at=started_at.isoformat(timespec="seconds"),
            finished_at=finished_at.isoformat(timespec="seconds"),
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _execute_tests(
        self,
        test_cases: list[TestCase],
        options: ScanOptions,
        on_result: Callable[[RunResult], None] | None,
    ) -> list[RunResult]:
        """Create runner, execute tests, track cost."""
        from pathlib import Path

        from aipop.runners.live import LiveRunner, LiveRunnerConfig
        from aipop.utils.cost_tracker import CostTracker

        cost_tracker = CostTracker()

        runner = LiveRunner(
            adapter=self.adapter,
            config=LiveRunnerConfig(
                seed=options.seed,
                budget=options.budget,
                transcripts_dir=(
                    Path(options.transcripts_dir) if options.transcripts_dir else None
                ),
            ),
            detectors=self.detectors if self.detectors else None,
            orchestrator=options.orchestrator,
            judge=options.judge,
            judge_threshold=options.judge_threshold,
        )

        results: list[RunResult] = []
        for result in runner.execute_many(test_cases):
            results.append(result)

            # Track cost from adapter response metadata
            if result.metadata and "model_meta" in result.metadata:
                model_meta = result.metadata["model_meta"]
                cost = model_meta.get("cost_usd", 0.0)
                tokens = model_meta.get("tokens_prompt", 0) + model_meta.get("tokens_completion", 0)
                model_id = model_meta.get("model", getattr(self.adapter, "model", "unknown"))
                if cost > 0 or tokens > 0:
                    cost_tracker.track(
                        operation="run",
                        tokens=tokens,
                        model=model_id,
                        cost=cost,
                    )

            if on_result:
                on_result(result)

        # Stash cost and ASR data for caller to read
        self._cost_summary = cost_tracker.get_summary()
        self._runner = runner

        return results

    def _build_metadata(
        self,
        options: ScanOptions,
        run_id: str,
        started_at: datetime,
        finished_at: datetime,
    ) -> dict[str, Any]:
        """Build the metadata dict that becomes part of ScanResult."""
        suite_hash = self._compute_suite_hash(options.suite)
        git_commit = self._get_git_commit()

        return {
            "suite_hash": suite_hash,
            "version": __version__,
            "utc_started": started_at.isoformat(timespec="seconds"),
            "utc_finished": finished_at.isoformat(timespec="seconds"),
            "seed": options.seed,
            "response_mode": options.response_mode,
            "git_commit": git_commit,
            "python_version": platform.python_version(),
            "platform": platform.system(),
        }

    def _adapter_name(self) -> str:
        """Derive adapter name from class."""
        name = type(self.adapter).__name__.lower()
        for suffix in ("adapter",):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
        return name or "unknown"

    def _model_name(self) -> str:
        return getattr(self.adapter, "model", "mock") or "mock"

    @staticmethod
    def _compute_suite_hash(suite: str) -> str:
        try:
            from aipop.utils.paths import get_package_data_path

            suite_path = get_package_data_path("suites") / suite
            if suite_path.is_dir():
                content = b"".join(sorted(p.read_bytes() for p in suite_path.rglob("*.yaml")))
                return hashlib.sha256(content).hexdigest()[:12]
        except Exception:
            pass
        return ""

    @staticmethod
    def _get_git_commit() -> str:
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Post-scan accessors (for CLI display — Scanner doesn't use these)
    # ------------------------------------------------------------------

    def get_cost_summary(self) -> dict[str, Any]:
        """Return cost data from last scan. CLI uses this for display."""
        return getattr(self, "_cost_summary", {})

    def get_asr_summary(self) -> dict[str, Any]:
        """Return ASR data from last scan's runner. CLI uses this for display."""
        runner = getattr(self, "_runner", None)
        if runner and hasattr(runner, "get_asr_summary"):
            return runner.get_asr_summary()
        return {"enabled": False}
