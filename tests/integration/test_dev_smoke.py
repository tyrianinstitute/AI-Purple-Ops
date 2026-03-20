from __future__ import annotations

from pathlib import Path

from aipop.utils.config import load_config
from aipop.utils.preflight import preflight


def test_preflight_creates_dirs(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Point output to temp dir to avoid touching repo root
    y = tmp_path / "h.yaml"
    y.write_text(
        "run:\n  output_dir: outx\n  reports_dir: outx/reports\n"
        "  transcripts_dir: outx/transcripts\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    cfg = load_config(str(y))
    preflight()
    assert Path(cfg.run.output_dir).exists()
    assert Path(cfg.run.reports_dir).exists()
    assert Path(cfg.run.transcripts_dir).exists()
