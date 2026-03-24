from __future__ import annotations

from aipop.utils.config import load_config


def test_env_overrides_yaml(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    y = tmp_path / "h.yaml"
    y.write_text("run:\n  output_dir: custom_out\n  log_level: DEBUG\n", encoding="utf-8")
    monkeypatch.setenv("AIPO_OUTPUT_DIR", "env_out")
    cfg = load_config(str(y))
    assert cfg.run.output_dir == "env_out"  # env > yaml
    assert cfg.run.log_level == "DEBUG"  # yaml > defaults
