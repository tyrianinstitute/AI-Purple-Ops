"""Tests that adapter quick flow enforces gitignore protection."""

from __future__ import annotations

from pathlib import Path

from aipop.cli import harness as cli_harness


def test_adapter_quick_path_invokes_gitignore_protection(monkeypatch, tmp_path: Path) -> None:
    """Quick flow should invoke ensure_gitignore_protection via warning path."""
    calls: dict[str, Path] = {}
    monkeypatch.chdir(tmp_path)

    from rich.prompt import Confirm

    from aipop.adapters import error_handlers, quick_adapter
    from aipop.utils import security_check

    monkeypatch.setattr(
        quick_adapter,
        "parse_curl",
        lambda _curl: {
            "url": "https://api.example.local/v1/chat",
            "method": "POST",
            "auth_type": "none",
            "headers": {},
            "prompt_field": "message",
            "body": {"message": "hello"},
        },
    )
    monkeypatch.setattr(
        quick_adapter, "generate_adapter_config", lambda _parsed, _name: {"id": "cfg"}
    )
    monkeypatch.setattr(quick_adapter, "save_adapter_config", lambda _config, _path: None)
    monkeypatch.setattr(error_handlers, "show_config_location", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(security_check, "check_config_for_secrets", lambda _path: ["secret"])
    monkeypatch.setattr(Confirm, "ask", lambda *_args, **_kwargs: False)

    def fake_ensure(
        repo_root: Path, adapter_dir: Path | None = None
    ) -> tuple[bool, str, list[str], str | None]:
        calls["repo_root"] = repo_root
        if adapter_dir is not None:
            calls["adapter_dir"] = adapter_dir
        return True, "adapters", ["adapters/*.yaml", "adapters/*.yml"], None

    monkeypatch.setattr(security_check, "ensure_gitignore_protection", fake_ensure)

    cli_harness._adapter_quick(
        name="target_app",
        from_curl="curl https://api.example.local/v1/chat",
        from_http=None,
        from_clipboard=False,
    )

    assert calls["repo_root"] == tmp_path
    assert calls["adapter_dir"] == Path("adapters")
