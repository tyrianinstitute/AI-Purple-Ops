from __future__ import annotations

from aipop.utils.log_utils import ConsoleLogger


def test_style_prefixes(capsys) -> None:  # type: ignore[no-untyped-def]
    log = ConsoleLogger()
    log.info("info")
    log.ok("ok")
    log.warn("warn")
    log.error("error")
    log.try_("try")
    log.skip("skip")
    log.step("step")
    out = capsys.readouterr().out
    for token in ["[*]", "[+]", "[!]", "[x]", "[~]", "[-]", "[>]"]:
        assert token in out
    # Unicode resilience smoke
    log.info("π 🔒 ✓")  # should not raise
