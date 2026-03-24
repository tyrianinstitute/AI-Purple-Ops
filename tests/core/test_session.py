"""Tests for session history."""

import json
from pathlib import Path
from aipop.core.models import RunResult
from aipop.core.session import SessionHistory


class TestSessionHistory:
    def test_empty_session(self):
        sh = SessionHistory()
        assert len(sh) == 0
        assert sh.last is None

    def test_record_scan(self):
        sh = SessionHistory()
        results = [
            RunResult(test_id="t1", response="ok", passed=True, metadata={}),
            RunResult(test_id="t2", response="fail", passed=False, metadata={}),
        ]
        entry = sh.record_scan("run --suite test", results)
        assert entry.entry_type == "scan"
        assert "2 tests" in entry.summary
        assert len(sh) == 1
        assert sh.last == entry

    def test_record_tool(self):
        sh = SessionHistory()
        entry = sh.record_tool("tool promptfoo --help", {
            "tool": "promptfoo", "exit_code": 0, "elapsed_secs": 1.5
        })
        assert entry.entry_type == "tool"
        assert "promptfoo" in entry.summary

    def test_record_morph(self):
        sh = SessionHistory()
        entry = sh.record_morph("morph --base64", "hello", "aGVsbG8=", "base64")
        assert entry.entry_type == "morph"
        assert "base64" in entry.summary

    def test_get_by_index(self):
        sh = SessionHistory()
        sh.record_scan("run 1", [RunResult("t1", "ok", True, {})])
        sh.record_scan("run 2", [RunResult("t2", "ok", True, {})])
        assert sh.get(0).command == "run 1"
        assert sh.get(1).command == "run 2"
        assert sh.get(99) is None

    def test_export(self, tmp_path):
        sh = SessionHistory()
        sh.record_scan("test", [RunResult("t1", "ok", True, {})])
        path = tmp_path / "session.json"
        json_str = sh.export(path)
        data = json.loads(json_str)
        assert data["session_entries"] == 1
        assert path.exists()
