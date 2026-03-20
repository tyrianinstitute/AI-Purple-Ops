"""Tests for smart error handling."""

from __future__ import annotations

from aipop.cli.errors import SmartError, handle_error, _match_error


class TestErrorMatching:
    def test_api_key_openai(self):
        err = ValueError("OpenAI API key not found. Set OPENAI_API_KEY environment variable.")
        smart = _match_error(err)
        assert smart is not None
        assert "OpenAI" in smart.title
        assert any("OPENAI_API_KEY" in s for s in smart.suggestions)

    def test_api_key_anthropic(self):
        err = ValueError("Anthropic API key not found")
        smart = _match_error(err)
        assert smart is not None
        assert "Anthropic" in smart.title

    def test_unknown_adapter(self):
        err = ValueError("Unknown adapter: foobar. Available: static, mock, openai")
        smart = _match_error(err)
        assert smart is not None
        assert "Adapter" in smart.title
        assert any("static" in s for s in smart.suggestions)

    def test_no_test_cases(self):
        err = ValueError("No test cases found in suite: fake/suite")
        smart = _match_error(err)
        assert smart is not None
        assert "Suite" in smart.title
        assert any("suites list" in s for s in smart.suggestions)

    def test_connection_refused(self):
        err = ConnectionError("Connection refused to localhost:8080")
        smart = _match_error(err)
        assert smart is not None
        assert "Connection" in smart.title
        assert any("ollama" in s.lower() for s in smart.suggestions)

    def test_timeout(self):
        err = TimeoutError("Request timeout after 30s")
        smart = _match_error(err)
        assert smart is not None
        assert "Timeout" in smart.title

    def test_import_error(self):
        err = ImportError("No module named 'duckdb'")
        smart = _match_error(err)
        assert smart is not None
        assert "Dependency" in smart.title
        assert any("pip install" in s for s in smart.suggestions)

    def test_permission_denied(self):
        err = PermissionError("Permission denied: out/reports/summary.json")
        smart = _match_error(err)
        assert smart is not None
        assert "Permission" in smart.title

    def test_unknown_error_returns_none(self):
        err = RuntimeError("Something completely unexpected")
        smart = _match_error(err)
        assert smart is None  # No known pattern


class TestHandleError:
    def test_known_error_returns_exit_code(self):
        err = ValueError("Unknown adapter: bad")
        code = handle_error(err)
        assert code == 2

    def test_unknown_error_returns_4(self):
        err = RuntimeError("Something weird")
        code = handle_error(err)
        assert code == 4

    def test_connection_error_returns_4(self):
        err = ConnectionError("Connection refused")
        code = handle_error(err)
        assert code == 4

    def test_import_error_returns_3(self):
        err = ImportError("No module named 'torch'")
        code = handle_error(err)
        assert code == 3


class TestSmartErrorStructure:
    def test_smart_error_has_suggestions(self):
        se = SmartError(
            title="Test",
            message="test message",
            suggestions=["do this", "or that"],
        )
        assert len(se.suggestions) == 2
        assert se.exit_code == 2  # default
