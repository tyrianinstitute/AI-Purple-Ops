"""CLI tests for conversation replay commands."""

from __future__ import annotations

import importlib.util

import pytest

from aipop.cli.harness import app
from typer.testing import CliRunner

_has_sqlalchemy = importlib.util.find_spec("sqlalchemy") is not None

runner = CliRunner()


def test_list_conversations_help():
    """Test list-conversations --help."""
    result = runner.invoke(app, ["list-conversations", "--help"])

    assert result.exit_code == 0
    assert "List all conversation IDs" in result.output
    assert "--db-path" in result.output


def test_replay_conversation_help():
    """Test replay-conversation --help."""
    result = runner.invoke(app, ["replay-conversation", "--help"])

    assert result.exit_code == 0
    assert "Replay a conversation from PyRIT" in result.output
    assert "--format" in result.output
    assert "--db-path" in result.output
    assert "--output" in result.output


@pytest.mark.skipif(not _has_sqlalchemy, reason="sqlalchemy not installed")
def test_list_conversations_missing_database():
    """Test list-conversations with non-existent database."""
    result = runner.invoke(
        app, ["list-conversations", "--db-path", "/fake/path/that/does/not/exist.duckdb"]
    )

    assert result.exit_code == 1
    assert "Database not found" in result.output


def test_replay_conversation_missing_argument():
    """Test replay-conversation without conversation ID."""
    result = runner.invoke(app, ["replay-conversation"])

    assert result.exit_code == 2  # Typer missing argument error
    assert "Missing argument" in result.output or "CONVERSATION_ID" in result.output


@pytest.mark.skipif(not _has_sqlalchemy, reason="sqlalchemy not installed")
def test_replay_conversation_missing_database():
    """Test replay-conversation with non-existent database."""
    result = runner.invoke(
        app, ["replay-conversation", "fake-id-12345", "--db-path", "/fake/path/db.duckdb"]
    )

    assert result.exit_code == 1
    assert "Database not found" in result.output


def test_replay_conversation_json_format():
    """Test replay-conversation with JSON format."""
    # This will fail with missing database, but tests format parameter
    result = runner.invoke(
        app, ["replay-conversation", "test-id", "--format", "json", "--db-path", "/tmp/test.duckdb"]
    )

    # Should accept format parameter (will fail on DB not found)
    assert "--format" not in result.output or "invalid" not in result.output.lower()


def test_replay_conversation_interactive_format():
    """Test replay-conversation with interactive format."""
    result = runner.invoke(
        app,
        [
            "replay-conversation",
            "test-id",
            "--format",
            "interactive",
            "--db-path",
            "/tmp/test.duckdb",
        ],
    )

    # Should accept format parameter
    assert "--format" not in result.output or "invalid" not in result.output.lower()


def test_verify_suite_with_orchestrator_help():
    """Test verify-suite shows orchestrator options in help."""
    result = runner.invoke(app, ["verify-suite", "--help"])

    assert result.exit_code == 0
    assert "--orchestrator" in result.output
    assert "--max-turns" in result.output
    # Note: Flag may be truncated in help display as --multi-turn-scori...
    assert "multi-turn" in result.output.lower()
