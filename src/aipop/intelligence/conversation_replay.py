"""Conversation replay functionality for PyRIT orchestrator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from pyrit.memory import DuckDBMemory
except ImportError:
    DuckDBMemory = None  # type: ignore[assignment,misc]
from sqlalchemy import text


class ConversationReplayError(Exception):
    """Error during conversation replay."""


def replay_conversation(
    conversation_id: str,
    db_path: str = "out/conversations.duckdb",
    format_type: str = "text",
) -> str | dict[str, Any]:
    """Replay a conversation from DuckDB memory.

    Args:
        conversation_id: Conversation ID to replay
        db_path: Path to DuckDB file (default: out/conversations.duckdb)
        format_type: Output format (text, json, interactive)

    Returns:
        Formatted conversation (string for text/interactive, dict for json)

    Raises:
        ConversationReplayError: If conversation not found or DB error
    """
    if DuckDBMemory is None:
        raise ImportError(
            "PyRIT is required for this feature. "
            "Install with: pip install ai-purple-ops[pyrit]"
        )

    db_path_obj = Path(db_path)

    if not db_path_obj.exists():
        raise ConversationReplayError(f"Database not found: {db_path}")

    try:
        memory = DuckDBMemory(db_path=db_path)
        entries = memory.get_prompt_request_pieces(conversation_id=conversation_id)

        if not entries:
            raise ConversationReplayError(
                f"Conversation '{conversation_id}' not found in database. "
                f"Available conversations can be listed with: aipop list-conversations"
            )

        # Group entries into turns (user/assistant pairs)
        turns = []
        current_turn = {}
        turn_number = 0

        for entry in entries:
            if entry.role == "user":
                if current_turn:
                    turns.append(current_turn)
                turn_number += 1
                current_turn = {
                    "turn": turn_number,
                    "user": entry.converted_value,
                    "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                }
            elif entry.role == "assistant":
                current_turn["assistant"] = entry.converted_value

        # Add last turn if exists
        if current_turn and "assistant" in current_turn:
            turns.append(current_turn)

        # Format output based on type
        if format_type == "json":
            return {
                "conversation_id": conversation_id,
                "total_turns": len(turns),
                "turns": turns,
            }
        elif format_type == "interactive":
            return _format_interactive(conversation_id, turns)
        else:  # text
            return _format_text(conversation_id, turns)

    except Exception as e:
        if isinstance(e, ConversationReplayError):
            raise
        raise ConversationReplayError(f"Error reading conversation: {e}") from e


def _format_text(conversation_id: str, turns: list[dict[str, Any]]) -> str:
    """Format conversation as plain text.

    Args:
        conversation_id: Conversation ID
        turns: List of turn dictionaries

    Returns:
        Formatted text string
    """
    lines = [
        f"Conversation: {conversation_id}",
        f"Total turns: {len(turns)}",
        "=" * 80,
        "",
    ]

    for turn in turns:
        lines.append(f"Turn {turn['turn']}:")
        lines.append(f"  User: {turn['user']}")
        lines.append(f"  Assistant: {turn['assistant']}")
        if turn.get("timestamp"):
            lines.append(f"  Timestamp: {turn['timestamp']}")
        lines.append("")

    return "\n".join(lines)


def _format_interactive(conversation_id: str, turns: list[dict[str, Any]]) -> str:
    """Format conversation with rich formatting for terminal.

    Args:
        conversation_id: Conversation ID
        turns: List of turn dictionaries

    Returns:
        Rich-formatted string
    """
    from io import StringIO

    from rich.console import Console
    from rich.panel import Panel

    buffer = StringIO()
    console = Console(file=buffer, force_terminal=True)

    console.print(f"\n[bold cyan]Conversation ID:[/bold cyan] {conversation_id}")
    console.print(f"[bold cyan]Total Turns:[/bold cyan] {len(turns)}\n")

    for turn in turns:
        # User message
        console.print(
            Panel(
                turn["user"],
                title=f"[bold green]Turn {turn['turn']} - User[/bold green]",
                border_style="green",
            )
        )

        # Assistant message
        console.print(
            Panel(
                turn["assistant"],
                title=f"[bold blue]Turn {turn['turn']} - Assistant[/bold blue]",
                border_style="blue",
            )
        )

        if turn.get("timestamp"):
            console.print(f"[dim]  {turn['timestamp']}[/dim]\n")
        else:
            console.print("")

    return buffer.getvalue()


def list_conversations(db_path: str = "out/conversations.duckdb") -> list[str]:
    """List all conversation IDs in the database.

    Args:
        db_path: Path to DuckDB file

    Returns:
        List of conversation IDs

    Raises:
        ConversationReplayError: If database not found or error
    """
    if DuckDBMemory is None:
        raise ImportError(
            "PyRIT is required for this feature. "
            "Install with: pip install ai-purple-ops[pyrit]"
        )

    db_path_obj = Path(db_path)

    if not db_path_obj.exists():
        raise ConversationReplayError(f"Database not found: {db_path}")

    try:
        memory = DuckDBMemory(db_path=db_path)

        # Query distinct conversation IDs from PyRIT memory
        # This uses the DuckDB connection directly
        with memory.get_session() as session:
            result = session.execute(
                text(
                    "SELECT DISTINCT conversation_id FROM PromptMemoryEntries WHERE conversation_id IS NOT NULL ORDER BY conversation_id"
                )
            )
            conversation_ids = [row[0] for row in result.fetchall()]

        return conversation_ids

    except Exception as e:
        raise ConversationReplayError(f"Error listing conversations: {e}") from e
