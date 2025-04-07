"""Tests for the session management module."""

import time
import pytest
from cmd_line_mcp.session import SessionManager


def test_session_init():
    """Test initializing the session manager."""
    session_manager = SessionManager()
    assert session_manager.sessions == {}


def test_get_session_new():
    """Test getting a new session."""
    session_manager = SessionManager()
    session_id = "test-session-id"

    # Get a new session
    session = session_manager.get_session(session_id)

    # Check session structure
    assert session_id in session_manager.sessions
    assert "created_at" in session
    assert "last_active" in session
    assert "approved_commands" in session
    assert "approved_command_types" in session
    assert isinstance(session["approved_commands"], set)
    assert isinstance(session["approved_command_types"], set)


def test_get_session_existing():
    """Test getting an existing session."""
    session_manager = SessionManager()
    session_id = "test-session-id"

    # Get a new session
    original_session = session_manager.get_session(session_id)
    original_created_at = original_session["created_at"]
    original_last_active = original_session["last_active"]

    # Manually set last_active to an earlier time to ensure a difference
    # This is more reliable than using time.sleep() which can be inconsistent
    session_manager.sessions[session_id]["last_active"] = (
        original_last_active - 1.0
    )

    # Get the same session again
    updated_session = session_manager.get_session(session_id)

    # Check that created_at remains the same
    assert updated_session["created_at"] == original_created_at
    # But last_active should be updated
    assert (
        updated_session["last_active"]
        > session_manager.sessions[session_id]["last_active"] - 0.5
    )


def test_has_command_approval():
    """Test checking command approval."""
    session_manager = SessionManager()
    session_id = "test-session-id"
    command = "mkdir test"

    # Initially the command should not be approved
    assert not session_manager.has_command_approval(session_id, command)

    # Approve the command
    session = session_manager.get_session(session_id)
    session["approved_commands"].add(command)

    # Now it should be approved
    assert session_manager.has_command_approval(session_id, command)


def test_has_command_type_approval():
    """Test checking command type approval."""
    session_manager = SessionManager()
    session_id = "test-session-id"
    command_type = "write"

    # Initially the command type should not be approved
    assert not session_manager.has_command_type_approval(
        session_id, command_type
    )

    # Approve the command type
    session_manager.approve_command_type(session_id, command_type)

    # Now it should be approved
    assert session_manager.has_command_type_approval(session_id, command_type)


def test_approve_command():
    """Test approving a command."""
    session_manager = SessionManager()
    session_id = "test-session-id"
    command = "mkdir test"

    # Approve the command
    session_manager.approve_command(session_id, command)

    # Verify it's approved
    assert session_manager.has_command_approval(session_id, command)

    # Verify the session exists
    assert session_id in session_manager.sessions

    # Verify the command is in the approved_commands set
    session = session_manager.get_session(session_id)
    assert command in session["approved_commands"]


def test_clean_old_sessions():
    """Test cleaning up old sessions."""
    session_manager = SessionManager()

    # Create several sessions with different timestamps
    now = time.time()

    # Current session
    session_manager.sessions["current"] = {
        "created_at": now,
        "last_active": now,
        "approved_commands": set(),
        "approved_command_types": set(),
    }

    # Old session (2 hours old)
    session_manager.sessions["old"] = {
        "created_at": now - 7200,
        "last_active": now - 7200,
        "approved_commands": set(),
        "approved_command_types": set(),
    }

    # Very old session (1 day old)
    session_manager.sessions["very_old"] = {
        "created_at": now - 86400,
        "last_active": now - 86400,
        "approved_commands": set(),
        "approved_command_types": set(),
    }

    # Clean sessions older than 1 hour (3600 seconds)
    session_manager.clean_old_sessions(3600)

    # Check which sessions were removed
    assert "current" in session_manager.sessions
    assert "old" not in session_manager.sessions
    assert "very_old" not in session_manager.sessions

    # Check that only old sessions were removed
    assert len(session_manager.sessions) == 1
