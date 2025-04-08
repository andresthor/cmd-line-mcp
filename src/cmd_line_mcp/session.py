"""Session management for the command-line MCP server."""

import time
import os
from typing import Dict, Any, Set


class SessionManager:
    """Manage user sessions for command permissions."""

    def __init__(self):
        """Initialize the session manager."""
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def get_session(self, session_id: str) -> Dict[str, Any]:
        """Get a session by ID, creating it if it doesn't exist.

        Args:
            session_id: The session ID

        Returns:
            The session data
        """
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "created_at": time.time(),
                "last_active": time.time(),
                "approved_commands": set(),
                "approved_command_types": set(),
                "approved_directories": set(),  # New: track approved directories
            }

        # Update last active time
        self.sessions[session_id]["last_active"] = time.time()
        return self.sessions[session_id]

    def has_command_approval(self, session_id: str, command: str) -> bool:
        """Check if a command has been approved for a session.

        Args:
            session_id: The session ID
            command: The command to check

        Returns:
            True if the command has been approved, False otherwise
        """
        session = self.get_session(session_id)
        return command in session["approved_commands"]

    def has_command_type_approval(self, session_id: str, command_type: str) -> bool:
        """Check if a command type has been approved for a session.

        Args:
            session_id: The session ID
            command_type: The command type to check

        Returns:
            True if the command type has been approved, False otherwise
        """
        session = self.get_session(session_id)
        return command_type in session["approved_command_types"]

    def approve_command(self, session_id: str, command: str) -> None:
        """Approve a command for a session.

        Args:
            session_id: The session ID
            command: The command to approve
        """
        session = self.get_session(session_id)
        session["approved_commands"].add(command)

    def approve_command_type(self, session_id: str, command_type: str) -> None:
        """Approve a command type for a session.

        Args:
            session_id: The session ID
            command_type: The command type to approve
        """
        session = self.get_session(session_id)
        session["approved_command_types"].add(command_type)

    def has_directory_approval(self, session_id: str, directory: str) -> bool:
        """Check if a directory has been approved for a session.

        Args:
            session_id: The session ID
            directory: The directory to check

        Returns:
            True if the directory has been approved, False otherwise
        """
        session = self.get_session(session_id)
        approved_dirs = session["approved_directories"]

        # Check if the directory or any of its parents have been approved
        for approved_dir in approved_dirs:
            # Exact match
            if directory == approved_dir:
                return True

            # Check if directory is a subdirectory of an approved directory
            if directory.startswith(approved_dir + os.sep):
                return True

        return False

    def approve_directory(self, session_id: str, directory: str) -> None:
        """Approve a directory for a session.

        Args:
            session_id: The session ID
            directory: The directory to approve
        """
        session = self.get_session(session_id)
        session["approved_directories"].add(directory)

    def get_approved_directories(self, session_id: str) -> Set[str]:
        """Get all approved directories for a session.

        Args:
            session_id: The session ID

        Returns:
            Set of approved directories
        """
        session = self.get_session(session_id)
        return session["approved_directories"]

    def clean_old_sessions(self, max_age: int = 3600) -> None:
        """Clean up old sessions.

        Args:
            max_age: Maximum age of sessions in seconds (default: 1 hour)
        """
        now = time.time()
        to_remove = []

        for session_id, session in self.sessions.items():
            if now - session["last_active"] > max_age:
                to_remove.append(session_id)

        for session_id in to_remove:
            del self.sessions[session_id]
