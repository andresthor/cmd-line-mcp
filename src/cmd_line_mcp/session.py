"""Session management for the command-line MCP server."""

import time
from typing import Dict, Optional, Set

class SessionManager:
    """Manage user sessions for command permissions."""
    
    def __init__(self):
        """Initialize the session manager."""
        self.sessions: Dict[str, Dict[str, any]] = {}
        
    def get_session(self, session_id: str) -> Dict[str, any]:
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