"""Tests for the directory permission system."""

import os
import pytest
from unittest.mock import patch, MagicMock

from cmd_line_mcp.security import (
    normalize_path,
    extract_directory_from_command,
    is_directory_whitelisted,
)
from cmd_line_mcp.session import SessionManager


def test_normalize_path():
    """Test path normalization."""
    # Since the actual result depends on the OS and filesystem,
    # we'll fully mock it to ensure consistent tests
    
    # Test absolute path
    with patch("os.path.abspath", return_value="/home/user"):
        with patch("os.path.normpath", return_value="/home/user"):
            with patch("os.path.realpath", return_value="/home/user"):
                assert normalize_path("/home/user") == "/home/user"
    
    # Test relative path conversion to absolute
    with patch("os.path.abspath", return_value="/home/user/docs"):
        with patch("os.path.normpath", return_value="/home/user/docs"):
            with patch("os.path.realpath", return_value="/home/user/docs"):
                assert normalize_path("./docs") == "/home/user/docs"
    
    # Test resolving parent directory
    with patch("os.path.abspath", return_value="/home/user"):
        with patch("os.path.normpath", return_value="/home/user"):
            with patch("os.path.realpath", return_value="/home/user"):
                assert normalize_path("/home/user/docs/..") == "/home/user"


def test_extract_directory_from_command():
    """Test extracting directory from command."""
    # Test ls command
    with patch("os.path.isdir", return_value=True):
        with patch("cmd_line_mcp.security.normalize_path", return_value="/home/user/docs"):
            assert extract_directory_from_command("ls /home/user/docs") == "/home/user/docs"
    
    # Test cat command with file
    with patch("os.path.isdir", return_value=False):
        with patch("os.path.dirname", return_value="/home/user"):
            with patch("cmd_line_mcp.security.normalize_path", return_value="/home/user"):
                assert extract_directory_from_command("cat /home/user/file.txt") == "/home/user"
    
    # Test command without directory argument
    with patch("os.getcwd", return_value="/current/dir"):
        with patch("cmd_line_mcp.security.normalize_path", return_value="/current/dir"):
            assert extract_directory_from_command("pwd") == "/current/dir"


def test_is_directory_whitelisted():
    """Test directory whitelisting check."""
    whitelisted_dirs = ["/home", "/tmp", "/usr/local/share"]
    
    # We need to patch normalize_path completely because it's used both for
    # the input directory and for each whitelisted directory in the function
    
    # Test exact match
    with patch("cmd_line_mcp.security.normalize_path") as mock_normalize:
        # Set up the mock to return the input unchanged
        mock_normalize.side_effect = lambda x: x
        
        assert is_directory_whitelisted("/home", whitelisted_dirs) == True
        
        # Check that normalize_path was called at least once
        mock_normalize.assert_called()
    
    # Test subdirectory match
    with patch("cmd_line_mcp.security.normalize_path") as mock_normalize:
        # Set up the mock to return the input unchanged
        mock_normalize.side_effect = lambda x: x
        
        assert is_directory_whitelisted("/home/user/docs", whitelisted_dirs) == True
        
        # Check that normalize_path was called at least once
        mock_normalize.assert_called()
    
    # Test non-whitelisted directory
    with patch("cmd_line_mcp.security.normalize_path") as mock_normalize:
        # Set up the mock to return the input unchanged
        mock_normalize.side_effect = lambda x: x
        
        assert is_directory_whitelisted("/var/www", whitelisted_dirs) == False
        
        # Check that normalize_path was called at least once
        mock_normalize.assert_called()


def test_session_manager_directory_approval():
    """Test session manager directory approval."""
    session_manager = SessionManager()
    session_id = "test-session"
    
    # Test adding directory approval
    session_manager.approve_directory(session_id, "/home/user/project")
    assert session_manager.has_directory_approval(session_id, "/home/user/project") == True
    
    # Test subdirectory approval
    assert session_manager.has_directory_approval(session_id, "/home/user/project/src") == True
    
    # Test non-approved directory
    assert session_manager.has_directory_approval(session_id, "/var/www") == False
    
    # Test getting approved directories
    approved_dirs = session_manager.get_approved_directories(session_id)
    assert "/home/user/project" in approved_dirs


def test_session_timeout_clears_directory_approvals():
    """Test that session timeout clears directory approvals."""
    session_manager = SessionManager()
    session_id = "test-session"
    
    # Approve a directory
    session_manager.approve_directory(session_id, "/home/user/project")
    
    # Mock time to simulate timeout
    with patch("time.time", return_value=0):
        # Create session with last_active=0
        session = session_manager.get_session(session_id)
        
    # Fast forward 2 hours
    with patch("time.time", return_value=7200):
        # Clean sessions with 1 hour timeout
        session_manager.clean_old_sessions(3600)
        
        # Session should be removed
        assert session_id not in session_manager.sessions