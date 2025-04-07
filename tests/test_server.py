"""Tests for the command-line MCP server."""

import asyncio
import pytest
from cmd_line_mcp.server import CommandLineMCP
from cmd_line_mcp.security import validate_command

@pytest.fixture
def server():
    """Create a CommandLineMCP instance for testing."""
    return CommandLineMCP()

def test_command_categories(server):
    """Test that command categories are correctly defined."""
    result = asyncio.run(server.app.tools["list_available_commands"].func())
    
    assert isinstance(result, dict)
    assert "read_commands" in result
    assert "write_commands" in result
    assert "system_commands" in result
    assert "blocked_commands" in result
    
    # Verify some key commands are in the right categories
    assert "ls" in result["read_commands"]
    assert "rm" in result["write_commands"]
    assert "ps" in result["system_commands"]
    assert "sudo" in result["blocked_commands"]

def test_validate_command():
    """Test the command validation function."""
    # Valid read command
    result = validate_command("ls -la")
    assert result["is_valid"] is True
    assert result["command_type"] == "read"
    assert result["error"] is None
    
    # Valid write command
    result = validate_command("mkdir test_dir")
    assert result["is_valid"] is True
    assert result["command_type"] == "write"
    assert result["error"] is None
    
    # Valid system command
    result = validate_command("ps aux")
    assert result["is_valid"] is True
    assert result["command_type"] == "system"
    assert result["error"] is None
    
    # Blocked command
    result = validate_command("sudo rm -rf /")
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert result["error"] is not None
    
    # Dangerous pattern
    result = validate_command("rm -rf /")
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert result["error"] is not None
    
    # Unsupported command
    result = validate_command("nonsense_command")
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert result["error"] is not None

@pytest.mark.asyncio
async def test_execute_read_command(server):
    """Test executing a read command."""
    # Valid read command
    result = await server.app.tools["execute_read_command"].func("pwd")
    assert result["success"] is True
    assert len(result["output"]) > 0
    assert result["command_type"] == "read"
    
    # Try to execute write command with read-only tool
    result = await server.app.tools["execute_read_command"].func("touch test_file.txt")
    assert result["success"] is False
    assert "This tool only supports read commands" in result["error"]

@pytest.mark.asyncio
async def test_session_management(server):
    """Test session management and approval flow."""
    session_id = "test-session-id"
    
    # Try to execute write command without approval
    result = await server._execute_command("mkdir test_dir", session_id=session_id)
    assert result["success"] is False
    assert "requires approval" in result["error"]
    assert result["requires_approval"] is True
    assert result["command_type"] == "write"
    
    # Approve the command type
    approval = await server.app.tools["approve_command_type"].func(
        "write", session_id, True
    )
    assert approval["success"] is True
    
    # Try again after approval
    result = await server._execute_command("mkdir test_dir", session_id=session_id)
    assert "requires_approval" not in result
    
    # Clean up if the directory was created
    if result["success"]:
        cleanup = await server._execute_command("rmdir test_dir", session_id=session_id)
        assert cleanup["success"] is True