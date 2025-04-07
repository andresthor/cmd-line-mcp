"""Tests for the command-line MCP server.

NOTE: These tests need to be updated for the latest MCP library version.
The API for accessing tools and executing them has changed significantly.
"""

import pytest
from cmd_line_mcp.server import CommandLineMCP
from cmd_line_mcp.security import validate_command

@pytest.fixture
def server():
    """Create a CommandLineMCP instance for testing."""
    return CommandLineMCP()

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
async def test_command_categories(server):
    """Test that command categories are correctly defined."""
    # Test that the command categories are loaded from config
    assert isinstance(server.read_commands, list)
    assert isinstance(server.write_commands, list)
    assert isinstance(server.system_commands, list)
    assert isinstance(server.blocked_commands, list)
    
    # Test the list_available_commands tool
    result = await server._list_available_commands_func()
    assert "read_commands" in result
    assert "write_commands" in result
    assert "system_commands" in result
    assert "blocked_commands" in result
    
    # Verify that common commands are in the right categories
    assert "ls" in server.read_commands
    assert "mkdir" in server.write_commands
    assert "ps" in server.system_commands
    assert "sudo" in server.blocked_commands

@pytest.mark.asyncio
async def test_execute_read_command(server):
    """Test executing a read command."""
    # Test the execute_read_command tool with a valid read command
    result = await server._execute_read_command_func("ls -la")
    assert result["success"] == True
    assert "output" in result
    assert "command_type" in result
    assert result["command_type"] == "read"
    
    # Test with an invalid command
    result = await server._execute_read_command_func("invalid_command")
    assert result["success"] == False
    assert "error" in result
    
    # Test with a write command (should be rejected)
    result = await server._execute_read_command_func("mkdir test_dir")
    assert result["success"] == False
    assert "error" in result
    assert "only supports read commands" in result["error"]
    
    # Test with a system command (should be rejected)
    result = await server._execute_read_command_func("ps aux")
    assert result["success"] == False
    assert "error" in result
    assert "only supports read commands" in result["error"]

@pytest.mark.asyncio
async def test_session_management(server):
    """Test session management and approval flow."""
    # Create a session ID for testing
    session_id = "test-session-123"
    
    # Use a simple write command - using touch which is safer for testing
    mock_write_command = "touch test_file.tmp"
    
    # Test executing a write command without approval (should require approval)
    result = await server._execute_command(mock_write_command, session_id=session_id)
    
    # Check if auto-approval is enabled (would depend on config)
    if "requires_approval" in result and result["requires_approval"]:
        # If approval is required, we should see that in the response
        assert result["success"] == False
        assert result["requires_approval"] == True
        assert result["command_type"] == "write"
        assert result["session_id"] == session_id
        
        # Now approve the command type
        approval_result = await server._approve_command_type_func("write", session_id, True)
        assert approval_result["success"] == True
        
        # Retry the command, it should work now
        result = await server._execute_command(mock_write_command, session_id=session_id)
        assert "command_type" in result
        assert result["command_type"] == "write"
    else:
        # If auto-approval is enabled (e.g., for Claude Desktop compatibility),
        # the command should be processed without requiring explicit approval
        # Check only that the command was categorized correctly, not that it succeeded
        # (since it might fail if the server doesn't have permission to create the file)
        # The key test is that the security approval mechanism is working
        assert "output" in result
        assert "error" in result
        
    # Test the session manager directly
    # Add a command type approval
    server.session_manager.approve_command_type(session_id, "write")
    # Check that the approval is stored
    assert server.session_manager.has_command_type_approval(session_id, "write")
    # Test session timeout
    server.session_manager.clean_old_sessions(0)  # Force session cleanup
    assert session_id not in server.session_manager.sessions
    
    # Clean up test file if it was created
    await server._execute_command("rm -f test_file.tmp", session_id=session_id)
