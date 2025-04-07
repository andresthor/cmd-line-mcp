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

# The following tests need to be updated to use the newer API:
# 
# @pytest.mark.asyncio
# async def test_command_categories(server):
#     """Test that command categories are correctly defined."""
#     # Get the tools and check command categories
#     # ...
# 
# @pytest.mark.asyncio
# async def test_execute_read_command(server):
#     """Test executing a read command."""
#     # Get the execute_read_command tool and test it
#     # ...
# 
# @pytest.mark.asyncio
# async def test_session_management(server):
#     """Test session management and approval flow."""
#     # Test session-based approvals
#     # ...
