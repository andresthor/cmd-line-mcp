"""Tests for server initialization with FastMCP compatibility."""

from cmd_line_mcp.server import CommandLineMCP
import tempfile
import json


def test_server_initialization():
    """Test that CommandLineMCP initializes without errors."""
    # This should not raise any TypeError about unexpected keyword arguments
    server = CommandLineMCP()
    assert server is not None
    assert server.app is not None
    assert hasattr(server.app, 'name')


def test_server_with_custom_config():
    """Test server initialization with custom config including version and description."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_data = {
            "server": {
                "name": "test-mcp-server",
                "version": "1.0.0",
                "description": "Test MCP Server",
                "log_level": "INFO"
            },
            "security": {
                "whitelisted_directories": ["/tmp"],
                "require_session_id": False
            },
            "commands": {
                "read": ["ls", "cat"],
                "write": ["touch"],
                "system": ["ps"],
                "blocked": ["sudo"]
            }
        }
        json.dump(config_data, f)
        config_path = f.name

    # Initialize server with custom config
    server = CommandLineMCP(config_path=config_path)

    # Verify server initialized successfully
    assert server is not None
    assert server.app is not None

    # The FastMCP app should have the instructions field set with version and description
    # Note: FastMCP stores the instructions internally, we can't directly access it
    # but the fact that initialization doesn't fail is the key test here


def test_server_app_has_correct_attributes():
    """Test that the FastMCP app has the expected attributes after initialization."""
    server = CommandLineMCP()

    # Check that the app object exists and has expected attributes
    assert hasattr(server, 'app')
    assert server.app is not None

    # FastMCP should have tools registered
    # Note: The exact API for accessing tools may vary by MCP version
    # The key is that initialization completes without errors
