"""Tests for the configuration module."""

import os
import json
import tempfile
import pytest
from pathlib import Path
from cmd_line_mcp.config import Config

def test_config_init_default():
    """Test initializing Config with defaults."""
    config = Config()
    assert config.config is not None
    # Check that default config has basic sections
    assert "server" in config.config
    assert "commands" in config.config
    assert "security" in config.config

def test_config_from_file():
    """Test loading config from a file."""
    # Create a temporary config file
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as temp_file:
        test_config = {
            "server": {
                "name": "test-server",
                "version": "0.0.1",
                "log_level": "DEBUG"
            },
            "commands": {
                "read_commands": ["test-read"],
                "write_commands": ["test-write"],
                "system_commands": ["test-system"],
                "blocked_commands": ["test-blocked"],
                "dangerous_patterns": ["test-pattern"]
            },
            "security": {
                "allow_user_confirmation": True,
                "require_session_id": True,
                "session_timeout": 1800
            }
        }
        json.dump(test_config, temp_file)
        temp_file_path = temp_file.name
    
    try:
        # Load the config from the temp file
        config = Config(temp_file_path)
        
        # Test that values were loaded correctly
        assert config.get("server", "name") == "test-server"
        assert config.get("server", "version") == "0.0.1"
        assert config.get("server", "log_level") == "DEBUG"
        assert config.get("commands", "read_commands") == ["test-read"]
        assert config.get("security", "session_timeout") == 1800
    finally:
        # Clean up the temporary file
        os.unlink(temp_file_path)

def test_config_get_default_value():
    """Test getting config values with defaults."""
    config = Config()
    # Test getting an existing value
    assert isinstance(config.get("commands", "read_commands"), list)
    # Test getting a non-existent value with a default
    assert config.get("nonexistent", "value", "default") == "default"
    # Test getting a nested path that doesn't exist
    assert config.get("server", "nonexistent", "default") == "default"

def test_config_get_section():
    """Test getting an entire config section."""
    config = Config()
    server_section = config.get_section("server")
    assert isinstance(server_section, dict)
    assert "name" in server_section
    assert "version" in server_section
    
    # Test getting a non-existent section
    nonexistent_section = config.get_section("nonexistent")
    assert nonexistent_section == {}
    
    # Note: The get_section method doesn't support a default parameter
    # so we're not testing that case

def test_config_from_env_vars():
    """Test loading config from environment variables."""
    # Set some environment variables for testing
    # Note: The Config class only checks for specific environment variables,
    # CMD_LINE_MCP_SERVER_NAME is not one of them
    os.environ["CMD_LINE_MCP_LOG_LEVEL"] = "ERROR"
    os.environ["CMD_LINE_MCP_SESSION_TIMEOUT"] = "7200"
    os.environ["CMD_LINE_MCP_MAX_OUTPUT_SIZE"] = "50000"
    
    try:
        config = Config()
        # The env vars should override the defaults
        assert config.get("server", "log_level") == "ERROR"
        assert config.get("security", "session_timeout") == 7200
        assert config.get("security", "max_output_size") == 50000
    finally:
        # Clean up the environment variables
        del os.environ["CMD_LINE_MCP_LOG_LEVEL"]
        del os.environ["CMD_LINE_MCP_SESSION_TIMEOUT"]
        del os.environ["CMD_LINE_MCP_MAX_OUTPUT_SIZE"]

def test_load_json_error_handling():
    """Test error handling when loading invalid JSON."""
    # Create a temp file with invalid JSON
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as temp_file:
        temp_file.write("not valid json")
        temp_file_path = temp_file.name
    
    try:
        # Should not raise an exception, but log an error and use defaults
        config = Config(temp_file_path)
        # Verify defaults were used
        assert "server" in config.config
        assert "commands" in config.config
        assert "security" in config.config
    finally:
        # Clean up the temporary file
        os.unlink(temp_file_path)
