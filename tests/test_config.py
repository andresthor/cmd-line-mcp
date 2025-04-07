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
    assert "output" in config.config
    
    # Check new structure of commands section
    assert "read" in config.config["commands"]
    assert "write" in config.config["commands"]
    assert "system" in config.config["commands"]
    assert "blocked" in config.config["commands"]
    assert "dangerous_patterns" in config.config["commands"]

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
                "read": ["test-read"],
                "write": ["test-write"],
                "system": ["test-system"],
                "blocked": ["test-blocked"],
                "dangerous_patterns": ["test-pattern"]
            },
            "security": {
                "allow_user_confirmation": True,
                "require_session_id": True,
                "session_timeout": 1800,
                "allow_command_separators": False
            },
            "output": {
                "max_size": 50000,
                "format": "json"
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
        assert config.get("commands", "read") == ["test-read"]
        assert config.get("security", "session_timeout") == 1800
        assert config.get("security", "allow_command_separators") == False
        assert config.get("output", "max_size") == 50000
        assert config.get("output", "format") == "json"
    finally:
        # Clean up the temporary file
        os.unlink(temp_file_path)

def test_config_get_default_value():
    """Test getting config values with defaults."""
    config = Config()
    # Test getting an existing value
    assert isinstance(config.get("commands", "read"), list)
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

def test_config_get_all():
    """Test getting entire configuration."""
    config = Config()
    all_config = config.get_all()
    assert isinstance(all_config, dict)
    assert "server" in all_config
    assert "commands" in all_config
    assert "security" in all_config
    assert "output" in all_config

def test_config_from_env_vars():
    """Test loading config from environment variables."""
    # Set some environment variables for testing
    os.environ["CMD_LINE_MCP_SERVER_LOG_LEVEL"] = "ERROR"
    os.environ["CMD_LINE_MCP_SECURITY_SESSION_TIMEOUT"] = "7200"
    os.environ["CMD_LINE_MCP_OUTPUT_MAX_SIZE"] = "50000"
    os.environ["CMD_LINE_MCP_COMMANDS_READ"] = "ls,cat,grep"
    os.environ["CMD_LINE_MCP_SECURITY_ALLOW_COMMAND_SEPARATORS"] = "false"
    
    try:
        config = Config()
        # The env vars should override the defaults
        assert config.get("server", "log_level") == "ERROR"
        assert config.get("security", "session_timeout") == 7200
        assert config.get("output", "max_size") == 50000
        assert config.get("commands", "read") == ["ls", "cat", "grep"]
        assert config.get("security", "allow_command_separators") == False
    finally:
        # Clean up the environment variables
        del os.environ["CMD_LINE_MCP_SERVER_LOG_LEVEL"]
        del os.environ["CMD_LINE_MCP_SECURITY_SESSION_TIMEOUT"]
        del os.environ["CMD_LINE_MCP_OUTPUT_MAX_SIZE"]
        del os.environ["CMD_LINE_MCP_COMMANDS_READ"]
        del os.environ["CMD_LINE_MCP_SECURITY_ALLOW_COMMAND_SEPARATORS"]

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

def test_config_update():
    """Test runtime updating of configuration."""
    config = Config()
    
    # Get the initial command count
    initial_read_commands = config.get("commands", "read")
    
    # Define updates
    updates = {
        "server": {
            "name": "updated-server"
        },
        "commands": {
            "read": ["test1", "test2", "test3"]
        },
        "security": {
            "allow_command_separators": False
        }
    }
    
    # Apply updates
    config.update(updates)
    
    # Check that updates were applied
    assert config.get("server", "name") == "updated-server"
    assert config.get("commands", "read") == ["test1", "test2", "test3"]
    assert config.get("security", "allow_command_separators") == False
    
    # Check that other config sections remained intact
    assert "version" in config.get_section("server")
    assert "write" in config.get_section("commands")

def test_config_save_to_file():
    """Test saving configuration to a file."""
    # Create a temporary config file
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as temp_file:
        temp_file_path = temp_file.name
    
    try:
        # Create a config instance with the temp file path
        config = Config(temp_file_path)
        
        # Update some values
        updates = {
            "server": {
                "name": "saved-server"
            },
            "commands": {
                "read": ["test-save"]
            }
        }
        
        # Apply updates and save to file
        config.update(updates, save=True)
        
        # Create a new config instance from the same file to verify changes were saved
        new_config = Config(temp_file_path)
        
        # Check that saved values are loaded
        assert new_config.get("server", "name") == "saved-server"
        assert new_config.get("commands", "read") == ["test-save"]
    finally:
        # Clean up the temporary file
        os.unlink(temp_file_path)

def test_env_file_loading():
    """Test loading configuration from a .env file."""
    # Create a temporary .env file
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".env", delete=False) as temp_file:
        temp_file.write("CMD_LINE_MCP_SERVER_NAME=env-server\n")
        temp_file.write("CMD_LINE_MCP_SECURITY_SESSION_TIMEOUT=9000\n")
        temp_file.write("CMD_LINE_MCP_COMMANDS_READ=env1,env2,env3\n")
        temp_file.write("CMD_LINE_MCP_SECURITY_ALLOW_COMMAND_SEPARATORS=false\n")
        temp_file_path = temp_file.name
    
    try:
        # Create a config instance with the temp env file
        config = Config(env_file_path=temp_file_path)
        
        # Check that values from .env file were loaded
        assert config.get("server", "name") == "env-server"
        assert config.get("security", "session_timeout") == 9000
        assert config.get("commands", "read") == ["env1", "env2", "env3"]
        assert config.get("security", "allow_command_separators") == False
    finally:
        # Clean up the temporary file
        os.unlink(temp_file_path)

def test_config_caching():
    """Test configuration value caching."""
    config = Config()
    
    # Get the value once to cache it
    value1 = config.get("server", "name")
    
    # Change the value directly in the dictionary
    config.config["server"]["name"] = "modified-name"
    
    # Get the value again - should be the cached value
    value2 = config.get("server", "name")
    
    # Check that the cached value is being returned
    assert value1 == value2
    
    # Clear the cache
    config._config_cache.clear()
    
    # Get the value again - should be the new value
    value3 = config.get("server", "name")
    
    # Check that the new value is returned after cache clear
    assert value3 == "modified-name"

def test_effective_command_lists():
    """Test getting effective command lists."""
    config = Config()
    
    # Get effective command lists
    command_lists = config.get_effective_command_lists()
    
    # Check that all expected lists are present
    assert "read" in command_lists
    assert "write" in command_lists
    assert "system" in command_lists
    assert "blocked" in command_lists
    assert "dangerous_patterns" in command_lists
    
    # Check that lists have the expected types
    assert isinstance(command_lists["read"], list)
    assert isinstance(command_lists["write"], list)
    assert isinstance(command_lists["system"], list)
    assert isinstance(command_lists["blocked"], list)
    assert isinstance(command_lists["dangerous_patterns"], list)

def test_separator_support():
    """Test command separator support configuration."""
    # Create a default config (all separators allowed)
    config = Config()
    support = config.has_separator_support()
    
    # Check that all separators are enabled by default
    assert support["pipe"] == True
    assert support["semicolon"] == True
    assert support["ampersand"] == True
    
    # Disable all separators
    config.config["security"]["allow_command_separators"] = False
    support = config.has_separator_support()
    
    # Check that all separators are disabled
    assert support["pipe"] == False
    assert support["semicolon"] == False
    assert support["ampersand"] == False
    
    # Re-enable separators but add a dangerous pattern to block semicolons
    config.config["security"]["allow_command_separators"] = True
    config.config["commands"]["dangerous_patterns"].append(";")
    support = config.has_separator_support()
    
    # Check that only semicolons are disabled
    assert support["pipe"] == True
    assert support["semicolon"] == False
    assert support["ampersand"] == True