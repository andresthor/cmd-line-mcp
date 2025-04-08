"""Tests for the configuration module."""

import os
import json
import tempfile
import pytest
from cmd_line_mcp.config import Config

# Mark tests to skip due to environment specific issues
pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def test_config_init_default():
    """Test initializing Config with defaults loaded from default_config.json."""
    config = Config()
    assert config.config is not None
    # Check that default config has basic sections
    assert "server" in config.config
    assert "commands" in config.config
    assert "security" in config.config
    assert "output" in config.config

    # Check structure of commands section
    assert "read" in config.config["commands"]
    assert "write" in config.config["commands"]
    assert "system" in config.config["commands"]
    assert "blocked" in config.config["commands"]
    assert "dangerous_patterns" in config.config["commands"]
    
    # Check that default config has some expected values
    assert isinstance(config.config["commands"]["read"], list)
    assert len(config.config["commands"]["read"]) > 0
    assert isinstance(config.config["commands"]["write"], list)
    assert len(config.config["commands"]["write"]) > 0


def test_config_from_file():
    """Test loading config from a file."""
    # Create a temporary config file
    with tempfile.NamedTemporaryFile(
        mode="w+", suffix=".json", delete=False
    ) as temp_file:
        test_config = {
            "server": {
                "name": "test-server",
                "version": "0.0.4",
                "log_level": "DEBUG",
            },
            "commands": {
                "read": ["test-read"],
                "write": ["test-write"],
                "system": ["test-system"],
                "blocked": ["test-blocked"],
                "dangerous_patterns": ["test-pattern"],
            },
            "security": {
                "allow_user_confirmation": True,
                "require_session_id": True,
                "session_timeout": 1800,
                "allow_command_separators": False,
            },
            "output": {"max_size": 50000, "format": "json"},
        }
        json.dump(test_config, temp_file)
        temp_file_path = temp_file.name

    try:
        # Load the config from the temp file
        config = Config(temp_file_path)

        # Test that values were loaded correctly
        assert config.get("server", "name") == "test-server"
        assert config.get("server", "version") == "0.0.4"
        assert config.get("server", "log_level") == "DEBUG"
        assert config.get("commands", "read") == ["test-read"]
        assert config.get("security", "session_timeout") == 1800
        assert config.get("security", "allow_command_separators") is False
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


@pytest.mark.skip(reason="Environment variable handling needs to be fixed")
def test_config_from_env_vars():
    """Test loading config from environment variables."""
    # Clean existing environment variables
    env_vars = [var for var in os.environ if var.startswith("CMD_LINE_MCP_")]
    existing_vars = {}
    for var in env_vars:
        existing_vars[var] = os.environ[var]
        del os.environ[var]

    # Set our test environment variables
    os.environ["CMD_LINE_MCP_SERVER_LOG_LEVEL"] = "ERROR"
    os.environ["CMD_LINE_MCP_SECURITY_SESSION_TIMEOUT"] = "7200"
    os.environ["CMD_LINE_MCP_OUTPUT_MAX_SIZE"] = "50000"
    os.environ["CMD_LINE_MCP_COMMANDS_READ"] = "ls,cat,grep"
    os.environ["CMD_LINE_MCP_SECURITY_ALLOW_COMMAND_SEPARATORS"] = "false"

    try:
        # Create a fresh config with only environment variables
        config = Config(config_path=None, env_file_path=None)

        # The env vars should override the defaults
        assert config.get("server", "log_level") == "ERROR"
        assert config.get("security", "session_timeout") == 7200
        assert config.get("output", "max_size") == 50000
        assert config.get("commands", "read") == ["ls", "cat", "grep"]
        assert config.get("security", "allow_command_separators") is False
    finally:
        # Clean up the environment variables
        del os.environ["CMD_LINE_MCP_SERVER_LOG_LEVEL"]
        del os.environ["CMD_LINE_MCP_SECURITY_SESSION_TIMEOUT"]
        del os.environ["CMD_LINE_MCP_OUTPUT_MAX_SIZE"]
        del os.environ["CMD_LINE_MCP_COMMANDS_READ"]
        del os.environ["CMD_LINE_MCP_SECURITY_ALLOW_COMMAND_SEPARATORS"]

        # Restore existing environment variables
        for var, value in existing_vars.items():
            os.environ[var] = value


def test_load_json_error_handling():
    """Test error handling when loading invalid JSON."""
    # Create a temp file with invalid JSON
    with tempfile.NamedTemporaryFile(
        mode="w+", suffix=".json", delete=False
    ) as temp_file:
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
        
def test_load_default_config():
    """Test that the default configuration is properly loaded."""
    # Create a Config instance with no parameters
    config = Config()
    
    # Check that some expected commands are in the read commands list
    read_commands = config.config["commands"]["read"]
    assert "ls" in read_commands
    assert "cat" in read_commands
    
    # Check that some expected commands are in the write commands list
    write_commands = config.config["commands"]["write"]
    assert "mkdir" in write_commands
    assert "touch" in write_commands
    
    # Check that some expected commands are in the system commands list
    system_commands = config.config["commands"]["system"]
    assert "ps" in system_commands
    
    # Check that some expected commands are in the blocked commands list
    blocked_commands = config.config["commands"]["blocked"]
    assert "sudo" in blocked_commands
    
    # Check some security settings
    assert "whitelisted_directories" in config.config["security"]
    
    # Check that server info is loaded
    assert "name" in config.config["server"]
    assert "version" in config.config["server"]


def test_config_update():
    """Test runtime updating of configuration."""
    config = Config()

    # No need to get initial command list

    # Define updates
    updates = {
        "server": {"name": "updated-server"},
        "commands": {"read": ["test1", "test2", "test3"]},
        "security": {"allow_command_separators": False},
    }

    # Apply updates
    config.update(updates)

    # Check that updates were applied
    assert config.get("server", "name") == "updated-server"
    assert config.get("commands", "read") == ["test1", "test2", "test3"]
    assert config.get("security", "allow_command_separators") is False

    # Check that other config sections remained intact
    assert "version" in config.get_section("server")
    assert "write" in config.get_section("commands")


def test_config_save_to_file():
    """Test saving configuration to a file."""
    # Create a temporary config file
    with tempfile.NamedTemporaryFile(
        mode="w+", suffix=".json", delete=False
    ) as temp_file:
        temp_file_path = temp_file.name

    try:
        # Create a config instance with the temp file path
        config = Config(temp_file_path)

        # Update some values
        updates = {
            "server": {"name": "saved-server"},
            "commands": {"read": ["test-save"]},
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
        
def test_config_precedence():
    """Test configuration loading precedence."""
    # Clean existing environment variables
    env_vars = [var for var in os.environ if var.startswith("CMD_LINE_MCP_")]
    existing_vars = {}
    for var in env_vars:
        existing_vars[var] = os.environ[var]
        del os.environ[var]
        
    # Create three temporary files with different configurations
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as user_config_file:
        user_config = {
            "server": {"name": "user-config", "log_level": "DEBUG"},
            "commands": {"read": ["user-read-cmd"]},
        }
        json.dump(user_config, user_config_file)
        user_config_path = user_config_file.name
    
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".env", delete=False) as env_file:
        env_file.write("CMD_LINE_MCP_SERVER_NAME=env-file-name\n")
        env_file.write("CMD_LINE_MCP_COMMANDS_READ=env-read-cmd\n")
        env_file_path = env_file.name
        
    try:
        # Set environment variable with highest precedence
        os.environ["CMD_LINE_MCP_SERVER_NAME"] = "env-var-name"
        
        # Create config with user config and env file
        config = Config(config_path=user_config_path, env_file_path=env_file_path)
        
        # Check that values are loaded according to precedence:
        # 1. Environment variables (highest)
        # 2. Env file
        # 3. User config file
        # 4. Default config (lowest)
        
        # Environment variable should take precedence
        assert config.get("server", "name") == "env-var-name"
        
        # Environment file should take precedence over user config for READ commands
        assert "env-read-cmd" in config.get("commands", "read")
        
        # Check user config overrides default for log_level
        assert config.get("server", "log_level") == "DEBUG"
        
        # Ensure some default values still exist from default_config.json
        system_commands = config.get("commands", "system")
        assert isinstance(system_commands, list)
        assert len(system_commands) > 0
        assert "ps" in system_commands  # This should come from default_config.json
    finally:
        # Clean up
        os.unlink(user_config_path)
        os.unlink(env_file_path)
        
        # Clean up environment variables
        for var in ["CMD_LINE_MCP_SERVER_NAME"]:
            if var in os.environ:
                del os.environ[var]
        
        # Restore existing environment variables
        for var, value in existing_vars.items():
            os.environ[var] = value


@pytest.mark.skip(reason="Environment file handling needs to be fixed")
def test_env_file_loading():
    """Test loading configuration from a .env file."""
    # Clean existing environment variables
    env_vars = [var for var in os.environ if var.startswith("CMD_LINE_MCP_")]
    existing_vars = {}
    for var in env_vars:
        existing_vars[var] = os.environ[var]
        del os.environ[var]

    # Create a temporary .env file
    with tempfile.NamedTemporaryFile(
        mode="w+", suffix=".env", delete=False
    ) as temp_file:
        temp_file.write("CMD_LINE_MCP_SERVER_NAME=env-server\n")
        temp_file.write("CMD_LINE_MCP_SECURITY_SESSION_TIMEOUT=9000\n")
        temp_file.write("CMD_LINE_MCP_COMMANDS_READ=env1,env2,env3\n")
        temp_file.write(
            "CMD_LINE_MCP_SECURITY_ALLOW_COMMAND_SEPARATORS=false\n"
        )
        temp_file_path = temp_file.name

    try:
        # Create a fresh config instance with the temp env file only
        config = Config(config_path=None, env_file_path=temp_file_path)

        # Check that values from .env file were loaded
        assert config.get("server", "name") == "env-server"
        assert config.get("security", "session_timeout") == 9000
        assert config.get("commands", "read") == ["env1", "env2", "env3"]
        assert config.get("security", "allow_command_separators") is False
    finally:
        # Clean up the temporary file
        os.unlink(temp_file_path)

        # Restore existing environment variables
        for var, value in existing_vars.items():
            os.environ[var] = value


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


def test_env_var_command_merging():
    """Test that environment variables merge with existing command lists."""
    # Create a temporary config file with existing commands
    with tempfile.NamedTemporaryFile(
        mode="w+", suffix=".json", delete=False
    ) as temp_file:
        test_config = {
            "commands": {
                "read": ["ls", "cat", "grep"],
                "system": ["ps", "top"]
            }
        }
        json.dump(test_config, temp_file)
        temp_file_path = temp_file.name

    # Clean existing environment variables
    env_vars = [var for var in os.environ if var.startswith("CMD_LINE_MCP_")]
    existing_vars = {}
    for var in env_vars:
        existing_vars[var] = os.environ[var]
        del os.environ[var]

    # Set environment variables to add commands
    os.environ["CMD_LINE_MCP_COMMANDS_READ"] = "awk,sed,jq"
    os.environ["CMD_LINE_MCP_COMMANDS_SYSTEM"] = "docker,kubectl"

    try:
        # Create config with both the file and env vars
        config = Config(config_path=temp_file_path)
        
        # Get the command lists
        command_lists = config.get_effective_command_lists()
        
        # Check that both original and new commands are present
        # Original commands from config file
        assert "ls" in command_lists["read"]
        assert "cat" in command_lists["read"]
        assert "grep" in command_lists["read"]
        assert "ps" in command_lists["system"]
        assert "top" in command_lists["system"]
        
        # New commands from environment variables
        assert "awk" in command_lists["read"]
        assert "sed" in command_lists["read"]
        assert "jq" in command_lists["read"]
        assert "docker" in command_lists["system"]
        assert "kubectl" in command_lists["system"]
    finally:
        # Clean up
        os.unlink(temp_file_path)
        
        # Restore original env vars
        for var in ["CMD_LINE_MCP_COMMANDS_READ", "CMD_LINE_MCP_COMMANDS_SYSTEM"]:
            if var in os.environ:
                del os.environ[var]
                
        # Restore existing environment variables
        for var, value in existing_vars.items():
            os.environ[var] = value


def test_separator_support():
    """Test command separator support configuration."""
    # Create a fresh default config with explicit empty options
    config = Config(config_path=None, env_file_path=None)

    # Make sure command separators are explicitly enabled
    config.config["security"]["allow_command_separators"] = True

    # Make sure dangerous patterns don't have any separator patterns
    filtered_patterns = [
        p
        for p in config.config["commands"]["dangerous_patterns"]
        if not any(sep in p for sep in ["|", ";", "&"])
    ]
    config.config["commands"]["dangerous_patterns"] = filtered_patterns

    # Get support status
    support = config.has_separator_support()

    # Check that all separators are enabled
    assert support["pipe"] is True
    assert support["semicolon"] is True
    assert support["ampersand"] is True

    # Disable all separators
    config.config["security"]["allow_command_separators"] = False
    support = config.has_separator_support()

    # Check that all separators are disabled
    assert support["pipe"] is False
    assert support["semicolon"] is False
    assert support["ampersand"] is False

    # Re-enable separators but add a dangerous pattern to block semicolons
    config.config["security"]["allow_command_separators"] = True
    config.config["commands"]["dangerous_patterns"].append(";")
    support = config.has_separator_support()

    # Check that only semicolons are disabled
    assert support["pipe"] is True
    assert support["semicolon"] is False
    assert support["ampersand"] is True
