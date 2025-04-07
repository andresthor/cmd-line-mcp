"""Configuration utilities for the command-line MCP server."""

import os
import json
from typing import Dict, Optional, Any, List
from pathlib import Path

# Default configuration
DEFAULT_CONFIG = {
    "server": {
        "name": "cmd-line-mcp",
        "version": "0.2.0",
        "description": "MCP server for safely executing command-line tools",
        "log_level": "INFO",
    },
    "security": {
        "session_timeout": 3600,  # 1 hour
        "max_output_size": 102400,  # 100KB
        "allow_user_confirmation": True,
        "require_session_id": False,  # For Claude Desktop compatibility
        # Allow pipes, semicolons, ampersands
        "allow_command_separators": True,
    },
    "commands": {
        "read": [
            "ls",
            "pwd",
            "cat",
            "less",
            "head",
            "tail",
            "grep",
            "find",
            "which",
            "du",
            "df",
            "file",
            "uname",
            "hostname",
            "uptime",
            "date",
            "whoami",
            "id",
            "env",
            "history",
            "man",
            "info",
            "help",
            "sort",
        ],
        "write": [
            "cp",
            "mv",
            "rm",
            "mkdir",
            "rmdir",
            "touch",
            "chmod",
            "chown",
            "ln",
            "echo",
            "printf",
            "export",
            "tar",
            "gzip",
            "zip",
            "unzip",
        ],
        "system": [
            "ps",
            "top",
            "htop",
            "who",
            "netstat",
            "ifconfig",
            "ping",
            "ssh",
            "scp",
            "curl",
            "wget",
        ],
        "blocked": [
            "sudo",
            "su",
            "bash",
            "sh",
            "zsh",
            "ksh",
            "csh",
            "fish",
            "screen",
            "tmux",
            "nc",
            "telnet",
            "nmap",
            "dd",
            "mkfs",
            "mount",
            "umount",
            "shutdown",
            "reboot",
            "passwd",
            "chpasswd",
            "useradd",
            "userdel",
            "groupadd",
            "groupdel",
            "eval",
            "exec",
            "source",
            ".",
        ],
        "dangerous_patterns": [
            r"rm\s+-rf\s+/",  # Delete root directory
            r">\s+/dev/(sd|hd|nvme|xvd)",  # Write to block devices
            r">\s+/dev/null",  # Output redirection
            r">\s+/etc/",  # Write to system config
            r">\s+/boot/",  # Write to boot
            r">\s+/bin/",  # Write to binaries
            r">\s+/sbin/",  # Write to system binaries
            r">\s+/usr/bin/",  # Write to user binaries
            r">\s+/usr/sbin/",  # Write to system binaries
            r">\s+/usr/local/bin/",  # Write to local binaries
            r"2>&1",  # Redirect stderr to stdout
            r"\$\(",  # Command substitution
            r"\$\{\w+\}",  # Variable substitution
            r"`",  # Backtick command substitution
        ],
    },
    "output": {
        "max_size": 102400,  # 100KB
        "format": "text",
    },
}


class Config:
    """Configuration for the command-line MCP server."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        env_file_path: Optional[str] = None,
    ):
        """Initialize the configuration.

        Args:
            config_path: Optional path to a configuration file
            env_file_path: Optional path to a .env file
        """
        self.config = DEFAULT_CONFIG.copy()
        self._config_path = config_path
        self._env_file_path = env_file_path
        self._config_cache = {}
        self._env_vars = {}

        # Load configuration in order of precedence:
        # 1. Default config
        # 2. Config file from environment variable
        # 3. Config file from constructor parameter
        # 4. .env file
        # 5. Environment variables

        # Try to load configuration from environment variable
        env_config_path = os.environ.get("CMD_LINE_MCP_CONFIG")
        if env_config_path and os.path.exists(env_config_path):
            self._load_config_from_json(env_config_path)

        # Load configuration from specified path, overriding environment config
        if config_path and os.path.exists(config_path):
            self._load_config_from_json(config_path)

        # Load .env file if provided
        if env_file_path and os.path.exists(env_file_path):
            self._load_env_file(env_file_path)
        else:
            # Look for .env in current directory and parent directories (up to 3 levels)
            current_dir = Path.cwd()
            potential_paths = [current_dir]
            for _ in range(3):  # Check up to 3 parent directories
                parent = current_dir.parent
                if parent == current_dir:  # Reached root
                    break
                potential_paths.append(parent)
                current_dir = parent

            for path in potential_paths:
                env_file = path / ".env"
                if env_file.exists():
                    self._load_env_file(str(env_file))
                    break

        # Override with environment variables - this now takes all CMD_LINE_MCP_* vars
        self._load_from_environment_variables()

    def _load_config_from_json(self, config_path: str) -> None:
        """Load configuration from a JSON file.

        Args:
            config_path: Path to the configuration file
        """
        try:
            with open(config_path, "r") as f:
                loaded_config = json.load(f)

            # Merge loaded config with default config
            self._update_config_recursively(self.config, loaded_config)
        except Exception as e:
            print(f"Error loading configuration from {config_path}: {str(e)}")

    def _update_config_recursively(self, target: Dict, source: Dict) -> None:
        """Recursively update configuration dictionary.

        Args:
            target: Target dictionary to update
            source: Source dictionary with new values
        """
        for key, value in source.items():
            if (
                key in target
                and isinstance(target[key], dict)
                and isinstance(value, dict)
            ):
                self._update_config_recursively(target[key], value)
            else:
                target[key] = value

    def _load_env_file(self, env_file_path: str) -> None:
        """Load configuration from a .env file.

        Args:
            env_file_path: Path to the .env file
        """
        try:
            with open(env_file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip()

                        # Remove quotes if present
                        if (value.startswith('"') and value.endswith('"')) or (
                            value.startswith("'") and value.endswith("'")
                        ):
                            value = value[1:-1]

                        # Only process CMD_LINE_MCP_ variables
                        if key.startswith("CMD_LINE_MCP_"):
                            self._env_vars[key] = value
        except Exception as e:
            print(f"Error loading .env file from {env_file_path}: {str(e)}")

    def _load_from_environment_variables(self) -> None:
        """Load configuration from environment variables."""
        # First priority: actual environment variables
        for key, value in os.environ.items():
            if key.startswith("CMD_LINE_MCP_"):
                self._env_vars[key] = value

        # Process all environment variables
        for key, value in self._env_vars.items():
            if not key.startswith("CMD_LINE_MCP_"):
                continue

            # Remove prefix and get the nested keys
            config_key = key[13:].lower()  # Remove "CMD_LINE_MCP_" prefix

            # Handle special cases for commands and arrays
            if config_key.startswith("commands_"):
                # Handle command categories (read, write, system, blocked)
                category = config_key[9:]  # Remove "commands_" prefix
                if category in ["read", "write", "system", "blocked"]:
                    # Split comma-separated values
                    commands = [
                        cmd.strip() for cmd in value.split(",") if cmd.strip()
                    ]
                    # Merge with existing commands rather than replacing them
                    # Make sure no duplicates by converting to set and back to list
                    existing_commands = self.config["commands"][category]
                    merged_commands = list(set(existing_commands + commands))
                    self.config["commands"][category] = merged_commands
            elif config_key == "dangerous_patterns":
                # Split comma-separated patterns
                patterns = [
                    pattern.strip()
                    for pattern in value.split(",")
                    if pattern.strip()
                ]
                # Merge with existing patterns rather than replacing them
                existing_patterns = self.config["commands"]["dangerous_patterns"]
                merged_patterns = list(set(existing_patterns + patterns))
                self.config["commands"]["dangerous_patterns"] = merged_patterns
            elif config_key.startswith("security_"):
                # Handle security settings
                setting = config_key[9:]  # Remove "security_" prefix
                if setting in self.config["security"]:
                    # Convert value type based on the default
                    default_value = self.config["security"][setting]
                    if isinstance(default_value, bool):
                        self.config["security"][setting] = value.lower() in [
                            "true",
                            "1",
                            "yes",
                        ]
                    elif isinstance(default_value, int):
                        try:
                            self.config["security"][setting] = int(value)
                        except ValueError:
                            print(f"Invalid integer value for {key}: {value}")
                    else:
                        self.config["security"][setting] = value
            elif config_key.startswith("server_"):
                # Handle server settings
                setting = config_key[7:]  # Remove "server_" prefix
                if setting in self.config["server"]:
                    # Convert value type based on the default
                    default_value = self.config["server"][setting]
                    if isinstance(default_value, bool):
                        self.config["server"][setting] = value.lower() in [
                            "true",
                            "1",
                            "yes",
                        ]
                    elif isinstance(default_value, int):
                        try:
                            self.config["server"][setting] = int(value)
                        except ValueError:
                            print(f"Invalid integer value for {key}: {value}")
                    else:
                        self.config["server"][setting] = value
            elif config_key.startswith("output_"):
                # Handle output settings
                setting = config_key[7:]  # Remove "output_" prefix
                if setting in self.config["output"]:
                    # Convert value type based on the default
                    default_value = self.config["output"][setting]
                    if isinstance(default_value, bool):
                        self.config["output"][setting] = value.lower() in [
                            "true",
                            "1",
                            "yes",
                        ]
                    elif isinstance(default_value, int):
                        try:
                            self.config["output"][setting] = int(value)
                        except ValueError:
                            print(f"Invalid integer value for {key}: {value}")
                    else:
                        self.config["output"][setting] = value

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value.

        Args:
            section: Configuration section
            key: Configuration key
            default: Default value if not found

        Returns:
            The configuration value
        """
        # Check cache first
        cache_key = f"{section}.{key}"
        if cache_key in self._config_cache:
            return self._config_cache[cache_key]

        # Get value from config
        if section in self.config and key in self.config[section]:
            value = self.config[section][key]
            # Cache the result
            self._config_cache[cache_key] = value
            return value
        return default

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get a configuration section.

        Args:
            section: Configuration section

        Returns:
            The configuration section
        """
        return self.config.get(section, {})

    def get_all(self) -> Dict[str, Any]:
        """Get the entire configuration.

        Returns:
            The complete configuration dictionary
        """
        return self.config

    def update(self, updates: Dict[str, Any], save: bool = False) -> None:
        """Update the configuration.

        Args:
            updates: Dictionary with configuration updates
            save: Whether to save the configuration to the file
        """
        self._update_config_recursively(self.config, updates)

        # Clear cache
        self._config_cache.clear()

        # Save to file if requested
        if save and self._config_path:
            try:
                with open(self._config_path, "w") as f:
                    json.dump(self.config, f, indent=2)
            except Exception as e:
                print(
                    f"Error saving configuration to {self._config_path}: {str(e)}"
                )

    def get_effective_command_lists(self) -> Dict[str, List[str]]:
        """Get the effective command lists taking into account all configuration.

        Returns:
            Dictionary with read, write, system, and blocked command lists
        """
        return {
            "read": self.config["commands"]["read"],
            "write": self.config["commands"]["write"],
            "system": self.config["commands"]["system"],
            "blocked": self.config["commands"]["blocked"],
            "dangerous_patterns": self.config["commands"][
                "dangerous_patterns"
            ],
        }

    def has_separator_support(self) -> Dict[str, bool]:
        """Get support status for command separators.

        Returns:
            Dictionary with support status for each separator
        """
        # Use patterns to check if separators are in dangerous_patterns
        separators = {
            "pipe": True,
            "semicolon": True,
            "ampersand": True,
        }  # |  # ;  # &

        dangerous_patterns = self.config["commands"]["dangerous_patterns"]
        allow_separators = self.config["security"].get(
            "allow_command_separators", True
        )

        if not allow_separators:
            return {key: False for key in separators}

        # Check if there's a pattern that would block these separators
        for pattern in dangerous_patterns:
            # Be very careful with the pipe character checking
            # Only block if the pipe character is the ENTIRE pattern
            if pattern == ";" or pattern == ";":
                separators["semicolon"] = False
            if pattern == "&" or pattern == "&":
                separators["ampersand"] = False
            if pattern == "|" or pattern == r"\|":
                separators["pipe"] = False

        return separators
