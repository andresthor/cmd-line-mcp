"""Configuration utilities for the command-line MCP server."""

import os
import json
from typing import Dict, Optional, Any

# Default configuration
DEFAULT_CONFIG = {
    "server": {
        "name": "cmd-line-mcp",
        "version": "0.1.0",
        "description": "MCP server for safely executing command-line tools",
        "log_level": "INFO",
    },
    "security": {
        "session_timeout": 3600,  # 1 hour
        "max_output_size": 102400,  # 100KB
        "allow_user_confirmation": True,
        "require_session_id": False,  # For Claude Desktop compatibility
    },
    "commands": {
        "read_commands": [
            "ls", "pwd", "cat", "less", "head", "tail", "grep",
            "find", "which", "du", "df", "file", "uname", "hostname", 
            "uptime", "date", "whoami", "id", "env", "history", "man",
            "info", "help"
        ],
        "write_commands": [
            "cp", "mv", "rm", "mkdir", "rmdir", "touch", "chmod", "chown",
            "ln", "echo", "printf"
        ],
        "system_commands": [
            "ps", "top", "htop", "who", "netstat", "ifconfig", "ping",
            "ssh", "scp", "tar", "gzip", "zip", "unzip", "curl", "wget"
        ],
        "blocked_commands": [
            "sudo", "su", "bash", "sh", "zsh", "ksh", "csh", "fish",
            "screen", "tmux", "nc", "telnet", "nmap",
            "dd", "mkfs", "mount", "umount", "shutdown", "reboot",
            "passwd", "chpasswd", "useradd", "userdel", "groupadd", "groupdel",
            "eval", "exec", "source", "."
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
            r"[;&|]",  # Command chaining
            r"`",  # Backtick command substitution
        ]
    }
}

class Config:
    """Configuration for the command-line MCP server."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the configuration.
        
        Args:
            config_path: Optional path to a configuration file
        """
        self.config = DEFAULT_CONFIG.copy()
        
        # Try to load configuration from environment variable
        env_config_path = os.environ.get("CMD_LINE_MCP_CONFIG")
        if env_config_path and os.path.exists(env_config_path):
            self._load_config(env_config_path)
            
        # Load configuration from specified path, overriding environment config
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)
            
        # Override with environment variables
        log_level = os.environ.get("CMD_LINE_MCP_LOG_LEVEL")
        if log_level is not None:
            self.config["server"]["log_level"] = log_level
            
        session_timeout = os.environ.get("CMD_LINE_MCP_SESSION_TIMEOUT")
        if session_timeout is not None:
            self.config["security"]["session_timeout"] = int(session_timeout)
            
        max_output_size = os.environ.get("CMD_LINE_MCP_MAX_OUTPUT_SIZE")
        if max_output_size is not None:
            self.config["security"]["max_output_size"] = int(max_output_size)
            
        allow_user_confirmation = os.environ.get("CMD_LINE_MCP_ALLOW_USER_CONFIRMATION")
        if allow_user_confirmation is not None:
            self.config["security"]["allow_user_confirmation"] = allow_user_confirmation.lower() in ["true", "1", "yes"]
            
        require_session_id = os.environ.get("CMD_LINE_MCP_REQUIRE_SESSION_ID")
        if require_session_id is not None:
            self.config["security"]["require_session_id"] = require_session_id.lower() in ["true", "1", "yes"]
    
    def _load_config(self, config_path: str) -> None:
        """Load configuration from a file.
        
        Args:
            config_path: Path to the configuration file
        """
        try:
            with open(config_path, "r") as f:
                loaded_config = json.load(f)
                
            # Merge loaded config with default config
            for section, values in loaded_config.items():
                if section in self.config:
                    if isinstance(self.config[section], dict) and isinstance(values, dict):
                        self.config[section].update(values)
                    else:
                        self.config[section] = values
                else:
                    self.config[section] = values
        except Exception as e:
            print(f"Error loading configuration from {config_path}: {str(e)}")
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value.
        
        Args:
            section: Configuration section
            key: Configuration key
            default: Default value if not found
            
        Returns:
            The configuration value
        """
        if section in self.config and key in self.config[section]:
            return self.config[section][key]
        return default
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get a configuration section.
        
        Args:
            section: Configuration section
            
        Returns:
            The configuration section
        """
        return self.config.get(section, {})
