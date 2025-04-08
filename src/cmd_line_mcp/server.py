"""
Command-line MCP server that safely executes Unix/macOS terminal commands.
"""

import argparse
import asyncio
import logging
import os
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

from cmd_line_mcp.config import Config
from cmd_line_mcp.security import (
    validate_command,
    extract_directory_from_command,
    is_directory_whitelisted,
    normalize_path,
)
from cmd_line_mcp.session import SessionManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class CommandLineMCP:
    """Command-line MCP server for Unix/macOS terminal commands."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        env_file_path: Optional[str] = None,
    ):
        """Initialize the MCP server.

        Args:
            config_path: Optional path to a configuration file
            env_file_path: Optional path to a .env file
        """
        self.config = Config(config_path, env_file_path)
        self.session_manager = SessionManager()

        # Create a fixed persistent session for Claude Desktop mode - FIXED ID
        self.claude_desktop_session_id = "claude_desktop_fixed_session"

        # NOTE: We don't pre-approve any directories - let the user explicitly approve them
        # or configure them in the whitelist

        logger.info(
            f"Created persistent Claude Desktop session: {self.claude_desktop_session_id}"
        )

        # Set up logging
        log_level = self.config.get("server", "log_level", "INFO")
        logger.setLevel(getattr(logging, log_level))

        # Load command lists from config
        command_lists = self.config.get_effective_command_lists()
        self.read_commands = command_lists["read"]
        self.write_commands = command_lists["write"]
        self.system_commands = command_lists["system"]
        self.blocked_commands = command_lists["blocked"]
        self.dangerous_patterns = command_lists["dangerous_patterns"]

        # Get separator support status
        self.separator_support = self.config.has_separator_support()

        # Get whitelisted directories from config
        self.whitelisted_directories = self.config.get_section("security").get(
            "whitelisted_directories", ["/home", "/tmp"]
        )

        # Initialize MCP app
        server_config = self.config.get_section("server")
        self.app = FastMCP(
            server_config.get("name", "cmd-line-mcp"),
            version=server_config.get("version", "0.4.0"),
            description=server_config.get(
                "description",
                "MCP server for safely executing command-line tools",
            ),
        )

        # Store capabilities data to use in get_command_help tool
        self.command_capabilities = {
            "supported_commands": {
                "read": self.read_commands,
                "write": self.write_commands,
                "system": self.system_commands,
            },
            "blocked_commands": self.blocked_commands,
            "command_chaining": {
                "pipe": (
                    "Supported" if self.separator_support["pipe"] else "Not supported"
                ),
                "semicolon": (
                    "Supported"
                    if self.separator_support["semicolon"]
                    else "Not supported"
                ),
                "ampersand": (
                    "Supported"
                    if self.separator_support["ampersand"]
                    else "Not supported"
                ),
            },
            "command_restrictions": "Special characters like $(), ${}, backticks, and I/O redirection are blocked",
        }

        self.usage_examples = [
            {
                "command": "ls ~/Downloads",
                "description": "List files in downloads directory",
            },
            {
                "command": "cat ~/.bashrc",
                "description": "View bash configuration",
            },
            {
                "command": "du -h ~/Downloads/* | grep G",
                "description": "Find large files in downloads folder",
            },
            {
                "command": 'find ~/Downloads -type f -name "*.pdf"',
                "description": "Find all PDF files in downloads",
            },
            {
                "command": "head -n 20 ~/Documents/notes.txt",
                "description": "View the first 20 lines of a file",
            },
            {
                "command": "ls -la | awk '{print $1, $9}'",
                "description": "List files showing permissions and names using awk",
            },
            {
                "command": "cat file.txt | awk '{if($1>10) print $0}'",
                "description": "Filter lines where first column is greater than 10",
            },
        ]

        # Register tools
        execute_command_tool = self.app.tool()

        @execute_command_tool  # Keep decorator reference to satisfy linters
        async def execute_command(
            command: str, session_id: Optional[str] = None
        ) -> Dict[str, Any]:
            """
            Execute a Unix/macOS terminal command.

            Args:
                command: The command to execute
                session_id: Optional session ID for permission management

            Returns:
                A dictionary with command output and status
            """
            # For Claude Desktop compatibility, use the fixed session ID
            require_session_id = self.config.get(
                "security", "require_session_id", False
            )
            if not session_id or not require_session_id:
                session_id = self.claude_desktop_session_id
                logger.info(f"Using persistent Claude Desktop session: {session_id}")

            return await self._execute_command(command, session_id=session_id)

        # Store reference to silence linter warnings
        self._execute_command_func = execute_command

        execute_read_command_tool = self.app.tool()

        @execute_read_command_tool  # Keep decorator reference to satisfy linters
        async def execute_read_command(
            command: str, session_id: Optional[str] = None
        ) -> Dict[str, Any]:
            """
            Execute a read-only Unix/macOS terminal command (ls, cat, grep, etc.).

            Args:
                command: The read-only command to execute
                session_id: Optional session ID for permission management

            Returns:
                A dictionary with command output and status
            """
            # For Claude Desktop compatibility, use the fixed session ID when no session ID provided
            if not session_id:
                session_id = self.claude_desktop_session_id
                logger.info(
                    f"Using persistent Claude Desktop session for read command: {session_id}"
                )

            # Validate command and check directory permissions in one go
            # Get the latest command lists
            command_lists = self.config.get_effective_command_lists()
            allow_separators = self.config.get(
                "security", "allow_command_separators", True
            )

            validation = validate_command(
                command,
                command_lists["read"],
                command_lists["write"],
                command_lists["system"],
                command_lists["blocked"],
                command_lists["dangerous_patterns"],
                allow_command_separators=allow_separators,
            )

            if not validation["is_valid"]:
                return {
                    "success": False,
                    "output": "",
                    "error": validation["error"],
                }

            if validation["command_type"] != "read":
                return {
                    "success": False,
                    "output": "",
                    "error": "This tool only supports read commands. Use execute_command for other command types.",
                }

            # Extract directory and check permissions (apply same directory checks as in _execute_command)
            working_dir = extract_directory_from_command(command)
            logger.info(f"Read command - extracted working directory: {working_dir}")

            # Check if directory is whitelisted or has session approval
            directory_allowed = False

            if working_dir:
                # Check global whitelist first
                if is_directory_whitelisted(working_dir, self.whitelisted_directories):
                    directory_allowed = True
                    logger.info(
                        f"Read command - directory '{working_dir}' is globally whitelisted"
                    )
                # Check session approvals if we have a session ID
                elif session_id and self.session_manager.has_directory_approval(
                    session_id, working_dir
                ):
                    directory_allowed = True
                    logger.info(
                        f"Read command - directory '{working_dir}' is approved for session {session_id}"
                    )
                else:
                    logger.warning(
                        f"Read command - directory '{working_dir}' is not whitelisted or approved"
                    )
                    # For Claude Desktop compatibility mode (require_session_id = False)
                    require_session_id = self.config.get(
                        "security", "require_session_id", False
                    )
                    auto_approve_in_desktop = self.config.get_section("security").get(
                        "auto_approve_directories_in_desktop_mode", False
                    )

                    if not require_session_id:
                        # Check if the directory is approved in the persistent desktop session
                        if self.session_manager.has_directory_approval(
                            self.claude_desktop_session_id, working_dir
                        ):
                            directory_allowed = True
                            logger.info(
                                f"Read command - directory '{working_dir}' is approved in persistent desktop session"
                            )
                        elif auto_approve_in_desktop:
                            # Auto-approve directories in desktop mode if configured
                            directory_allowed = True
                            # Also add to persistent session for future requests
                            self.session_manager.approve_directory(
                                self.claude_desktop_session_id, working_dir
                            )
                            logger.warning(
                                f"Read command - auto-approving directory access in desktop mode: {working_dir}"
                            )
                        else:
                            # Only allow whitelisted directories if auto-approve is off
                            directory_allowed = False
                            logger.warning(
                                f"Read command - directory '{working_dir}' is not whitelisted - restricting access"
                            )
            else:
                # If we couldn't extract a directory, default to requiring permission
                logger.warning(
                    "Read command - could not extract working directory from command"
                )
                working_dir = os.getcwd()  # Default to current directory

                # Check whitelist for current directory
                if is_directory_whitelisted(working_dir, self.whitelisted_directories):
                    directory_allowed = True
                elif session_id and self.session_manager.has_directory_approval(
                    session_id, working_dir
                ):
                    directory_allowed = True
                else:
                    # For Claude Desktop compatibility mode
                    require_session_id = self.config.get(
                        "security", "require_session_id", False
                    )
                    auto_approve_in_desktop = self.config.get_section("security").get(
                        "auto_approve_directories_in_desktop_mode", False
                    )

                    if not require_session_id:
                        # Check if the directory is approved in the persistent desktop session
                        if self.session_manager.has_directory_approval(
                            self.claude_desktop_session_id, working_dir
                        ):
                            directory_allowed = True
                            logger.info(
                                f"Read command - directory '{working_dir}' is approved in persistent desktop session"
                            )
                        elif auto_approve_in_desktop:
                            # Auto-approve directories in desktop mode if configured
                            directory_allowed = True
                            # Also add to persistent session for future requests
                            self.session_manager.approve_directory(
                                self.claude_desktop_session_id, working_dir
                            )
                            logger.warning(
                                f"Read command - auto-approving directory access in desktop mode: {working_dir}"
                            )
                        else:
                            # Only allow whitelisted directories if auto-approve is off
                            directory_allowed = False

            # If directory is not allowed
            if not directory_allowed:
                # Check if we're in Claude Desktop mode (no session ID or require_session_id=false)
                require_session_id = self.config.get(
                    "security", "require_session_id", False
                )
                if not session_id or not require_session_id:
                    # Always use the fixed persistent session ID for Claude Desktop
                    desktop_session_id = self.claude_desktop_session_id

                    # Include approval request information for Claude Desktop
                    return {
                        "success": False,
                        "output": "",
                        "error": f"Read command - access to directory '{working_dir}' is not allowed. Only whitelisted directories can be accessed.\n"
                        + f"Whitelisted directories include: {', '.join(self.whitelisted_directories)}\n"
                        + "Note: To request access to this directory, use the approve_directory tool with:\n"
                        + f'  approve_directory(directory="{working_dir}", session_id="{desktop_session_id}", remember=True)',
                        "directory": working_dir,
                        "session_id": desktop_session_id,
                        "requires_directory_approval": True,  # Signal that approval is needed
                    }
                else:
                    # For normal mode, request approval
                    return {
                        "success": False,
                        "output": "",
                        "error": f"Read command - directory '{working_dir}' requires approval. Use approve_directory tool with session_id '{session_id}'.",
                        "requires_directory_approval": True,
                        "directory": working_dir,
                        "session_id": session_id,
                    }

            # Now that we've validated both the command and directory permissions, execute the command
            return await self._execute_command(
                command, command_type="read", session_id=session_id
            )

        # Store reference to silence linter warnings
        self._execute_read_command_func = execute_read_command

        list_available_commands_tool = self.app.tool()

        @list_available_commands_tool  # Keep decorator reference to satisfy linters
        async def list_available_commands() -> Dict[str, List[str]]:
            """
            List all available commands by category.

            Returns:
                A dictionary with commands grouped by category
            """
            # Get the latest command lists
            command_lists = self.config.get_effective_command_lists()

            return {
                "read_commands": command_lists["read"],
                "write_commands": command_lists["write"],
                "system_commands": command_lists["system"],
                "blocked_commands": command_lists["blocked"],
            }

        # Store reference to silence linter warnings
        self._list_available_commands_func = list_available_commands

        get_command_help_tool = self.app.tool()

        @get_command_help_tool  # Keep decorator reference to satisfy linters
        async def get_command_help() -> Dict[str, Any]:
            """
            Get detailed help about command capabilities and usage.

            This tool provides comprehensive information about:
            - Supported commands in each category (read, write, system)
            - Blocked commands for security reasons
            - Command chaining capabilities (pipes, semicolons, ampersands)
            - Usage restrictions and examples

            Returns:
                A dictionary with detailed information about command capabilities and usage
            """
            # Get the latest command lists and separator support
            command_lists = self.config.get_effective_command_lists()
            separator_support = self.config.has_separator_support()

            # Log the separator support for debugging
            logger.info(f"Separator support status: {separator_support}")
            logger.info(
                f"allow_command_separators setting: {self.config.get('security', 'allow_command_separators')}"
            )

            # Extra check for pipe character in dangerous patterns
            pipe_in_patterns = any(
                "|" in p or r"\|" in p for p in command_lists["dangerous_patterns"]
            )
            logger.info(
                f"Pipe character found in dangerous patterns: {pipe_in_patterns}"
            )

            # Update capabilities
            updated_capabilities = {
                "supported_commands": {
                    "read": command_lists["read"],
                    "write": command_lists["write"],
                    "system": command_lists["system"],
                },
                "blocked_commands": command_lists["blocked"],
                "command_chaining": {
                    "pipe": (
                        "Supported" if separator_support["pipe"] else "Not supported"
                    ),
                    "semicolon": (
                        "Supported"
                        if separator_support["semicolon"]
                        else "Not supported"
                    ),
                    "ampersand": (
                        "Supported"
                        if separator_support["ampersand"]
                        else "Not supported"
                    ),
                },
                "command_restrictions": "Special characters like $(), ${}, backticks, and I/O redirection are blocked",
            }

            # Provide helpful information for Claude to understand command usage
            return {
                "capabilities": updated_capabilities,
                "examples": self.usage_examples,
                "recommended_approach": {
                    "finding_large_files": "Use 'du -h <directory>/* | sort -hr | head -n 10' to find the 10 largest files",
                    "file_searching": "Use 'find <directory> -type f -name \"pattern\"' for file searches",
                    "text_searching": "Use 'grep \"pattern\" <file>' to search in files",
                    "file_viewing": "Use 'cat', 'head', or 'tail' for viewing files",
                    "sorting": "Use 'sort' with options like -n (numeric), -r (reverse), -h (human readable sizes)",
                    "text_processing": "Use 'awk' for advanced text processing. For example: 'ls -la | awk \"{print $1, $9}\"' to show permissions and filenames",
                    "column_filtering": "Use 'awk' to filter by column values: 'cat data.txt | awk \"{if($3 > 100) print}\"' to show lines where column 3 exceeds 100",
                },
                "permissions": {
                    "read_commands": "Can be executed without confirmation",
                    "write_commands": "Require approval for first use in a session",
                    "system_commands": "Require approval for first use in a session",
                },
            }

        # Store reference to silence linter warnings
        self._get_command_help_func = get_command_help

        approve_command_type_tool = self.app.tool()

        @approve_command_type_tool  # Keep decorator reference to satisfy linters
        async def approve_command_type(
            command_type: str, session_id: str, remember: bool = False
        ) -> Dict[str, Any]:
            """
            Approve a command type for the current session.

            Args:
                command_type: The command type to approve (read, write, system)
                session_id: The session ID
                remember: Whether to remember this approval for the session

            Returns:
                A dictionary with approval status
            """
            if command_type not in ["read", "write", "system"]:
                return {
                    "success": False,
                    "message": f"Invalid command type: {command_type}",
                }

            if remember:
                self.session_manager.approve_command_type(session_id, command_type)
                return {
                    "success": True,
                    "message": f"Command type '{command_type}' approved for this session",
                }
            else:
                return {
                    "success": True,
                    "message": f"Command type '{command_type}' approved for one-time use",
                }

        # Store reference to silence linter warnings
        self._approve_command_type_func = approve_command_type

        # Add tool for directory approval
        approve_directory_tool = self.app.tool()

        @approve_directory_tool  # Keep decorator reference to satisfy linters
        async def approve_directory(
            directory: str, session_id: str, remember: bool = True
        ) -> Dict[str, Any]:
            """
            Approve access to a directory for the current session.

            Args:
                directory: The directory to approve access to
                session_id: The session ID
                remember: Whether to remember this approval for the session

            Returns:
                A dictionary with approval status
            """
            # Normalize the directory path
            normalized_dir = normalize_path(directory)

            # Check if directory is already whitelisted globally
            if is_directory_whitelisted(normalized_dir, self.whitelisted_directories):
                return {
                    "success": True,
                    "message": f"Directory '{normalized_dir}' is already globally whitelisted",
                    "directory": normalized_dir,
                }

            # Check if directory is already approved for this session
            if self.session_manager.has_directory_approval(session_id, normalized_dir):
                return {
                    "success": True,
                    "message": f"Directory '{normalized_dir}' is already approved for this session",
                    "directory": normalized_dir,
                }

            # Approve the directory for this session
            if remember:
                self.session_manager.approve_directory(session_id, normalized_dir)
                return {
                    "success": True,
                    "message": f"Directory '{normalized_dir}' approved for this session",
                    "directory": normalized_dir,
                }
            else:
                return {
                    "success": True,
                    "message": f"Directory '{normalized_dir}' approved for one-time use",
                    "directory": normalized_dir,
                }

        # Store reference to silence linter warnings
        self._approve_directory_func = approve_directory

        # Tool to list whitelisted and approved directories
        list_directories_tool = self.app.tool()

        @list_directories_tool  # Keep decorator reference to satisfy linters
        async def list_directories(session_id: Optional[str] = None) -> Dict[str, Any]:
            """
            List all whitelisted and approved directories.

            Args:
                session_id: Optional session ID to get session-specific approvals

            Returns:
                A dictionary with globally whitelisted and session-approved directories
            """
            result = {
                "whitelisted_directories": self.whitelisted_directories,
                "session_approved_directories": [],
            }

            if session_id:
                result["session_approved_directories"] = list(
                    self.session_manager.get_approved_directories(session_id)
                )

            return result

        # Store reference to silence linter warnings
        self._list_directories_func = list_directories

        # Register new tools for configuration
        get_configuration_tool = self.app.tool()

        @get_configuration_tool  # Keep decorator reference to satisfy linters
        async def get_configuration() -> Dict[str, Any]:
            """
            Get the current configuration settings.

            Returns:
                The current configuration settings
            """
            # Get a safe copy of the configuration
            config_copy = self.config.get_all()

            # Format it for display
            return {
                "server": config_copy["server"],
                "security": config_copy["security"],
                "commands": {
                    "read_count": len(config_copy["commands"]["read"]),
                    "write_count": len(config_copy["commands"]["write"]),
                    "system_count": len(config_copy["commands"]["system"]),
                    "blocked_count": len(config_copy["commands"]["blocked"]),
                    "dangerous_patterns_count": len(
                        config_copy["commands"]["dangerous_patterns"]
                    ),
                    "full_command_lists": config_copy["commands"],
                },
                "output": config_copy["output"],
                "separator_support": self.config.has_separator_support(),
                "directory_whitelisting": {
                    "enabled": True,
                    "whitelisted_directories": self.whitelisted_directories,
                    "note": "Directories not in this list will require session approval",
                },
            }

        # Store reference to silence linter warnings
        self._get_configuration_func = get_configuration

        # update_configuration tool removed

    async def _execute_command(
        self,
        command: str,
        command_type: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute a Unix/macOS terminal command.

        Args:
            command: The command to execute
            command_type: Optional type of command (read, write, system)
            session_id: Optional session ID for permission management

        Returns:
            A dictionary with command output and status
        """
        # Get the latest command lists and separator settings
        command_lists = self.config.get_effective_command_lists()
        allow_separators = self.config.get("security", "allow_command_separators", True)

        # Validate the command
        validation = validate_command(
            command,
            command_lists["read"],
            command_lists["write"],
            command_lists["system"],
            command_lists["blocked"],
            command_lists["dangerous_patterns"],
            allow_command_separators=allow_separators,
        )

        if not validation["is_valid"]:
            return {
                "success": False,
                "output": "",
                "error": validation["error"],
            }

        # If command_type is specified, ensure it matches the validated type
        if command_type and validation["command_type"] != command_type:
            return {
                "success": False,
                "output": "",
                "error": f"Command type mismatch. Expected {command_type}, got {validation['command_type']}",
            }

        actual_command_type = validation["command_type"]

        # Extract the working directory from the command
        working_dir = extract_directory_from_command(command)
        logger.info(f"Extracted working directory from command: {working_dir}")

        # Check if directory is whitelisted or has session approval
        directory_allowed = False

        if working_dir:
            # Check global whitelist first
            if is_directory_whitelisted(working_dir, self.whitelisted_directories):
                directory_allowed = True
                logger.info(f"Directory '{working_dir}' is globally whitelisted")
            # Check session approvals if we have a session ID
            elif session_id and self.session_manager.has_directory_approval(
                session_id, working_dir
            ):
                directory_allowed = True
                logger.info(
                    f"Directory '{working_dir}' is approved for session {session_id}"
                )
            else:
                logger.warning(
                    f"Directory '{working_dir}' is not whitelisted or approved"
                )
                # For Claude Desktop compatibility mode (require_session_id = False)
                require_session_id = self.config.get(
                    "security", "require_session_id", False
                )
                auto_approve_in_desktop = self.config.get_section("security").get(
                    "auto_approve_directories_in_desktop_mode", False
                )

                if not require_session_id:
                    # Check if the directory is approved in the persistent desktop session
                    if self.session_manager.has_directory_approval(
                        self.claude_desktop_session_id, working_dir
                    ):
                        directory_allowed = True
                        logger.info(
                            f"Directory '{working_dir}' is approved in persistent desktop session"
                        )
                    elif auto_approve_in_desktop:
                        # Auto-approve directories in desktop mode if configured
                        directory_allowed = True
                        # Also add to persistent session for future requests
                        self.session_manager.approve_directory(
                            self.claude_desktop_session_id, working_dir
                        )
                        logger.warning(
                            f"Auto-approving directory access in desktop mode: {working_dir}"
                        )
                    else:
                        # Only allow whitelisted directories if auto-approve is off
                        directory_allowed = False
                        logger.warning(
                            f"Directory '{working_dir}' is not whitelisted - restricting access"
                        )
        else:
            # If we couldn't extract a directory, default to requiring permission
            logger.warning("Could not extract working directory from command")
            working_dir = os.getcwd()  # Default to current directory

            # Check whitelist for current directory
            if is_directory_whitelisted(working_dir, self.whitelisted_directories):
                directory_allowed = True
            elif session_id and self.session_manager.has_directory_approval(
                session_id, working_dir
            ):
                directory_allowed = True
            else:
                # For Claude Desktop compatibility mode
                require_session_id = self.config.get(
                    "security", "require_session_id", False
                )
                auto_approve_in_desktop = self.config.get_section("security").get(
                    "auto_approve_directories_in_desktop_mode", False
                )

                if not require_session_id:
                    # Check if the directory is approved in the persistent desktop session
                    if self.session_manager.has_directory_approval(
                        self.claude_desktop_session_id, working_dir
                    ):
                        directory_allowed = True
                        logger.info(
                            f"Directory '{working_dir}' is approved in persistent desktop session"
                        )
                    elif auto_approve_in_desktop:
                        # Auto-approve directories in desktop mode if configured
                        directory_allowed = True
                        # Also add to persistent session for future requests
                        self.session_manager.approve_directory(
                            self.claude_desktop_session_id, working_dir
                        )
                        logger.warning(
                            f"Auto-approving directory access in desktop mode: {working_dir}"
                        )
                    else:
                        # Only allow whitelisted directories if auto-approve is off
                        directory_allowed = False

        # If directory is not allowed
        if not directory_allowed:
            # Check if we're in Claude Desktop mode (no session ID or require_session_id=false)
            require_session_id = self.config.get(
                "security", "require_session_id", False
            )
            if not session_id or not require_session_id:
                # Always use the fixed persistent session ID for Claude Desktop
                desktop_session_id = self.claude_desktop_session_id

                # Include approval request information for Claude Desktop
                return {
                    "success": False,
                    "output": "",
                    "error": f"Access to directory '{working_dir}' is not allowed. Only whitelisted directories can be accessed.\n"
                    + f"Whitelisted directories include: {', '.join(self.whitelisted_directories)}\n"
                    + "Note: To request access to this directory, use the approve_directory tool with:\n"
                    + f'  approve_directory(directory="{working_dir}", session_id="{desktop_session_id}", remember=True)',
                    "directory": working_dir,
                    "session_id": desktop_session_id,
                    "requires_directory_approval": True,  # Signal that approval is needed
                }
            else:
                # For normal mode, request approval
                return {
                    "success": False,
                    "output": "",
                    "error": f"Directory '{working_dir}' requires approval. Use approve_directory tool with session_id '{session_id}'.",
                    "requires_directory_approval": True,
                    "directory": working_dir,
                    "session_id": session_id,
                }

        # For read commands, bypass command type approval
        if actual_command_type == "read":
            # No approval needed for read commands
            pass
        # For write and system commands with user confirmation enabled
        elif actual_command_type in ["write", "system"] and self.config.get(
            "security", "allow_user_confirmation", True
        ):

            # Check if we require a session ID (turn off for Claude Desktop compatibility)
            require_session_id = self.config.get(
                "security", "require_session_id", False
            )

            # WORKAROUND FOR CLAUDE DESKTOP:
            # Either auto-approve if no session_id provided OR if require_session_id is False
            if not session_id or not require_session_id:
                if not session_id:
                    logger.warning(
                        "No session ID provided, auto-approving command: %s",
                        command,
                    )
                else:
                    logger.warning(
                        "Session validation disabled, auto-approving command: %s",
                        command,
                    )
                # Auto-approve without requiring explicit permission
                pass
            # Normal session-based approval when require_session_id is True
            elif not self.session_manager.has_command_approval(
                session_id, command
            ) and not self.session_manager.has_command_type_approval(
                session_id, actual_command_type
            ):
                return {
                    "success": False,
                    "output": "",
                    "error": f"Command '{command}' requires approval. Use approve_command_type tool with session_id '{session_id}'.",
                    "requires_approval": True,
                    "command_type": actual_command_type,
                    "session_id": session_id,
                }

        # Execute the command
        try:
            logger.info(f"Executing command: {command}")
            # Using subprocess with shell=True is necessary for many shell commands,
            # but we've validated the command for safety already
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            output = stdout.decode("utf-8", errors="replace")
            error = stderr.decode("utf-8", errors="replace")

            # Limit output size to prevent huge responses
            max_output_size = self.config.get(
                "output", "max_size", 100 * 1024
            )  # 100KB default
            if len(output) > max_output_size:
                output = (
                    output[:max_output_size] + "\n... [output truncated due to size]"
                )

            return {
                "success": process.returncode == 0,
                "output": output,
                "error": error,
                "exit_code": process.returncode,
                "command_type": actual_command_type,
            }
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            return {"success": False, "output": "", "error": str(e)}

    async def run_async(self):
        """Run the MCP server asynchronously."""

        # Clean old sessions periodically
        async def clean_sessions():
            while True:
                session_timeout = self.config.get(
                    "security", "session_timeout", 3600
                )  # 1 hour default
                await asyncio.sleep(session_timeout)
                self.session_manager.clean_old_sessions(session_timeout)

        # Start session cleaning task
        asyncio.create_task(clean_sessions())

        # Run the MCP server using its internal method
        # This is used when we want to run within an existing event loop
        await self.app.run_stdio_async()

    def run(self):
        """Run the MCP server with its own event loop."""
        # Let the app handle the event loop directly
        self.app.run()


def main():
    """Run the command-line MCP server."""
    parser = argparse.ArgumentParser(description="Command-line MCP server")
    parser.add_argument("--config", "-c", help="Path to configuration file")
    parser.add_argument("--env", "-e", help="Path to .env file")
    args = parser.parse_args()

    server = CommandLineMCP(config_path=args.config, env_file_path=args.env)
    server.run()


if __name__ == "__main__":
    main()
