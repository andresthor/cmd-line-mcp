"""
Command-line MCP server that safely executes Unix/macOS terminal commands.
"""

import argparse
import asyncio
import logging
import math
import os
import signal
from collections.abc import Iterable
from typing import Any

from mcp.server.fastmcp import FastMCP

from cmd_line_mcp.config import Config
from cmd_line_mcp.security import (
    CommandRejected,
    is_directory_whitelisted,
    normalize_path,
    prepare_command,
)
from cmd_line_mcp.session import SessionManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Variables that make sh or bash source files, import functions or change
# parsing before the command runs; BASH_FUNC_* names are removed too.
_SHELL_STARTUP_ENV = frozenset(
    {"ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "CDPATH", "GLOBIGNORE", "IFS"}
)
_DEFAULT_COMMAND_TIMEOUT = 60.0
_READ_CHUNK_SIZE = 64 * 1024
_KILL_GRACE_SECONDS = 5
_TRUNCATED_MARKER = "\n... [output truncated due to size]"
_AND_OR_SUPPORTED = "Supported (&& and ||; background & is rejected)"
_COMMAND_RESTRICTIONS = (
    "Variables ($NAME), command substitution ($() and backticks), background "
    "'&', subshells, here-documents and line breaks are rejected. Redirect "
    "targets must be in approved directories, and '>' or '>>' makes the "
    "command a write command."
)


def _kill_process_group(process: asyncio.subprocess.Process) -> None:
    """Send SIGKILL to the process group led by ``process``."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        # Group already gone; macOS reports EPERM for a group of zombies.
        pass


class CommandLineMCP:
    """Command-line MCP server for Unix/macOS terminal commands."""

    def __init__(
        self,
        config_path: str | None = None,
        env_file_path: str | None = None,
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
        self._warned_invalid_timeout = False

        # NOTE: We don't pre-approve any directories - let the user explicitly
        # approve them or configure them in the whitelist

        logger.info(
            "Created persistent Claude Desktop session: "
            f"{self.claude_desktop_session_id}"
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
        version = server_config.get("version", "0.6.0")
        description = server_config.get(
            "description",
            "MCP server for safely executing command-line tools",
        )
        instructions = f"{description} (v{version})"

        self.app = FastMCP(
            server_config.get("name", "cmd-line-mcp"),
            instructions=instructions,
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
                    _AND_OR_SUPPORTED
                    if self.separator_support["ampersand"]
                    else "Not supported"
                ),
            },
            "command_restrictions": _COMMAND_RESTRICTIONS,
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
                "command": "ls -la | grep '^d'",
                "description": "List only the directories",
            },
            {
                "command": "du -sh ~/Downloads/* | sort -h",
                "description": "Sort downloads by size",
            },
        ]

        # Register tools
        execute_command_tool = self.app.tool()

        @execute_command_tool  # Keep decorator reference to satisfy linters
        async def execute_command(
            command: str, session_id: str | None = None
        ) -> dict[str, Any]:
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
            command: str, session_id: str | None = None
        ) -> dict[str, Any]:
            """
            Execute a read-only Unix/macOS terminal command (ls, cat, grep, etc.).

            Args:
                command: The read-only command to execute
                session_id: Optional session ID for permission management

            Returns:
                A dictionary with command output and status
            """
            # For Claude Desktop compatibility, use the fixed session ID when no
            # session ID is provided
            if not session_id:
                session_id = self.claude_desktop_session_id
                logger.info(
                    "Using persistent Claude Desktop session for read command: "
                    f"{session_id}"
                )

            return await self._execute_command(
                command, command_type="read", session_id=session_id
            )

        # Store reference to silence linter warnings
        self._execute_read_command_func = execute_read_command

        list_available_commands_tool = self.app.tool()

        @list_available_commands_tool  # Keep decorator reference to satisfy linters
        async def list_available_commands() -> dict[str, list[str]]:
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
        async def get_command_help() -> dict[str, Any]:
            """
            Get detailed help about command capabilities and usage.

            This tool provides comprehensive information about:
            - Supported commands in each category (read, write, system)
            - Blocked commands for security reasons
            - Command chaining capabilities (|, ;, && and ||)
            - Usage restrictions and examples

            Returns:
                A dictionary with detailed information about command capabilities
                and usage
            """
            # Get the latest command lists and separator support
            command_lists = self.config.get_effective_command_lists()
            separator_support = self.config.has_separator_support()

            # Log the separator support for debugging
            logger.info(f"Separator support status: {separator_support}")
            logger.info(
                "allow_command_separators setting: "
                f"{self.config.get('security', 'allow_command_separators')}"
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
                        _AND_OR_SUPPORTED
                        if separator_support["ampersand"]
                        else "Not supported"
                    ),
                },
                "command_restrictions": _COMMAND_RESTRICTIONS,
            }

            # Provide helpful information for Claude to understand command usage
            return {
                "capabilities": updated_capabilities,
                "examples": self.usage_examples,
                "recommended_approach": {
                    "finding_large_files": (
                        "Use 'du -h <directory>/* | sort -hr | head -n 10' to find "
                        "the 10 largest files"
                    ),
                    "file_searching": (
                        "Use 'find <directory> -type f -name \"pattern\"' for file "
                        "searches"
                    ),
                    "text_searching": (
                        "Use 'grep \"pattern\" <file>' to search in files"
                    ),
                    "file_viewing": "Use 'cat', 'head', or 'tail' for viewing files",
                    "sorting": (
                        "Use 'sort' with options like -n (numeric), -r (reverse), "
                        "-h (human readable sizes)"
                    ),
                    "text_filtering": (
                        "Pipe output into 'grep' to filter lines. For example: "
                        "\"ls -la | grep '^d'\" to list only directories"
                    ),
                    "size_sorting": (
                        "Use 'du -sh <directory>/* | sort -h' to list entries "
                        "by size"
                    ),
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
        ) -> dict[str, Any]:
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
                    "message": (
                        f"Command type '{command_type}' approved for this session"
                    ),
                }
            else:
                return {
                    "success": True,
                    "message": (
                        f"Command type '{command_type}' approved for one-time use"
                    ),
                }

        # Store reference to silence linter warnings
        self._approve_command_type_func = approve_command_type

        # Add tool for directory approval
        approve_directory_tool = self.app.tool()

        @approve_directory_tool  # Keep decorator reference to satisfy linters
        async def approve_directory(
            directory: str, session_id: str, remember: bool = True
        ) -> dict[str, Any]:
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
                    "message": (
                        f"Directory '{normalized_dir}' is already globally "
                        "whitelisted"
                    ),
                    "directory": normalized_dir,
                }

            # Check if directory is already approved for this session
            if self.session_manager.has_directory_approval(session_id, normalized_dir):
                return {
                    "success": True,
                    "message": (
                        f"Directory '{normalized_dir}' is already approved for "
                        "this session"
                    ),
                    "directory": normalized_dir,
                }

            # Approve the directory for this session
            if remember:
                self.session_manager.approve_directory(session_id, normalized_dir)
                return {
                    "success": True,
                    "message": (
                        f"Directory '{normalized_dir}' approved for this session"
                    ),
                    "directory": normalized_dir,
                }
            else:
                return {
                    "success": True,
                    "message": (
                        f"Directory '{normalized_dir}' approved for one-time use"
                    ),
                    "directory": normalized_dir,
                }

        # Store reference to silence linter warnings
        self._approve_directory_func = approve_directory

        # Tool to list whitelisted and approved directories
        list_directories_tool = self.app.tool()

        @list_directories_tool  # Keep decorator reference to satisfy linters
        async def list_directories(session_id: str | None = None) -> dict[str, Any]:
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
        async def get_configuration() -> dict[str, Any]:
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
                    "note": (
                        "Directories not in this list will require session approval"
                    ),
                },
            }

        # Store reference to silence linter warnings
        self._get_configuration_func = get_configuration

        # update_configuration tool removed

    async def _execute_command(
        self,
        command: str,
        command_type: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute a Unix/macOS terminal command.

        Args:
            command: The command to execute
            command_type: Optional type of command (read, write, system)
            session_id: Optional session ID for permission management

        Returns:
            A dictionary with command output and status
        """
        command_lists = self.config.get_effective_command_lists()
        allow_separators = self.config.get("security", "allow_command_separators", True)
        timeout = self._command_timeout()

        try:
            cwd = os.getcwd()
        except OSError as error:
            return {
                "success": False,
                "output": "",
                "error": f"Cannot determine the working directory: {error}",
            }
        try:
            # Glob expansion lists directories; keep it off the event loop.
            prepared = await asyncio.wait_for(
                asyncio.to_thread(
                    prepare_command,
                    command,
                    command_lists,
                    command_lists["dangerous_patterns"],
                    allow_separators,
                    cwd,
                ),
                timeout,
            )
        except CommandRejected as error:
            return {"success": False, "output": "", "error": str(error)}
        except asyncio.TimeoutError:
            return {
                "success": False,
                "output": "",
                "error": f"Validating the command took longer than {timeout:g} "
                "seconds",
            }

        actual_command_type = prepared.command_type
        if command_type == "read" and actual_command_type != "read":
            return {
                "success": False,
                "output": "",
                "error": "This tool only supports read commands. "
                "Use execute_command for other command types.",
            }
        if command_type and actual_command_type != command_type:
            return {
                "success": False,
                "output": "",
                "error": f"Command type mismatch. Expected {command_type}, "
                f"got {actual_command_type}",
            }

        denied = self._check_directories(prepared.directories, session_id)
        if denied is not None:
            return denied

        if actual_command_type in ("write", "system"):
            require_session_id = self.config.get(
                "security", "require_session_id", False
            )
            allow_confirmation = self.config.get(
                "security", "allow_user_confirmation", True
            )
            approval_session_id = session_id or self.claude_desktop_session_id

            # WORKAROUND FOR CLAUDE DESKTOP:
            # Auto-approve if no session_id is provided or require_session_id is off
            if allow_confirmation and (not session_id or not require_session_id):
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
            # Without confirmation only an explicit session approval allows it
            elif not self.session_manager.has_command_approval(
                approval_session_id, command
            ) and not self.session_manager.has_command_type_approval(
                approval_session_id, actual_command_type
            ):
                return {
                    "success": False,
                    "output": "",
                    "error": f"Command '{command}' requires approval. Use "
                    "approve_command_type tool with session_id "
                    f"'{approval_session_id}'.",
                    "requires_approval": True,
                    "command_type": actual_command_type,
                    "session_id": approval_session_id,
                }

        try:
            logger.info(f"Executing command: {prepared.canonical}")
            result = await self._run_shell(prepared.canonical, timeout)
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            return {"success": False, "output": "", "error": str(e)}
        returncode, output, error, stdout_cut, stderr_cut, timed_out = result

        if stdout_cut:
            output += _TRUNCATED_MARKER
        if stderr_cut:
            error += _TRUNCATED_MARKER
        if timed_out:
            error += f"\nCommand timed out after {timeout:g} seconds and was stopped"

        return {
            # Output stopped at the size cap is usable if stderr is complete.
            "success": not timed_out
            and (returncode == 0 or (stdout_cut and not stderr_cut)),
            "output": output,
            "error": error,
            "exit_code": returncode,
            "command_type": actual_command_type,
            "truncated": stdout_cut or stderr_cut,
            "timed_out": timed_out,
        }

    def _command_timeout(self) -> float:
        """Return ``security.command_timeout``, or the default if invalid."""
        value = self.config.get("security", "command_timeout")
        try:
            timeout = float(value)
        except (TypeError, ValueError):
            timeout = 0.0
        if math.isfinite(timeout) and timeout > 0:
            return timeout
        if not self._warned_invalid_timeout:
            self._warned_invalid_timeout = True
            logger.warning(
                f"Invalid security.command_timeout {value!r}; using "
                f"{_DEFAULT_COMMAND_TIMEOUT} seconds"
            )
        return _DEFAULT_COMMAND_TIMEOUT

    def _check_directories(
        self, directories: Iterable[str], session_id: str | None
    ) -> dict[str, Any] | None:
        """Check every directory against the whitelist and session approvals.

        A directory is allowed if it is whitelisted, approved for the session,
        or (when session IDs are not required) approved in the Claude Desktop
        session or auto-approved there.

        Args:
            directories: Normalized directories the command touches
            session_id: Optional session ID for permission management

        Returns:
            The approval request for the first denied directory, or ``None``
            if every directory is allowed.
        """
        require_session_id = self.config.get("security", "require_session_id", False)
        auto_approve_in_desktop = self.config.get_section("security").get(
            "auto_approve_directories_in_desktop_mode", False
        )
        desktop_session_id = self.claude_desktop_session_id

        for directory in directories:
            if is_directory_whitelisted(directory, self.whitelisted_directories):
                continue
            if session_id and self.session_manager.has_directory_approval(
                session_id, directory
            ):
                continue
            if not require_session_id:
                if self.session_manager.has_directory_approval(
                    desktop_session_id, directory
                ):
                    continue
                if auto_approve_in_desktop:
                    self.session_manager.approve_directory(
                        desktop_session_id, directory
                    )
                    logger.warning(
                        f"Auto-approving directory access in desktop mode: {directory}"
                    )
                    continue

            logger.warning(f"Directory '{directory}' is not whitelisted or approved")
            if not session_id or not require_session_id:
                return {
                    "success": False,
                    "output": "",
                    "error": f"Access to directory '{directory}' is not allowed. "
                    "Only whitelisted directories can be accessed.\n"
                    "Whitelisted directories include: "
                    f"{', '.join(self.whitelisted_directories)}\n"
                    "Note: To request access to this directory, use the "
                    "approve_directory tool with:\n"
                    f'  approve_directory(directory="{directory}", '
                    f'session_id="{desktop_session_id}", remember=True)',
                    "directory": directory,
                    "session_id": desktop_session_id,
                    "requires_directory_approval": True,
                }
            return {
                "success": False,
                "output": "",
                "error": f"Directory '{directory}' requires approval. Use "
                f"approve_directory tool with session_id '{session_id}'.",
                "requires_directory_approval": True,
                "directory": directory,
                "session_id": session_id,
            }
        return None

    async def _run_shell(
        self, canonical: str, timeout: float
    ) -> tuple[int | None, str, str, bool, bool, bool]:
        """Run a canonical command string under ``/bin/sh`` with limits.

        The command runs in its own process group with no stdin. The whole
        group is killed once combined output exceeds ``output.max_size``
        bytes or ``timeout`` seconds pass.

        Args:
            canonical: The rendered command from ``prepare_command``
            timeout: Seconds before the command is killed

        Returns:
            ``(exit_code, stdout, stderr, stdout_truncated, stderr_truncated,
            timed_out)``
        """
        max_size = int(self.config.get("output", "max_size", 100 * 1024))
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in _SHELL_STARTUP_ENV and not k.startswith("BASH_FUNC_")
        }

        process = await asyncio.create_subprocess_exec(
            "/bin/sh",
            "-c",
            "--",
            canonical,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            env=env,
        )
        stdout, stderr = bytearray(), bytearray()
        cut = {"stdout": False, "stderr": False}
        timed_out = False

        async def drain(
            stream: asyncio.StreamReader, buffer: bytearray, name: str
        ) -> None:
            # Keep reading past the cap: a paused pipe never reaches EOF, and
            # process.wait() only returns once both pipes are closed.
            while chunk := await stream.read(_READ_CHUNK_SIZE):
                room = max(max_size - len(stdout) - len(stderr), 0)
                buffer += chunk[:room]
                if len(chunk) > room:
                    if not any(cut.values()):
                        _kill_process_group(process)
                    cut[name] = True

        async def collect() -> int:
            assert process.stdout is not None and process.stderr is not None
            await asyncio.gather(
                drain(process.stdout, stdout, "stdout"),
                drain(process.stderr, stderr, "stderr"),
            )
            return await process.wait()

        try:
            try:
                returncode: int | None = await asyncio.wait_for(collect(), timeout)
            except asyncio.TimeoutError:
                timed_out = True
                _kill_process_group(process)
                try:
                    returncode = await asyncio.wait_for(collect(), _KILL_GRACE_SECONDS)
                except asyncio.TimeoutError:
                    # A descendant that left the process group still holds a pipe.
                    logger.warning("Command output pipes still open after kill")
                    returncode = process.returncode
        finally:
            if process.returncode is None:
                _kill_process_group(process)

        return (
            returncode,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            cut["stdout"],
            cut["stderr"],
            timed_out,
        )

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
