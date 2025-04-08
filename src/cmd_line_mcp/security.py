"""Security utilities for the command-line MCP server."""

import logging
import os
import re
import shlex
from typing import Dict, List, Optional, Tuple, Union

# Configure logger
logger = logging.getLogger(__name__)


def parse_command(command: str) -> Tuple[str, List[str]]:
    """Parse a command string into command and arguments.

    Args:
        command: The command string

    Returns:
        A tuple of (command, arguments)
    """
    # Handle the case where a pipe segment might not start with a command
    # For example: `-v` is a flag, not a command in `cmd | -v`
    command = command.strip()

    # If it starts with a dash, it's probably a flag/option continuation
    if command.startswith("-"):
        return "", [command]

    try:
        parts = shlex.split(command)
        if not parts:
            return "", []
        return parts[0], parts[1:]
    except ValueError:
        # If shlex.split fails (e.g., on unbalanced quotes),
        # fall back to a simpler split
        parts = command.strip().split()
        if not parts:
            return "", []
        return parts[0], parts[1:]


def validate_command(
    command: str,
    read_commands: List[str],
    write_commands: List[str],
    system_commands: List[str],
    blocked_commands: List[str],
    dangerous_patterns: List[str],
    allow_command_separators: bool = True,
) -> Dict[str, Union[bool, str, Optional[str]]]:
    """Validate a command for security.

    Args:
        command: The command to validate
        read_commands: List of read-only commands
        write_commands: List of write commands
        system_commands: List of system commands
        blocked_commands: List of blocked commands
        dangerous_patterns: List of dangerous patterns to block
        allow_command_separators: Whether to allow command separators (|, ;, &)

    Returns:
        A dictionary with validation results
    """
    result = {"is_valid": False, "command_type": None, "error": None}

    # Empty command
    if not command.strip():
        result["error"] = "Empty command"
        return result

    # If command separators are not allowed, check for them
    if not allow_command_separators:
        # Check for pipe, semicolon, or ampersand
        if re.search(r"[|;&]", command):
            result["error"] = (
                "Command separators (|, ;, &) are not allowed in the current configuration"
            )
            return result

    # Check for dangerous patterns
    for pattern in dangerous_patterns:
        if re.search(pattern, command):
            # More descriptive error message
            if pattern == r"\$\(":
                result["error"] = (
                    "Command contains command substitution $(). This is blocked for security reasons."
                )
            elif pattern == r"\$\{\w+\}":
                result["error"] = (
                    "Command contains variable substitution ${var}. This is blocked for security reasons."
                )
            elif pattern == r"`":
                result["error"] = (
                    "Command contains backtick command substitution. This is blocked for security reasons."
                )
            else:
                result["error"] = f"Command contains dangerous pattern: {pattern}"
            return result

    # If command chaining is allowed, validate each part
    for separator in ["|", ";", "&"]:
        if separator in command:
            # Initialize these variables to fix "possibly unbound" warnings
            parts = []
            separator_name = "command chain"

            # Determine which separator is being used
            if separator == "|":
                parts = command.split("|")
                separator_name = "pipeline"
            elif separator == ";":
                parts = command.split(";")
                separator_name = "command sequence"
            elif separator == "&":
                parts = command.split("&")
                separator_name = "background command"

            # Track command types across all parts
            all_parts_types = []

            for part in parts:
                part = part.strip()
                if not part:
                    result["error"] = f"Empty command in {separator_name}"
                    return result

                # Parse each command - be smarter about pipes
                try:
                    cmd_part, _ = parse_command(part)
                except ValueError as e:
                    result["error"] = (
                        f"Invalid command syntax in {separator_name}: {str(e)}"
                    )
                    return result

                # Special handling for pipeline segments that aren't simple commands
                if separator == "|" and (part.strip().startswith("-") or not cmd_part):
                    # This is likely a continuation of a previous pipe, not a command itself
                    # For example: `command | grep "pattern"` vs `command | -v`
                    # We'll consider these as safe continuations
                    continue

                # Check if any command is blocked
                if cmd_part in blocked_commands:
                    result["error"] = (
                        f"Command '{cmd_part}' in {separator_name} is blocked for security reasons"
                    )
                    return result

                # Check if the command is recognized
                # Skip this check for empty/continuation pipeline segments
                if (
                    cmd_part
                    and cmd_part not in read_commands
                    and cmd_part not in write_commands
                    and cmd_part not in system_commands
                ):
                    result["error"] = (
                        f"Command '{cmd_part}' in {separator_name} is not recognized or supported. Supported commands: {', '.join(read_commands + write_commands + system_commands)}"
                    )
                    return result

                # Track command types (only for actual commands)
                if cmd_part:
                    if cmd_part in read_commands:
                        all_parts_types.append("read")
                    elif cmd_part in write_commands:
                        all_parts_types.append("write")
                    elif cmd_part in system_commands:
                        all_parts_types.append("system")

            # Determine the most privileged command type
            if "system" in all_parts_types:
                result["command_type"] = "system"
            elif "write" in all_parts_types:
                result["command_type"] = "write"
            else:
                result["command_type"] = "read"

            result["is_valid"] = True
            return result

    # For non-pipeline commands, validate normally
    try:
        main_cmd, _ = parse_command(command)
    except ValueError as e:
        result["error"] = f"Invalid command syntax: {str(e)}"
        return result

    # Check if command is blocked
    if main_cmd in blocked_commands:
        result["error"] = f"Command '{main_cmd}' is blocked for security reasons"
        return result

    # Determine command type with better error message
    if main_cmd in read_commands:
        result["command_type"] = "read"
        result["is_valid"] = True
    elif main_cmd in write_commands:
        result["command_type"] = "write"
        result["is_valid"] = True
    elif main_cmd in system_commands:
        result["command_type"] = "system"
        result["is_valid"] = True
    else:
        # List available commands
        supported_cmds = read_commands + write_commands + system_commands
        result["error"] = (
            f"Command '{main_cmd}' is not recognized or supported. Supported commands: {', '.join(supported_cmds)}"
        )

    return result


def normalize_path(path: str) -> str:
    """Normalize a path to absolute path with no symlinks or relative components.

    Args:
        path: The path to normalize

    Returns:
        Normalized absolute path
    """
    # Expand user directory for paths that start with ~
    if path.startswith("~"):
        path = os.path.expanduser(path)

    # Convert to absolute path
    abs_path = os.path.abspath(path)
    # Normalize to resolve '..' and '.' components
    norm_path = os.path.normpath(abs_path)
    # Try to resolve any symlinks if possible
    try:
        real_path = os.path.realpath(norm_path)
        return real_path
    except (OSError, IOError):
        # Fall back to normalized path if realpath fails
        return norm_path


def extract_directory_from_command(command: str) -> Optional[str]:
    """Extract the working directory from a command.

    Args:
        command: The command string

    Returns:
        The working directory or None if it can't be determined
    """
    # We need to analyze the command to figure out which directory it's operating in
    # This is a heuristic approach and may need refinement for specific commands

    try:
        # Special case for tilde paths in the command
        if "~/" in command:
            # Find the tilde path pattern
            match = re.search(r"~/\S+", command)
            if match:
                tilde_path = match.group(0)
                # Get everything up to a space, pipe, or other delimiter
                # to capture just the path part
                expanded_path = os.path.expanduser(tilde_path)

                if os.path.isdir(expanded_path):
                    return normalize_path(expanded_path)
                else:
                    # If it's a file, get its parent directory
                    parent = os.path.dirname(expanded_path)
                    if parent:
                        return normalize_path(parent)

        # Handle pipeline commands
        if "|" in command:
            # For piped commands, check each part and take the most specific directory
            pipe_parts = command.split("|")
            for part in pipe_parts:
                # If any part of the pipeline accesses a specific directory, use that
                dir_from_part = extract_directory_from_command(part.strip())
                if dir_from_part and dir_from_part != os.getcwd():
                    return dir_from_part

            # If we couldn't find a specific directory in any part, analyze the first command
            return extract_directory_from_command(pipe_parts[0].strip())

        # Handle semicolon-separated commands
        if ";" in command:
            # For semicolon-separated commands, process each command independently
            # Return the first specific directory found (not current directory)
            commands = command.split(";")
            for cmd in commands:
                dir_from_cmd = extract_directory_from_command(cmd.strip())
                if dir_from_cmd and dir_from_cmd != os.getcwd():
                    return dir_from_cmd

            # If no specific directory found, use the first command's directory
            return extract_directory_from_command(commands[0].strip())

        # Process a single command
        parts = shlex.split(command)
        if not parts:
            return None

        main_cmd = parts[0]
        args = parts[1:]

        # First check for directory arguments containing tilde expansion
        for arg in args:
            if not arg.startswith("-") and ("~" in arg):
                expanded_path = os.path.expanduser(arg)

                if os.path.isdir(expanded_path):
                    return normalize_path(expanded_path)
                parent = os.path.dirname(expanded_path)
                if parent and parent != "." and os.path.isdir(parent):
                    return normalize_path(parent)

        # Handle common file/directory commands
        if main_cmd in [
            "ls",
            "cd",
            "find",
            "du",
            "rm",
            "mkdir",
            "rmdir",
            "touch",
            "chmod",
            "chown",
        ]:
            # For these commands, the first non-flag argument is usually the directory
            for arg in args:
                if not arg.startswith("-"):
                    # Get the directory part
                    if os.path.isdir(arg):
                        return normalize_path(arg)
                    else:
                        parent = os.path.dirname(arg)
                        if parent:
                            return normalize_path(parent)
                        else:
                            # If no parent directory specified, assume current directory
                            return os.getcwd()

            # If no directory argument found, assume current directory
            return os.getcwd()

        # For cat, less, head, tail, grep, wc, etc. operating on files
        elif main_cmd in ["cat", "less", "head", "tail", "grep", "wc", "awk", "sed"]:
            # Get the last non-flag argument which is usually the file
            file_arg = None
            for arg in args:
                if not arg.startswith("-"):
                    file_arg = arg

            if file_arg:
                parent = os.path.dirname(file_arg)
                if parent:
                    return normalize_path(parent)
                elif "~" in file_arg:
                    # Handle tilde in path
                    expanded = os.path.expanduser(file_arg)
                    parent = os.path.dirname(expanded)
                    if parent:
                        return normalize_path(parent)

            # Default to current directory
            return os.getcwd()

        # For commands that don't specify a directory
        else:
            # Default to current directory
            return os.getcwd()

    except (ValueError, IndexError):
        # If parsing fails, default to current directory
        return os.getcwd()


def is_directory_whitelisted(directory: str, whitelisted_dirs: List[str]) -> bool:
    """Check if a directory is whitelisted or is a subdirectory of a whitelisted directory.

    Args:
        directory: The directory to check
        whitelisted_dirs: List of whitelisted directories

    Returns:
        True if the directory is whitelisted, False otherwise
    """
    try:
        normalized_dir = normalize_path(directory)

        # Check if the directory is explicitly whitelisted
        for whitelist_dir in whitelisted_dirs:
            # Handle special whitelisted paths
            if whitelist_dir == "~" or whitelist_dir.startswith("~/"):
                # Convert ~ to user's home directory
                normalized_whitelist = normalize_path(whitelist_dir)
            else:
                normalized_whitelist = normalize_path(whitelist_dir)

            # Exact match
            if normalized_dir == normalized_whitelist:
                return True

            # Check if it's a subdirectory of a whitelisted directory
            if normalized_dir.startswith(normalized_whitelist + os.sep):
                return True

            # Handle wildcard paths
            if "*" in whitelist_dir:
                # Convert glob pattern to regex pattern
                pattern = whitelist_dir.replace("*", ".*")
                if re.match(pattern, normalized_dir):
                    return True

        return False
    except Exception as error:
        # If there's any error in normalization or checking, log it and return False
        logger.error(f"Error checking if directory is whitelisted: {str(error)}")
        return False
