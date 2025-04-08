"""Security utilities for the command-line MCP server."""

import re
import shlex
from typing import Dict, List, Optional, Tuple, Union

# These constant lists are just for reference and backward compatibility
# Actual command lists should come from the Config object and be passed to validate_command
# DO NOT use these lists directly in the code - always pass in the current command lists from Config
READ_COMMANDS = [
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
]

WRITE_COMMANDS = [
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
]

SYSTEM_COMMANDS = [
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
]

BLOCKED_COMMANDS = [
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
]

DANGEROUS_PATTERNS = [
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
]


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
    read_commands: Optional[List[str]] = None,
    write_commands: Optional[List[str]] = None,
    system_commands: Optional[List[str]] = None,
    blocked_commands: Optional[List[str]] = None,
    dangerous_patterns: Optional[List[str]] = None,
    allow_command_separators: bool = True,
) -> Dict[str, Union[bool, str, Optional[str]]]:
    """Validate a command for security.

    Args:
        command: The command to validate
        read_commands: List of read-only commands (defaults to READ_COMMANDS if None)
        write_commands: List of write commands (defaults to WRITE_COMMANDS if None)
        system_commands: List of system commands (defaults to SYSTEM_COMMANDS if None)
        blocked_commands: List of blocked commands (defaults to BLOCKED_COMMANDS if None)
        dangerous_patterns: List of dangerous patterns to block (defaults to DANGEROUS_PATTERNS if None)
        allow_command_separators: Whether to allow command separators (|, ;, &)

    Returns:
        A dictionary with validation results
    """
    # Use default command lists if not provided
    if read_commands is None:
        read_commands = READ_COMMANDS
    if write_commands is None:
        write_commands = WRITE_COMMANDS
    if system_commands is None:
        system_commands = SYSTEM_COMMANDS
    if blocked_commands is None:
        blocked_commands = BLOCKED_COMMANDS
    if dangerous_patterns is None:
        dangerous_patterns = DANGEROUS_PATTERNS
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
                result["error"] = (
                    f"Command contains dangerous pattern: {pattern}"
                )
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
                if separator == "|" and (
                    part.strip().startswith("-") or not cmd_part
                ):
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
        result["error"] = (
            f"Command '{main_cmd}' is blocked for security reasons"
        )
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
