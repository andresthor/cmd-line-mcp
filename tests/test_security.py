"""Tests for the security module."""

import pytest
from cmd_line_mcp.security import validate_command, parse_command


def test_validate_command_success_cases():
    """Test successful validation of commands."""
    # Setup test data
    read_commands = ["ls", "cat", "grep", "find", "head", "tail"]
    write_commands = ["mkdir", "touch", "rm", "cp", "mv"]
    system_commands = ["ps", "top", "who", "netstat"]
    blocked_commands = ["sudo", "su", "eval", "exec"]
    dangerous_patterns = [
        "rm -rf /",
        "/etc/passwd",
        "/etc/shadow",
        "> /dev/sda",
    ]

    # Test valid read command
    result = validate_command(
        "ls -la",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is True
    assert result["command_type"] == "read"
    assert result["error"] is None

    # Test valid write command
    result = validate_command(
        "mkdir /tmp/test",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is True
    assert result["command_type"] == "write"
    assert result["error"] is None

    # Test valid system command
    result = validate_command(
        "ps aux",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is True
    assert result["command_type"] == "system"
    assert result["error"] is None


def test_validate_command_blocked_commands():
    """Test validation of blocked commands."""
    # Setup test data
    read_commands = ["ls", "cat"]
    write_commands = ["mkdir", "touch"]
    system_commands = ["ps", "top"]
    blocked_commands = ["sudo", "su", "eval", "exec"]
    dangerous_patterns = []

    # Test a blocked command without any dangerous patterns
    # so we can isolate the blocked command validation
    result = validate_command(
        "sudo ls",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert result["error"] is not None
    assert (
        "blocked" in result["error"].lower()
        or "sudo" in result["error"].lower()
    )

    # Test a command with the blocked command as an argument
    result = validate_command(
        "echo 'sudo is not allowed'",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is False  # Should still catch this
    assert result["command_type"] is None
    assert result["error"] is not None


def test_validate_command_dangerous_patterns():
    """Test validation of dangerous patterns."""
    # Setup test data
    read_commands = ["ls", "cat"]
    write_commands = ["rm"]
    system_commands = ["ps"]
    blocked_commands = ["sudo"]
    dangerous_patterns = [
        r"rm\s+-rf\s+/",
        r"/etc/passwd",
        r"/etc/shadow",
        r">\s+/dev/sda",
        r"\$\(",  # Command substitution - use raw string with proper escaping
    ]

    # Test a dangerous pattern
    result = validate_command(
        "rm -rf /",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert result["error"] is not None
    assert "dangerous pattern" in result["error"].lower()

    # Test command with dangerous pattern embedded
    result = validate_command(
        "cat /etc/passwd",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert result["error"] is not None
    assert "dangerous pattern" in result["error"].lower()

    # Test command with command substitution using properly escaped pattern
    result = validate_command(
        "echo $(ls -la)",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert result["error"] is not None


def test_validate_command_unsupported_commands():
    """Test validation of unsupported commands."""
    # Setup test data
    read_commands = ["ls", "cat"]
    write_commands = ["mkdir", "touch"]
    system_commands = ["ps", "top"]
    blocked_commands = ["sudo"]
    dangerous_patterns = ["rm -rf /"]

    # Test a command that's not in any list
    result = validate_command(
        "unsupported_command",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert result["error"] is not None
    assert "unsupported" in result["error"].lower()


def test_validate_command_with_pipes():
    """Test validation of commands with pipes."""
    # Setup test data
    read_commands = ["ls", "cat", "grep", "sort", "head"]
    write_commands = ["mkdir", "touch"]
    system_commands = ["ps", "top"]
    blocked_commands = ["sudo"]
    # Use empty list for dangerous patterns to avoid pipe issues
    dangerous_patterns = []

    # Test a valid piped command with all supported commands
    result = validate_command(
        "ls -la | grep 'file' | sort -r | head -5",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is True
    assert result["command_type"] == "read"
    assert result["error"] is None

    # Test a piped command with an unsupported command
    result = validate_command(
        "ls -la | unsupported_command",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert result["error"] is not None

    # Test a piped command with a blocked command
    result = validate_command(
        "ls -la | sudo cat /etc/passwd",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert result["error"] is not None


def test_validate_command_with_semicolons():
    """Test validation of commands with semicolons."""
    # Setup test data
    read_commands = ["ls", "cat", "pwd"]
    write_commands = ["mkdir", "touch"]
    system_commands = ["ps"]
    blocked_commands = ["sudo"]
    dangerous_patterns = ["rm -rf /"]

    # Test a valid sequence of commands
    result = validate_command(
        "mkdir temp; ls -la; pwd",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is True
    # The command type should be the most privileged one (write in this case)
    assert result["command_type"] == "write"
    assert result["error"] is None

    # Test a sequence with an unsupported command
    result = validate_command(
        "mkdir temp; unsupported_command",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert result["error"] is not None


def test_validate_command_with_special_characters():
    """Test validation of commands with special shell characters."""
    # Setup test data
    read_commands = ["ls", "cat", "echo"]
    write_commands = ["mkdir"]
    system_commands = ["ps"]
    blocked_commands = ["sudo"]

    # Commands with environment variables should be valid
    # Using no dangerous patterns for this test
    dangerous_patterns = []

    # Test a command with environment variable substitution
    result = validate_command(
        "echo $HOME",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    # This should be valid because $HOME is a legitimate env var
    assert result["is_valid"] is True
    assert result["command_type"] == "read"

    # Now use a specific dangerous pattern to test brace expansion
    dangerous_patterns = [r"\$\{.*:\d+:\d+\}"]  # Match ${var:x:y} pattern

    # Test a command with dangerous brace expansion
    result = validate_command(
        "echo ${PATH:0:10}",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert result["error"] is not None


def test_parse_command():
    """Test parsing command strings."""
    # Test normal command
    cmd, args = parse_command("ls -la")
    assert cmd == "ls"
    assert args == ["-la"]

    # Test command with multiple arguments
    cmd, args = parse_command("grep -r pattern ./dir")
    assert cmd == "grep"
    assert args == ["-r", "pattern", "./dir"]

    # Test command with quoted arguments
    cmd, args = parse_command('grep "complex pattern" file.txt')
    assert cmd == "grep"
    assert args == ["complex pattern", "file.txt"]

    # Test empty command
    cmd, args = parse_command("")
    assert cmd == ""
    assert args == []

    # Test command starting with dash (for pipe continuation)
    cmd, args = parse_command("-v pattern")
    assert cmd == ""
    assert args == ["-v pattern"]


def test_validate_command_with_separator_control():
    """Test command validation with separator control."""
    # Setup test data
    read_commands = ["ls", "cat", "grep"]
    write_commands = ["mkdir", "touch"]
    system_commands = ["ps"]
    blocked_commands = ["sudo"]
    dangerous_patterns = []

    # Test with separators allowed (default)
    result = validate_command(
        "ls -la | grep pattern",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
        allow_command_separators=True,
    )
    assert result["is_valid"] is True
    assert result["command_type"] == "read"

    # Test with separators disallowed
    result = validate_command(
        "ls -la | grep pattern",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
        allow_command_separators=False,
    )
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert "separators" in result["error"].lower()

    # Test semicolon with separators disallowed
    result = validate_command(
        "mkdir test; ls -la",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
        allow_command_separators=False,
    )
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert "separators" in result["error"].lower()

    # Test ampersand with separators disallowed
    result = validate_command(
        "ps aux &",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
        allow_command_separators=False,
    )
    assert result["is_valid"] is False
    assert result["command_type"] is None
    assert "separators" in result["error"].lower()


def test_command_type_elevation():
    """Test that command type is properly elevated to the most privileged type."""
    # Setup test data
    read_commands = ["ls", "cat", "grep"]
    write_commands = ["mkdir", "touch"]
    system_commands = ["ps"]
    blocked_commands = ["sudo"]
    dangerous_patterns = []

    # Test with all read commands
    result = validate_command(
        "ls -la | grep pattern | cat file.txt",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is True
    assert result["command_type"] == "read"

    # Test with mixed read and write commands
    result = validate_command(
        "ls -la; mkdir test",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is True
    assert result["command_type"] == "write"

    # Test with mixed read, write, and system commands
    result = validate_command(
        "ls -la; mkdir test; ps aux",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is True
    assert result["command_type"] == "system"


def test_custom_command_list():
    """Test validation with custom command lists to ensure they're respected."""
    # Custom command lists including awk and jq
    read_commands = ["ls", "cat", "grep", "awk", "jq"]
    write_commands = ["mkdir", "touch"]
    system_commands = ["ps"]
    blocked_commands = ["sudo"]
    dangerous_patterns = []

    # Test awk in a simple command
    result = validate_command(
        "awk '{print $1}' file.txt",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is True
    assert result["command_type"] == "read"

    # Test awk in a pipeline with other commands
    result = validate_command(
        "cat file.txt | awk '{print $1}' | grep pattern",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is True
    assert result["command_type"] == "read"

    # Test jq in a pipeline
    result = validate_command(
        "cat data.json | jq '.name'",
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is True
    assert result["command_type"] == "read"

    # Verify command not in custom list is rejected
    result = validate_command(
        "sed 's/old/new/g' file.txt",  # sed not in our custom list
        read_commands,
        write_commands,
        system_commands,
        blocked_commands,
        dangerous_patterns,
    )
    assert result["is_valid"] is False
    assert "not recognized" in result["error"]
    assert "sed" in result["error"]
