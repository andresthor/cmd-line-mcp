"""Baseline tests for supported functionality.

These tests document commands that must continue to work correctly.
They use the real default configuration so any changes to command lists
or dangerous patterns will be reflected here.
"""

import pytest
from cmd_line_mcp.config import Config
from cmd_line_mcp.security import validate_command


@pytest.fixture
def default_cmd_lists():
    """Return command lists from the real default configuration."""
    config = Config()
    return config.get_effective_command_lists()


def _valid(cmd_lists, command, expected_type):
    """Assert a command is valid with the expected type."""
    result = validate_command(
        command,
        cmd_lists["read"],
        cmd_lists["write"],
        cmd_lists["system"],
        cmd_lists["blocked"],
        cmd_lists["dangerous_patterns"],
    )
    assert result["is_valid"] is True, (
        f"Expected '{command}' to be valid, got error: {result['error']}"
    )
    assert result["command_type"] == expected_type


# ---------------------------------------------------------------------------
# Read commands
# ---------------------------------------------------------------------------


def test_ls(default_cmd_lists):
    _valid(default_cmd_lists, "ls -la", "read")


def test_ls_path(default_cmd_lists):
    _valid(default_cmd_lists, "ls /tmp", "read")


def test_cat(default_cmd_lists):
    _valid(default_cmd_lists, "cat /tmp/file.txt", "read")


def test_grep(default_cmd_lists):
    _valid(default_cmd_lists, "grep -r pattern /tmp", "read")


def test_grep_pattern(default_cmd_lists):
    _valid(default_cmd_lists, "grep 'search term' /tmp/file.txt", "read")


def test_find_by_name(default_cmd_lists):
    _valid(default_cmd_lists, 'find /tmp -name "*.txt"', "read")


def test_find_by_type(default_cmd_lists):
    _valid(default_cmd_lists, "find /tmp -type f -name '*.pdf'", "read")


def test_find_maxdepth(default_cmd_lists):
    _valid(default_cmd_lists, "find /tmp -maxdepth 2 -mtime -1", "read")


def test_head(default_cmd_lists):
    _valid(default_cmd_lists, "head -n 10 /tmp/file.txt", "read")


def test_tail(default_cmd_lists):
    _valid(default_cmd_lists, "tail -n 20 /tmp/file.txt", "read")


def test_wc(default_cmd_lists):
    _valid(default_cmd_lists, "wc -l /tmp/file.txt", "read")


def test_sort(default_cmd_lists):
    _valid(default_cmd_lists, "sort /tmp/file.txt", "read")


def test_sort_numeric(default_cmd_lists):
    _valid(default_cmd_lists, "sort -rn /tmp/file.txt", "read")


def test_du(default_cmd_lists):
    _valid(default_cmd_lists, "du -sh /tmp", "read")


def test_df(default_cmd_lists):
    _valid(default_cmd_lists, "df -h", "read")


def test_pwd(default_cmd_lists):
    _valid(default_cmd_lists, "pwd", "read")


def test_whoami(default_cmd_lists):
    _valid(default_cmd_lists, "whoami", "read")


def test_date(default_cmd_lists):
    _valid(default_cmd_lists, "date", "read")


def test_env_bare(default_cmd_lists):
    """env with no arguments (show environment) must remain valid."""
    _valid(default_cmd_lists, "env", "read")


# ---------------------------------------------------------------------------
# Write commands
# ---------------------------------------------------------------------------


def test_mkdir(default_cmd_lists):
    _valid(default_cmd_lists, "mkdir /tmp/newdir", "write")


def test_touch(default_cmd_lists):
    _valid(default_cmd_lists, "touch /tmp/file.txt", "write")


def test_cp(default_cmd_lists):
    _valid(default_cmd_lists, "cp /tmp/a.txt /tmp/b.txt", "write")


def test_mv(default_cmd_lists):
    _valid(default_cmd_lists, "mv /tmp/a.txt /tmp/b.txt", "write")


def test_rm(default_cmd_lists):
    _valid(default_cmd_lists, "rm /tmp/file.txt", "write")


def test_chmod(default_cmd_lists):
    _valid(default_cmd_lists, "chmod 644 /tmp/file.txt", "write")


def test_echo(default_cmd_lists):
    _valid(default_cmd_lists, "echo hello world", "write")


def test_tar_create(default_cmd_lists):
    _valid(default_cmd_lists, "tar -czf /tmp/archive.tar.gz /tmp/dir", "write")


def test_tar_extract(default_cmd_lists):
    _valid(default_cmd_lists, "tar -xzf /tmp/archive.tar.gz -C /tmp", "write")


def test_gzip(default_cmd_lists):
    _valid(default_cmd_lists, "gzip /tmp/file.txt", "write")


def test_zip(default_cmd_lists):
    _valid(default_cmd_lists, "zip /tmp/archive.zip /tmp/file.txt", "write")


def test_unzip(default_cmd_lists):
    _valid(default_cmd_lists, "unzip /tmp/archive.zip -d /tmp", "write")


# ---------------------------------------------------------------------------
# System commands
# ---------------------------------------------------------------------------


def test_ps(default_cmd_lists):
    _valid(default_cmd_lists, "ps aux", "system")


def test_ping(default_cmd_lists):
    _valid(default_cmd_lists, "ping -c 1 localhost", "system")


def test_curl(default_cmd_lists):
    _valid(default_cmd_lists, "curl -s https://example.com", "system")


def test_who(default_cmd_lists):
    _valid(default_cmd_lists, "who", "system")


# ---------------------------------------------------------------------------
# Safe awk — text processing without execution
# ---------------------------------------------------------------------------


def test_awk_print_columns(default_cmd_lists):
    """awk column extraction must remain valid."""
    _valid(default_cmd_lists, "ls -la | awk '{print $1, $9}'", "write")


def test_awk_conditional_filter(default_cmd_lists):
    """awk conditional filtering must remain valid."""
    _valid(default_cmd_lists, "cat /tmp/file | awk '{if($1>10) print $0}'", "write")


def test_awk_field_separator(default_cmd_lists):
    """awk with custom field separator must remain valid."""
    _valid(default_cmd_lists, "awk -F: '{print $1}' /tmp/file", "write")


def test_awk_arithmetic(default_cmd_lists):
    """awk arithmetic must remain valid."""
    _valid(default_cmd_lists, "awk '{sum += $1} END {print sum}' /tmp/file", "write")


def test_awk_pattern_match(default_cmd_lists):
    """awk pattern matching must remain valid."""
    _valid(default_cmd_lists, "awk '/pattern/ {print $0}' /tmp/file", "write")


# ---------------------------------------------------------------------------
# Safe sed — substitution without /e flag
# ---------------------------------------------------------------------------


def test_sed_basic_substitution(default_cmd_lists):
    """sed basic substitution must remain valid."""
    _valid(default_cmd_lists, "sed 's/foo/bar/' /tmp/file", "write")


def test_sed_global_substitution(default_cmd_lists):
    """sed global substitution must remain valid."""
    _valid(default_cmd_lists, "echo hello | sed 's/hello/world/g'", "write")


def test_sed_case_insensitive(default_cmd_lists):
    """sed case-insensitive substitution must remain valid."""
    _valid(default_cmd_lists, "sed 's/foo/bar/i' /tmp/file", "write")


def test_sed_line_range(default_cmd_lists):
    """sed line range printing must remain valid."""
    _valid(default_cmd_lists, "sed -n '1,5p' /tmp/file", "write")


def test_sed_delete_lines(default_cmd_lists):
    """sed line deletion must remain valid."""
    _valid(default_cmd_lists, "sed '/^#/d' /tmp/file", "write")


# ---------------------------------------------------------------------------
# Pipelines
# ---------------------------------------------------------------------------


def test_pipeline_grep_sort_wc(default_cmd_lists):
    _valid(default_cmd_lists, "cat /tmp/file | grep pattern | sort | wc -l", "read")


def test_pipeline_find_grep(default_cmd_lists):
    _valid(default_cmd_lists, "find /tmp -name '*.log' | grep error", "read")


def test_pipeline_du_sort(default_cmd_lists):
    _valid(default_cmd_lists, "du -h /tmp | sort -h", "read")


def test_pipeline_ls_awk(default_cmd_lists):
    _valid(default_cmd_lists, "ls -la /tmp | awk '{print $5, $9}'", "write")


# ---------------------------------------------------------------------------
# Safe xargs use
# ---------------------------------------------------------------------------


def test_xargs_grep(default_cmd_lists):
    """xargs piped to grep must remain valid."""
    _valid(default_cmd_lists, "find /tmp -name '*.txt' | xargs grep pattern", "system")


def test_xargs_cat(default_cmd_lists):
    """xargs piped to cat must remain valid."""
    _valid(default_cmd_lists, "echo /tmp/file | xargs cat", "system")


def test_xargs_wc(default_cmd_lists):
    """xargs piped to wc must remain valid."""
    _valid(default_cmd_lists, "find /tmp -name '*.txt' | xargs wc -l", "system")
