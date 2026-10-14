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


@pytest.fixture
def opt_in_cmd_lists(default_cmd_lists):
    """Default lists plus commands left out of the defaults, as a user config would."""
    lists = {k: list(v) for k, v in default_cmd_lists.items()}
    lists["read"] += ["find", "sort"]
    lists["write"] += ["tar", "zip", "unzip", "awk", "sed"]
    lists["system"] += ["curl", "wget"]
    return lists


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
    assert (
        result["is_valid"] is True
    ), f"Expected '{command}' to be valid, got error: {result['error']}"
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


def test_find_by_name(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, 'find /tmp -name "*.txt"', "read")


def test_find_by_type(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "find /tmp -type f -name '*.pdf'", "read")


def test_find_maxdepth(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "find /tmp -maxdepth 2 -mtime -1", "read")


def test_head(default_cmd_lists):
    _valid(default_cmd_lists, "head -n 10 /tmp/file.txt", "read")


def test_tail(default_cmd_lists):
    _valid(default_cmd_lists, "tail -n 20 /tmp/file.txt", "read")


def test_wc(default_cmd_lists):
    _valid(default_cmd_lists, "wc -l /tmp/file.txt", "read")


def test_sort(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "sort /tmp/file.txt", "read")


def test_sort_numeric(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "sort -rn /tmp/file.txt", "read")


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
    """env runs other programs, so it is hard-blocked even with no arguments."""
    result = validate_command(
        "env",
        default_cmd_lists["read"],
        default_cmd_lists["write"],
        default_cmd_lists["system"],
        default_cmd_lists["blocked"],
        default_cmd_lists["dangerous_patterns"],
    )
    assert result["is_valid"] is False


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


def test_tar_create(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "tar -czf /tmp/archive.tar.gz /tmp/dir", "write")


def test_tar_extract(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "tar -xzf /tmp/archive.tar.gz -C /tmp", "write")


def test_gzip(default_cmd_lists):
    _valid(default_cmd_lists, "gzip /tmp/file.txt", "write")


def test_zip(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "zip /tmp/archive.zip /tmp/file.txt", "write")


def test_unzip(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "unzip /tmp/archive.zip -d /tmp", "write")


# ---------------------------------------------------------------------------
# System commands
# ---------------------------------------------------------------------------


def test_ps(default_cmd_lists):
    _valid(default_cmd_lists, "ps aux", "system")


def test_ping(default_cmd_lists):
    _valid(default_cmd_lists, "ping -c 1 localhost", "system")


def test_curl(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "curl -s https://example.com", "system")


def test_who(default_cmd_lists):
    _valid(default_cmd_lists, "who", "system")


# ---------------------------------------------------------------------------
# Safe awk — user-added, text processing without execution
# ---------------------------------------------------------------------------


def test_awk_print_columns(opt_in_cmd_lists):
    """awk column extraction must remain valid."""
    _valid(opt_in_cmd_lists, "ls -la | awk '{print $1, $9}'", "write")


def test_awk_conditional_filter(opt_in_cmd_lists):
    """awk conditional filtering must remain valid."""
    _valid(opt_in_cmd_lists, "cat /tmp/file | awk '{if($1>10) print $0}'", "write")


def test_awk_field_separator(opt_in_cmd_lists):
    """awk with custom field separator must remain valid."""
    _valid(opt_in_cmd_lists, "awk -F: '{print $1}' /tmp/file", "write")


def test_awk_arithmetic(opt_in_cmd_lists):
    """awk arithmetic must remain valid."""
    _valid(opt_in_cmd_lists, "awk '{sum += $1} END {print sum}' /tmp/file", "write")


def test_awk_pattern_match(opt_in_cmd_lists):
    """awk pattern matching must remain valid."""
    _valid(opt_in_cmd_lists, "awk '/pattern/ {print $0}' /tmp/file", "write")


# ---------------------------------------------------------------------------
# Safe sed — user-added, substitution without /e flag
# ---------------------------------------------------------------------------


def test_sed_basic_substitution(opt_in_cmd_lists):
    """sed basic substitution must remain valid."""
    _valid(opt_in_cmd_lists, "sed 's/foo/bar/' /tmp/file", "write")


def test_sed_global_substitution(opt_in_cmd_lists):
    """sed global substitution must remain valid."""
    _valid(opt_in_cmd_lists, "echo hello | sed 's/hello/world/g'", "write")


def test_sed_case_insensitive(opt_in_cmd_lists):
    """sed case-insensitive substitution must remain valid."""
    _valid(opt_in_cmd_lists, "sed 's/foo/bar/i' /tmp/file", "write")


def test_sed_line_range(opt_in_cmd_lists):
    """sed line range printing must remain valid."""
    _valid(opt_in_cmd_lists, "sed -n '1,5p' /tmp/file", "write")


def test_sed_delete_lines(opt_in_cmd_lists):
    """sed line deletion must remain valid."""
    _valid(opt_in_cmd_lists, "sed '/^#/d' /tmp/file", "write")


# ---------------------------------------------------------------------------
# Pipelines
# ---------------------------------------------------------------------------


def test_pipeline_grep_sort_wc(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "cat /tmp/file | grep pattern | sort | wc -l", "read")


def test_pipeline_find_grep(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "find /tmp -name '*.log' | grep error", "read")


def test_pipeline_du_sort(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "du -h /tmp | sort -h", "read")


def test_pipeline_ls_awk(opt_in_cmd_lists):
    _valid(opt_in_cmd_lists, "ls -la /tmp | awk '{print $5, $9}'", "write")


# ---------------------------------------------------------------------------
# xargs runs other programs, so it is hard-blocked whatever it wraps
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "find /tmp -name '*.txt' | xargs grep pattern",
        "echo /tmp/file | xargs cat",
        "find /tmp -name '*.txt' | xargs wc -l",
    ],
)
def test_xargs_hard_blocked(opt_in_cmd_lists, command):
    result = validate_command(
        command,
        opt_in_cmd_lists["read"],
        opt_in_cmd_lists["write"],
        opt_in_cmd_lists["system"],
        opt_in_cmd_lists["blocked"],
        opt_in_cmd_lists["dangerous_patterns"],
    )
    assert result["is_valid"] is False
    assert "'xargs' is blocked" in result["error"]
