"""Tests for how the server validates, confines and runs commands."""

import asyncio
import os
import time
from unittest.mock import patch

import pytest

from cmd_line_mcp.security import prepare_command
from cmd_line_mcp import server as server_module
from cmd_line_mcp.server import CommandLineMCP

_real_exec = asyncio.create_subprocess_exec


@pytest.fixture
def server(tmp_path, monkeypatch):
    """A server confined to ``tmp_path``, which is also the cwd."""
    monkeypatch.chdir(tmp_path)
    server = CommandLineMCP()
    server.whitelisted_directories = [str(tmp_path)]
    commands = server.config.config["commands"]
    commands["read"] = [*commands["read"], "sleep", "yes"]
    return server


@pytest.fixture
def spawn():
    """Spy on process creation while still running the real command."""
    with patch("asyncio.create_subprocess_exec", wraps=_real_exec) as spy:
        yield spy


async def test_runs_canonical_not_raw_command(server, spawn):
    """The rendered command runs, never the client's string."""
    raw = "echo   'a  b'    c"
    canonical = prepare_command(raw, server.config.get_effective_command_lists())
    assert canonical.canonical != raw

    result = await server._execute_command(raw)

    assert result["success"] is True
    assert result["output"] == "a  b c\n"
    spawn.assert_called_once()
    assert spawn.call_args.args == ("/bin/sh", "-c", "--", canonical.canonical)


async def test_read_tool_rejects_redirect_to_file(server, spawn, tmp_path):
    """A redirect makes a read command a write, which the read tool refuses."""
    result = await server._execute_read_command_func("ls > out.txt")

    assert result["success"] is False
    assert "only supports read commands" in result["error"]
    assert not (tmp_path / "out.txt").exists()
    spawn.assert_not_called()


@pytest.mark.parametrize(
    "template",
    [
        "ls {allowed} ; ls {other}",
        "ls {allowed} && ls {other}",
        "cat {allowed}/a.txt | grep x {other}/b.txt",
        "ls {other} || ls {allowed}",
    ],
)
async def test_directory_outside_whitelist_in_any_segment_is_denied(
    server, spawn, tmp_path, template
):
    """Every segment's paths are checked, not just the first one."""
    allowed, other = tmp_path / "allowed", tmp_path / "other"
    allowed.mkdir()
    other.mkdir()
    (allowed / "a.txt").write_text("x\n")
    (other / "b.txt").write_text("x\n")
    server.whitelisted_directories = [str(allowed)]

    result = await server._execute_command(
        template.format(allowed=allowed, other=other)
    )

    assert result["success"] is False
    assert result["requires_directory_approval"] is True
    assert result["directory"] == os.path.realpath(other)
    spawn.assert_not_called()


async def test_denied_directory_with_session_ids_required(server, tmp_path):
    """With session IDs required the denial asks for approval in that session."""
    other = tmp_path / "other"
    other.mkdir()
    server.whitelisted_directories = [str(tmp_path / "allowed")]
    server.config.config["security"]["require_session_id"] = True

    result = await server._execute_command(f"ls {other}", session_id="s-1")

    assert result["requires_directory_approval"] is True
    assert result["session_id"] == "s-1"
    assert result["directory"] == os.path.realpath(other)

    server.session_manager.approve_directory("s-1", os.path.realpath(other))
    result = await server._execute_command(f"ls {other}", session_id="s-1")
    assert result["success"] is True


async def test_stdin_is_devnull(server, spawn):
    """A command that reads stdin sees EOF instead of waiting for input."""
    result = await asyncio.wait_for(server._execute_command("cat"), 10)

    assert result["success"] is True
    assert result["output"] == ""
    assert spawn.call_args.kwargs["stdin"] is asyncio.subprocess.DEVNULL
    assert spawn.call_args.kwargs["start_new_session"] is True


async def test_timeout_kills_process_group(server):
    """Every process of a pipeline is stopped once the timeout passes."""
    server.config.config["security"]["command_timeout"] = 0.2

    started = time.monotonic()
    # sort keeps the pipe open until sleep exits, so this only returns
    # early if the whole group is killed.
    result = await asyncio.wait_for(server._execute_command("sleep 5 | sort"), 10)

    assert time.monotonic() - started < 3
    assert result["timed_out"] is True
    assert result["success"] is False
    assert "timed out" in result["error"]


async def test_output_cap_truncates_and_stops_command(server):
    """An endless producer is stopped once output reaches the cap."""
    server.config.config["output"]["max_size"] = 1000

    result = await asyncio.wait_for(server._execute_command("yes"), 10)

    assert result["truncated"] is True
    assert result["timed_out"] is False
    assert result["success"] is True
    assert "truncated" not in result["error"]
    assert result["output"].startswith("y\ny\n")
    assert result["output"].endswith("[output truncated due to size]")
    assert len(result["output"].split("\n...")[0]) == 1000


async def test_output_under_cap_is_not_truncated(server):
    result = await server._execute_command("echo hello")

    assert result["output"] == "hello\n"
    assert result["truncated"] is False
    assert result["timed_out"] is False


@pytest.mark.parametrize(
    "name",
    [
        "ENV",
        "BASH_ENV",
        "BASH_FUNC_x%%",
        "SHELLOPTS",
        "BASHOPTS",
        "CDPATH",
        "GLOBIGNORE",
        "IFS",
    ],
)
async def test_shell_startup_variables_are_not_passed(server, spawn, monkeypatch, name):
    """Variables that change how the shell starts never reach it."""
    monkeypatch.setenv(name, "x")
    monkeypatch.setenv("CMD_LINE_MCP_TEST_MARKER", "kept")

    result = await server._execute_command("echo hello")

    assert result["success"] is True
    env = spawn.call_args.kwargs["env"]
    assert name not in env
    assert env["CMD_LINE_MCP_TEST_MARKER"] == "kept"


async def test_exported_shell_function_is_not_imported(server, monkeypatch):
    monkeypatch.setenv("BASH_FUNC_echo%%", '() { builtin printf "replaced\\n"; }')

    result = await server._execute_command("echo hello")

    assert result["output"] == "hello\n"


async def test_rejected_command_does_not_run(server, spawn):
    result = await server._execute_command("echo $HOME")

    assert result["success"] is False
    assert "Unsupported shell syntax" in result["error"]
    spawn.assert_not_called()


async def test_usage_examples_pass_validation(server):
    """Examples shown to the model use only accepted syntax and commands."""
    commands = server.config.get_effective_command_lists()
    for example in server.usage_examples:
        prepare_command(example["command"], commands, commands["dangerous_patterns"])


async def test_stderr_cap_marks_only_stderr(server):
    """Only the stream that lost output gets the marker."""
    server.config.config["output"]["max_size"] = 50

    result = await server._execute_command(
        "ls missing-1 missing-2 missing-3 missing-4 missing-5"
    )

    assert result["truncated"] is True
    assert result["error"].endswith("[output truncated due to size]")
    assert "truncated" not in result["output"]
    assert result["success"] is False


async def test_slow_validation_times_out(server, spawn, monkeypatch):
    """Validation runs off the event loop and is bounded by the timeout."""
    server.config.config["security"]["command_timeout"] = 0.2
    real_prepare = server_module.prepare_command

    def slow_prepare(*args, **kwargs):
        time.sleep(0.5)
        return real_prepare(*args, **kwargs)

    monkeypatch.setattr(server_module, "prepare_command", slow_prepare)

    started = time.monotonic()
    result = await server._execute_command("echo hello")

    assert time.monotonic() - started < 0.45
    assert result["success"] is False
    assert "Validating the command took longer than 0.2 seconds" in result["error"]
    spawn.assert_not_called()


async def test_missing_working_directory_is_an_error(server, spawn, monkeypatch):
    def no_cwd():
        raise FileNotFoundError("cwd removed")

    monkeypatch.setattr(os, "getcwd", no_cwd)

    result = await server._execute_command("echo hello")

    assert result["success"] is False
    assert "Cannot determine the working directory" in result["error"]
    spawn.assert_not_called()


@pytest.mark.parametrize("session_id", [None, "claude_desktop_fixed_session"])
async def test_write_needs_approval_when_confirmation_is_off(server, spawn, session_id):
    """With confirmation off, write commands need an explicit approval."""
    server.config.config["security"]["allow_user_confirmation"] = False
    server.config.config["security"]["require_session_id"] = False

    result = await server._execute_command("echo hello", session_id=session_id)

    assert result["success"] is False
    assert result["requires_approval"] is True
    assert result["command_type"] == "write"
    assert result["session_id"] == "claude_desktop_fixed_session"
    spawn.assert_not_called()

    server.session_manager.approve_command_type(result["session_id"], "write")
    result = await server._execute_command("echo hello", session_id=session_id)
    assert result["success"] is True


async def test_command_type_mismatch(server, spawn):
    result = await server._execute_command("ls", command_type="system")

    assert result["success"] is False
    assert result["error"] == "Command type mismatch. Expected system, got read"
    spawn.assert_not_called()


@pytest.mark.parametrize("value", [None, "soon", 0, -5, "nan", float("inf")])
def test_invalid_command_timeout_uses_default(server, caplog, value):
    server.config.config["security"]["command_timeout"] = value

    with caplog.at_level("WARNING", logger="cmd_line_mcp.server"):
        assert server._command_timeout() == 60
        assert server._command_timeout() == 60

    warnings = [r for r in caplog.records if "command_timeout" in r.getMessage()]
    assert len(warnings) == 1


def test_command_timeout_is_coerced(server):
    server.config.config["security"]["command_timeout"] = "1.5"
    assert server._command_timeout() == 1.5
