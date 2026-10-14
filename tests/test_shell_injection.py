"""Regression tests: shell syntax outside the validated subset never runs, and
``/bin/sh`` splits every accepted command into exactly the validated argv."""

import asyncio
import os
import subprocess
from unittest.mock import patch

import pytest

from cmd_line_mcp.config import Config
from cmd_line_mcp.security import prepare_command, validate_command
from cmd_line_mcp.server import CommandLineMCP
from cmd_line_mcp.shell_lexer import render

SH = "/bin/sh"
MARKER = "cmdmcp-marker"
# The lexer rejects control characters, so no validated argument can equal a tag.
TAG = "\x01cmd"

_real_exec = asyncio.create_subprocess_exec

needs_sh = pytest.mark.skipif(not os.path.exists(SH), reason="no /bin/sh")


def default_lists():
    """Command lists and patterns of the shipped default configuration."""
    return Config().get_effective_command_lists()


def validate(command):
    """``validate_command`` with the default configuration."""
    lists = default_lists()
    return validate_command(
        command,
        lists["read"],
        lists["write"],
        lists["system"],
        lists["blocked"],
        lists["dangerous_patterns"],
    )


@pytest.fixture
def home(tmp_path, monkeypatch):
    """``tmp_path`` as cwd and ``$HOME``, with awkward file names to expand."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    # Any expansion of a variable would land where the marker is checked.
    monkeypatch.setenv("CMDMCP_DIR", str(tmp_path))
    (tmp_path / "f").write_text("a|b\n;\n")
    (tmp_path / "in.txt").write_text("b\na\n")
    (tmp_path / "-n").write_text("")
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    for name in ("a b.txt", "it's.txt", "-n", "G.iso"):
        (downloads / name).write_text("x\n")
    return tmp_path


# ---------------------------------------------------------------------------
# Rejected input
# ---------------------------------------------------------------------------

REJECT = [
    pytest.param(f"ls\ntouch {MARKER}", r"'\n'", id="newline"),
    pytest.param(f"ls\r\ntouch {MARKER}", r"'\r'", id="crlf"),
    pytest.param(f"ls\rtouch {MARKER}", r"'\r'", id="cr"),
    pytest.param(f"ls | grep x ; tee {MARKER}", "'tee' is not recognized", id="mixed"),
    pytest.param(f"ls ; ls | tee {MARKER}", "'tee' is not recognized", id="mixed-2"),
    pytest.param(f"ls | -v; touch {MARKER}", "may not start with '-'", id="dash"),
    pytest.param(f"ls <(touch {MARKER})", "'('", id="procsub-in"),
    pytest.param(f"ls >(touch {MARKER})", "'('", id="procsub-out"),
    pytest.param(f"echo x > $HOME/{MARKER}", "'$'", id="home-redirect"),
    pytest.param(f"echo x >$HOME/{MARKER}", "'$'", id="home-redirect-nospace"),
    pytest.param(f"echo x >${{HOME}}/{MARKER}", "${var}", id="home-braces"),
    pytest.param(f"echo x > $CMDMCP_DIR/{MARKER}", "'$'", id="var-redirect"),
    pytest.param(f"ls & touch {MARKER}", "background '&'", id="background"),
    pytest.param(f"ls &> {MARKER}", "'&>'", id="amp-redirect"),
    pytest.param(f"ls |& touch {MARKER}", "|&", id="pipe-amp"),
    pytest.param(f"echo `touch {MARKER}`", "backtick", id="backtick"),
    pytest.param(f"echo $(touch {MARKER})", "$()", id="cmdsub"),
    pytest.param(f"(touch {MARKER})", "'('", id="subshell"),
    pytest.param(f"{{ touch {MARKER}; }}", "'{'", id="group"),
    pytest.param(f"ls \\; touch {MARKER}", "'\\\\'", id="backslash"),
]


@pytest.mark.parametrize("command, reason", REJECT)
def test_rejected_by_default_config(home, command, reason):
    """Each form is rejected for its own reason, not an unrelated one."""
    result = validate(command)

    assert result["is_valid"] is False
    assert reason in result["error"]
    assert result["canonical_command"] is None


@pytest.mark.parametrize("command, reason", REJECT)
async def test_rejected_command_never_runs(home, command, reason):
    """Validation alone stops the command: the marker is inside the whitelist."""
    server = CommandLineMCP()
    server.whitelisted_directories = [str(home)]

    with patch("asyncio.create_subprocess_exec", wraps=_real_exec) as spawn:
        result = await server._execute_command(command)

    assert result["success"] is False
    spawn.assert_not_called()
    assert not (home / MARKER).exists()


def test_redirect_raises_read_to_write(home):
    """A redirect to a file makes a read-listed command a write."""
    assert validate("cat f")["command_type"] == "read"
    assert validate("cat f > out.txt")["command_type"] == "write"


async def test_read_tool_refuses_read_command_with_redirect(home):
    """``execute_read_command`` refuses a read command that writes a file."""
    server = CommandLineMCP()
    server.whitelisted_directories = [str(home)]

    result = await server._execute_read_command_func("cat f > out.txt")

    assert result["success"] is False
    assert "only supports read commands" in result["error"]
    assert not (home / "out.txt").exists()


# ---------------------------------------------------------------------------
# Accepted input
# ---------------------------------------------------------------------------

ACCEPT = [
    ('grep "a|b" f', "read"),
    ("ls | grep x", "read"),
    ("ls && pwd", "read"),
    ("ls;pwd", "read"),
    ("ls 2>&1", "read"),
    ("du -h ~/Downloads/* | grep G", "read"),
    ("grep ';' f", "read"),
    ('grep "&&" f', "read"),
    ("echo 'a > b' \"c | d\"", "write"),
    ("echo 'a'\"b\"c", "write"),
    ('echo "it\'s" \'say "hi"\'', "write"),
]


@pytest.mark.parametrize("command, expected", ACCEPT)
def test_accepted_by_default_config(home, command, expected):
    """Pipes, separators and quoted operators keep working."""
    result = validate(command)

    assert result["error"] is None
    assert result["is_valid"] is True
    assert result["command_type"] == expected


# ---------------------------------------------------------------------------
# Argv differential against /bin/sh
# ---------------------------------------------------------------------------

DIFFERENTIAL = [command for command, _ in ACCEPT] + [
    "grep '' f",
    "ls || pwd",
    "ls && pwd || id",
    "ls *",
    "du -h ~/Downloads/* ~",
    "cat < in.txt",
    "ls > out.txt",
    "ls >> log.txt",
    "ls > out.txt 2>&1",
    "ls 2>&1 > out.txt",
    "ls 2> err.txt",
    "ls >&2",
    "ls 1>&2",
    "ls > a.txt | grep x",
    "cat < in.txt | sort > sorted.txt",
    "ls ; echo 'x y' >> log.txt ; pwd",
]


def run_printf_render(prepared, cwd):
    """Run the canonical structure with every command replaced by ``printf``.

    Each command prints a tag naming its index, then its arguments, each
    followed by NUL. Returns the completed process.
    """
    argvs = [
        ["printf", "%s\\0", f"{TAG}{i}", *argv[1:]]
        for i, argv in enumerate(prepared.argv_per_command)
    ]
    script = render(prepared.parsed, argvs, prepared.redirect_targets)
    env = {k: v for k, v in os.environ.items() if k not in ("ENV", "BASH_ENV")}
    return subprocess.run(
        [SH, "-c", "--", script],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        cwd=cwd,
        env=env,
        timeout=10,
    )


def expected_destinations(prepared, cwd):
    """Where each observable command's stdout ends up: stream or file path.

    ``printf`` always succeeds, so only a pipeline right after ``||`` is
    skipped. Stdout into a pipe is consumed by the next ``printf`` unseen.
    """
    parsed = prepared.parsed
    where = {}
    index = 0
    for n, pipeline in enumerate(parsed.pipelines):
        runs = n == 0 or parsed.connectors[n - 1] != "||"
        for position, cmd in enumerate(pipeline):
            last = position == len(pipeline) - 1
            fds = {1: "stdout" if last else "pipe", 2: "stderr"}
            targets = prepared.redirect_targets[index]
            for redirect, target in zip(cmd.redirects, targets):
                if redirect.op == ">&":
                    fds[redirect.fd] = fds[redirect.dup]
                elif redirect.op != "<":
                    fds[redirect.fd] = os.path.join(cwd, target)
            if runs and fds[1] != "pipe":
                where[index] = fds[1]
            index += 1
    return where


def records(data):
    """Split ``printf`` output into ``{index: args}`` by tag."""
    fields = data.decode().split("\0")
    assert fields[-1] == "", data
    found = {}
    current = None
    for field in fields[:-1]:
        if field.startswith(TAG):
            current = int(field.removeprefix(TAG))
            found[current] = []
        else:
            assert current is not None, data
            found[current].append(field)
    return {i: tuple(args) for i, args in found.items()}


@needs_sh
@pytest.mark.parametrize("command", DIFFERENTIAL)
def test_sh_splits_canonical_into_validated_argv(home, command):
    """``/bin/sh`` sees exactly the argv and redirects that were validated."""
    lists = default_lists()
    prepared = prepare_command(
        command, lists, lists["dangerous_patterns"], True, str(home)
    )
    where = expected_destinations(prepared, str(home))
    assert where, "case observes no command"

    proc = run_printf_render(prepared, str(home))

    assert proc.returncode == 0, proc.stderr
    streams = {"stdout": proc.stdout, "stderr": proc.stderr}
    for path in set(where.values()) - set(streams):
        with open(path, "rb") as handle:
            streams[path] = handle.read()
    seen = {}
    for name, data in streams.items():
        for index, args in records(data).items():
            assert index not in seen, command
            seen[index] = (name, args)
    expected = {
        index: (destination, prepared.argv_per_command[index][1:])
        for index, destination in where.items()
    }
    assert seen == expected
