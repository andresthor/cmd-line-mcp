"""Tests for the command policy module."""

import pytest

from cmd_line_mcp.policy import (
    ARG_RULES,
    CommandRejected,
    PathUse,
    check_arguments,
    check_command_word,
    classify,
    is_hard_blocked,
    most_privileged,
    normalize_command_name,
)
from cmd_line_mcp.shell_lexer import Redirect, Word


@pytest.mark.parametrize(
    "name, expected",
    [
        ("ls", "ls"),
        ("/usr/bin/env", "env"),
        ("python3.12", "python"),
        ("bash-5", "bash"),
        ("gzip", "gzip"),
    ],
)
def test_normalize_command_name(name, expected):
    assert normalize_command_name(name) == expected


@pytest.mark.parametrize(
    "name", ["env", "xargs", "bash", "python3.12", "/usr/bin/env", "noglob", "."]
)
def test_hard_blocked(name):
    assert is_hard_blocked(name)


@pytest.mark.parametrize("name", ["ls", "grep", "gzip", "cat", "curl"])
def test_not_hard_blocked(name):
    assert not is_hard_blocked(name)


@pytest.mark.parametrize(
    "word",
    [Word("l*", glob=True), Word("~", tilde=True), Word("/bin/ls"), Word("./ls")],
)
def test_check_command_word_rejects(word):
    with pytest.raises(CommandRejected):
        check_command_word(word)


def test_check_command_word_accepts_plain_name():
    check_command_word(Word("ls"))


@pytest.mark.parametrize(
    "name, argv, expected",
    [
        ("curl", ["https://example.com", "-o", "out"], [PathUse("out", "write")]),
        ("curl", ["-sSo", "out", "https://example.com"], [PathUse("out", "write")]),
        ("curl", ["--output=out", "https://example.com"], [PathUse("out", "write")]),
        ("curl", ["-oout", "https://example.com"], [PathUse("out", "write")]),
        ("wget", ["-P", "dir", "https://example.com"], [PathUse("dir", "write")]),
        ("tar", ["-czf", "out.tgz", "dir"], [PathUse("out.tgz", "write")]),
        ("tar", ["czf", "out.tgz", "dir"], [PathUse("out.tgz", "write")]),
        (
            "tar",
            ["-xf", "a.tgz", "-C", "dst"],
            [
                PathUse("a.tgz", "write"),
                PathUse("dst", "write"),
            ],
        ),
        ("unzip", ["a.zip", "-d", "dst"], [PathUse("dst", "write")]),
        ("ls", ["-la", "/tmp"], []),
        ("curl", ["https://example.com"], []),
    ],
)
def test_check_arguments_file_options(name, argv, expected):
    assert check_arguments(name, argv) == expected


def test_check_arguments_applies_registered_rule(monkeypatch):
    def deny_x(argv):
        if "-x" in argv:
            raise CommandRejected("demo: -x is not allowed")

    monkeypatch.setitem(ARG_RULES, "demo", deny_x)
    assert check_arguments("demo", ["-y"]) == []
    with pytest.raises(CommandRejected):
        check_arguments("/usr/bin/demo", ["-x"])


@pytest.mark.parametrize(
    "base, redirects, targets, expected",
    [
        ("read", [Redirect(">", 1, Word("f"))], ["f"], "write"),
        ("read", [Redirect(">>", 1, Word("f"))], ["f"], "write"),
        ("read", [Redirect(">", 1, Word("/dev/null"))], ["/dev/null"], "read"),
        ("read", [Redirect("<", 0, Word("f"))], ["f"], "read"),
        ("read", [Redirect(">&", 2, dup=1)], [None], "read"),
        ("system", [Redirect(">", 1, Word("f"))], ["f"], "system"),
        ("read", [], [], "read"),
    ],
)
def test_classify(base, redirects, targets, expected):
    assert classify(base, redirects, targets) == expected


def test_most_privileged():
    assert most_privileged(["read", "system", "write"]) == "system"
    assert most_privileged(["read"]) == "read"
