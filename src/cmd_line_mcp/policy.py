"""Command policy applied to lexed commands.

Pure: no I/O, no configuration. Rules here apply regardless of user config,
because a user's command lists replace the defaults rather than merging.
"""

import os
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from .shell_lexer import Redirect, Word

# Programs that run other programs, shells and interpreters. Never allowed,
# even when a user config lists them.
HARD_BLOCKED: frozenset[str] = frozenset(
    (
        # wrappers
        "env xargs nice nohup time timeout busybox command builtin exec eval "
        "source . doas sudo su watch setsid stdbuf flock parallel chroot "
        "strace ltrace script expect "
        # shells
        "sh bash zsh ksh csh tcsh fish dash ash "
        # interpreters
        "python python2 python3 perl ruby node nodejs lua php tclsh wish "
        "Rscript osascript "
        # other
        "ssh-agent nc telnet screen tmux noglob nocorrect repeat foreach coproc"
    ).split()
)

# Options whose value names a file the command writes or reads.
FILE_OPTIONS: dict[str, dict[str, Literal["read", "write"]]] = {
    "curl": {"-o": "write", "--output": "write", "--output-dir": "write"},
    "wget": {
        "-O": "write",
        "--output-document": "write",
        "-P": "write",
        "--directory-prefix": "write",
    },
    "tar": {"-f": "write", "--file": "write", "-C": "write", "--directory": "write"},
    "unzip": {"-d": "write"},
}

_TYPE_RANK = {"read": 0, "write": 1, "system": 2}
_VERSION_SUFFIX = re.compile(r"[-.]?\d+(\.\d+)*$")


class CommandRejected(ValueError):
    """A command violates policy. The message is shown to the user."""


@dataclass(frozen=True)
class PathUse:
    """A path a command touches, and whether it writes to it."""

    path: str
    kind: Literal["read", "write"]


ArgRule = Callable[[Sequence[str]], None]

# Per-command argument rules, keyed by normalized command name. A rule raises
# CommandRejected; it applies to user-added commands as well as defaults.
ARG_RULES: dict[str, ArgRule] = {}


def normalize_command_name(name: str) -> str:
    """Return the basename of ``name`` without a trailing version suffix."""
    base = os.path.basename(name)
    stripped = _VERSION_SUFFIX.sub("", base)
    return stripped or base


def is_hard_blocked(name: str) -> bool:
    """Whether ``name`` (or its normalized form) is never allowed."""
    return name in HARD_BLOCKED or normalize_command_name(name) in HARD_BLOCKED


def check_command_word(word: Word) -> None:
    """Reject command words that need expansion or name a path.

    Raises:
        CommandRejected: The word is not a plain command name.
    """
    if word.glob or word.tilde:
        raise CommandRejected(f"Command name '{word.text}' may not use ~ or globs")
    if "/" in word.text:
        raise CommandRejected(
            f"Command '{word.text}' must be given by name, not by path"
        )


def check_arguments(name: str, argv: Sequence[str]) -> list[PathUse]:
    """Apply argument rules to expanded ``argv`` (command word excluded).

    Returns:
        Paths named by file-valued options such as ``curl -o``.

    Raises:
        CommandRejected: An argument rule rejected the arguments.
    """
    key = normalize_command_name(name)
    rule = ARG_RULES.get(key)
    if rule is not None:
        rule(argv)
    args = list(argv)
    # tar accepts its first bundle without a dash: tar czf out.tgz dir
    if key == "tar" and args and not args[0].startswith("-"):
        args[0] = "-" + args[0]
    return _file_option_paths(FILE_OPTIONS.get(key, {}), args)


def classify(
    base_type: str,
    redirects: Sequence[Redirect],
    targets: Sequence[str | None],
) -> str:
    """Raise ``base_type`` to at least ``write`` for output redirects.

    Args:
        base_type: Type from the command lists (read, write or system).
        redirects: The command's redirects.
        targets: Expanded target per redirect, ``None`` for fd dups.
    """
    for redirect, target in zip(redirects, targets):
        if redirect.op in (">", ">>") and target != "/dev/null":
            return max(base_type, "write", key=_TYPE_RANK.__getitem__)
    return base_type


def most_privileged(types: Sequence[str]) -> str:
    """The most privileged of ``types`` (read < write < system)."""
    return max(types, key=_TYPE_RANK.__getitem__)


def _file_option_paths(
    options: dict[str, Literal["read", "write"]], argv: Sequence[str]
) -> list[PathUse]:
    paths: list[PathUse] = []
    has_next = len(argv) - 1
    for i, arg in enumerate(argv):
        if arg.startswith("--"):
            opt, sep, value = arg.partition("=")
            if opt in options and sep:
                paths.append(PathUse(value, options[opt]))
            elif opt in options and i < has_next:
                paths.append(PathUse(argv[i + 1], options[opt]))
        elif arg.startswith("-") and len(arg) > 1:
            last = "-" + arg[-1]
            if arg in options or (arg[1:].isalpha() and last in options):
                # -o out, or a bundle ending in the option: -czf out.tgz
                if i < has_next:
                    opt = arg if arg in options else last
                    paths.append(PathUse(argv[i + 1], options[opt]))
            elif arg[:2] in options:
                # Attached value: -oout
                paths.append(PathUse(arg[2:], options[arg[:2]]))
    return paths
