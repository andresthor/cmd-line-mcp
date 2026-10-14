"""Security utilities for the command-line MCP server.

:func:`prepare_command` is the single decision point for a command: it lexes
the string, applies policy to the expanded argv, collects every path the
command touches and renders the canonical string to execute.
"""

import glob
import itertools
import logging
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .policy import (
    CommandRejected,
    PathUse,
    check_arguments,
    check_command_word,
    classify,
    is_hard_blocked,
    most_privileged,
    normalize_command_name,
)
from .shell_lexer import Command, LexError, ParsedCommand, Redirect, Word, lex, render

__all__ = [
    "CommandRejected",
    "ExpandedCommand",
    "PathUse",
    "PreparedCommand",
    "collect_paths",
    "expand",
    "extract_directory_from_command",
    "is_directory_whitelisted",
    "normalize_path",
    "parse_command",
    "prepare_command",
    "validate_command",
]

logger = logging.getLogger(__name__)

MAX_GLOB_MATCHES = 1000
MAX_TOTAL_GLOB_MATCHES = 10000

COMMAND_TYPES = ("read", "write", "system")

SEPARATORS_DISABLED_ERROR = (
    "Command separators (|, ;, &) are not allowed in the current configuration"
)

# Commands whose operands are files or directories.
PATH_COMMANDS = frozenset(
    "ls cat head tail cp mv rm mkdir rmdir touch chmod chown ln find du tar "
    "gzip zip unzip wc file stat diff".split()
)

# Commands that operate on the working directory when given no operand.
_IMPLICIT_CWD = frozenset({"ls", "find", "du"})

# Options of PATH_COMMANDS whose value is a count, format or suffix.
_NON_PATH_VALUES: dict[str, frozenset[str]] = {
    "head": frozenset({"-n", "-c"}),
    "tail": frozenset({"-n", "-c"}),
    "du": frozenset({"-d"}),
    "diff": frozenset({"-U", "-C"}),
    "stat": frozenset({"-f", "-c", "-t"}),
    "gzip": frozenset({"-S"}),
    "cp": frozenset({"-S"}),
    "mv": frozenset({"-S"}),
    "ln": frozenset({"-S"}),
}

_GREP = frozenset({"grep", "egrep", "fgrep"})
# Short options that take a value, attached or as the next argument.
_GREP_SHORT_VALUES = frozenset("efABCmdD")
# Long options handled like their short form.
_GREP_LONG = {"--regexp": "e", "--file": "f", "--directories": "d"}
_GREP_LONG_RECURSIVE = ("--recursive", "--dereference-recursive")

_FIND_LEADING_OPTIONS = frozenset({"-H", "-L", "-P", "-E", "-X", "-d", "-s", "-x"})
_FIND_PATTERN_PRIMARIES = frozenset(
    "-name -iname -path -ipath -wholename -iwholename -regex -iregex "
    "-lname -ilname".split()
)
_FIND_EXPRESSION_START = frozenset({"(", ")", "!"})

_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")

Kind = Literal["read", "write"]


@dataclass(frozen=True)
class ExpandedCommand:
    """Argv and redirect targets after tilde and glob expansion.

    Attributes:
        argv_per_command: Final argv of each command, command word first.
        redirect_targets: Target per redirect of each command, ``None`` for
            ``>&`` dups.
        from_glob: Per argv word, whether it is a glob match.
    """

    argv_per_command: tuple[tuple[str, ...], ...]
    redirect_targets: tuple[tuple[str | None, ...], ...]
    from_glob: tuple[tuple[bool, ...], ...]


@dataclass(frozen=True)
class PreparedCommand:
    """A command that passed validation, ready to execute.

    Attributes:
        parsed: Lexed structure of the input.
        expanded: Final argv and redirect targets.
        command_types: Type of each command after redirect classification.
        command_type: Most privileged of ``command_types``.
        canonical: String to run with ``/bin/sh -c``; never run the input.
        paths: Every path the command touches, normalized.
        directories: Directories of ``paths`` to check against the
            whitelist, without duplicates.
    """

    parsed: ParsedCommand
    expanded: ExpandedCommand
    command_types: tuple[str, ...]
    command_type: str
    canonical: str
    paths: tuple[PathUse, ...]
    directories: tuple[str, ...]

    @property
    def argv_per_command(self) -> tuple[tuple[str, ...], ...]:
        """Final argv of each command."""
        return self.expanded.argv_per_command

    @property
    def redirect_targets(self) -> tuple[tuple[str | None, ...], ...]:
        """Final target of each redirect of each command."""
        return self.expanded.redirect_targets


def parse_command(command: str) -> tuple[str, list[str]]:
    """Return the first command's name and arguments, for display only.

    Never base a security decision on this; use :func:`prepare_command`.

    Args:
        command: The command string

    Returns:
        A tuple of (command, arguments), or ``("", [])`` if the command
        cannot be lexed.
    """
    try:
        parsed = lex(command)
    except LexError:
        return "", []
    first = parsed.commands[0]
    return first.name, list(first.args)


def expand(parsed: ParsedCommand, cwd: str) -> ExpandedCommand:
    """Expand ``~`` and globs the way ``sh`` would, relative to ``cwd``.

    Command words are never expanded. A glob without matches stays literal,
    as in POSIX sh. Matches starting with ``-`` get a ``./`` prefix so they
    cannot be read as options.

    Raises:
        CommandRejected: A glob matches too many entries.
    """
    total = 0
    argvs: list[tuple[str, ...]] = []
    targets: list[tuple[str | None, ...]] = []
    from_glob: list[tuple[bool, ...]] = []
    for cmd in parsed.commands:
        argv = [cmd.name]
        globbed = [False]
        for word in cmd.words[1:]:
            matches = _glob(word, cwd) if word.glob else []
            total += len(matches)
            if total > MAX_TOTAL_GLOB_MATCHES:
                raise CommandRejected(
                    f"Globs match more than {MAX_TOTAL_GLOB_MATCHES} entries in total"
                )
            if matches:
                argv += matches
                globbed += [True] * len(matches)
            else:
                argv.append(_expand_tilde(word))
                globbed.append(False)
        argvs.append(tuple(argv))
        from_glob.append(tuple(globbed))
        targets.append(
            tuple(
                None if r.target is None else _expand_tilde(r.target)
                for r in cmd.redirects
            )
        )
    return ExpandedCommand(tuple(argvs), tuple(targets), tuple(from_glob))


def prepare_command(
    command: str,
    command_lists: Mapping[str, Sequence[str]],
    dangerous_patterns: Sequence[str] = (),
    allow_separators: bool = True,
    cwd: str | None = None,
) -> PreparedCommand:
    """Validate ``command`` and produce what to execute and what to check.

    Args:
        command: The command string from the client.
        command_lists: ``read``, ``write``, ``system`` and ``blocked`` lists;
            missing keys count as empty.
        dangerous_patterns: Regexes that reject the command when they match
            the raw string or its normalized view.
        allow_separators: Whether more than one command is allowed.
        cwd: Directory the command runs in; defaults to the process cwd.

    Raises:
        CommandRejected: The command is not allowed. The message is shown
            to the user.
    """
    if not command.strip():
        raise CommandRejected("Empty command")
    cwd = os.path.abspath(os.getcwd() if cwd is None else cwd)

    # Raw patterns run before lexing so their specific messages still surface.
    _check_patterns(command, dangerous_patterns)
    try:
        parsed = lex(command)
    except LexError as error:
        raise CommandRejected(f"Unsupported shell syntax: {error}") from error
    if not allow_separators and len(parsed.commands) > 1:
        raise CommandRejected(SEPARATORS_DISABLED_ERROR)
    _check_patterns(_normalized_view(parsed), dangerous_patterns)

    # Before expansion, so a rejected command never triggers a directory listing.
    base_types = [_base_type(cmd, command_lists) for cmd in parsed.commands]

    expanded = expand(parsed, cwd)
    command_types = []
    option_paths = []
    for cmd, argv, targets, base_type in zip(
        parsed.commands,
        expanded.argv_per_command,
        expanded.redirect_targets,
        base_types,
    ):
        uses = check_arguments(cmd.name, argv[1:])
        option_paths.append(uses)
        command_type = classify(base_type, cmd.redirects, targets)
        if any(use.kind == "write" for use in uses):
            # Output-file options such as curl -o write just as a redirect does.
            command_type = most_privileged([command_type, "write"])
        command_types.append(command_type)

    operand_kinds: list[Kind] = ["read" if t == "read" else "write" for t in base_types]
    paths = collect_paths(parsed, expanded, cwd, operand_kinds, option_paths)
    return PreparedCommand(
        parsed=parsed,
        expanded=expanded,
        command_types=tuple(command_types),
        command_type=most_privileged(command_types),
        canonical=render(parsed, expanded.argv_per_command, expanded.redirect_targets),
        paths=tuple(paths),
        directories=_directories(paths, cwd),
    )


def collect_paths(
    parsed: ParsedCommand,
    expanded: ExpandedCommand,
    cwd: str,
    operand_kinds: Sequence[Kind],
    option_paths: Sequence[Sequence[PathUse]],
) -> list[PathUse]:
    """Every path a command reads or writes, normalized, in source order.

    Covers redirect targets, path-like and existing operands, glob matches,
    option values, file options and implicit uses of ``cwd`` of every
    command. Write targets must be regular files (directories where the
    command takes one) and not symlinks. Falls back to ``cwd`` when nothing
    is found.

    Args:
        parsed: Lexed command.
        expanded: Its expansion.
        cwd: Directory the command runs in.
        operand_kinds: Per command, ``write`` if its listed type writes.
        option_paths: Per command, file options from ``check_arguments``.

    Raises:
        CommandRejected: A path is not allowed or cannot be resolved.
    """
    try:
        return _collect_paths(
            parsed, expanded, os.path.abspath(cwd), operand_kinds, option_paths
        )
    except CommandRejected:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise CommandRejected(
            f"Could not resolve the paths in this command: {error}"
        ) from error


def validate_command(
    command: str,
    read_commands: list[str],
    write_commands: list[str],
    system_commands: list[str],
    blocked_commands: list[str],
    dangerous_patterns: list[str],
    allow_command_separators: bool = True,
) -> dict[str, Any]:
    """Validate a command for security.

    Args:
        command: The command to validate
        read_commands: List of read-only commands
        write_commands: List of write commands
        system_commands: List of system commands
        blocked_commands: List of blocked commands
        dangerous_patterns: List of dangerous patterns to block
        allow_command_separators: Whether to allow ``|``, ``;``, ``&&``, ``||``

    Returns:
        A dictionary with ``is_valid``, ``command_type``, ``error``,
        ``canonical_command`` and ``directories``.
    """
    result: dict[str, Any] = {
        "is_valid": False,
        "command_type": None,
        "error": None,
        "canonical_command": None,
        "directories": [],
    }
    command_lists = {
        "read": read_commands,
        "write": write_commands,
        "system": system_commands,
        "blocked": blocked_commands,
    }
    try:
        prepared = prepare_command(
            command, command_lists, dangerous_patterns, allow_command_separators
        )
    except CommandRejected as error:
        result["error"] = str(error)
        return result
    result.update(
        is_valid=True,
        command_type=prepared.command_type,
        canonical_command=prepared.canonical,
        directories=list(prepared.directories),
    )
    return result


def normalize_path(path: str) -> str:
    """Normalize a path to absolute path with no symlinks or relative components.

    Args:
        path: The path to normalize

    Returns:
        Normalized absolute path
    """
    p = Path(path).expanduser().resolve()
    return str(p)


def extract_directory_from_command(command: str) -> str | None:
    """Return the directory of the first path ``command`` touches.

    Kept for backwards compatibility; every command word counts as allowed,
    so only syntax, the hard-blocked floor and argument rules apply.

    Args:
        command: The command string

    Returns:
        The directory, or ``None`` if the command is rejected.
    """
    try:
        names = [cmd.name for cmd in lex(command).commands]
        prepared = prepare_command(command, {"read": names})
    except (LexError, CommandRejected):
        return None
    return prepared.directories[0]


def is_directory_whitelisted(directory: str, whitelisted_dirs: list[str]) -> bool:
    """Check if a directory is, or is below, a whitelisted directory.

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
            # normalize_path also expands a leading ~
            normalized_whitelist = normalize_path(whitelist_dir)

            # Exact match
            if normalized_dir == normalized_whitelist:
                return True

            # Check if it's a subdirectory of a whitelisted directory
            if normalized_dir.startswith(normalized_whitelist + os.sep):
                return True

            # Handle wildcard paths
            if "*" in whitelist_dir:
                # Build pattern from the already-normalized whitelist entry so
                # that symlinks (e.g. /tmp -> /private/tmp on macOS) are resolved
                # consistently.  Escape regex metacharacters (e.g. literal dots
                # in directory names) before restoring * as .* and use
                # fullmatch so the pattern must cover the entire path.
                escaped = re.escape(normalized_whitelist).replace(r"\*", ".*")
                if re.fullmatch(escaped, normalized_dir):
                    return True

        return False
    except Exception as error:
        # If there's any error in normalization or checking, log it and return False
        logger.error(f"Error checking if directory is whitelisted: {str(error)}")
        return False


def _check_patterns(text: str, dangerous_patterns: Sequence[str]) -> None:
    for pattern in dangerous_patterns:
        if re.search(pattern, text):
            raise CommandRejected(_pattern_error(pattern))


def _pattern_error(pattern: str) -> str:
    if pattern == r"\$\(":
        return (
            "Command contains command substitution $(). "
            "This is blocked for security reasons."
        )
    if pattern == r"\$\{\w+\}":
        return (
            "Command contains variable substitution ${var}. "
            "This is blocked for security reasons."
        )
    if pattern == r"`":
        return (
            "Command contains backtick command substitution. "
            "This is blocked for security reasons."
        )
    return f"Command contains dangerous pattern: {pattern}"


def _normalized_view(parsed: ParsedCommand) -> str:
    """Dequoted words, operators and redirects joined by single spaces."""
    parts: list[str] = []
    for i, pipeline in enumerate(parsed.pipelines):
        if i:
            parts.append(parsed.connectors[i - 1])
        for j, cmd in enumerate(pipeline):
            if j:
                parts.append("|")
            parts += [w.text for w in cmd.words]
            parts += [_redirect_text(r) for r in cmd.redirects]
    return " ".join(parts)


def _redirect_text(redirect: Redirect) -> str:
    if redirect.target is None:
        return f"{redirect.fd}>&{redirect.dup}"
    default_fd = 0 if redirect.op == "<" else 1
    fd = "" if redirect.fd == default_fd else str(redirect.fd)
    return f"{fd}{redirect.op} {redirect.target.text}"


def _base_type(cmd: Command, command_lists: Mapping[str, Sequence[str]]) -> str:
    """Check the command word against policy and return its listed type."""
    check_command_word(cmd.words[0])
    name = cmd.name
    listed = [t for t in COMMAND_TYPES if name in command_lists.get(t, ())]
    if is_hard_blocked(name):
        if listed:
            logger.warning("Ignoring '%s' in the command lists: never allowed", name)
        raise CommandRejected(f"Command '{name}' is blocked for security reasons")
    blocked = command_lists.get("blocked", ())
    if name in blocked or normalize_command_name(name) in blocked:
        raise CommandRejected(f"Command '{name}' is blocked for security reasons")
    if not listed:
        supported = [c for t in COMMAND_TYPES for c in command_lists.get(t, ())]
        raise CommandRejected(
            f"Command '{name}' is not recognized or supported. "
            f"Supported commands: {', '.join(supported)}"
        )
    return most_privileged(listed)


def _expand_tilde(word: Word) -> str:
    return os.path.expanduser(word.text) if word.tilde else word.text


def _glob(word: Word, cwd: str) -> list[str]:
    pattern = word.glob_pattern
    if word.tilde:
        # $HOME is substituted before globbing, so its characters are literal.
        pattern = glob.escape(os.path.expanduser("~")) + pattern[1:]
    found = list(
        itertools.islice(glob.iglob(pattern, root_dir=cwd), MAX_GLOB_MATCHES + 1)
    )
    if len(found) > MAX_GLOB_MATCHES:
        raise CommandRejected(
            f"'{word.text}' matches more than {MAX_GLOB_MATCHES} entries"
        )
    return ["./" + m if m.startswith("-") else m for m in sorted(found)]


def _collect_paths(
    parsed: ParsedCommand,
    expanded: ExpandedCommand,
    cwd: str,
    operand_kinds: Sequence[Kind],
    option_paths: Sequence[Sequence[PathUse]],
) -> list[PathUse]:
    # Insertion-ordered set: glob matches can make the list long.
    uses: dict[PathUse, None] = {}

    def add(raw: str, kind: Kind) -> None:
        uses[PathUse(normalize_path(os.path.join(cwd, raw)), kind)] = None

    for index, cmd in enumerate(parsed.commands):
        args = expanded.argv_per_command[index][1:]
        from_glob = expanded.from_glob[index][1:]
        for raw, kind in _argv_paths(
            cmd.name, args, from_glob, operand_kinds[index], cwd
        ):
            if kind == "write":
                # Operands may be directories (rm -r, cp into a directory).
                path = os.path.join(cwd, raw)
                _check_write_target(
                    raw, path, allow_directory=True, require_parent=False
                )
            add(raw, kind)
        for use in option_paths[index]:
            if use.kind == "write":
                # Directory-valued options such as tar -C or wget -P.
                _check_write_target(use.path, os.path.join(cwd, use.path), True)
            add(use.path, use.kind)
        for redirect, target in zip(cmd.redirects, expanded.redirect_targets[index]):
            if target is None or _is_dev_null(target, cwd):
                continue
            if redirect.op == "<":
                add(target, "read")
            else:
                _check_write_target(target, os.path.join(cwd, target), False)
                add(target, "write")

    if not uses:
        return [PathUse(normalize_path(cwd), "read")]
    return list(uses)


def _directories(paths: Sequence[PathUse], cwd: str) -> tuple[str, ...]:
    cwd_path = normalize_path(os.path.abspath(cwd))
    found: dict[str, None] = {}
    for use in paths:
        if use.path == cwd_path or os.path.isdir(use.path):
            found[use.path] = None
        else:
            found[os.path.dirname(use.path)] = None
    return tuple(found)


def _is_dev_null(target: str, cwd: str) -> bool:
    """Whether a redirect target is /dev/null; rejects any other device path."""
    path = os.path.normpath(os.path.join(cwd, target))
    if path == "/dev/null":
        return True
    if path.startswith("/dev/") or os.path.realpath(path).startswith("/dev/"):
        raise CommandRejected(f"Redirection to '{target}' is not allowed")
    return False


def _check_write_target(
    raw: str, path: str, allow_directory: bool, require_parent: bool = True
) -> None:
    """Reject write targets that are not a regular file or allowed directory.

    A directory reached through a symlink is accepted because the whitelist
    check uses its resolved path. ``os.stat`` never opens the target, so a
    FIFO cannot block here.
    """
    try:
        info: os.stat_result | None = os.stat(path)
    except FileNotFoundError:
        info = None
    if info is not None:
        if allow_directory and stat.S_ISDIR(info.st_mode):
            return
        if not stat.S_ISREG(info.st_mode):
            raise CommandRejected(f"Cannot write to '{raw}': not a regular file")
    if os.path.islink(path):
        raise CommandRejected(f"Cannot write to '{raw}': it is a symbolic link")
    if require_parent and not os.path.isdir(os.path.dirname(path)):
        raise CommandRejected(f"Cannot write to '{raw}': directory does not exist")


def _flag_mask(args: Sequence[str]) -> list[bool]:
    """Whether each argument is an option; everything after ``--`` is not."""
    mask = []
    options_ended = False
    for arg in args:
        if not options_ended and arg == "--":
            mask.append(True)
            options_ended = True
        else:
            is_flag = arg.startswith("-") and arg != "-"
            mask.append(not options_ended and is_flag)
    return mask


def _argv_paths(
    name: str,
    args: Sequence[str],
    from_glob: Sequence[bool],
    kind: Kind,
    cwd: str,
) -> list[tuple[str, Kind]]:
    """Paths named or implied by one command's arguments, unresolved.

    Args:
        name: The command word.
        args: Expanded arguments, command word excluded.
        from_glob: Per argument, whether it is a glob match.
        kind: Kind of the command's operands unless a role overrides it.
        cwd: Directory the command runs in.
    """
    key = normalize_command_name(name)
    mask = _flag_mask(args)
    exempt: set[int] = set()
    skip_options: set[int] = set()
    roles: dict[int, tuple[str, Kind]] = {}
    implied: list[tuple[str, Kind]] = []
    if key in _GREP:
        grep = _scan_grep(args, mask)
        exempt, skip_options = grep.exempt, grep.skip_options
        implied += [(path, "read") for path in grep.pattern_files]
        if grep.recursive and not grep.files:
            implied.append((cwd, "read"))
    elif key == "find":
        exempt = {i + 1 for i, a in enumerate(args) if a in _FIND_PATTERN_PRIMARIES}
    if key in PATH_COMMANDS:
        positions = _operands(key, args, mask)
        roles = {i: (args[i], kind) for i in positions}
        if key in ("cp", "mv", "ln"):
            destination_roles, implied_link = _destination_roles(
                key, args, mask, sorted(positions), cwd
            )
            roles.update(destination_roles)
            implied += implied_link
        if key in _IMPLICIT_CWD and not positions:
            implied.append((cwd, "read"))
    if _writes_into_cwd(key, args, mask):
        implied.append((cwd, "write"))

    found: list[tuple[str, Kind]] = []
    for i, arg in enumerate(args):
        if i in roles:
            found.append(roles[i])
        elif from_glob[i]:
            found.append((arg, kind))
        elif i in exempt or i in skip_options:
            continue
        elif mask[i]:
            value = _option_value(arg)
            if value is not None and _looks_like_path(value, cwd):
                found.append((value, kind))
        elif _looks_like_path(arg, cwd):
            found.append((arg, kind))
    return found + implied


def _looks_like_path(word: str, cwd: str) -> bool:
    if not word or _URL.match(word):
        return False
    if word.startswith(("/", "~", ".")) or "/" in word:
        return True
    return os.path.lexists(os.path.join(cwd, word))


def _option_value(arg: str) -> str | None:
    """Value of ``--opt=VALUE`` or of an attached short option ``-xVALUE``."""
    if arg.startswith("--"):
        _, sep, value = arg.partition("=")
        return value if sep else None
    return arg[2:] if len(arg) > 2 else None


def _long_option(arg: str, names: Sequence[str]) -> str | None:
    """Resolve ``--opt`` or ``--opt=value`` against ``names`` by unique prefix."""
    opt = arg.partition("=")[0]
    if opt in names:
        return opt
    matches = [n for n in names if n.startswith(opt)] if len(opt) > 3 else []
    return matches[0] if len(matches) == 1 else None


def _short_letters(arg: str, flags: str, values: str = "") -> set[str]:
    """Letters from ``flags`` set by a short-option bundle.

    Letters after the first one in ``values`` are its attached value.
    """
    found = set()
    for ch in arg[1:] if _is_short_bundle(arg) else "":
        if ch in flags:
            found.add(ch)
        if ch in values:
            break
    return found


def _is_short_bundle(arg: str) -> bool:
    return arg.startswith("-") and not arg.startswith("--") and len(arg) > 1


def _operands(key: str, args: Sequence[str], mask: Sequence[bool]) -> set[int]:
    """Positions of a PATH_COMMANDS command's file and directory operands."""
    if key == "find":
        return _find_start_points(args)
    skip_value = _NON_PATH_VALUES.get(key, frozenset())
    positions: list[int] = []
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
        elif mask[i]:
            skip_next = arg in skip_value
        else:
            positions.append(i)
    # chmod's mode, chown's owner and tar's dashless first bundle are not paths.
    if key in ("chmod", "chown") or (key == "tar" and positions[:1] == [0]):
        positions = positions[1:]
    return set(positions)


def _destination_roles(
    key: str, args: Sequence[str], mask: Sequence[bool], operands: list[int], cwd: str
) -> tuple[dict[int, tuple[str, Kind]], list[tuple[str, Kind]]]:
    """Roles of cp, mv and ln operands: sources, then a destination.

    A relative ``ln -s`` target is resolved from the link's directory,
    which is where the kernel resolves it.

    Returns:
        Path and kind per operand position, and implied paths.
    """
    target_dir: str | None = None
    for i, arg in enumerate(args):
        if not mask[i]:
            continue
        if arg == "-t" or _long_option(arg, ("--target-directory",)):
            _, sep, value = arg.partition("=")
            if sep:
                target_dir = value
            elif i + 1 < len(args) and i + 1 in operands:
                target_dir = args[i + 1]
                operands = [p for p in operands if p != i + 1]
    roles: dict[int, tuple[str, Kind]] = {}
    implied: list[tuple[str, Kind]] = []
    sources = list(operands)
    if target_dir is not None:
        link_dir = target_dir
        implied.append((target_dir, "write"))
    elif len(sources) >= 2:
        destination = sources.pop()
        dest = args[destination]
        roles[destination] = (dest, "write")
        into = len(sources) > 1 or os.path.isdir(os.path.join(cwd, dest))
        link_dir = dest if into else os.path.dirname(dest)
    else:
        # One operand: the copy or link is created in the working directory.
        link_dir = ""
        implied.append((cwd, "write"))
    symbolic = key == "ln" and _ln_is_symbolic(args, mask)
    source_kind: Kind = "write" if key == "mv" else "read"
    for i in sources:
        raw = os.path.join(link_dir, args[i]) if symbolic else args[i]
        roles[i] = (raw, source_kind)
    return roles, implied


def _ln_is_symbolic(args: Sequence[str], mask: Sequence[bool]) -> bool:
    return any(
        flag
        and (
            _long_option(arg, ("--symbolic",)) is not None
            or "s" in _short_letters(arg, "s", "St")
        )
        for arg, flag in zip(args, mask)
    )


def _writes_into_cwd(key: str, args: Sequence[str], mask: Sequence[bool]) -> bool:
    """Whether the command creates files in the working directory by default."""
    flags = [a for a, m in zip(args, mask) if m]
    short = set().union(*(_short_letters(a, "dxCOPv") for a in flags))
    if key == "unzip":
        return "d" not in short
    if key == "tar":
        bundle = set(args[0]) if args and not mask[0] else set()
        extract = "x" in short | bundle or any(
            _long_option(a, ("--extract", "--get")) for a in flags
        )
        directory = "C" in short | bundle or any(
            _long_option(a, ("--directory",)) for a in flags
        )
        return extract and not directory
    if key == "wget":
        named = ("--output-document", "--directory-prefix")
        return not (short & {"O", "P"}) and not any(
            _long_option(a, named) for a in flags
        )
    if key == "curl":
        remote = "O" in short or any(
            a.partition("=")[0] in ("--remote-name", "--remote-name-all") for a in flags
        )
        return remote and not any(a.partition("=")[0] == "--output-dir" for a in flags)
    return False


def _find_start_points(args: Sequence[str]) -> set[int]:
    positions: set[int] = set()
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-f" and i + 1 < len(args):
            # BSD find: -f names a starting point that may begin with '-'.
            positions.add(i + 1)
            i += 2
            continue
        if arg in _FIND_LEADING_OPTIONS:
            i += 1
            continue
        if arg.startswith("-") or arg in _FIND_EXPRESSION_START:
            break
        positions.add(i)
        i += 1
    return positions


@dataclass
class _GrepArguments:
    """How grep reads its arguments.

    Attributes:
        exempt: Positions of patterns and option values, never paths.
        skip_options: Option positions whose value is handled here.
        files: Positions of file operands.
        pattern_files: Files named by ``-f``/``--file``.
        recursive: ``-r``, ``-R``, ``-d recurse`` or a long form.
    """

    exempt: set[int] = field(default_factory=set)
    skip_options: set[int] = field(default_factory=set)
    files: list[int] = field(default_factory=list)
    pattern_files: list[str] = field(default_factory=list)
    recursive: bool = False


def _scan_grep(args: Sequence[str], mask: Sequence[bool]) -> _GrepArguments:
    """Parse grep options the way getopt does, for its pattern and files."""
    result = _GrepArguments()
    operands: list[int] = []
    explicit = False
    i = 0
    while i < len(args):
        arg = args[i]
        letter: str | None = None
        value: str | None = None
        if not mask[i]:
            operands.append(i)
        elif arg.startswith("--") and len(arg) > 2:
            if _long_option(arg, _GREP_LONG_RECURSIVE):
                result.recursive = True
            name = _long_option(arg, tuple(_GREP_LONG))
            if name is not None:
                letter = _GREP_LONG[name]
                _, sep, attached = arg.partition("=")
                value = attached if sep else None
                result.skip_options.add(i)
        elif arg != "--":
            result.skip_options.add(i)
            for k, ch in enumerate(arg[1:], start=2):
                result.recursive = result.recursive or ch in "rR"
                if ch in _GREP_SHORT_VALUES:
                    letter, value = ch, arg[k:] or None
                    break
        if letter is not None and value is None and i + 1 < len(args):
            i += 1
            value = args[i]
            result.exempt.add(i)
        if letter in ("e", "f"):
            explicit = True
        if letter == "f" and value:
            result.pattern_files.append(value)
        if letter == "d" and value == "recurse":
            result.recursive = True
        i += 1
    if not explicit and operands:
        result.exempt.add(operands.pop(0))
    result.files = operands
    return result
