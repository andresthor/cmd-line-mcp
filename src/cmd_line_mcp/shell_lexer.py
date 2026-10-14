"""Strict-subset shell lexer and canonical renderer.

``lex`` turns a command string into pipelines of simple commands, accepting
only a small grammar that every POSIX shell reads the same way; anything else
raises :class:`LexError`. ``render`` turns validated, already-expanded argv
back into a string for ``/bin/sh -c`` in which every word is quoted and every
operator is our own, so the shell performs no expansion of its own.

Pure: no I/O, no configuration.
"""

import shlex
import string
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from glob import escape as _glob_escape

MAX_LENGTH = 4096

_WORD_CHARS = frozenset(string.ascii_letters + string.digits + "_@%+=:,./-")
_GLOB_CHARS = frozenset("*?[]")
_BLANKS = (" ", "\t")
_OPERATOR_CHARS = ("|", ";", "&", "<", ">")
# Allowed fd duplications as (fd, target fd): 2>&1, >&2 and 1>&2.
_DUPS = ((2, "1"), (1, "2"))
# POSIX/bash reserved words plus zsh precommand and loop words; a command
# word must never be one of these.
_KEYWORDS = frozenset(
    "! { } [[ ]] case coproc do done elif else end esac fi for foreach "
    "function if in noglob nocorrect repeat select then time until "
    "while".split()
)
# POSIX bracket classes, equivalence classes and collating symbols, which
# Python's glob does not implement.
_BRACKET_CLASSES = ("[:", "[=", "[.")

Piece = tuple[str, bool]


class LexError(ValueError):
    """Input falls outside the supported shell subset.

    The message is shown to the user.
    """


@dataclass(frozen=True)
class Word:
    """A shell word after quote removal, before tilde and glob expansion.

    Attributes:
        text: Quote-removed value.
        glob: An unquoted ``*``, ``?``, ``[`` or ``]`` is present.
        tilde: Starts with an unquoted ``~`` (only ``~`` and ``~/...``).
        quoted: Any part of the word was quoted.
        pieces: ``(text, quoted)`` runs, adjacent runs with the same flag
            merged. Defaults to a single run of ``text``.
    """

    text: str
    glob: bool = False
    tilde: bool = False
    quoted: bool = False
    pieces: tuple[Piece, ...] = ()

    def __post_init__(self) -> None:
        if not self.pieces:
            object.__setattr__(self, "pieces", ((self.text, self.quoted),))

    @property
    def glob_pattern(self) -> str:
        """Pattern for ``glob.glob`` with quoted characters matched literally.

        ``lex`` rejects bracket expressions mixed with quoting, so escaping
        quoted pieces is enough for Python and sh to agree.
        """
        return "".join(_glob_escape(t) if q else t for t, q in self.pieces)


@dataclass(frozen=True)
class Redirect:
    """One redirection.

    ``op`` is ``>``, ``>>``, ``<`` or ``>&``. File redirects carry a
    ``target``; ``>&`` carries the ``dup`` fd instead.
    """

    op: str
    fd: int
    target: Word | None = None
    dup: int | None = None


@dataclass(frozen=True)
class Command:
    """A simple command: its words and its redirections, in source order."""

    words: tuple[Word, ...]
    redirects: tuple[Redirect, ...] = ()

    @property
    def name(self) -> str:
        """The command word."""
        return self.words[0].text

    @property
    def args(self) -> tuple[str, ...]:
        """Quote-removed argument texts, excluding the command word."""
        return tuple(w.text for w in self.words[1:])


@dataclass(frozen=True)
class ParsedCommand:
    """Pipelines joined by connectors (``;``, ``&&``, ``||``).

    ``len(connectors) == len(pipelines) - 1``.
    """

    pipelines: tuple[tuple[Command, ...], ...]
    connectors: tuple[str, ...] = ()

    @property
    def commands(self) -> tuple[Command, ...]:
        """Every simple command, left to right."""
        return tuple(c for p in self.pipelines for c in p)


def lex(raw: str) -> ParsedCommand:
    """Parse ``raw`` into a :class:`ParsedCommand`.

    Raises:
        LexError: ``raw`` uses syntax outside the supported subset.
    """
    _precheck(raw)
    return _Lexer(raw).run()


def render(
    parsed: ParsedCommand,
    argv_per_command: Sequence[Sequence[str]],
    redirect_targets: Sequence[Sequence[str | None]],
) -> str:
    """Render final argv into a canonical string for ``/bin/sh -c``.

    Args:
        parsed: Supplies the pipeline structure, connectors and redirects.
        argv_per_command: Expanded argv for each of ``parsed.commands``.
        redirect_targets: Expanded target for each redirect of each command,
            ``None`` for ``>&`` dups.

    Raises:
        ValueError: The argv or targets do not match ``parsed``.
    """
    commands = parsed.commands
    if len(argv_per_command) != len(commands):
        raise ValueError("argv_per_command does not match the commands")
    if len(redirect_targets) != len(commands):
        raise ValueError("redirect_targets does not match the commands")

    rendered = []
    per_command = zip(commands, argv_per_command, redirect_targets)
    for cmd, argv, targets in per_command:
        if not argv:
            raise ValueError("every command needs at least one word")
        if len(targets) != len(cmd.redirects):
            raise ValueError("redirect_targets does not match the redirects")
        parts = [_quote(argv[0], command_word=True)]
        parts += [_quote(a) for a in argv[1:]]
        for redirect, target in zip(cmd.redirects, targets):
            if (target is None) != (redirect.target is None):
                raise ValueError("targets are for file redirects only")
            quoted = None if target is None else _quote(target)
            parts.append(_render_redirect(redirect, quoted))
        rendered.append(" ".join(parts))
    return _join(parsed, rendered)


def render_parsed(parsed: ParsedCommand) -> str:
    """Render ``parsed`` with its unexpanded words and original quoting.

    ``lex(render_parsed(p)) == p``. For display and tests only; execute
    :func:`render` output instead.
    """
    rendered = []
    for cmd in parsed.commands:
        parts = [_render_pieces(w) for w in cmd.words]
        for r in cmd.redirects:
            target = None if r.target is None else _render_pieces(r.target)
            parts.append(_render_redirect(r, target))
        rendered.append(" ".join(parts))
    return _join(parsed, rendered)


def _precheck(raw: str) -> None:
    if len(raw) > MAX_LENGTH:
        raise LexError(f"command is longer than {MAX_LENGTH} characters")
    for ch in raw:
        if ch not in _BLANKS and not ch.isprintable():
            raise LexError(f"unsupported character {ch!r}")


def _is_word_char(ch: str) -> bool:
    if ch in _WORD_CHARS or ch in _GLOB_CHARS:
        return True
    # Marks as well as letters, so decomposed (NFD) filenames lex.
    return not ch.isascii() and unicodedata.category(ch)[0] in ("L", "M")


def _has_glob(text: str) -> bool:
    return not _GLOB_CHARS.isdisjoint(text)


def _ends_token(ch: str) -> bool:
    return ch == "" or ch in _BLANKS or ch in _OPERATOR_CHARS


class _Lexer:
    """Single-pass scanner; state is the word and command being built."""

    def __init__(self, src: str) -> None:
        self.src = src
        self.pos = 0
        self.pieces: list[Piece] = []
        self.pending: tuple[str, int] | None = None
        self.words: list[Word] = []
        self.redirects: list[Redirect] = []
        self.pipeline: list[Command] = []
        self.pipelines: list[tuple[Command, ...]] = []
        self.connectors: list[str] = []

    def peek(self, offset: int = 0) -> str:
        i = self.pos + offset
        return self.src[i] if i < len(self.src) else ""

    def run(self) -> ParsedCommand:
        while self.pos < len(self.src):
            ch = self.src[self.pos]
            if ch in _BLANKS:
                self.flush_word()
                self.pos += 1
            elif ch == "'":
                self.single_quote()
            elif ch == '"':
                self.double_quote()
            elif ch in _OPERATOR_CHARS:
                self.operator(ch)
            elif ch == "~":
                self.tilde()
            elif ch == "=" and not self.pieces:
                # zsh expands a leading unquoted "=cmd" to a path.
                raise LexError("a word may not start with '='")
            elif _is_word_char(ch):
                self.add_piece(ch, False)
                self.pos += 1
            else:
                raise LexError(f"unsupported character {ch!r}")
        self.end_pipeline()
        return ParsedCommand(tuple(self.pipelines), tuple(self.connectors))

    def add_piece(self, text: str, quoted: bool) -> None:
        if self.pieces and self.pieces[-1][1] == quoted:
            self.pieces[-1] = (self.pieces[-1][0] + text, quoted)
        else:
            self.pieces.append((text, quoted))

    def single_quote(self) -> None:
        start = self.pos + 1
        end = self.src.find("'", start)
        if end < 0:
            raise LexError("unterminated single quote")
        self.add_piece(self.src[start:end], True)
        self.pos = end + 1

    def double_quote(self) -> None:
        start = self.pos + 1
        end = start
        while True:
            if end >= len(self.src):
                raise LexError("unterminated double quote")
            ch = self.src[end]
            if ch == '"':
                break
            after = self.src[end + 1] if end + 1 < len(self.src) else ""
            if ch == "`":
                raise LexError("backtick is not supported")
            if ch == "$" and after != '"':
                raise LexError("'$' is only allowed before a closing '\"'")
            if ch == "\\" and after in ("$", "`", '"', "\\"):
                raise LexError(f"'\\{after}' is not supported in quotes")
            end += 1
        self.add_piece(self.src[start:end], True)
        self.pos = end + 1

    def tilde(self) -> None:
        if self.pieces:
            raise LexError("'~' is only supported at the start of a word")
        after = self.peek(1)
        if after != "/" and not _ends_token(after):
            raise LexError("only '~' and '~/...' are supported")
        self.add_piece("~", False)
        self.pos += 1

    def flush_word(self) -> None:
        if not self.pieces:
            return
        pieces = tuple(self.pieces)
        self.pieces.clear()
        word = Word(
            text="".join(t for t, _ in pieces),
            glob=any(not q and _has_glob(t) for t, q in pieces),
            tilde=not pieces[0][1] and pieces[0][0].startswith("~"),
            quoted=any(q for _, q in pieces),
            pieces=pieces,
        )
        if any(not q and "[" in t for t, q in pieces):
            if word.quoted:
                raise LexError("'[' patterns may not be combined with quotes")
            if any(c in word.text for c in _BRACKET_CLASSES):
                raise LexError("'[:', '[=' and '[.' are not supported")
        if self.pending is None:
            self.words.append(word)
            return
        op, fd = self.pending
        self.pending = None
        if word.glob:
            raise LexError("redirect target may not contain glob characters")
        if not word.text:
            raise LexError("redirect target is empty")
        self.redirects.append(Redirect(op, fd, word))

    def take_io_number(self) -> int | None:
        # Digits directly before < or > are an fd to sh, never a word.
        if len(self.pieces) != 1:
            return None
        text, quoted = self.pieces[0]
        if quoted or not (text.isascii() and text.isdigit()):
            return None
        self.pieces.clear()
        if text not in ("0", "1", "2"):
            raise LexError(f"file descriptor {text} is not supported")
        return int(text)

    def operator(self, ch: str) -> None:
        io = self.take_io_number() if ch in ("<", ">") else None
        self.flush_word()
        if self.pending is not None:
            raise LexError("redirect without a target")
        after = self.peek(1)
        if ch == "|":
            if after == "&":
                raise LexError("'|&' is not supported")
            if after == "|":
                self.end_pipeline("||")
                self.pos += 2
            else:
                self.end_command()
                self.pos += 1
        elif ch == ";":
            if after in (";", "&"):
                raise LexError(f"';{after}' is not supported")
            self.end_pipeline(";")
            self.pos += 1
        elif ch == "&":
            if after != "&":
                raise LexError("background '&' and '&>' are not supported")
            self.end_pipeline("&&")
            self.pos += 2
        elif ch == "<":
            if after in ("<", ">", "&"):
                raise LexError(f"'<{after}' is not supported")
            self.pending = ("<", 0 if io is None else io)
            self.pos += 1
        else:
            self.redirect_out(1 if io is None else io, after)

    def redirect_out(self, fd: int, after: str) -> None:
        if after == "&":
            dup = self.peek(2)
            if (fd, dup) not in _DUPS or not _ends_token(self.peek(3)):
                raise LexError("only 2>&1, >&2 and 1>&2 are supported")
            self.redirects.append(Redirect(">&", fd, None, int(dup)))
            self.pos += 3
        elif after == "|":
            raise LexError("'>|' is not supported")
        elif after == ">":
            self.pending = (">>", fd)
            self.pos += 2
        else:
            self.pending = (">", fd)
            self.pos += 1

    def end_command(self) -> None:
        self.flush_word()
        if self.pending is not None:
            raise LexError("redirect without a target")
        if not self.words:
            if self.redirects:
                raise LexError("redirect without a command")
            raise LexError("empty command")
        _check_command_word(self.words[0].text)
        self.pipeline.append(Command(tuple(self.words), tuple(self.redirects)))
        self.words, self.redirects = [], []

    def end_pipeline(self, connector: str | None = None) -> None:
        self.end_command()
        self.pipelines.append(tuple(self.pipeline))
        self.pipeline = []
        if connector is not None:
            self.connectors.append(connector)


def _check_command_word(name: str) -> None:
    # sh -c reads a leading -/+ as options; "A=1" is an assignment prefix.
    if name.startswith(("-", "+")):
        raise LexError(f"command may not start with '{name[0]}'")
    if "=" in name:
        raise LexError("variable assignments are not supported")
    if name in _KEYWORDS:
        raise LexError(f"shell keyword '{name}' is not supported")


def _force_quote(text: str) -> str:
    return "'" + text.replace("'", "'\"'\"'") + "'"


def _quote(text: str, command_word: bool = False) -> str:
    quoted = shlex.quote(text)
    if quoted != text:
        return quoted
    # Second layer behind _check_command_word: shlex leaves these bare, and
    # "=x" is a zsh path expansion in any position.
    if text.startswith("=") or (
        command_word
        and ("=" in text or text in _KEYWORDS or text.startswith(("-", "+")))
    ):
        return _force_quote(text)
    return text


def _render_pieces(word: Word) -> str:
    return "".join(_force_quote(t) if q else t for t, q in word.pieces)


def _render_redirect(redirect: Redirect, target: str | None) -> str:
    if redirect.op == ">&":
        return f"{redirect.fd}>&{redirect.dup}"
    default_fd = 0 if redirect.op == "<" else 1
    fd = "" if redirect.fd == default_fd else str(redirect.fd)
    return f"{fd}{redirect.op} {target}"


def _join(parsed: ParsedCommand, rendered: list[str]) -> str:
    out: list[str] = []
    it = iter(rendered)
    for i, pipeline in enumerate(parsed.pipelines):
        if i:
            out.append(parsed.connectors[i - 1])
        out.append(" | ".join(next(it) for _ in pipeline))
    return " ".join(out)
