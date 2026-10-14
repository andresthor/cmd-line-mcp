"""Tests for the strict-subset shell lexer and canonical renderer."""

import os
import random
import subprocess

import pytest

from cmd_line_mcp.shell_lexer import (
    MAX_LENGTH,
    Command,
    LexError,
    ParsedCommand,
    Redirect,
    Word,
    lex,
    render,
    render_parsed,
)

SH = "/bin/sh"
FORBIDDEN_UNQUOTED = set("$`\\(){}#\n")


def argv(parsed):
    """Quote-removed words of every command."""
    return [[w.text for w in c.words] for c in parsed.commands]


def redirects(parsed):
    """(op, fd, target text, dup) for every redirect of every command."""
    return [[_redirect_tuple(r) for r in c.redirects] for c in parsed.commands]


def _redirect_tuple(r):
    return (r.op, r.fd, r.target.text if r.target else None, r.dup)


def shape(parsed):
    """Number of commands in each pipeline."""
    return [len(p) for p in parsed.pipelines]


def render_texts(parsed):
    """Render with each word's literal text standing in for expansion."""
    targets = [
        [r.target.text if r.target else None for r in c.redirects]
        for c in parsed.commands
    ]
    return render(parsed, argv(parsed), targets)


def unquoted_regions(rendered):
    """Characters of ``rendered`` outside quotes, read independently of the
    lexer; the renderer only ever emits '...' and "'" quoting."""
    out = []
    i = 0
    while i < len(rendered):
        ch = rendered[i]
        if ch == "'":
            i = rendered.index("'", i + 1) + 1
        elif ch == '"':
            assert rendered.startswith('"\'"', i), rendered
            i += 3
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def sh_parses(script):
    """True if /bin/sh accepts ``script`` in parse-only mode."""
    env = {k: v for k, v in os.environ.items() if k not in ("ENV", "BASH_ENV")}
    proc = subprocess.run(
        [SH, "-n", "-c", "--", script],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=env,
        timeout=10,
    )
    return proc.returncode == 0


# --- Accept corpus: (input, expected argv per command) -------------------

ACCEPT = [
    # Blanks and charset
    ("ls -la", [["ls", "-la"]]),
    ("ls\tfoo", [["ls", "foo"]]),
    ("  ls   foo  ", [["ls", "foo"]]),
    ("ls a_b@c%d+e=f:g,h.i/j-k", [["ls", "a_b@c%d+e=f:g,h.i/j-k"]]),
    ("ls café", [["ls", "café"]]),
    ("ls cafe\u0301", [["ls", "cafe\u0301"]]),
    ("ls Δοκιμή 日本", [["ls", "Δοκιμή", "日本"]]),
    ("ls '€' \"—\"", [["ls", "€", "—"]]),
    ("ls " + "a" * (MAX_LENGTH - 3), [["ls", "a" * (MAX_LENGTH - 3)]]),
    # Globs
    ("ls *.txt", [["ls", "*.txt"]]),
    ("ls a?[bc]", [["ls", "a?[bc]"]]),
    ("ls 'my dir'/*.pdf", [["ls", "my dir/*.pdf"]]),
    ("ls '*'x*", [["ls", "*x*"]]),
    # Tilde
    ("ls ~", [["ls", "~"]]),
    ("ls ~/x", [["ls", "~/x"]]),
    ("ls ~/'a b'", [["ls", "~/a b"]]),
    ("ls ~|wc", [["ls", "~"], ["wc"]]),
    ("ls ~;pwd", [["ls", "~"], ["pwd"]]),
    ("ls '~'", [["ls", "~"]]),
    ("ls a=b", [["ls", "a=b"]]),
    ("ls ''=x", [["ls", "=x"]]),
    # Single quotes
    ("echo 'a b'", [["echo", "a b"]]),
    (
        "echo '$HOME' '`id`' '\\' '#!(){}|;&<>^'",
        [["echo", "$HOME", "`id`", "\\", "#!(){}|;&<>^"]],
    ),
    ("echo ''", [["echo", ""]]),
    ("echo a''b", [["echo", "ab"]]),
    ("echo 'it'\"'\"'s'", [["echo", "it's"]]),
    ("echo \"a\"'b'c", [["echo", "abc"]]),
    ("'ls' -l", [["ls", "-l"]]),
    ('"l"s', [["ls"]]),
    # Double quotes
    ('grep "a|b" f', [["grep", "a|b", "f"]]),
    ('grep "a\\|b" f', [["grep", "a\\|b", "f"]]),
    ('grep "x$" f', [["grep", "x$", "f"]]),
    ('echo "$"', [["echo", "$"]]),
    ('echo "a\\nb"', [["echo", "a\\nb"]]),
    ('echo "it\'s" "#!(){}"', [["echo", "it's", "#!(){}"]]),
    ("grep '^x$' f", [["grep", "^x$", "f"]]),
    # Operators
    ("ls | grep x", [["ls"], ["grep", "x"]]),
    ("ls|grep x", [["ls"], ["grep", "x"]]),
    ("ls;pwd", [["ls"], ["pwd"]]),
    ("ls ; pwd", [["ls"], ["pwd"]]),
    ("ls&&pwd", [["ls"], ["pwd"]]),
    ("ls || pwd", [["ls"], ["pwd"]]),
    (
        "ls | sort | uniq && pwd ; id || pwd",
        [["ls"], ["sort"], ["uniq"], ["pwd"], ["id"], ["pwd"]],
    ),
    # Redirects
    ("cat < in", [["cat"]]),
    ("cat <in", [["cat"]]),
    ("cat 0<in", [["cat"]]),
    ("ls > out", [["ls"]]),
    ("ls >out", [["ls"]]),
    ("ls >> out", [["ls"]]),
    ("ls 1>out 2>err", [["ls"]]),
    ("ls 2> err", [["ls"]]),
    ("ls >> out | wc", [["ls"], ["wc"]]),
    ("> out ls -l", [["ls", "-l"]]),
    ("ls '2'> out", [["ls", "2"]]),
    ("ls 2 > out", [["ls", "2"]]),
    ("ls a2>out", [["ls", "a2"]]),
    # Arguments may use what command words may not
    ("ls -- -x +y a=b", [["ls", "--", "-x", "+y", "a=b"]]),
    ("ls if time noglob", [["ls", "if", "time", "noglob"]]),
    ("ls [abc]* '['a]", [["ls", "[abc]*", "[a]"]]),
    ("ls > '*.txt'", [["ls"]]),
    ("ls > ~/out", [["ls"]]),
    ("ls>out", [["ls"]]),
    # Dups
    ("ls 2>&1", [["ls"]]),
    ("ls >&2", [["ls"]]),
    ("ls 1>&2", [["ls"]]),
    ("ls 2>&1 | wc", [["ls"], ["wc"]]),
    ("ls > out 2>&1", [["ls"]]),
    ("ls 2>&1>out", [["ls"]]),
    ("ls 2>&1;pwd", [["ls"], ["pwd"]]),
    ("ls 2>&1|wc", [["ls"], ["wc"]]),
    ("ls >&2&&pwd", [["ls"], ["pwd"]]),
    ("ls 1>&2||pwd", [["ls"], ["pwd"]]),
    (
        "touch /tmp/cmdmcp-marker && id",
        [["touch", "/tmp/cmdmcp-marker"], ["id"]],
    ),
]
ACCEPT_INPUTS = [s for s, _ in ACCEPT]


@pytest.mark.parametrize("raw,expected", ACCEPT)
def test_accept(raw, expected):
    assert argv(lex(raw)) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("cat < in", [[("<", 0, "in", None)]]),
        ("cat 0<in", [[("<", 0, "in", None)]]),
        ("ls >> out | wc", [[(">>", 1, "out", None)], []]),
        ("ls 1>out 2>err", [[(">", 1, "out", None), (">", 2, "err", None)]]),
        ("> out ls -l", [[(">", 1, "out", None)]]),
        ("ls '2'> out", [[(">", 1, "out", None)]]),
        ("ls 0>out", [[(">", 0, "out", None)]]),
        ("ls 2<in", [[("<", 2, "in", None)]]),
        ("ls 2>&1", [[(">&", 2, None, 1)]]),
        ("ls >&2", [[(">&", 1, None, 2)]]),
        ("ls 1>&2", [[(">&", 1, None, 2)]]),
        ("ls 2>&1>out", [[(">&", 2, None, 1), (">", 1, "out", None)]]),
    ],
)
def test_redirect_structure(raw, expected):
    assert redirects(lex(raw)) == expected


@pytest.mark.parametrize(
    "raw,connectors,shape_",
    [
        ("ls 2>&1;pwd", (";",), [1, 1]),
        ("ls 2>&1|wc", (), [2]),
        ("ls >&2&&pwd", ("&&",), [1, 1]),
        ("ls 1>&2||pwd", ("||",), [1, 1]),
    ],
)
def test_dup_directly_followed_by_operator(raw, connectors, shape_):
    parsed = lex(raw)
    assert parsed.connectors == connectors
    assert shape(parsed) == shape_


def test_structure_and_connectors():
    parsed = lex("ls | sort && pwd ; id || pwd")
    assert [len(p) for p in parsed.pipelines] == [2, 1, 1, 1]
    assert parsed.connectors == ("&&", ";", "||")
    assert parsed.commands[0] == Command((Word("ls"),))
    assert parsed.commands[1].name == "sort"


def test_word_flags():
    words = lex("ls *.txt '*.txt' ~/x '~' 'a'b ~").commands[0].words
    assert [(w.glob, w.tilde, w.quoted) for w in words[1:]] == [
        (True, False, False),
        (False, False, True),
        (False, True, False),
        (False, False, True),
        (False, False, True),
        (False, True, False),
    ]


def test_word_pieces_and_glob_pattern():
    word = lex("ls '[a]*'x*").commands[0].words[1]
    assert word.text == "[a]*x*"
    assert word.glob and word.quoted
    assert word.pieces == (("[a]*", True), ("x*", False))
    assert word.glob_pattern == "[[]a][*]x*"
    assert lex("ls '['a]").commands[0].words[1].glob_pattern == "[[]a]"


def test_word_default_pieces_match_lexed():
    assert Word("ls") == lex("ls").commands[0].words[0]
    assert Word("a b", quoted=True) == lex("echo 'a b'").commands[0].words[1]


def test_command_name_and_args():
    cmd = lex("grep -n 'a b' f").commands[0]
    assert cmd.name == "grep"
    assert cmd.args == ("-n", "a b", "f")


# --- Reject corpus --------------------------------------------------------

REJECT = [
    # Length, control and Unicode format/space characters
    "ls " + "a" * (MAX_LENGTH - 2),
    "",
    "   ",
    "\t",
    "ls\nid",
    "ls\rid",
    "ls\r\nid",
    "ls 'a\nb'",
    'ls "a\rb"',
    "ls\x00",
    "ls \x1b[0m",
    "ls\x7f",
    "ls\x85",
    "ls\xa0x",
    "ls\u200bx",
    "ls\u2028x",
    "\ufeffls",
    "ls '\u200b'",
    "ls \ud800",
    "ls \ue000",
    # Unquoted characters outside the subset
    "ls €",
    "ls a—b",
    "ls a\\ b",
    "ls \\; id",
    "ls #x",
    "ls a#b",
    "ls !x",
    "! ls",
    "ls ^x",
    "ls (x)",
    "(ls)",
    "{ ls; }",
    "ls {a,b}",
    "ls <(id)",
    "ls >(id)",
    # Dollar and backtick
    "echo $HOME",
    "echo ${HOME}",
    "ls $(id)",
    "echo $",
    "echo `id`",
    'echo "$HOME"',
    'echo "a$b"',
    'echo "$(id)"',
    'echo "`id`"',
    # Escapes in double quotes
    'echo "a\\$"',
    'echo "a\\`"',
    'echo "a\\""',
    'echo "a\\\\"',
    # Unterminated quotes
    "echo 'abc",
    'echo "abc',
    # Tilde forms
    "ls foo~",
    "ls a/~",
    "ls ''~",
    "ls ~root",
    "ls ~root/x",
    "ls ~+",
    "ls ~-",
    "ls ~'x'",
    "ls --dir=~/x",
    "ls a:~/x",
    # Leading '='
    "=ls",
    "ls =x",
    "ls > =x",
    # Operators
    "ls &",
    "ls & pwd",
    "ls |& wc",
    "ls &> f",
    "ls >| f",
    "ls <> f",
    "cat << EOF",
    "cat <<< x",
    "cat <&0",
    "ls ;; pwd",
    "ls ;& pwd",
    "ls ; ; pwd",
    "ls | | wc",
    "ls ||| pwd",
    "ls &&& pwd",
    "ls || | pwd",
    "; ls",
    "ls ;",
    "| ls",
    "ls |",
    "&& ls",
    "ls &&",
    "ls ||",
    # Redirects
    "ls >",
    "ls > | wc",
    "ls < ; pwd",
    "ls > > f",
    "ls >> > f",
    "ls >>| f",
    "ls >>& f",
    "> f",
    "> f | wc",
    "ls | > f",
    "ls > *.txt",
    "ls > a?",
    "ls > ''",
    "ls 3>f",
    "ls 12>f",
    "ls 9<f",
    "ls >&1",
    "ls 1>&1",
    "ls 2>&2",
    "ls 0>&1",
    "ls 2>&3",
    "ls 2>&-",
    "ls 2>&1x",
    "ls >&f",
    "ls >& f",
    "2>&1",
    # Command words
    "+x",
    "+2 b",
    "< f +9",
    "- id",
    "--",
    "ls | -v",
    "noglob id",
    "nocorrect id",
    "repeat 3 id",
    "foreach x",
    "end",
    "coproc id",
    "if true; then id; fi",
    "'if' true",
    "time id",
    "A=1 id",
    "'A=1' id",
    "[[ a ]]",
    # Bracket expressions mixed with quoting, or POSIX classes
    "ls ['!'a]",
    "ls [a'-'c]",
    "ls ['a]']",
    "ls [[:alpha:]]",
    "ls [[=a=]]",
    "ls [[.a.]]",
]


@pytest.mark.parametrize("raw", REJECT)
def test_reject(raw):
    with pytest.raises(LexError):
        lex(raw)


def test_length_boundary():
    assert lex("ls " + "a" * (MAX_LENGTH - 3))
    with pytest.raises(LexError, match="longer than"):
        lex("ls " + "a" * (MAX_LENGTH - 2))


# --- Rendering ------------------------------------------------------------


@pytest.mark.parametrize("raw", ACCEPT_INPUTS)
def test_render_parsed_round_trip(raw):
    parsed = lex(raw)
    assert lex(render_parsed(parsed)) == parsed


@pytest.mark.parametrize("raw", ACCEPT_INPUTS)
def test_render_round_trips_argv(raw):
    parsed = lex(raw)
    rendered = render_texts(parsed)
    again = lex(rendered)
    assert argv(again) == argv(parsed)
    assert redirects(again) == redirects(parsed)
    assert again.connectors == parsed.connectors
    assert shape(again) == shape(parsed)


@pytest.mark.parametrize("raw", ACCEPT_INPUTS)
def test_render_unquoted_regions_are_safe(raw):
    parsed = lex(raw)
    for rendered in (render_parsed(parsed), render_texts(parsed)):
        assert not FORBIDDEN_UNQUOTED & set(unquoted_regions(rendered))


def test_render_quotes_expanded_words():
    parsed = lex("> f ls *.txt ~/x 2>&1 | grep 'a b'")
    rendered = render(
        parsed,
        [["ls", "./-rf", "/home/u/x"], ["grep", "a b"]],
        [["/home/u/f", None], []],
    )
    assert rendered == "ls ./-rf /home/u/x > /home/u/f 2>&1 | grep 'a b'"


def test_render_emits_default_fds_implicitly():
    parsed = lex("cat < in > out 2> err >&2")
    assert render_texts(parsed) == "cat < in > out 2> err 1>&2"


@pytest.mark.parametrize(
    "words,expected",
    [
        (["FOO=1", "x"], "'FOO=1' x"),
        (["if", "x"], "'if' x"),
        (["time", "x"], "'time' x"),
        (["-c", "id"], "'-c' id"),
        (["+x", "id"], "'+x' id"),
        (["noglob", "id"], "'noglob' id"),
        (["ls", "=x", "a=b"], "ls '=x' a=b"),
        (["ls", "", "*", "~", "$HOME"], "ls '' '*' '~' '$HOME'"),
    ],
)
def test_render_forces_quotes_where_sh_would_reinterpret(words, expected):
    parsed = ParsedCommand(((Command(tuple(Word(w) for w in words)),),))
    assert render(parsed, [words], [[]]) == expected


def test_render_rejects_shape_mismatch():
    parsed = lex("ls > f | wc")
    with pytest.raises(ValueError):
        render(parsed, [["ls"]], [["f"], []])
    with pytest.raises(ValueError):
        render(parsed, [["ls"], []], [["f"], []])
    with pytest.raises(ValueError):
        render(parsed, [["ls"], ["wc"]], [["f"]])
    with pytest.raises(ValueError):
        render(parsed, [["ls"], ["wc"]], [[], []])
    with pytest.raises(ValueError):
        render(parsed, [["ls"], ["wc"]], [[None], []])
    with pytest.raises(ValueError):
        render(lex("ls 2>&1"), [["ls"]], [["f"]])


def test_render_uses_expanded_redirect_target():
    parsed = lex("ls > ~/out")
    assert render(parsed, [["ls"]], [["/home/u/out"]]) == "ls > /home/u/out"


def test_redirect_dataclass_defaults():
    assert Redirect(">&", 2, dup=1).target is None


# --- sh parse-only differential --------------------------------------------

needs_sh = pytest.mark.skipif(not os.path.exists(SH), reason="no /bin/sh")


@needs_sh
@pytest.mark.parametrize("raw", ACCEPT_INPUTS)
def test_sh_parses_renders(raw):
    parsed = lex(raw)
    assert sh_parses(render_parsed(parsed))
    assert sh_parses(render_texts(parsed))


# --- Fuzz -----------------------------------------------------------------

FUZZ_CASES = 10000
FUZZ_ALPHABET = (
    list("lsax12-+./_=") * 6
    + [" "] * 8
    + ["\t", "~", "*", "?", "[", "]"]
    + ["'", '"'] * 3
    + ["|", ";", "&", "<", ">"] * 2
    + list("$`\\(){}#!^")
    + ["\n", "\r", "\x00", "é", "€", "\xa0", "\u0301"]
    # Whole tokens, so quoted words and operators survive often enough.
    + ["'a b'", '"c|d"', "''", " | ", " ; ", " && ", " || ", " > o ", " 2>&1"]
)


def fuzz_inputs():
    rng = random.Random(0xC0FFEE)
    for _ in range(FUZZ_CASES):
        length = rng.randint(1, 16)
        yield "".join(rng.choice(FUZZ_ALPHABET) for _ in range(length))


def test_fuzz_lex_render():
    accepted = []
    for raw in fuzz_inputs():
        try:
            parsed = lex(raw)
        except LexError:
            continue
        accepted.append(parsed)
        assert lex(render_parsed(parsed)) == parsed, raw
        for rendered in (render_parsed(parsed), render_texts(parsed)):
            unquoted = unquoted_regions(rendered)
            assert not FORBIDDEN_UNQUOTED & set(unquoted), (raw, rendered)
        assert argv(lex(render_texts(parsed))) == argv(parsed), raw
    # Guards against a generator that only ever produces rejects.
    assert len(accepted) >= FUZZ_CASES // 10


@needs_sh
def test_fuzz_sh_parses_accepted_renders():
    rng = random.Random(7)
    accepted = []
    for raw in fuzz_inputs():
        try:
            accepted.append(lex(raw))
        except LexError:
            pass
    for parsed in rng.sample(accepted, min(200, len(accepted))):
        rendered = render_texts(parsed)
        assert sh_parses(rendered), rendered
