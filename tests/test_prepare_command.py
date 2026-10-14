"""Tests for prepare_command, expand and collect_paths."""

import os

import pytest

from cmd_line_mcp import security
from cmd_line_mcp.security import (
    SEPARATORS_DISABLED_ERROR,
    CommandRejected,
    PathUse,
    PreparedCommand,
    collect_paths,
    expand,
    extract_directory_from_command,
    is_directory_whitelisted,
    parse_command,
    prepare_command,
    validate_command,
)
from cmd_line_mcp.shell_lexer import lex

LISTS = {
    "read": ["ls", "cat", "grep", "find", "du", "head", "wc", "echo", "sort"],
    "write": ["touch", "tar", "cp", "mv", "ln", "rm", "mkdir", "chmod", "unzip"],
    "system": ["curl", "wget"],
    "blocked": ["blockedtool"],
}


@pytest.fixture
def workdir(tmp_path):
    """A scratch directory with files, a subdirectory and a sibling."""
    (tmp_path / "a.txt").write_text("a\n")
    (tmp_path / "b.txt").write_text("b\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c.txt").write_text("c\n")
    (tmp_path / "other").mkdir()
    return tmp_path


def real(path):
    """Resolved form of ``path`` (tmp_path is under a symlink on macOS)."""
    return os.path.realpath(path)


def prepare(command, cwd, lists=LISTS, patterns=(), allow_separators=True):
    return prepare_command(command, lists, patterns, allow_separators, str(cwd))


def rejection(command, cwd, **kwargs):
    with pytest.raises(CommandRejected) as info:
        prepare(command, cwd, **kwargs)
    return str(info.value)


# ---------------------------------------------------------------------------
# validate_command wrapper
# ---------------------------------------------------------------------------


def test_validate_command_returns_canonical_and_directories(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = validate_command("ls -la /tmp | grep x", ["ls", "grep"], [], [], [], [])
    assert result["is_valid"] is True
    assert result["command_type"] == "read"
    assert result["error"] is None
    assert result["canonical_command"] == "ls -la /tmp | grep x"
    assert result["directories"] == [real("/tmp")]


@pytest.mark.parametrize("command", ["", "echo $HOME", "unknown", "ls; ls"])
def test_validate_command_rejection_keeps_dict_shape(command):
    result = validate_command(command, ["ls"], [], [], [], [], False)
    assert result == {
        "is_valid": False,
        "command_type": None,
        "error": result["error"],
        "canonical_command": None,
        "directories": [],
    }
    assert result["error"]


# ---------------------------------------------------------------------------
# Rejection reasons
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command, expected",
    [
        ("   ", "Empty command"),
        ("echo $HOME", "Unsupported shell syntax"),
        ("ls &", "Unsupported shell syntax"),
        ("unknown -x", "is not recognized or supported"),
        ("blockedtool -x", "is blocked"),
        ("ls | env", "is blocked"),
        ("/bin/ls", "must be given by name"),
        ("l* a.txt", "may not use ~ or globs"),
    ],
)
def test_rejection_reasons(workdir, command, expected):
    assert expected in rejection(command, workdir)


def test_hard_blocked_even_when_listed(workdir):
    lists = dict(LISTS, read=LISTS["read"] + ["env"])
    assert "is blocked" in rejection("env", workdir, lists=lists)


def test_separators_disabled(workdir):
    message = rejection("ls && ls", workdir, allow_separators=False)
    assert message == SEPARATORS_DISABLED_ERROR
    assert prepare("ls", workdir, allow_separators=False).command_type == "read"


def test_pattern_on_raw_string(workdir):
    message = rejection("cat a.txt", workdir, patterns=[r"a\.txt"])
    assert "Command contains dangerous pattern" in message


def test_pattern_on_normalized_view(workdir):
    # Quotes and missing spaces do not hide a match from the normalized view.
    patterns = [r"cat a\.txt", r">\s+/blocked/"]
    assert "dangerous pattern" in rejection('cat "a".txt', workdir, patterns=patterns)
    assert "dangerous pattern" in rejection(
        "ls >/blocked/x", workdir, patterns=patterns
    )


def test_rejected_command_is_not_expanded(workdir, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("glob ran before the command word was checked")

    monkeypatch.setattr(security.glob, "iglob", fail)
    assert "not recognized" in rejection("unknown *.txt", workdir)


def test_glob_match_cap(workdir, monkeypatch):
    monkeypatch.setattr(security, "MAX_GLOB_MATCHES", 1)
    assert "matches more than 1 entries" in rejection("ls *.txt", workdir)


def test_glob_wildcard_component_cap(workdir):
    assert "more than 3 path components" in rejection("ls */*/*/*/x", workdir)
    assert prepare("ls */*/*/x", workdir).argv_per_command == (("ls", "*/*/*/x"),)


def test_glob_visited_cap_counts_entries_without_matches(workdir, monkeypatch):
    for name in "defgh":
        (workdir / "sub" / name).mkdir()
    monkeypatch.setattr(security, "MAX_GLOB_VISITED", 5)
    message = rejection("ls */*/missing", workdir)
    assert "requires listing more than 5 entries" in message


def test_glob_time_cap(workdir, monkeypatch):
    monkeypatch.setattr(security, "MAX_GLOB_SECONDS", -1)
    assert "takes too long to expand" in rejection("ls *.txt", workdir)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command, expected",
    [
        ("ls", "read"),
        ("ls > out.txt", "write"),
        ("ls >> out.txt", "write"),
        ("ls > /dev/null", "read"),
        ("ls 2>&1", "read"),
        ("cat < a.txt", "read"),
        ("ls; touch new.txt", "write"),
        ("ls | grep x && curl https://example.com", "system"),
        ("curl -o page.html https://example.com", "system"),
    ],
)
def test_classification(workdir, command, expected):
    assert prepare(command, workdir).command_type == expected


def test_output_file_option_raises_read_to_write(workdir):
    lists = dict(LISTS, read=["curl"], system=[])
    prepared = prepare("curl -o page.html https://example.com", workdir, lists=lists)
    assert prepared.command_types == ("write",)


def test_command_in_several_lists_gets_most_privileged_type(workdir):
    lists = dict(LISTS, write=LISTS["write"] + ["ls"])
    assert prepare("ls", workdir, lists=lists).command_type == "write"


# ---------------------------------------------------------------------------
# Expansion and canonical rendering
# ---------------------------------------------------------------------------


def test_relative_glob_expands_sorted(workdir):
    prepared = prepare("ls *.txt", workdir)
    assert prepared.argv_per_command == (("ls", "a.txt", "b.txt"),)
    assert prepared.canonical == "ls a.txt b.txt"


def test_glob_match_starting_with_dash_gets_prefix(workdir):
    (workdir / "-n.txt").write_text("")
    prepared = prepare("cat *.txt", workdir)
    assert prepared.argv_per_command[0][1] == "./-n.txt"


def test_glob_without_match_stays_literal_and_quoted(workdir):
    prepared = prepare("ls *.none", workdir)
    assert prepared.argv_per_command == (("ls", "*.none"),)
    assert prepared.canonical == "ls '*.none'"


def test_quoted_glob_is_not_expanded(workdir):
    prepared = prepare("ls '*.txt'", workdir)
    assert prepared.argv_per_command == (("ls", "*.txt"),)


def test_tilde_expands_in_argv_and_canonical(workdir, monkeypatch):
    monkeypatch.setenv("HOME", str(workdir))
    prepared = prepare("ls ~/sub", workdir)
    assert prepared.argv_per_command == (("ls", f"{workdir}/sub"),)
    assert prepared.canonical == f"ls {workdir}/sub"


def test_tilde_glob_treats_home_literally(tmp_path, monkeypatch):
    home = tmp_path / "h[1]"
    home.mkdir()
    (home / "x.txt").write_text("")
    monkeypatch.setenv("HOME", str(home))
    prepared = prepare("ls ~/*.txt", tmp_path)
    assert prepared.argv_per_command == (("ls", f"{home}/x.txt"),)


def test_canonical_quotes_words(workdir):
    prepared = prepare("grep 'a b' a.txt", workdir)
    assert prepared.canonical == "grep 'a b' a.txt"


def test_parse_command_is_display_only():
    assert parse_command("grep 'a b' f | wc -l") == ("grep", ["a b", "f"])
    assert parse_command("echo $HOME") == ("", [])


# ---------------------------------------------------------------------------
# Directory collection
# ---------------------------------------------------------------------------


def test_no_path_falls_back_to_cwd(workdir):
    prepared = prepare("echo hello", workdir)
    assert prepared.paths == (PathUse(real(workdir), "read"),)
    assert prepared.directories == (real(workdir),)


def test_every_segment_is_collected(workdir):
    prepared = prepare(f"ls {workdir}/sub; cat {workdir}/other/x", workdir)
    assert prepared.directories == (
        real(workdir / "sub"),
        real(workdir / "other"),
    )


def test_pipeline_filter_adds_no_directory(workdir):
    prepared = prepare(f"ls {workdir}/sub | grep x", workdir)
    assert prepared.directories == (real(workdir / "sub"),)


def test_listing_without_operand_reads_cwd(workdir):
    prepared = prepare(f"ls {workdir}/sub; ls", workdir)
    assert real(workdir) in prepared.directories


def test_recursive_grep_without_file_reads_cwd(workdir):
    prepared = prepare(f"ls {workdir}/sub; grep -r x", workdir)
    assert real(workdir) in prepared.directories


def test_relative_glob_into_subdirectory(workdir):
    prepared = prepare("cat sub/*.txt", workdir)
    assert prepared.directories == (real(workdir / "sub"),)


def test_glob_matches_are_all_collected(workdir):
    prepared = prepare("du -sh *", workdir)
    assert real(workdir / "sub") in prepared.directories
    assert real(workdir / "other") in prepared.directories


def test_existing_relative_word_is_collected(workdir):
    prepared = prepare(f"wc {workdir}/sub/c.txt a.txt", workdir)
    assert prepared.directories == (real(workdir / "sub"), real(workdir))


def test_option_value_path_is_collected(workdir):
    prepared = prepare(f"grep --exclude-from={workdir}/other/list x a.txt", workdir)
    assert real(workdir / "other") in prepared.directories


def test_grep_pattern_is_not_a_path(workdir):
    prepared = prepare(f"grep a/b {workdir}/sub/c.txt", workdir)
    assert prepared.directories == (real(workdir / "sub"),)


def test_find_name_value_is_not_a_path(workdir):
    prepared = prepare(f"find {workdir}/sub -name '*/x' -type f", workdir)
    assert prepared.directories == (real(workdir / "sub"),)


def test_url_is_not_a_path(workdir):
    prepared = prepare("curl -s https://example.com/a/b", workdir)
    assert prepared.directories == (real(workdir),)


def test_file_option_target_is_collected(workdir):
    prepared = prepare(
        f"curl -o {workdir}/other/page.html https://example.com", workdir
    )
    assert PathUse(real(workdir / "other" / "page.html"), "write") in prepared.paths
    assert prepared.directories == (real(workdir / "other"),)


def test_directory_valued_option_may_be_a_directory(workdir):
    prepared = prepare(f"tar -C {workdir}/other -xf a.tar", workdir)
    assert real(workdir / "other") in prepared.directories


def test_redirect_targets_are_collected(workdir):
    prepared = prepare(f"cat < {workdir}/sub/c.txt > {workdir}/other/out.txt", workdir)
    assert prepared.paths == (
        PathUse(real(workdir / "sub" / "c.txt"), "read"),
        PathUse(real(workdir / "other" / "out.txt"), "write"),
    )


def test_path_operand_of_write_command(workdir):
    prepared = prepare(f"touch {workdir}/other/new.txt", workdir)
    assert prepared.paths == (PathUse(real(workdir / "other" / "new.txt"), "write"),)


def test_numeric_option_value_is_not_an_operand(workdir):
    prepared = prepare(f"head -n 5 {workdir}/sub/c.txt", workdir)
    assert prepared.directories == (real(workdir / "sub"),)


def test_chmod_mode_is_not_an_operand(workdir):
    prepared = prepare(f"chmod 644 {workdir}/sub/c.txt", workdir)
    assert prepared.directories == (real(workdir / "sub"),)


def test_symlinked_operand_resolves_to_target(workdir):
    (workdir / "sub" / "to-other").symlink_to(workdir / "other")
    prepared = prepare("ls sub/to-other", workdir)
    assert prepared.directories == (real(workdir / "other"),)


# ---------------------------------------------------------------------------
# Write targets
# ---------------------------------------------------------------------------


def test_write_to_new_file_in_existing_directory(workdir):
    prepared = prepare("echo hi > new.txt", workdir)
    assert prepared.paths == (PathUse(real(workdir / "new.txt"), "write"),)


def test_append_to_regular_file(workdir):
    assert prepare("echo hi >> a.txt", workdir).command_type == "write"


def test_write_target_fifo_rejected(workdir):
    os.mkfifo(workdir / "pipe")
    assert "not a regular file" in rejection("echo hi > pipe", workdir)


def test_write_target_directory_rejected(workdir):
    assert "not a regular file" in rejection("echo hi > sub", workdir)


def test_write_target_symlink_rejected(workdir):
    (workdir / "link").symlink_to(workdir / "a.txt")
    assert "symbolic link" in rejection("echo hi > link", workdir)


def test_write_target_dangling_symlink_rejected(workdir):
    (workdir / "dangling").symlink_to(workdir / "missing")
    assert "symbolic link" in rejection("echo hi > dangling", workdir)


def test_write_target_missing_directory_rejected(workdir):
    assert "does not exist" in rejection("echo hi > missing/x.txt", workdir)


def test_device_redirect_rejected(workdir):
    assert "not allowed" in rejection("echo hi > /dev/zero", workdir)


def test_dev_null_redirect_adds_no_path(workdir):
    prepared = prepare(f"ls {workdir}/sub 2> /dev/null", workdir)
    assert prepared.directories == (real(workdir / "sub"),)


# ---------------------------------------------------------------------------
# Compatibility wrapper
# ---------------------------------------------------------------------------


def test_extract_directory_from_command(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert extract_directory_from_command("ls /tmp | grep x") == real("/tmp")
    assert extract_directory_from_command("echo $HOME") is None
    assert extract_directory_from_command("env") is None


# ---------------------------------------------------------------------------
# Pipeline structure
# ---------------------------------------------------------------------------


def test_check_arguments_runs_once_per_command(workdir, monkeypatch):
    calls = []
    original = security.check_arguments

    def counting(name, argv):
        calls.append(name)
        return original(name, argv)

    monkeypatch.setattr(security, "check_arguments", counting)
    prepare("cat a.txt | wc -l", workdir)
    assert calls == ["cat", "wc"]


def test_collect_paths_needs_no_prepared_command(workdir):
    parsed = lex("cat sub/c.txt > other/out.txt")
    expanded = expand(parsed, str(workdir))
    paths = collect_paths(parsed, expanded, str(workdir), ["read"], [[]])
    assert paths == [
        PathUse(real(workdir / "sub" / "c.txt"), "read"),
        PathUse(real(workdir / "other" / "out.txt"), "write"),
    ]


def test_prepared_command_requires_paths_and_directories(workdir):
    parsed = lex("ls")
    with pytest.raises(TypeError):
        PreparedCommand(parsed, expand(parsed, str(workdir)), ("read",), "read", "ls")


# ---------------------------------------------------------------------------
# Links, copies and moves
# ---------------------------------------------------------------------------


def test_relative_symlink_target_resolves_from_link_directory(workdir):
    prepared = prepare("ln -s ../other/x.txt sub/link", workdir)
    assert prepared.paths == (
        PathUse(real(workdir / "other" / "x.txt"), "read"),
        PathUse(real(workdir / "sub" / "link"), "write"),
    )


def test_symlink_into_existing_directory(workdir):
    prepared = prepare("ln -s c.txt sub", workdir)
    assert PathUse(real(workdir / "sub" / "c.txt"), "read") in prepared.paths


def test_hard_link_source_resolves_from_cwd(workdir):
    prepared = prepare("ln a.txt other/copy.txt", workdir)
    assert PathUse(real(workdir / "a.txt"), "read") in prepared.paths


def test_copy_source_is_read_and_destination_written(workdir):
    prepared = prepare("cp a.txt other", workdir)
    assert prepared.paths == (
        PathUse(real(workdir / "a.txt"), "read"),
        PathUse(real(workdir / "other"), "write"),
    )


def test_copy_target_directory_option(workdir):
    prepared = prepare("cp -t other a.txt", workdir)
    assert PathUse(real(workdir / "other"), "write") in prepared.paths
    assert PathUse(real(workdir / "a.txt"), "read") in prepared.paths


# ---------------------------------------------------------------------------
# Write-kind operands
# ---------------------------------------------------------------------------


def test_write_operand_may_be_a_directory(workdir):
    assert prepare("rm -r sub", workdir).paths == (
        PathUse(real(workdir / "sub"), "write"),
    )


def test_write_operand_through_directory_symlink(workdir):
    (workdir / "to-other").symlink_to(workdir / "other")
    prepared = prepare("cp a.txt to-other", workdir)
    assert PathUse(real(workdir / "other"), "write") in prepared.paths


def test_write_operand_symlink_to_file_rejected(workdir):
    (workdir / "link").symlink_to(workdir / "a.txt")
    assert "symbolic link" in rejection("cp b.txt link", workdir)


def test_write_operand_fifo_rejected(workdir):
    os.mkfifo(workdir / "pipe")
    assert "not a regular file" in rejection("touch pipe", workdir)


def test_write_operand_parent_may_be_missing(workdir):
    prepared = prepare("mkdir -p new/deeper", workdir)
    assert prepared.paths == (PathUse(real(workdir / "new" / "deeper"), "write"),)


def test_read_operand_symlink_allowed(workdir):
    (workdir / "link").symlink_to(workdir / "a.txt")
    assert prepare("cat link", workdir).command_type == "read"


# ---------------------------------------------------------------------------
# Implicit use of the working directory
# ---------------------------------------------------------------------------

CWD_WRITE = [
    "unzip other/a.zip",
    "tar -xf other/a.tar",
    "tar xf other/a.tar",
    "tar --extract --file=other/a.tar",
    "wget https://example.com",
    "curl -O https://example.com/a",
    "curl -sLO https://example.com/a",
    "curl --remote-name https://example.com/a",
    "ls sub; unzip other/a.zip",
]


@pytest.mark.parametrize("command", CWD_WRITE)
def test_command_writing_into_cwd(workdir, command):
    assert PathUse(real(workdir), "write") in prepare(command, workdir).paths


@pytest.mark.parametrize(
    "command",
    [
        "unzip -d sub other/a.zip",
        "tar -xf other/a.tar -C sub",
        "tar --extract --file=other/a.tar --directory=sub",
        "tar -cf other/a.tar sub",
        "wget -P sub https://example.com",
        "wget -O sub/page.html https://example.com",
        "curl -O --output-dir sub https://example.com/a",
        "curl -o sub/a https://example.com/a",
    ],
)
def test_command_with_explicit_output_location(workdir, command):
    assert PathUse(real(workdir), "write") not in prepare(command, workdir).paths


@pytest.mark.parametrize(
    "command",
    [
        "grep -r x",
        "grep -R x",
        "grep --recursive x",
        "grep --recur x",
        "grep --dereference-recursive x",
        "grep -d recurse x",
        "grep -drecurse x",
        "grep --directories=recurse x",
        "ls sub; grep -r x",
    ],
)
def test_recursive_grep_reads_cwd(workdir, command):
    assert PathUse(real(workdir), "read") in prepare(command, workdir).paths


def test_recursive_grep_with_file_operand(workdir):
    prepared = prepare("grep -r x sub", workdir)
    assert prepared.paths == (PathUse(real(workdir / "sub"), "read"),)


# ---------------------------------------------------------------------------
# grep option parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("option", ["-f{}", "--file={}", "-f {}", "-if{}"])
def test_grep_pattern_file_is_read(workdir, option):
    patterns = workdir / "other" / "patterns"
    prepared = prepare(f"grep {option.format(patterns)} a.txt", workdir)
    assert PathUse(real(patterns), "read") in prepared.paths
    assert PathUse(real(workdir / "a.txt"), "read") in prepared.paths


@pytest.mark.parametrize(
    "command",
    [
        "grep -ie a/b sub/c.txt",
        "grep -ea/b sub/c.txt",
        "grep --regexp=a/b sub/c.txt",
        "grep -ri a/b sub/c.txt",
        "grep -dread a/b sub/c.txt",
        "grep -A 2 a/b sub/c.txt",
    ],
)
def test_grep_pattern_is_never_a_path(workdir, command):
    assert prepare(command, workdir).directories == (real(workdir / "sub"),)


def test_grep_value_letter_not_last_takes_attached_value(workdir):
    # -ei: e takes "i" as the pattern, so the operand is a file.
    prepared = prepare("grep -ei sub/c.txt", workdir)
    assert prepared.paths == (PathUse(real(workdir / "sub" / "c.txt"), "read"),)


# ---------------------------------------------------------------------------
# Whitelist
# ---------------------------------------------------------------------------


def test_whitelist_expands_home(workdir, monkeypatch):
    monkeypatch.setenv("HOME", str(workdir))
    assert is_directory_whitelisted(str(workdir / "sub"), ["~"])
    assert is_directory_whitelisted(str(workdir / "sub"), ["~/sub"])
    assert not is_directory_whitelisted(str(workdir / "sub"), ["~/other"])
