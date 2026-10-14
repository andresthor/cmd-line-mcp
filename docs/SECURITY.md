# Security

## Threat Model

The adversary is the model itself: a prompt-injected assistant that sends whatever command string helps the attacker. The server's job is to make sure only allow-listed commands run, only against approved directories.

**This is not a sandbox.** Commands run as your user, with your environment and your `PATH`. Treat every whitelisted or approved directory as readable and, for write commands, writable by the model.

## Architecture

The server implements three layers of security:

```
┌──────────────────┬────────────────────────┬───────────────────┐
│ COMMAND SECURITY │   DIRECTORY SECURITY   │ SESSION SECURITY  │
├──────────────────┼────────────────────────┼───────────────────┤
│ Strict lexer     │ Directory whitelist    │ Session IDs       │
│ Hard-blocked     │ Runtime approvals      │ Persistent perms  │
│   floor          │ Every path checked     │ Auto timeouts     │
│ Allow/block lists│ Path normalization     │ Desktop mode      │
│ Dangerous pattern│ Symlink resolution     │                   │
│   matching       │ Subdirectory           │                   │
│ Command type     │   inheritance          │                   │
│   classification │                        │                   │
└──────────────────┴────────────────────────┴───────────────────┘
```

## Command Validation Pipeline

Every command passes through this pipeline before execution:

1. **Dangerous pattern check** &mdash; regex patterns matched against the raw string and again against a normalized view of the parsed command
2. **Lexing** &mdash; the string is parsed into commands joined by `|`, `;`, `&&` and `||`; anything outside the [accepted syntax](#accepted-syntax) is rejected
3. **Command word check** &mdash; each command must be given by name (no path, `~` or glob) and must not be on the hard-blocked floor
4. **Allow list check** &mdash; each command must be in the read, write or system list and not in `blocked`
5. **Expansion** &mdash; `~` and globs are expanded by the server, producing each command's final arguments
6. **Argument and path check** &mdash; every path-like operand, glob match, file option and redirect target of every command must be whitelisted or session-approved
7. **Command type check** &mdash; the most privileged type wins; an output redirect (other than to `/dev/null`) makes a command at least `write`; write/system commands require approval
8. **Execution** &mdash; the server runs its own re-rendered command, not the input

### What Actually Runs

The server never hands your input to the shell. It renders the validated, already-expanded arguments back into a new string in which every word is quoted, and runs that with `/bin/sh -c`. The shell only connects pipes, sequences and redirects; it performs no expansion of its own.

```
input:    ls ~/Downloads/*.pdf | grep report
executed: ls /Users/you/Downloads/a.pdf /Users/you/Downloads/b.pdf | grep report
```

### Accepted Syntax

| Accepted | Rejected |
|---|---|
| Pipes `\|`, sequences `;`, `&&`, `\|\|` | `$` unquoted or inside double quotes (variables, `$(...)`), except right before the closing `"`; `$` inside single quotes is accepted |
| Redirects `>`, `>>`, `<` | Backticks |
| `2>&1`, `>&2`, `1>&2` | Unquoted backslash |
| Single and double quotes | Unquoted `#`, `!` |
| Globs `*`, `?`, `[...]` | Unquoted parentheses and braces (subshells, groups) |
| `~` and `~/...` at the start of a word | Background `&`, `&>`, `\|&`, `>\|` and other combined operators |
| Spaces and tabs | Newlines and other control characters |

Commands longer than 4096 characters are rejected. Setting `allow_command_separators: false` rejects any input with more than one command, pipes included.

### Execution Limits

- Empty stdin
- Own process group, killed on timeout (`security.command_timeout`, default 60 seconds)
- Output cap (`output.max_size`, default 102400 bytes, stdout and stderr combined); the process group is killed when it is reached
- Shell startup variables (`ENV`, `BASH_ENV`, `BASH_FUNC_*` and similar) are removed from the child's environment

## Blocked Commands

### Hard-Blocked Floor

`policy.HARD_BLOCKED` is enforced in code. These commands are rejected as a command **even if your config lists them**, and names are matched after stripping the directory and a version suffix (`python3.12` counts as `python`):

- **Wrappers**: `env`, `xargs`, `nice`, `nohup`, `time`, `timeout`, `busybox`, `command`, `builtin`, `exec`, `eval`, `source`, `.`, `doas`, `sudo`, `su`, `watch`, `setsid`, `stdbuf`, `flock`, `parallel`, `chroot`, `strace`, `ltrace`, `script`, `expect`
- **Shells**: `sh`, `bash`, `zsh`, `ksh`, `csh`, `tcsh`, `fish`, `dash`, `ash`
- **Interpreters**: `python`, `python2`, `python3`, `perl`, `ruby`, `node`, `nodejs`, `lua`, `php`, `tclsh`, `wish`, `Rscript`, `osascript`
- **Other**: `ssh-agent`, `nc`, `telnet`, `screen`, `tmux`, `noglob`, `nocorrect`, `repeat`, `foreach`, `coproc`

### Default Blocked List

The `blocked` list in the default config adds `dd`, `mkfs`, `mount`, `umount`, `shutdown`, `reboot`, `passwd`, `chpasswd`, `useradd`, `userdel`, `groupadd`, `groupdel` and `nmap`. This list is configuration: a JSON config that sets `blocked` replaces it.

## Argument Rules

Per-command argument rules live in `policy.ARG_RULES` and apply to user-added commands as well as defaults. Rules are being added; until a command has one, only `dangerous_patterns` constrain its flags.

File-valued options of `curl`, `wget`, `tar` and `unzip` (such as `curl -o`) are path-checked like any other path, and writing options make the command a write command.

## Dangerous Patterns

The default `dangerous_patterns` act as a backstop. They are configuration: a JSON config that sets the list replaces them, and environment variables add to them.

| Vector | Example | Default pattern |
|---|---|---|
| Writes to system paths | `echo x > /etc/hosts`, `cp evil /usr/local/bin/` | Redirects and `cp`/`mv` into `/etc`, `/boot`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, block devices |
| Recursive root delete | `rm -rf /` | `rm\s+-rf\s+/` |
| tar command execution | `tar --checkpoint-action=exec=id` | `--to-command`, `--checkpoint-action=exec`, `--use-compress-program`, `tar ... -I` |
| find `-exec` with listed interpreters | `find . -exec sh -c id {} +` | `sh`, `bash`, `zsh`, `ksh`, `csh`, `fish`, `python`, `python2`, `python3`, `perl`, `ruby`, `node`, `env` (bare or full path) after `-exec`, `-execdir`, `-ok`, `-okdir` |
| awk `system()`, sed `/e` | `awk 'BEGIN{system("id")}'` | Matter only if you add `awk` or `sed` back |
| Linker variables | `LD_PRELOAD=evil.so` | `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES` |

Add your own:

```json
{
  "commands": {
    "dangerous_patterns": [
      "your-custom-pattern-here"
    ]
  }
}
```

Patterns use `re.search()`.

## Known Limitations

These are documented, not fixed:

- **Redirect-open race**: the server checks a redirect target, then `/bin/sh` opens it. A concurrent local process could swap a path component for a symlink in between.
- **Glob listing before denial**: expanding a glob lists a directory before the path check can deny it. Matches are capped.
- **Approval tools are model-callable**: `approve_directory` and `approve_command_type` are ordinary MCP tools. The only gate is your client's per-tool confirmation.
- **Arguments that run programs or write files**: per-command argument rules (`policy.ARG_RULES`) are not written yet. `find`, `sort`, `tar`, `zip`, `unzip`, `curl` and `wget` are therefore left out of the defaults. If a config lists them, their options can run other programs or write and delete files without approval — e.g. `find -exec` with a program outside the pattern's interpreter set, `find -delete` or `-fprint`, `sort -o`.
- **`PATH` lookup**: the command word is resolved through `PATH`. A writable directory early in `PATH` can shadow `ls`.
- **Environment controls config**: whoever controls the server's environment or `.env` file can widen command lists and whitelists. The floor still applies.
- **`require_session_id: false`** (the default) auto-approves write and system commands. So does a client that sends no session ID while `allow_user_confirmation` is `true`. Set `allow_user_confirmation: false` to require an explicit approval.
- **`auto_approve_directories_in_desktop_mode: true`** (with `require_session_id: false`) approves every directory a command touches, which turns off directory confinement.
- **Detached children**: a child that calls `setsid` leaves the process group and survives the timeout kill.

An executor that runs commands without `/bin/sh` is planned for 0.7.

## Reporting Vulnerabilities

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue.
