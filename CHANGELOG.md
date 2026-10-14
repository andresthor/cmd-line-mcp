# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/).

## [0.6.1] - Unreleased

An executor that runs commands without `/bin/sh` is planned for 0.7.

### Security

- Fix shell command injection (advisory: GHSA pending). The validator and `/bin/sh` could disagree about where one command ended, so blocked or unlisted commands could run and directory checks could be skipped. Commands are now parsed by a strict lexer, and the server runs its own fully quoted rendering of the validated command instead of the raw input. Reported by Taran-Douley (Shroud Labs) and MartOcd1709.
- Every path, glob match, file option and redirect target in every command of a pipeline or chain is checked against the directory whitelist.
- Shells, interpreters and programs that run other programs (`env`, `xargs`, `nohup`, `timeout`, …) are hard-blocked as commands in code and cannot be re-enabled by configuration.
- Commands run with empty stdin in their own process group, and shell startup variables (`ENV`, `BASH_ENV`, `BASH_FUNC_*`, …) are removed from their environment.
- `docs/SECURITY.md` documents the threat model and known limitations, and vulnerabilities are now reported through GitHub private vulnerability reporting.

### Added

- `security.command_timeout` (default 60 seconds); the whole process group is killed when it expires.
- `timed_out` and `truncated` fields in command results.

### Changed

- Unsupported shell syntax is rejected: `$` unquoted or inside double quotes (variables and `$(...)`, except right before the closing `"`; single-quoted `$` is accepted), backticks, and unquoted backslash, `#`, `!`, parentheses and braces; background `&`, `&>`, `|&`, `>|`, newlines and control characters. Pipes, `;`, `&&`, `||`, `>`, `>>`, `<`, `2>&1`, globs and `~` still work.
- Commands must be given by name; a path, `~` or glob in the command word is rejected.
- An output redirect makes a command at least a write command.
- `2>&1` and `> /dev/null` are no longer blocked by the default patterns.
- Default redirect patterns now also match `>>` and forms without a space (`>>?\s*`), e.g. `>>/etc/hosts`.
- stderr now counts toward `output.max_size` together with stdout, and the command is killed when the cap is reached.
- `allow_user_confirmation: false` now denies write and system commands unless they were approved for the session; previously they ran without approval.
- Directory errors from `execute_read_command` no longer start with "Read command - ".
- `default_config.json` ships inside the package and is loaded from there, so wheel installs no longer run with empty command lists.
- `mcp` is pinned below 2, because 2.x removes `mcp.server.fastmcp`.

### Removed

- Default read commands: `less`, `env`, `history`, `man`, `info`, `help`, `find`, `sort`.
- Default write commands: `export`, `awk`, `sed`, `tar`, `zip`, `unzip`.
- Default system commands: `top`, `htop`, `ssh`, `scp`, `xargs`, `curl`, `wget`.
- `find`, `sort`, `tar`, `zip`, `unzip`, `curl` and `wget` stay out of the defaults until per-command argument rules exist for them; a user config can still list them.
- `env` and `xargs` moved to the blocked list.
