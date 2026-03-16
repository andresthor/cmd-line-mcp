# Security

## Architecture

The server implements three layers of security:

```
┌──────────────────┬────────────────────────┬───────────────────┐
│ COMMAND SECURITY │   DIRECTORY SECURITY   │ SESSION SECURITY  │
├──────────────────┼────────────────────────┼───────────────────┤
│ Command allow/   │ Directory whitelist    │ Session IDs       │
│   block lists    │ Runtime approvals      │ Persistent perms  │
│ Dangerous pattern│ Path normalization     │ Auto timeouts     │
│   matching       │ Symlink resolution     │ Desktop mode      │
│ Command type     │ Subdirectory           │                   │
│   classification │   inheritance          │                   │
└──────────────────┴────────────────────────┴───────────────────┘
```

## Command Validation Pipeline

Every command passes through this pipeline before execution:

1. **Dangerous pattern check** &mdash; regex patterns matched against the full command string
2. **Pipeline/chain splitting** &mdash; `|`, `;`, `&` split into segments, each validated independently
3. **Block list check** &mdash; each command checked against explicitly blocked commands
4. **Allow list check** &mdash; each command must appear in read, write, or system lists
5. **Directory check** &mdash; target directory must be whitelisted or session-approved
6. **Command type check** &mdash; write/system commands require approval

## Command Execution Hardening

Powerful utilities like `awk`, `sed`, `find`, `tar`, `env`, and `xargs` can be abused to execute arbitrary commands even when shells are blocked. The server detects and blocks these vectors:

| Attack Vector | Example | Defense |
|---|---|---|
| awk `system()` / getline | `awk 'BEGIN{system("id")}'` | Dangerous pattern match |
| sed `/e` execute flag | `sed 's/x/id/e'` (any delimiter) | Delimiter-aware regex |
| find `-exec` with interpreters | `find -exec sh -c 'id' {} +` | Blocks bare and full-path interpreters |
| env launching interpreters | `env -i sh -c id` | Flag-aware pattern match |
| xargs launching interpreters | `xargs -I{} sh -c id` | Flag-aware pattern match |
| tar command execution | `tar --checkpoint-action=exec=id` | Blocks `--to-command`, `-I`, `--use-compress-program` |
| cp/mv to system paths | `cp evil /etc/passwd` | Blocks writes to `/etc`, `/boot`, `/bin`, `/sbin`, `/usr/*bin` |
| Linker variable injection | `env LD_PRELOAD=evil.so cmd` | Blocks `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES` |
| Direct interpreter invocation | `python3 -c '...'` | Shells and scripting languages explicitly blocked |
| Command substitution | `$(id)`, `` `id` `` | Blocked by pattern |

## Blocked Commands

All shells and scripting interpreters are **explicitly blocked**, not just absent from allowlists:

- **Shells**: `bash`, `sh`, `zsh`, `ksh`, `csh`, `fish`
- **Scripting languages**: `python`, `python2`, `python3`, `perl`, `ruby`, `node`, `nodejs`, `lua`, `php`, `tclsh`, `wish`, `Rscript`
- **Privilege escalation**: `sudo`, `su`
- **Dangerous utilities**: `dd`, `mkfs`, `mount`, `umount`, `nc`, `telnet`, `nmap`
- **Execution primitives**: `eval`, `exec`, `source`, `.`
- **PTY tools**: `screen`, `tmux`, `expect`, `script`

## Custom Dangerous Patterns

Add regex patterns to `dangerous_patterns` in your config to block additional vectors:

```json
{
  "commands": {
    "dangerous_patterns": [
      "your-custom-pattern-here"
    ]
  }
}
```

Patterns are matched against the full command string using `re.search()` before any other validation.

## Reporting Vulnerabilities

If you discover a security vulnerability, please open an issue on GitHub.
