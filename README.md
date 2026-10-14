# Command-Line MCP Server

[![PyPI version](https://badge.fury.io/py/cmd-line-mcp.svg)](https://badge.fury.io/py/cmd-line-mcp)
[![Python Versions](https://img.shields.io/pypi/pyversions/cmd-line-mcp.svg)](https://pypi.org/project/cmd-line-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An MCP server that lets AI assistants run terminal commands safely. Commands are categorized (read/write/system), directories are whitelisted, and dangerous patterns are blocked automatically.

---

## Quick Start

```bash
pip install cmd-line-mcp

# Or from source
git clone https://github.com/andresthor/cmd-line-mcp.git
cd cmd-line-mcp
pip install -e .
```

Run the server:

```bash
cmd-line-mcp                        # default config
cmd-line-mcp --config config.json   # custom config
```

---

## Claude Desktop Setup

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cmd-line": {
      "command": "/path/to/venv/bin/cmd-line-mcp",
      "args": ["--config", "/path/to/config.json"],
      "env": {
        "CMD_LINE_MCP_SECURITY_REQUIRE_SESSION_ID": "false"
      }
    }
  }
}
```

Restart Claude Desktop after saving.

> [!WARNING]
> `require_session_id: false` is the default and prevents approval loops in Claude Desktop, but it auto-approves write and system commands; set `allow_user_confirmation: false` to require explicit approval instead. The model can request that approval itself through `approve_command_type`, so your client's tool confirmation is the real gate. `auto_approve_directories_in_desktop_mode: true` turns off directory confinement entirely. See [docs/SECURITY.md](docs/SECURITY.md#known-limitations).

---

## How It Works

Commands go through a validation pipeline before execution:

1. **Pattern matching** — rejects configured dangerous patterns (writes to system paths, `tar --to-command`, etc.)
2. **Parsing** — the command is parsed by a strict lexer; unsupported shell syntax is rejected
3. **Command classification** — each command must be in the read, write or system list, and not blocked
4. **Path check** — every path, glob match and redirect target in every command must be whitelisted or session-approved
5. **Approval check** — write/system commands require approval

Pipes, `;`, `&&` and `||` are supported, and each command is validated independently. Background `&`, variables (`$NAME`), command substitution and subshells are rejected. The server runs its own fully quoted rendering of the validated command, never the raw input.

### What's Allowed

| Category    | Commands                                                       | Approval       |
|:------------|:---------------------------------------------------------------|:--------------:|
| **Read**    | `ls`, `cat`, `grep`, `find`, `head`, `tail`, `sort`, `wc`, …  | Auto           |
| **Write**   | `cp`, `mv`, `rm`, `mkdir`, `touch`, `chmod`, `tar`, `echo`, … | Required       |
| **System**  | `ps`, `ping`, `curl`, `wget`, `netstat`, …                    | Required       |
| **Blocked** | `sudo`, `bash`, `sh`, `python`, `eval`, `env`, `xargs`, …     | Always denied  |

### What's Blocked

- **Hard-blocked floor** — shells, interpreters and programs that run other programs (`env`, `xargs`, `nohup`, `timeout`, …). Enforced in code, so a config cannot re-enable them.
- **Blocked list** — adds `dd`, `mkfs`, `mount`, `shutdown` and similar; configurable.
- **Dangerous patterns** — configurable regexes, by default covering writes to system paths, `rm -rf /`, `tar` command execution and `find -exec` with `sh`, `bash`, `zsh`, `ksh`, `csh`, `fish`, `python`/`python2`/`python3`, `perl`, `ruby`, `node` or `env`. Default read commands such as `find` and `sort` can still write files or run other programs until per-command argument rules land.

See [docs/SECURITY.md](docs/SECURITY.md) for the full lists, the threat model and known limitations.

---

## Configuration

The server works out of the box with sensible defaults. Customize via JSON config, environment variables, or `.env` files:

```bash
# Whitelist directories
export CMD_LINE_MCP_SECURITY_WHITELISTED_DIRECTORIES="/projects,/var/data"

# Add commands (merges with defaults)
export CMD_LINE_MCP_COMMANDS_READ="jq,rg"
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for full configuration reference, MCP tool documentation, and directory security details.

---

## License

MIT
