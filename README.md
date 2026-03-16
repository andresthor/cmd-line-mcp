# Command-Line MCP Server

[![PyPI version](https://badge.fury.io/py/cmd-line-mcp.svg)](https://badge.fury.io/py/cmd-line-mcp)
[![Python Versions](https://img.shields.io/pypi/pyversions/cmd-line-mcp.svg)](https://pypi.org/project/cmd-line-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An MCP server that lets AI assistants run terminal commands safely. Commands are categorized (read/write/system), directories are whitelisted, and dangerous patterns are blocked automatically.

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

## Claude Desktop Setup

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cmd-line": {
      "command": "/path/to/venv/bin/cmd-line-mcp",
      "args": ["--config", "/path/to/config.json"],
      "env": {
        "CMD_LINE_MCP_SECURITY_REQUIRE_SESSION_ID": "false",
        "CMD_LINE_MCP_SECURITY_AUTO_APPROVE_DIRECTORIES_IN_DESKTOP_MODE": "true"
      }
    }
  }
}
```

Restart Claude Desktop after saving.

> **Tip**: Set `require_session_id: false` to prevent approval loops in Claude Desktop.

## How It Works

Commands go through a validation pipeline before execution:

1. **Pattern matching** &mdash; blocks dangerous constructs (`system()`, shell escapes, etc.)
2. **Command classification** &mdash; each command must be in the read, write, system, or blocked list
3. **Directory check** &mdash; target directory must be whitelisted or session-approved
4. **Approval check** &mdash; write/system commands require session approval

Pipes, semicolons, and `&` are supported &mdash; each segment is validated independently.

### What's Allowed

| Category | Commands | Approval |
|----------|----------|----------|
| **Read** | `ls`, `cat`, `grep`, `find`, `head`, `tail`, `sort`, `wc`, ... | Auto |
| **Write** | `cp`, `mv`, `rm`, `mkdir`, `touch`, `chmod`, `awk`, `sed`, ... | Required |
| **System** | `ps`, `ping`, `curl`, `ssh`, `xargs`, ... | Required |
| **Blocked** | `sudo`, `bash`, `sh`, `python`, `eval`, ... | Always denied |

### What's Blocked

Shells, scripting interpreters, and known command-execution vectors are blocked &mdash; including indirect execution through `awk system()`, `sed /e`, `find -exec`, `tar --checkpoint-action`, `env`, and `xargs`. See [docs/SECURITY.md](docs/SECURITY.md) for the full list.

## Configuration

The server works out of the box with sensible defaults. Customize via JSON config, environment variables, or `.env` files:

```bash
# Whitelist directories
export CMD_LINE_MCP_SECURITY_WHITELISTED_DIRECTORIES="/projects,/var/data"

# Add commands (merges with defaults)
export CMD_LINE_MCP_COMMANDS_READ="jq,rg"
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for full configuration reference, MCP tool documentation, and directory security details.

## License

MIT
