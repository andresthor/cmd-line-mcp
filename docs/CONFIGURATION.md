# Configuration

## Configuration Methods

The server supports four configuration methods, in order of precedence:

1. **Environment variables** (highest priority)
2. **.env file**
3. **JSON configuration file**
4. **Built-in defaults** (`src/cmd_line_mcp/default_config.json`, shipped inside the package)

```bash
# JSON config
cmd-line-mcp --config config.json

# With .env overrides
cmd-line-mcp --config config.json --env .env
```

### Environment Variables

Environment variables use the pattern `CMD_LINE_MCP_<SECTION>_<SETTING>`:

```bash
export CMD_LINE_MCP_SECURITY_WHITELISTED_DIRECTORIES="/projects,/var/data"

# Command lists merge with defaults (not replace)
export CMD_LINE_MCP_COMMANDS_READ="jq,rg"
export CMD_LINE_MCP_COMMANDS_BLOCKED="npm,pip"
```

### JSON Configuration

Copy `src/cmd_line_mcp/default_config.json` and customize. Lists set in a JSON config replace the defaults rather than merging:

```json
{
  "security": {
    "whitelisted_directories": ["/home", "/tmp", "~"],
    "auto_approve_directories_in_desktop_mode": false,
    "require_session_id": false,
    "allow_command_separators": true,
    "allow_user_confirmation": true,
    "command_timeout": 60
  },
  "commands": {
    "read": ["ls", "cat", "grep"],
    "write": ["touch", "mkdir", "rm"],
    "system": ["ps", "ping"],
    "blocked": ["sudo", "bash", "eval"]
  },
  "output": {
    "max_size": 102400
  }
}
```

### Security Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `whitelisted_directories` | `~/Downloads`, `/tmp`, `/usr/local/share` | Directories commands may touch without approval |
| `require_session_id` | `false` | When `false`, write/system commands are auto-approved unless `allow_user_confirmation` is `false` |
| `allow_user_confirmation` | `true` | When `false`, write/system commands are denied unless approved for the session with `approve_command_type` |
| `auto_approve_directories_in_desktop_mode` | `false` | When `true` (with `require_session_id: false`), every directory is approved on use, which disables directory confinement |
| `allow_command_separators` | `true` | When `false`, any input with more than one command is rejected, pipes included |
| `command_timeout` | `60` | Seconds before a command's process group is killed |
| `session_timeout` | `3600` | Seconds before an idle session and its approvals expire |

`output.max_size` (default 102400 bytes) caps stdout and stderr **combined**; the command is killed when it is reached and the result has `truncated: true`. A timeout sets `timed_out: true`.

> [!WARNING]
> Write/system commands are auto-approved when `allow_user_confirmation` is `true` and either `require_session_id` is `false` or the client sends no session ID. See [SECURITY.md](SECURITY.md#known-limitations).

## Command Categories

| Category | Description | Examples | Requires Approval |
|----------|-------------|----------|-------------------|
| Read | Safe, read-only operations | `ls`, `cat`, `grep`, `head`, `tail`, `wc`, `du` | No |
| Write | Data modification | `cp`, `mv`, `rm`, `mkdir`, `touch`, `chmod`, `gzip`, `echo` | Yes |
| System | System-level operations | `ps`, `ping`, `netstat`, `who` | Yes |
| Blocked | Dangerous commands | `sudo`, `bash`, `sh`, `python`, `eval`, `env`, `xargs` | Always denied |

Commands on the hard-blocked floor (`policy.HARD_BLOCKED`: shells, interpreters and wrappers such as `env`, `xargs` and `timeout`) are rejected as a command even if a config lists them. See [SECURITY.md](SECURITY.md#hard-blocked-floor).

An output redirect (`>` or `>>`, except to `/dev/null`) makes any command at least a write command.

### Command Chaining

| Method | Symbol | Example | Config |
|--------|--------|---------|--------|
| Pipes | `\|` | `ls \| grep txt` | `allow_command_separators: true` |
| Sequence | `;` | `mkdir dir; ls dir` | `allow_command_separators: true` |
| And / Or | `&&`, `\|\|` | `mkdir dir && ls dir` | `allow_command_separators: true` |

All commands in a chain must be from the supported command list. Set `allow_command_separators: false` to disable chaining entirely, pipes included. Background `&` is not supported; see [SECURITY.md](SECURITY.md#accepted-syntax) for the full syntax.

## Directory Security

The server restricts command execution to specific directories.

### Security Modes

| Mode | Description | Best For |
|------|-------------|----------|
| **Strict** | Only whitelisted directories | Maximum security |
| **Approval** | Non-whitelisted require explicit approval | Interactive use (default) |
| **Auto-approve** | Auto-approves every directory for Claude Desktop; disables directory confinement | Not recommended |

### Directory Approval Flow

1. Command touches a path (operand, glob match, file option or redirect target)
2. Is its directory in the global whitelist? &rarr; Allow
3. Has the directory been approved this session? &rarr; Allow
4. Otherwise &rarr; Request approval (persists for session)

### Path Formats

- Absolute paths: `/home/user/documents`
- Home directory: `~`
- User subdirectories: `~/Downloads`
- Glob patterns in whitelist: `/projects/*`

## MCP Tools

| Tool | Purpose | Needs Approval |
|------|---------|----------------|
| `execute_command` | Run any command type | Yes, for write/system |
| `execute_read_command` | Run read-only commands | Directory approval only |
| `approve_directory` | Grant access to a directory | N/A |
| `approve_command_type` | Grant permission for command category | N/A |
| `list_directories` | Show authorized directories | No |
| `list_available_commands` | Show command categories | No |
| `get_command_help` | Get command usage guidance | No |
| `get_configuration` | View current settings | No |

### Tool Examples

```python
# Read commands
result = await execute_read_command("ls -la ~/Documents")

# Write/system commands (may require approval)
result = await execute_command(
    command="mkdir -p ~/Projects/new-folder",
    session_id="session123"
)

# Directory management
dirs = await list_directories(session_id="session123")
result = await approve_directory(
    directory="/projects/my-data",
    session_id="session123"
)
```
