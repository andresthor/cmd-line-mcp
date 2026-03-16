# Configuration

## Configuration Methods

The server supports four configuration methods, in order of precedence:

1. **Environment variables** (highest priority)
2. **.env file**
3. **JSON configuration file**
4. **Built-in defaults** (`default_config.json`)

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
export CMD_LINE_MCP_SECURITY_AUTO_APPROVE_DIRECTORIES_IN_DESKTOP_MODE=true

# Command lists merge with defaults (not replace)
export CMD_LINE_MCP_COMMANDS_READ="awk,jq"
export CMD_LINE_MCP_COMMANDS_BLOCKED="npm,pip"
```

### JSON Configuration

Copy `default_config.json` and customize:

```json
{
  "security": {
    "whitelisted_directories": ["/home", "/tmp", "~"],
    "auto_approve_directories_in_desktop_mode": false,
    "require_session_id": false,
    "allow_command_separators": true
  },
  "commands": {
    "read": ["ls", "cat", "grep"],
    "write": ["touch", "mkdir", "rm"],
    "system": ["ps", "ping"],
    "blocked": ["sudo", "bash", "eval"]
  }
}
```

## Command Categories

| Category | Description | Examples | Requires Approval |
|----------|-------------|----------|-------------------|
| Read | Safe, read-only operations | `ls`, `cat`, `grep`, `find`, `head`, `tail`, `sort`, `wc` | No |
| Write | Data modification | `cp`, `mv`, `rm`, `mkdir`, `touch`, `chmod`, `awk`, `sed` | Yes |
| System | System-level operations | `ps`, `ping`, `curl`, `ssh`, `xargs` | Yes |
| Blocked | Dangerous commands | `sudo`, `bash`, `sh`, `python`, `eval` | Always denied |

### Command Chaining

| Method | Symbol | Example | Config |
|--------|--------|---------|--------|
| Pipes | `\|` | `ls \| grep txt` | `allow_command_separators: true` |
| Sequence | `;` | `mkdir dir; cd dir` | `allow_command_separators: true` |
| Background | `&` | `find . -name "*.log" &` | `allow_command_separators: true` |

All commands in a chain must be from the supported command list. Set `allow_command_separators: false` to disable chaining entirely.

## Directory Security

The server restricts command execution to specific directories.

### Security Modes

| Mode | Description | Best For |
|------|-------------|----------|
| **Strict** | Only whitelisted directories | Maximum security |
| **Approval** | Non-whitelisted require explicit approval | Interactive use (default) |
| **Auto-approve** | Auto-approves for Claude Desktop | Convenience |

### Directory Approval Flow

1. Command targets a directory
2. Is the directory in the global whitelist? &rarr; Allow
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
