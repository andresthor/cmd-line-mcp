# Command-Line MCP Server

[![PyPI version](https://badge.fury.io/py/cmd-line-mcp.svg)](https://badge.fury.io/py/cmd-line-mcp)
[![Python Versions](https://img.shields.io/pypi/pyversions/cmd-line-mcp.svg)](https://pypi.org/project/cmd-line-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A secure Model Control Protocol (MCP) server that allows AI assistants to execute terminal commands with controlled directory access and command permissions.

## Overview

Command-Line MCP provides a security layer between AI assistants and your terminal. It implements a dual security model:

1. **Command Permissions**: Commands are categorized as read (safe), write (changes data), or system (affects system state), with different approval requirements
2. **Directory Permissions**: Commands can only access explicitly whitelisted directories or directories approved during a session

AI assistants interact with this server using standardized MCP tools, enabling safe terminal command execution while preventing access to sensitive files or dangerous operations. You can configure the security level from highly restrictive to more permissive based on your needs.

## Key Features

| Security | Usability | Integration |
|----------|-----------|-------------|
| Directory whitelisting | Command categorization (read/write/system) | Claude Desktop compatibility |
| Command filtering | Persistent session permissions | Standard MCP protocol |
| Pattern matching | Command chaining (pipes, etc.) | Auto-approval options |
| Dangerous command blocking | Intuitive approval workflow | Multiple config methods |

## Supported Commands (out of the box)

### Read Commands
- `ls`, `pwd`, `cat`, `less`, `head`, `tail`, `grep`, `find`, `which`, `du`, `df`, `file`, `sort`, etc.

### Write Commands  
- `cp`, `mv`, `rm`, `mkdir`, `rmdir`, `touch`, `chmod`, `chown`, etc.

### System Commands
- `ps`, `top`, `htop`, `who`, `netstat`, `ifconfig`, `ping`, etc.

## Security Architecture

The system implements a multi-layered security approach:

```
┌───────────────────────────────────────────────────────────────┐
│                   COMMAND-LINE MCP SERVER                     │
├──────────────────┬────────────────────────┬───────────────────┤
│ COMMAND SECURITY │   DIRECTORY SECURITY   │ SESSION SECURITY  │
├──────────────────┼────────────────────────┼───────────────────┤
│ ✓ Read commands  │ ✓ Directory whitelist  │ ✓ Session IDs     │
│ ✓ Write commands │ ✓ Runtime approvals    │ ✓ Persistent      │
│ ✓ System commands│ ✓ Path validation      │   permissions     │
│ ✓ Blocked list   │ ✓ Home dir expansion   │ ✓ Auto timeouts   │
│ ✓ Pattern filters│ ✓ Subdirectory check   │ ✓ Desktop mode    │
└──────────────────┴────────────────────────┴───────────────────┘
```

All security features can be configured from restrictive to permissive based on your threat model and convenience requirements.

## Quick Start

```bash
# Install
git clone https://github.com/yourusername/cmd-line-mcp.git
cd cmd-line-mcp
python -m venv venv
source venv/bin/activate
pip install -e .
cp config.json.example config.json

# Run
cmd-line-mcp                        # With default config
cmd-line-mcp --config config.json   # With specific config
```

### Configuration Options

The server supports four configuration methods in order of precedence:

1. **Built-in default configuration** (default_config.json)
2. **JSON configuration file** (recommended for customization)
   ```bash
   cmd-line-mcp --config config.json
   ```
3. **Environment variables** (for specific overrides)
   ```bash
   export CMD_LINE_MCP_SECURITY_WHITELISTED_DIRECTORIES="~,/tmp"
   ```
4. **.env file** (for environment-specific settings)
   ```bash
   cmd-line-mcp --config config.json --env .env
   ```

The default configuration is stored in `default_config.json` and is included with the package. You can copy this file to create your own custom configuration.

#### Core Configuration Settings

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
    "system": ["ps", "ping"]
  }
}
```

#### Environment Variable Format

Environment variables use a predictable naming pattern:
```
CMD_LINE_MCP_<SECTION>_<SETTING>
```

Examples:
```bash
# Security settings
export CMD_LINE_MCP_SECURITY_WHITELISTED_DIRECTORIES="/projects,/var/data"
export CMD_LINE_MCP_SECURITY_AUTO_APPROVE_DIRECTORIES_IN_DESKTOP_MODE=true

# Command additions (these merge with defaults)
export CMD_LINE_MCP_COMMANDS_READ="awk,jq,wc"
```

### Claude Desktop Integration

#### Setup

1. Install [Claude for Desktop](https://claude.ai/download)
2. Configure in `~/Library/Application Support/Claude/claude_desktop_config.json`:

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

#### Recommended Claude Desktop Settings

For best experience, configure:
- `require_session_id: false` - Essential to prevent approval loops
- `auto_approve_directories_in_desktop_mode: true` - Optional for convenient access
- Include common directories in your whitelist

After configuration, restart Claude for Desktop.

## AI Assistant Tools

The server provides these MCP tools for AI assistants:

| Tool | Purpose | Needs Approval |
|------|---------|----------------|
| `execute_command` | Run any command type | Yes, for write/system commands |
| `execute_read_command` | Run read-only commands | Directory approval only |
| `approve_directory` | Grant access to a directory | N/A - it's an approval tool |
| `approve_command_type` | Grant permission for command category | N/A - it's an approval tool |
| `list_directories` | Show authorized directories | No |
| `list_available_commands` | Show command categories | No |
| `get_command_help` | Get command usage guidance | No |
| `get_configuration` | View current settings | No |

### Tool Examples

#### Directory Management

```python
# Check available directories
dirs = await list_directories(session_id="session123")
whitelisted = dirs["whitelisted_directories"]
approved = dirs["session_approved_directories"]

# Request permission for a directory
if "/projects/my-data" not in whitelisted and "/projects/my-data" not in approved:
    result = await approve_directory(
        directory="/projects/my-data", 
        session_id="session123"
    )
```

#### Command Execution

```python
# Read commands (read permissions enforced)
result = await execute_read_command("ls -la ~/Documents")

# Any command type (may require command type approval)
result = await execute_command(
    command="mkdir -p ~/Projects/new-folder", 
    session_id="session123"
)
```

#### Get Configuration

```python
# Check current settings
config = await get_configuration()
whitelist = config["directory_whitelisting"]["whitelisted_directories"]
```


## Directory Security System

The server restricts command execution to specific directories, preventing access to sensitive files.

### Directory Security Modes

The system supports three security modes:

| Mode | Description | Best For | Configuration |
|------|-------------|----------|--------------|
| **Strict** | Only whitelisted directories allowed | Maximum security | `auto_approve_directories_in_desktop_mode: false` |
| **Approval** | Non-whitelisted directories require explicit approval | Interactive use | Default behavior for standard clients |
| **Auto-approve** | Auto-approves directories for Claude Desktop | Convenience | `auto_approve_directories_in_desktop_mode: true` |

### Whitelisted Directory Configuration

```json
"security": {
  "whitelisted_directories": [
    "/home",                  // System directories
    "/tmp",
    "~",                      // User's home
    "~/Documents"             // Common user directories
  ],
  "auto_approve_directories_in_desktop_mode": false  // Set to true for convenience
}
```

### Directory Approval Flow

1. Command is requested in a directory
2. System checks:
   - Is the directory in the global whitelist? → **Allow**
   - Has directory been approved in this session? → **Allow**
   - Neither? → **Request approval**
3. After approval, directory remains approved for the entire session

### Path Format Support

- Absolute paths: `/home/user/documents`
- Home directory: `~` (expands to user's home)
- User subdirectories: `~/Downloads`

### Claude Desktop Integration

The server maintains a persistent session for Claude Desktop, ensuring directory approvals persist between requests and preventing approval loops.

## Command Customization

The system uses command categorization to control access:

| Category | Description | Example Commands | Requires Approval |
|----------|-------------|------------------|-------------------|
| Read | Safe operations | ls, cat, find | No |
| Write | Data modification | mkdir, rm, touch | Yes |
| System | System operations | ps, ping, ifconfig | Yes |
| Blocked | Dangerous commands | sudo, bash, eval | Always denied |

### Customization Methods

```json
// In config.json
{
  "commands": {
    "read": ["ls", "cat", "grep", "awk", "jq"],
    "write": ["mkdir", "touch", "rm"],
    "system": ["ping", "ifconfig", "kubectl"],
    "blocked": ["sudo", "bash", "eval"]
  }
}
```

**Environment Variable Method:**
```bash
# Add to existing lists, not replace (comma-separated)
export CMD_LINE_MCP_COMMANDS_READ="awk,jq"
export CMD_LINE_MCP_COMMANDS_BLOCKED="npm,pip"
```

The MCP server merges these additions with existing commands, letting you extend functionality without recreating complete command lists.

### Command Chaining

The server supports three command chaining methods:

| Method | Symbol | Example | Config Setting |
|--------|--------|---------|---------------|
| Pipes | `\|` | `ls \| grep txt` | `allow_command_separators: true` |
| Sequence | `;` | `mkdir dir; cd dir` | `allow_command_separators: true` |
| Background | `&` | `find . -name "*.log" &` | `allow_command_separators: true` |

All commands in a chain must be from the supported command list. Security checks apply to the entire chain.

**Quick Configuration:**
```json
"security": {
  "allow_command_separators": true  // Set to false to disable all chaining
}
```

To disable specific separators, add them to the `dangerous_patterns` list.

## License

MIT
