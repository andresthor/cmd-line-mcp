# Command-Line MCP Server

A highly configurable Model Control Protocol (MCP) server that safely runs command-line arguments for Unix/macOS systems.

## Overview

This MCP server allows AI assistants to execute common Unix/macOS terminal commands through a controlled and secure interface. It supports the top ~40 most used terminal commands with appropriate security measures and offers extensive customization options. The command lists, security rules, and server behavior can all be tailored to your specific needs using configuration files, environment variables, or runtime updates.

## Features

- Safe execution of common Unix/macOS commands
- Security validation based on command type
- Command categorization (read, write, system)
- Interactive permission management
- Session-based approval system
- Configuration via environment variables or JSON file
- Comprehensive command filtering and pattern matching
- Support for command chaining via pipes (`|`), semicolons (`;`), and ampersands (`&`)
- Claude Desktop compatibility mode with auto-approval
- Detailed command metadata and help for AI assistants

## Supported Commands

### Read Commands
- `ls`, `pwd`, `cat`, `less`, `head`, `tail`, `grep`, `find`, `which`, `du`, `df`, `file`, `sort`, etc.

### Write Commands  
- `cp`, `mv`, `rm`, `mkdir`, `rmdir`, `touch`, `chmod`, `chown`, etc.

### System Commands
- `ps`, `top`, `htop`, `who`, `netstat`, `ifconfig`, `ping`, etc.

## Security Features

- Command categorization for permission control
- Blocked dangerous commands (sudo, eval, etc.)
- Pattern matching to prevent dangerous operations
- Session management for persistent approvals
- Per-session permission granting
- Option to grant approval for a command type for the entire session
- Automatic session timeouts
- Secure handling of command chaining (pipes, sequences, etc.)
- Configurable security options for different environments

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cmd-line-mcp.git
cd cmd-line-mcp

# Run the install script (Linux/macOS)
./install.sh

# Or install manually:
python -m venv venv
source venv/bin/activate
pip install -e .
cp config.json.example config.json  # Create initial config
```

## Usage

### Running the Server

```bash
# Run with default configuration
cmd-line-mcp

# Run with custom configuration file
cmd-line-mcp --config /path/to/config.json
```

### Configuration

You can configure the server using three methods:

1. JSON configuration file (recommended for complete configuration)
2. Environment variables (for overriding specific settings)
3. `.env` file (for environment-specific overrides)

**Configuration Best Practices:**
- Use the JSON configuration file as your primary configuration method
- Use environment variables or `.env` files for environment-specific overrides
- JSON provides comprehensive configuration, while env vars are better for quick overrides

#### Using a configuration file

Create a JSON file based on the example in `config.json.example`:

```bash
cp config.json.example config.json
# Edit config.json to customize settings
cmd-line-mcp --config config.json
```

The configuration file has this structure:

```json
{
  "server": {
    "name": "cmd-line-mcp",
    "version": "0.2.0",
    "description": "MCP server for safely executing command-line tools",
    "log_level": "INFO"
  },
  "security": {
    "session_timeout": 3600,
    "max_output_size": 102400,
    "allow_user_confirmation": true,
    "require_session_id": false,
    "allow_command_separators": true
  },
  "commands": {
    "read": [
      "ls", "pwd", "cat", "less", "head", "tail", "grep",
      "find", "which", "du", "df", "file", "sort", "..."
    ],
    "write": [
      "cp", "mv", "rm", "mkdir", "rmdir", "touch", "chmod", "..."
    ],
    "system": [
      "ps", "top", "htop", "who", "netstat", "ifconfig", "..."
    ],
    "blocked": [
      "sudo", "su", "bash", "sh", "zsh", "ksh", "..."
    ],
    "dangerous_patterns": [
      "rm\\s+-rf\\s+/",
      ">\\s+/dev/(sd|hd|nvme|xvd)",
      "..."
    ]
  },
  "output": {
    "max_size": 102400,
    "format": "text"
  }
}
```

#### Using environment variables and .env files for overrides

While the JSON configuration file is recommended for comprehensive configuration, you can use environment variables or a `.env` file to override specific settings. This is particularly useful for:

1. Deploying to different environments (dev, test, prod)
2. Overriding specific settings without modifying the JSON file
3. Setting environment-specific values like log levels or timeouts

**Environment Variables Example:**

```bash
# Override log level for debugging
export CMD_LINE_MCP_SERVER_LOG_LEVEL=DEBUG

# Extend session timeout
export CMD_LINE_MCP_SECURITY_SESSION_TIMEOUT=7200

# Add a custom command to the read commands list (comma-separated)
export CMD_LINE_MCP_COMMANDS_READ="wc,nl,column,jq" 

cmd-line-mcp --config /path/to/config.json
```

**Using a `.env` file for overrides:**

Create a `.env` file with only the settings you want to override:

```
# Set to DEBUG for more detailed logs
CMD_LINE_MCP_SERVER_LOG_LEVEL=DEBUG

# Extend session timeout to 2 hours
CMD_LINE_MCP_SECURITY_SESSION_TIMEOUT=7200

# For Claude Desktop compatibility
CMD_LINE_MCP_SECURITY_REQUIRE_SESSION_ID=false
```

Run the server with the base config plus `.env` overrides:

```bash
cmd-line-mcp --config /path/to/config.json --env /path/to/.env
```

**Configuration Precedence Order:**

The configuration methods follow this precedence order (from lowest to highest):
1. Default configuration (built-in)
2. Config file from CMD_LINE_MCP_CONFIG environment variable
3. Config file from --config parameter
4. `.env` file
5. Environment variables (highest precedence)

This means environment variables will override values from the `.env` file, which will override values from the JSON configuration file.

### Using with Claude for Desktop

1. Install Claude for Desktop from [https://claude.ai/download](https://claude.ai/download)
2. Configure Claude for Desktop to use this MCP server:

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cmd-line": {
      "command": "/path/to/venv/bin/cmd-line-mcp",
      "args": ["--config", "/path/to/config.json"]
    }
  }
}
```

You can also specify environment variable overrides directly in the Claude Desktop configuration:

```json
{
  "mcpServers": {
    "cmd-line": {
      "command": "/path/to/venv/bin/cmd-line-mcp",
      "args": ["--config", "/path/to/config.json"],
      "env": {
        "CMD_LINE_MCP_SERVER_LOG_LEVEL": "DEBUG",
        "CMD_LINE_MCP_SECURITY_SESSION_TIMEOUT": "7200",
        "CMD_LINE_MCP_SECURITY_REQUIRE_SESSION_ID": "false"
      }
    }
  }
}
```

For best compatibility with Claude Desktop, ensure these settings in your config.json:

```json
"security": {
  "require_session_id": false,  // Prevents approval loops with Claude Desktop
  "allow_user_confirmation": true
}
```

3. Restart Claude for Desktop

## MCP Tools

This server provides the following MCP tools to AI assistants:

1. `execute_command`: Execute any supported command (requires approval for write/system commands)
2. `execute_read_command`: Execute read-only commands (no approval required)
3. `list_available_commands`: List all available commands by category
4. `approve_command_type`: Grant approval for a command type (write or system) for the current session
5. `get_command_help`: Get detailed help about command capabilities and examples
6. `get_configuration`: Get the current configuration settings
7. `update_configuration`: Update configuration settings at runtime

### Configuration Tool Details

#### get_configuration

This tool retrieves the current configuration settings, including:
- Server settings (name, version, log level)
- Security settings (session timeout, command separator control)
- Command list statistics
- Output settings
- Separator support status

Example usage:
```python
config = await get_configuration()
print(f"Command separator support: {config['separator_support']}")
```

#### update_configuration

This tool allows dynamic updating of the configuration at runtime:

```python
# Update security settings
update_json = '''
{
  "security": {
    "allow_command_separators": false
  }
}
'''
result = await update_configuration(config_updates=update_json, save=False)

# Add a new command to the read list
update_json = '''
{
  "commands": {
    "read": ["ls", "pwd", "cat", "wc", "sort", "head", "tail"]
  }
}
'''
result = await update_configuration(config_updates=update_json, save=True)
```

- The `config_updates` parameter takes a JSON string with updates
- The `save` parameter determines if changes are saved to the config file
- After updating, all commands will immediately use the new settings

## Customizing Command Lists

You can customize the list of allowed, blocked, and categorized commands using either the configuration file or environment variable overrides.

### Using JSON Configuration

To customize commands in the JSON configuration file:

```json
{
  "commands": {
    "read": [
      "ls", "pwd", "cat", "less", "head", "tail", "grep",
      "wc", "nl", "column", "jq" 
    ],
    "system": [
      "ps", "top", "htop", "who", "netstat", "ifconfig", "ping",
      "kubectl", "docker", "aws", "gcloud"
    ],
    "blocked": [
      "sudo", "su", "bash", "sh", "zsh", "ksh", "csh", "fish",
      "npm", "pip", "apt", "apt-get", "yum", "brew"
    ]
  }
}
```

### Using Environment Variables for Additions

Environment variables will merge with (not replace) existing command lists. This allows you to add additional commands without losing the defaults:

```bash
# Add awk and jq to the read commands list (they'll be merged with existing commands)
export CMD_LINE_MCP_COMMANDS_READ="awk,jq"

# Add container tools to the system commands list
export CMD_LINE_MCP_COMMANDS_SYSTEM="kubectl,docker,aws"

# Add package managers to the blocked commands list
export CMD_LINE_MCP_COMMANDS_BLOCKED="npm,pip,apt-get"
```

When using these commands in pipelines, they'll be properly recognized:

```bash
# Now this will work because awk has been added to allowed commands
ls -la | awk '{print $1}'

# And cloud/container commands will work too
kubectl get pods | grep "Running"
```

Or in a `.env` file:
```
# Add text processing tools to the read commands
CMD_LINE_MCP_COMMANDS_READ=awk,sed,jq

# Add package managers to the blocked commands
CMD_LINE_MCP_COMMANDS_BLOCKED=npm,pip,apt-get
```

Example: Using in Claude Desktop config for command-line tool access:
```json
{
  "mcpServers": {
    "cmd-line": {
      "command": "/path/to/venv/bin/cmd-line-mcp",
      "args": ["--config", "/path/to/config.json"],
      "env": {
        "CMD_LINE_MCP_COMMANDS_READ": "awk,sed,jq",
        "CMD_LINE_MCP_SERVER_LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

This flexibility allows you to:
- Add custom commands to the appropriate category
- Block additional commands
- Add new dangerous patterns to match against
- Change security settings like session timeouts
- Enable or disable command separator support (pipes, semicolons, ampersands)
- Configure Claude Desktop compatibility settings

### Command Chaining Support

This server supports multiple ways to chain commands, all of which can be individually enabled or disabled in the configuration:

- **Pipes (`|`)**: Connect the output of one command to the input of another
  - Example: `du -h ~/Downloads/* | grep G | sort -hr | head -10`
- **Semicolons (`;`)**: Run multiple commands in sequence
  - Example: `mkdir test; cd test; touch file.txt`
- **Ampersands (`&`)**: Run commands in the background
  - Example: `find /large/directory -name "*.log" &`

All commands in a chain must be from the supported command list.

You can configure command separator support in several ways:

1. Using the config file:
```json
"security": {
  "allow_command_separators": true
}
```

2. Using environment variables for quick overrides:
```bash
# Start with the base configuration file, but override a single setting
export CMD_LINE_MCP_SECURITY_ALLOW_COMMAND_SEPARATORS=false
cmd-line-mcp --config /path/to/config.json
```

3. Using the update_configuration tool at runtime:
```python
update_json = '{"security": {"allow_command_separators": false}}'
await update_configuration(config_updates=update_json)
```

You can also add specific separators to the `dangerous_patterns` list to block them individually.

## License

MIT
