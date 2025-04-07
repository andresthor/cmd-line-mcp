# Command-Line MCP Server

A Model Control Protocol (MCP) server that safely runs command-line arguments for Unix/macOS systems.

## Overview

This MCP server allows AI assistants to execute common Unix/macOS terminal commands through a controlled and secure interface. It supports the top 40 most used terminal commands with appropriate security measures.

## Features

- Safe execution of common Unix/macOS commands
- Security validation based on command type
- Command categorization (read, write, system)
- Interactive permission management
- Session-based approval system
- Configuration via environment variables or JSON file
- Comprehensive command filtering and pattern matching

## Supported Commands

### Read Commands
- `ls`, `pwd`, `cat`, `less`, `head`, `tail`, `grep`, `find`, `which`, `du`, `df`, `file`, etc.

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

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cmd-line-mcp.git
cd cmd-line-mcp

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package
pip install -e .
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

You can configure the server using a JSON file or environment variables:

#### Using a configuration file

Create a JSON file based on the example in `config.json.example`:

```bash
cp config.json.example config.json
# Edit config.json to customize settings
cmd-line-mcp --config config.json
```

#### Using environment variables

```bash
export CMD_LINE_MCP_LOG_LEVEL=DEBUG
export CMD_LINE_MCP_SESSION_TIMEOUT=7200
export CMD_LINE_MCP_MAX_OUTPUT_SIZE=204800
export CMD_LINE_MCP_ALLOW_USER_CONFIRMATION=true
cmd-line-mcp
```

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

3. Restart Claude for Desktop

## MCP Tools

This server provides the following MCP tools to AI assistants:

1. `execute_command`: Execute any supported command (requires approval for write/system commands)
2. `execute_read_command`: Execute read-only commands (no approval required)
3. `list_available_commands`: List all available commands by category
4. `approve_command_type`: Grant approval for a command type (write or system) for the current session

## Customizing Command Lists

You can customize the list of allowed, blocked, and categorized commands by editing the configuration file. This allows you to:

- Add custom commands to the appropriate category
- Block additional commands
- Add new dangerous patterns to match against
- Change security settings like session timeouts

## License

MIT