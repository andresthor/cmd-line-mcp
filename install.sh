#!/bin/bash
# Simple installation script for cmd-line-mcp

set -e

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install the package
echo "Installing cmd-line-mcp..."
pip install -e .

# Create a config file if it doesn't exist
if [ ! -f "config.json" ]; then
    echo "Creating configuration file..."
    cp config.json.example config.json
    echo "You can customize your configuration in config.json"
fi

# Display information about how to set up with Claude for Desktop
echo ""
echo "Installation complete!"
echo ""
echo "To use with Claude for Desktop, add the following to your Claude desktop config file:"
echo "  (~/.config/Claude/claude_desktop_config.json on Linux)"
echo "  (~/Library/Application Support/Claude/claude_desktop_config.json on macOS)"
echo ""
echo "{" 
echo '  "mcpServers": {'
echo '    "cmd-line": {'
echo '      "command": "'$(pwd)'/venv/bin/cmd-line-mcp",'
echo '      "args": ["--config", "'$(pwd)'/config.json"]'
echo '    }'
echo '  }'
echo "}"
echo ""
echo "To run the server manually: venv/bin/cmd-line-mcp --config config.json"
echo "To try the example client: venv/bin/python examples/client_example.py --server \"venv/bin/cmd-line-mcp --config config.json\""
echo ""
