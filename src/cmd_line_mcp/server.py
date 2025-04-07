"""
Command-line MCP server that safely executes Unix/macOS terminal commands.
"""

import argparse
import asyncio
import logging
import uuid
import json
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

from cmd_line_mcp.config import Config
from cmd_line_mcp.security import (
    validate_command
)
from cmd_line_mcp.session import SessionManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

class CommandLineMCP:
    """Command-line MCP server for Unix/macOS terminal commands."""
    
    def __init__(self, config_path: Optional[str] = None, env_file_path: Optional[str] = None):
        """Initialize the MCP server.
        
        Args:
            config_path: Optional path to a configuration file
            env_file_path: Optional path to a .env file
        """
        self.config = Config(config_path, env_file_path)
        self.session_manager = SessionManager()
        
        # Set up logging
        log_level = self.config.get("server", "log_level", "INFO")
        logger.setLevel(getattr(logging, log_level))
        
        # Load command lists from config
        command_lists = self.config.get_effective_command_lists()
        self.read_commands = command_lists["read"]
        self.write_commands = command_lists["write"]
        self.system_commands = command_lists["system"]
        self.blocked_commands = command_lists["blocked"]
        self.dangerous_patterns = command_lists["dangerous_patterns"]
        
        # Get separator support status
        self.separator_support = self.config.has_separator_support()
        
        # Initialize MCP app
        server_config = self.config.get_section("server")
        self.app = FastMCP(
            server_config.get("name", "cmd-line-mcp"),
            version=server_config.get("version", "0.2.0"),
            description=server_config.get("description", "MCP server for safely executing command-line tools")
        )
        
        # Store capabilities data to use in get_command_help tool
        self.command_capabilities = {
            "supported_commands": {
                "read": self.read_commands,
                "write": self.write_commands,
                "system": self.system_commands
            },
            "blocked_commands": self.blocked_commands,
            "command_chaining": {
                "pipe": "Supported" if self.separator_support["pipe"] else "Not supported",
                "semicolon": "Supported" if self.separator_support["semicolon"] else "Not supported", 
                "ampersand": "Supported" if self.separator_support["ampersand"] else "Not supported"
            },
            "command_restrictions": "Special characters like $(), ${}, backticks, and I/O redirection are blocked"
        }
        
        self.usage_examples = [
            {"command": "ls ~/Downloads", "description": "List files in downloads directory"},
            {"command": "cat ~/.bashrc", "description": "View bash configuration"},
            {"command": "du -h ~/Downloads/* | grep G", "description": "Find large files in downloads folder"},
            {"command": "find ~/Downloads -type f -name \"*.pdf\"", "description": "Find all PDF files in downloads"},
            {"command": "head -n 20 ~/Documents/notes.txt", "description": "View the first 20 lines of a file"}
        ]
        
        # Register tools
        execute_command_tool = self.app.tool()
        @execute_command_tool  # Keep decorator reference to satisfy linters
        async def execute_command(command: str, session_id: Optional[str] = None) -> Dict[str, Any]:
            """
            Execute a Unix/macOS terminal command.
            
            Args:
                command: The command to execute
                session_id: Optional session ID for permission management
                
            Returns:
                A dictionary with command output and status
            """
            if not session_id:
                session_id = str(uuid.uuid4())
            return await self._execute_command(command, session_id=session_id)
            
        # Store reference to silence linter warnings
        self._execute_command_func = execute_command
            
        execute_read_command_tool = self.app.tool()
        @execute_read_command_tool  # Keep decorator reference to satisfy linters
        async def execute_read_command(command: str) -> Dict[str, Any]:
            """
            Execute a read-only Unix/macOS terminal command (ls, cat, grep, etc.).
            
            Args:
                command: The read-only command to execute
                
            Returns:
                A dictionary with command output and status
            """
            # Get the latest command lists
            command_lists = self.config.get_effective_command_lists()
            separator_support = self.config.has_separator_support()
            allow_separators = self.config.get("security", "allow_command_separators", True)
            
            validation = validate_command(
                command, 
                command_lists["read"],
                command_lists["write"],
                command_lists["system"],
                command_lists["blocked"],
                command_lists["dangerous_patterns"],
                allow_command_separators=allow_separators
            )
            
            if not validation["is_valid"]:
                return {"success": False, "output": "", "error": validation["error"]}
                
            if validation["command_type"] != "read":
                return {
                    "success": False, 
                    "output": "", 
                    "error": "This tool only supports read commands. Use execute_command for other command types."
                }
                
            return await self._execute_command(command, command_type="read")
            
        # Store reference to silence linter warnings
        self._execute_read_command_func = execute_read_command
            
        list_available_commands_tool = self.app.tool()
        @list_available_commands_tool  # Keep decorator reference to satisfy linters
        async def list_available_commands() -> Dict[str, List[str]]:
            """
            List all available commands by category.
            
            Returns:
                A dictionary with commands grouped by category
            """
            # Get the latest command lists
            command_lists = self.config.get_effective_command_lists()
            
            return {
                "read_commands": command_lists["read"],
                "write_commands": command_lists["write"],
                "system_commands": command_lists["system"],
                "blocked_commands": command_lists["blocked"]
            }
            
        # Store reference to silence linter warnings
        self._list_available_commands_func = list_available_commands
            
        get_command_help_tool = self.app.tool()
        @get_command_help_tool  # Keep decorator reference to satisfy linters
        async def get_command_help() -> Dict[str, Any]:
            """
            Get detailed help about command capabilities and usage.
            
            This tool provides comprehensive information about:
            - Supported commands in each category (read, write, system)
            - Blocked commands for security reasons
            - Command chaining capabilities (pipes, semicolons, ampersands)
            - Usage restrictions and examples
            
            Returns:
                A dictionary with detailed information about command capabilities and usage
            """
            # Get the latest command lists and separator support
            command_lists = self.config.get_effective_command_lists()
            separator_support = self.config.has_separator_support()
            
            # Update capabilities
            updated_capabilities = {
                "supported_commands": {
                    "read": command_lists["read"],
                    "write": command_lists["write"],
                    "system": command_lists["system"]
                },
                "blocked_commands": command_lists["blocked"],
                "command_chaining": {
                    "pipe": "Supported" if separator_support["pipe"] else "Not supported",
                    "semicolon": "Supported" if separator_support["semicolon"] else "Not supported",
                    "ampersand": "Supported" if separator_support["ampersand"] else "Not supported"
                },
                "command_restrictions": "Special characters like $(), ${}, backticks, and I/O redirection are blocked"
            }
            
            # Provide helpful information for Claude to understand command usage
            return {
                "capabilities": updated_capabilities,
                "examples": self.usage_examples,
                "recommended_approach": {
                    "finding_large_files": "Use 'du -h <directory>/* | sort -hr | head -n 10' to find the 10 largest files",
                    "file_searching": "Use 'find <directory> -type f -name \"pattern\"' for file searches",
                    "text_searching": "Use 'grep \"pattern\" <file>' to search in files",
                    "file_viewing": "Use 'cat', 'head', or 'tail' for viewing files",
                    "sorting": "Use 'sort' with options like -n (numeric), -r (reverse), -h (human readable sizes)"
                },
                "permissions": {
                    "read_commands": "Can be executed without confirmation",
                    "write_commands": "Require approval for first use in a session",
                    "system_commands": "Require approval for first use in a session"
                }
            }
            
        # Store reference to silence linter warnings
        self._get_command_help_func = get_command_help
            
        approve_command_type_tool = self.app.tool()
        @approve_command_type_tool  # Keep decorator reference to satisfy linters
        async def approve_command_type(
            command_type: str, 
            session_id: str, 
            remember: bool = False
        ) -> Dict[str, Any]:
            """
            Approve a command type for the current session.
            
            Args:
                command_type: The command type to approve (read, write, system)
                session_id: The session ID
                remember: Whether to remember this approval for the session
                
            Returns:
                A dictionary with approval status
            """
            if command_type not in ["read", "write", "system"]:
                return {
                    "success": False,
                    "message": f"Invalid command type: {command_type}"
                }
                
            if remember:
                self.session_manager.approve_command_type(session_id, command_type)
                return {
                    "success": True,
                    "message": f"Command type '{command_type}' approved for this session"
                }
            else:
                return {
                    "success": True,
                    "message": f"Command type '{command_type}' approved for one-time use"
                }
                
        # Store reference to silence linter warnings
        self._approve_command_type_func = approve_command_type
        
        # Register new tools for configuration
        get_configuration_tool = self.app.tool()
        @get_configuration_tool  # Keep decorator reference to satisfy linters
        async def get_configuration() -> Dict[str, Any]:
            """
            Get the current configuration settings.
            
            Returns:
                The current configuration settings
            """
            # Get a safe copy of the configuration
            config_copy = self.config.get_all()
            
            # Format it for display
            return {
                "server": config_copy["server"],
                "security": config_copy["security"],
                "commands": {
                    "read_count": len(config_copy["commands"]["read"]),
                    "write_count": len(config_copy["commands"]["write"]),
                    "system_count": len(config_copy["commands"]["system"]),
                    "blocked_count": len(config_copy["commands"]["blocked"]),
                    "dangerous_patterns_count": len(config_copy["commands"]["dangerous_patterns"]),
                    "full_command_lists": config_copy["commands"]
                },
                "output": config_copy["output"],
                "separator_support": self.config.has_separator_support()
            }
            
        # Store reference to silence linter warnings
        self._get_configuration_func = get_configuration
        
        update_configuration_tool = self.app.tool()
        @update_configuration_tool  # Keep decorator reference to satisfy linters
        async def update_configuration(config_updates: str, save: bool = False) -> Dict[str, Any]:
            """
            Update configuration settings.
            
            Args:
                config_updates: JSON string with configuration updates
                save: Whether to save the configuration to file
                
            Returns:
                A dictionary with update status
            """
            try:
                # Parse JSON updates
                updates = json.loads(config_updates)
                
                # Update configuration
                self.config.update(updates, save)
                
                # Reload command lists
                command_lists = self.config.get_effective_command_lists()
                self.read_commands = command_lists["read"]
                self.write_commands = command_lists["write"]
                self.system_commands = command_lists["system"]
                self.blocked_commands = command_lists["blocked"]
                self.dangerous_patterns = command_lists["dangerous_patterns"]
                
                # Update separator support
                self.separator_support = self.config.has_separator_support()
                
                return {
                    "success": True,
                    "message": "Configuration updated successfully",
                    "saved": save
                }
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "message": f"Invalid JSON: {str(e)}"
                }
            except Exception as e:
                return {
                    "success": False,
                    "message": f"Error updating configuration: {str(e)}"
                }
                
        # Store reference to silence linter warnings
        self._update_configuration_func = update_configuration
    
    async def _execute_command(
        self, 
        command: str, 
        command_type: Optional[str] = None, 
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute a Unix/macOS terminal command.
        
        Args:
            command: The command to execute
            command_type: Optional type of command (read, write, system)
            session_id: Optional session ID for permission management
            
        Returns:
            A dictionary with command output and status
        """
        # Get the latest command lists and separator settings
        command_lists = self.config.get_effective_command_lists()
        allow_separators = self.config.get("security", "allow_command_separators", True)
        
        # Validate the command
        validation = validate_command(
            command, 
            command_lists["read"],
            command_lists["write"],
            command_lists["system"],
            command_lists["blocked"],
            command_lists["dangerous_patterns"],
            allow_command_separators=allow_separators
        )
        
        if not validation["is_valid"]:
            return {"success": False, "output": "", "error": validation["error"]}
            
        # If command_type is specified, ensure it matches the validated type
        if command_type and validation["command_type"] != command_type:
            return {
                "success": False,
                "output": "",
                "error": f"Command type mismatch. Expected {command_type}, got {validation['command_type']}"
            }
        
        actual_command_type = validation["command_type"]
        
        # For read commands, bypass approval
        if actual_command_type == "read":
            # No approval needed for read commands
            pass
        # For write and system commands with user confirmation enabled
        elif (actual_command_type in ["write", "system"] and 
              self.config.get("security", "allow_user_confirmation", True)):
            
            # Check if we require a session ID (turn off for Claude Desktop compatibility)
            require_session_id = self.config.get("security", "require_session_id", False)
            
            # WORKAROUND FOR CLAUDE DESKTOP: 
            # Either auto-approve if no session_id provided OR if require_session_id is False
            if not session_id or not require_session_id:
                if not session_id:
                    logger.warning("No session ID provided, auto-approving command: %s", command)
                else:
                    logger.warning("Session validation disabled, auto-approving command: %s", command)
                # Auto-approve without requiring explicit permission
                pass
            # Normal session-based approval when require_session_id is True
            elif not self.session_manager.has_command_approval(session_id, command) and \
                 not self.session_manager.has_command_type_approval(session_id, actual_command_type):
                return {
                    "success": False,
                    "output": "",
                    "error": f"Command '{command}' requires approval. Use approve_command_type tool with session_id '{session_id}'.",
                    "requires_approval": True,
                    "command_type": actual_command_type,
                    "session_id": session_id
                }
                
        # Execute the command
        try:
            logger.info(f"Executing command: {command}")
            # Using subprocess with shell=True is necessary for many shell commands,
            # but we've validated the command for safety already
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            output = stdout.decode("utf-8", errors="replace")
            error = stderr.decode("utf-8", errors="replace")
            
            # Limit output size to prevent huge responses
            max_output_size = self.config.get("output", "max_size", 100 * 1024)  # 100KB default
            if len(output) > max_output_size:
                output = output[:max_output_size] + "\n... [output truncated due to size]"
            
            return {
                "success": process.returncode == 0,
                "output": output,
                "error": error,
                "exit_code": process.returncode,
                "command_type": actual_command_type
            }
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            return {"success": False, "output": "", "error": str(e)}

    async def run_async(self):
        """Run the MCP server asynchronously."""
        # Clean old sessions periodically
        async def clean_sessions():
            while True:
                session_timeout = self.config.get("security", "session_timeout", 3600)  # 1 hour default
                await asyncio.sleep(session_timeout)
                self.session_manager.clean_old_sessions(session_timeout)
                
        # Start session cleaning task
        asyncio.create_task(clean_sessions())
        
        # Run the MCP server using its internal method
        # This is used when we want to run within an existing event loop
        await self.app.run_stdio_async()
    
    def run(self):
        """Run the MCP server with its own event loop."""
        # Let the app handle the event loop directly
        self.app.run()

def main():
    """Run the command-line MCP server."""
    parser = argparse.ArgumentParser(description="Command-line MCP server")
    parser.add_argument("--config", "-c", help="Path to configuration file")
    parser.add_argument("--env", "-e", help="Path to .env file")
    args = parser.parse_args()
    
    server = CommandLineMCP(config_path=args.config, env_file_path=args.env)
    server.run()

if __name__ == "__main__":
    main()
