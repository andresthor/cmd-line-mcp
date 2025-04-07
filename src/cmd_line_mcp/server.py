"""
Command-line MCP server that safely executes Unix/macOS terminal commands.
"""

import argparse
import asyncio
import logging
import os
import subprocess
import sys
import uuid
from typing import Any, Dict, List, Optional

import mcp
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
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the MCP server.
        
        Args:
            config_path: Optional path to a configuration file
        """
        self.config = Config(config_path)
        self.session_manager = SessionManager()
        
        # Set up logging
        log_level = self.config.get("server", "log_level", "INFO")
        logger.setLevel(getattr(logging, log_level))
        
        # Load command lists from config
        self.read_commands = self.config.get("commands", "read_commands")
        self.write_commands = self.config.get("commands", "write_commands")
        self.system_commands = self.config.get("commands", "system_commands")
        self.blocked_commands = self.config.get("commands", "blocked_commands")
        self.dangerous_patterns = self.config.get("commands", "dangerous_patterns")
        
        # Initialize MCP app
        server_config = self.config.get_section("server")
        self.app = FastMCP(
            server_config.get("name", "cmd-line-mcp"),
            version=server_config.get("version", "0.1.0"),
            description=server_config.get("description", "MCP server for safely executing command-line tools")
        )
        
        # Add metadata to help clients understand capabilities
        self.app.metadata = {
            "command_capabilities": {
                "supported_commands": {
                    "read": self.read_commands,
                    "write": self.write_commands,
                    "system": self.system_commands
                },
                "blocked_commands": self.blocked_commands,
                "command_chaining": {
                    "pipe": "Supported - All commands in pipeline must be supported",
                    "semicolon": "Supported - All commands in sequence must be supported", 
                    "ampersand": "Supported - All commands must be supported"
                },
                "command_restrictions": "Special characters like $(), ${}, backticks, and I/O redirection are blocked"
            },
            "usage_examples": [
                {"command": "ls ~/Downloads", "description": "List files in downloads directory"},
                {"command": "cat ~/.bashrc", "description": "View bash configuration"},
                {"command": "du -h ~/Downloads/* | grep G", "description": "Find large files in downloads folder"},
                {"command": "find ~/Downloads -type f -name \"*.pdf\"", "description": "Find all PDF files in downloads"},
                {"command": "head -n 20 ~/Documents/notes.txt", "description": "View the first 20 lines of a file"}
            ]
        }
        
        # Register tools
        @self.app.tool()
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
            
        @self.app.tool()
        async def execute_read_command(command: str) -> Dict[str, Any]:
            """
            Execute a read-only Unix/macOS terminal command (ls, cat, grep, etc.).
            
            Args:
                command: The read-only command to execute
                
            Returns:
                A dictionary with command output and status
            """
            validation = validate_command(
                command, 
                self.read_commands, 
                self.write_commands, 
                self.system_commands, 
                self.blocked_commands, 
                self.dangerous_patterns
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
            
        @self.app.tool()
        async def list_available_commands() -> Dict[str, List[str]]:
            """
            List all available commands by category.
            
            Returns:
                A dictionary with commands grouped by category
            """
            return {
                "read_commands": self.read_commands,
                "write_commands": self.write_commands,
                "system_commands": self.system_commands,
                "blocked_commands": self.blocked_commands
            }
            
        @self.app.tool()
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
            # Provide helpful information for Claude to understand command usage
            return {
                "capabilities": self.app.metadata["command_capabilities"],
                "examples": self.app.metadata["usage_examples"],
                "recommended_approach": {
                    "finding_large_files": "Use 'du -h <directory>/* | grep G' or 'du -h <directory>/* | grep M' to find large files",
                    "file_searching": "Use 'find <directory> -type f -name \"pattern\"' for file searches",
                    "text_searching": "Use 'grep \"pattern\" <file>' to search in files",
                    "file_viewing": "Use 'cat', 'head', or 'tail' for viewing files",
                    "sorting_alternatives": "Since 'sort' is not available, consider using 'grep' with patterns to filter results"
                },
                "permissions": {
                    "read_commands": "Can be executed without confirmation",
                    "write_commands": "Require approval for first use in a session",
                    "system_commands": "Require approval for first use in a session"
                }
            }
            
        @self.app.tool()
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
        # Validate the command
        validation = validate_command(
            command, 
            self.read_commands, 
            self.write_commands, 
            self.system_commands, 
            self.blocked_commands, 
            self.dangerous_patterns
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
        
        # Check permissions for non-read commands if session_id is provided
        # and user confirmation is enabled
        if (session_id and 
            actual_command_type in ["write", "system"] and 
            self.config.get("security", "allow_user_confirmation", True)):
            
            if not self.session_manager.has_command_approval(session_id, command) and \
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
            max_output_size = self.config.get("security", "max_output_size", 100 * 1024)  # 100KB default
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
    args = parser.parse_args()
    
    server = CommandLineMCP(config_path=args.config)
    server.run()

if __name__ == "__main__":
    main()