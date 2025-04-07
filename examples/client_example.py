#!/usr/bin/env python3
"""Example client for cmd-line-mcp server."""

import argparse
import asyncio
import os
import subprocess
import sys
import json
from typing import Dict, List, Optional

async def main(server_command: str):
    """Run example client with the cmd-line-mcp server.
    
    Args:
        server_command: Command to run the server
    """
    # Start the server
    server_process = await asyncio.create_subprocess_shell(
        server_command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    print(f"Started server with PID {server_process.pid}")
    
    # Give the server a moment to start up
    await asyncio.sleep(2)
    
    try:
        # Example 1: List available commands
        print("\n=== Example 1: List available commands ===")
        result = await run_command(
            """
            import json
            import asyncio
            import sys
            import os
            
            async def main():
                from mcp.client import Client
                from mcp.transport import StdioTransport
                
                # Connect to server
                process = await asyncio.create_subprocess_shell(
                    sys.argv[1],
                    stdout=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.PIPE
                )
                
                client = Client()
                await client.connect(StdioTransport(
                    input=process.stdout,
                    output=process.stdin
                ))
                
                # List tools
                tools = await client.list_tools()
                
                # Call list_available_commands tool
                result = await client.call_tool('list_available_commands', {})
                print(json.dumps(result, indent=2))
                
                await client.close()
                process.terminate()
                
            asyncio.run(main())
            """,
            server_command
        )
        
        # Example 2: Execute a read command
        print("\n=== Example 2: Execute a read command ===")
        result = await run_command(
            """
            import json
            import asyncio
            import sys
            import os
            
            async def main():
                from mcp.client import Client
                from mcp.transport import StdioTransport
                
                # Connect to server
                process = await asyncio.create_subprocess_shell(
                    sys.argv[1],
                    stdout=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.PIPE
                )
                
                client = Client()
                await client.connect(StdioTransport(
                    input=process.stdout,
                    output=process.stdin
                ))
                
                # Call execute_read_command tool
                result = await client.call_tool('execute_read_command', {'command': 'ls -la'})
                print(json.dumps(result, indent=2))
                
                await client.close()
                process.terminate()
                
            asyncio.run(main())
            """,
            server_command
        )
        
        # Example 3: Execute a write command (requires approval)
        print("\n=== Example 3: Execute a write command (requires approval) ===")
        result = await run_command(
            """
            import json
            import asyncio
            import sys
            import os
            import uuid
            
            async def main():
                from mcp.client import Client
                from mcp.transport import StdioTransport
                
                # Connect to server
                process = await asyncio.create_subprocess_shell(
                    sys.argv[1],
                    stdout=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.PIPE
                )
                
                client = Client()
                await client.connect(StdioTransport(
                    input=process.stdout,
                    output=process.stdin
                ))
                
                # Generate a session ID
                session_id = str(uuid.uuid4())
                print(f"Session ID: {session_id}")
                
                # Try to execute write command (will require approval)
                result = await client.call_tool('execute_command', {
                    'command': 'mkdir test_dir', 
                    'session_id': session_id
                })
                print("First attempt (before approval):")
                print(json.dumps(result, indent=2))
                
                if result.get('requires_approval'):
                    # Approve the command type
                    approval = await client.call_tool('approve_command_type', {
                        'command_type': result.get('command_type'),
                        'session_id': session_id,
                        'remember': True
                    })
                    print("Approval result:")
                    print(json.dumps(approval, indent=2))
                    
                    # Try again after approval
                    result = await client.call_tool('execute_command', {
                        'command': 'mkdir test_dir',
                        'session_id': session_id
                    })
                    print("Second attempt (after approval):")
                    print(json.dumps(result, indent=2))
                    
                    # Clean up
                    cleanup = await client.call_tool('execute_command', {
                        'command': 'rmdir test_dir',
                        'session_id': session_id
                    })
                
                await client.close()
                process.terminate()
                
            asyncio.run(main())
            """,
            server_command
        )
    finally:
        # Kill the server
        if server_process.returncode is None:
            server_process.terminate()
            await server_process.wait()
        
        print(f"\nServer terminated with code {server_process.returncode}")

async def run_command(script: str, server_command: str) -> Dict:
    """Run a Python script with the server command as argument.
    
    Args:
        script: Python script to run
        server_command: Command to run the server
        
    Returns:
        The result of the script
    """
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-c", script, server_command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    stdout, stderr = await proc.communicate()
    
    if proc.returncode != 0:
        print(f"Error running script: {stderr.decode('utf-8')}")
        return {}
    
    stdout_str = stdout.decode("utf-8")
    print(stdout_str)
    return stdout_str

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Example client for cmd-line-mcp")
    parser.add_argument("--server", "-s", default="cmd-line-mcp", 
                        help="Command to run the server (default: cmd-line-mcp)")
    args = parser.parse_args()
    
    asyncio.run(main(args.server))