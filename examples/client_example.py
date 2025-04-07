#!/usr/bin/env python3
"""Example client for cmd-line-mcp server."""

import argparse
import asyncio
import sys

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
        # Example 1: Get command help and metadata
        print("\n=== Example 1: Get command help and metadata ===")
        _ = await run_command(
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
                print("Available tools:")
                for tool in tools:
                    print(f"- {tool.name}")
                
                # Call get_command_help tool to get detailed capabilities
                result = await client.call_tool('get_command_help', {})
                print("\\nCommand help and capabilities:")
                print(json.dumps(result, indent=2))
                
                # Call list_available_commands tool
                commands = await client.call_tool('list_available_commands', {})
                print("\\nAvailable commands by category:")
                print(json.dumps(commands, indent=2))
                
                await client.close()
                process.terminate()
                
            asyncio.run(main())
            """,
            server_command
        )
        
        # Example 2: Execute a read command
        print("\n=== Example 2: Execute a read command ===")
        _ = await run_command(
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
                
                # Call execute_read_command tool with a simple command
                result = await client.call_tool('execute_read_command', {'command': 'ls -la'})
                print("Simple command (ls -la):")
                print(json.dumps(result, indent=2))
                
                # Example of using a pipe command
                result = await client.call_tool('execute_read_command', {'command': 'du -h ~ | grep -E "M|G" | sort -hr | head -5'})
                print("\nPipe command (finding large files):")
                print(json.dumps(result, indent=2))
                
                await client.close()
                process.terminate()
                
            asyncio.run(main())
            """,
            server_command
        )
        
        # Example 3: Execute a write command with session approval
        print("\n=== Example 3: Execute a write command (requires approval) ===")
        _ = await run_command(
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
                
                # Try to execute write command (will require approval if require_session_id is True)
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
                else:
                    # If auto-approved (Claude Desktop compatibility mode), clean up
                    print("Command auto-approved (Claude Desktop compatibility mode)")
                    cleanup = await client.call_tool('execute_command', {
                        'command': 'rmdir test_dir',
                        'session_id': session_id
                    })
                    print("Cleanup result:")
                    print(json.dumps(cleanup, indent=2))
                
                await client.close()
                process.terminate()
                
            asyncio.run(main())
            """,
            server_command
        )
        
        # Example 4: Command chaining examples
        print("\n=== Example 4: Command chaining examples ===")
        _ = await run_command(
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
                
                # Example 1: Using pipes
                print("Example with pipes (|):")
                result = await client.call_tool('execute_read_command', {
                    'command': 'find /tmp -type f -name "*.txt" | grep -v "temp" | head -3'
                })
                print(json.dumps(result, indent=2))
                
                # Example 2: Using semicolons
                print("\\nExample with semicolons (;):")
                result = await client.call_tool('execute_read_command', {
                    'command': 'cd /tmp; ls -la; pwd'
                })
                print(json.dumps(result, indent=2))
                
                # Example 3: Using complex pipe chains with non-command segments
                print("\\nExample with complex pipe chain:")
                result = await client.call_tool('execute_read_command', {
                    'command': 'du -h ~ | grep -v "Permission denied" | grep -E "G" | sort -hr | head -3'
                })
                print(json.dumps(result, indent=2))
                
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

async def run_command(script: str, server_command: str) -> str:
    """Run a Python script with the server command as argument.
    
    Args:
        script: Python script to run
        server_command: Command to run the server
        
    Returns:
        The stdout output of the script as a string
    """
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-c", script, server_command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    stdout, stderr = await proc.communicate()
    
    if proc.returncode != 0:
        print(f"Error running script: {stderr.decode('utf-8')}")
        return ""
    
    stdout_str = stdout.decode("utf-8")
    print(stdout_str)
    return stdout_str

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Example client for cmd-line-mcp")
    parser.add_argument("--server", "-s", default="cmd-line-mcp", 
                        help="Command to run the server (default: cmd-line-mcp)")
    args = parser.parse_args()
    
    asyncio.run(main(args.server))
