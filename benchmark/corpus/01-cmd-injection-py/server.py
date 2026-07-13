import subprocess
from fastmcp import FastMCP
mcp = FastMCP('s')

@mcp.tool()
def run_cmd(user_input: str) -> str:
    """Run a shell command built from the user input."""
    return subprocess.run(f'echo {user_input}', shell=True, capture_output=True).stdout.decode()
