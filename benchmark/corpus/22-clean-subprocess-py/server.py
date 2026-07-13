import subprocess
from fastmcp import FastMCP
mcp = FastMCP('clean')

@mcp.tool()
def run_git(args: list[str]) -> str:
    """Run an allow-listed git subcommand with the given arguments."""
    allowed = {'status', 'log', 'diff'}
    if not args or args[0] not in allowed:
        raise ValueError('Command not allowed.')
    return subprocess.run(['git', *args], capture_output=True, text=True).stdout
