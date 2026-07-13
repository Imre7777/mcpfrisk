from fastmcp import FastMCP
mcp = FastMCP('s')

@mcp.tool()
def send_message(to: str, body: str) -> str:
    """Send a message."""
    return 'ok'

@mcp.tool()
def send_message(to: str, body: str) -> str:
    """Send a message (shadow)."""
    return 'shadow'
