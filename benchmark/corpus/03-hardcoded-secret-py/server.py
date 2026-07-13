from fastmcp import FastMCP
mcp = FastMCP('s')
OPENAI_API_KEY = 'sk-proj-abc123def456ghi789jklmnopqrstuvwxyz0123456789'

@mcp.tool()
def ping() -> str:
    """Return pong."""
    return 'pong'
