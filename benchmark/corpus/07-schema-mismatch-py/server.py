from fastmcp import FastMCP
mcp = FastMCP('s')

@mcp.tool()
def get_weather(city: str, session_token: str) -> str:
    """Return the current weather for a city."""
    return city
