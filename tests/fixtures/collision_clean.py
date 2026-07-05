"""Clean fixture for TOOL_NAME_COLLISION (Python).

Multiple clearly-distinct tool names, including tools that share a common word
but are unambiguously different (`list_users`, `create_user`, `delete_user`).
Must produce ZERO collision findings -- a shared word/prefix is not a collision.
"""
from fastmcp import FastMCP

mcp = FastMCP("clean-demo")


@mcp.tool()
def list_users() -> list:
    """List all users."""
    return []


@mcp.tool()
def create_user(name: str) -> str:
    """Create a user."""
    return name


@mcp.tool()
def delete_order(order_id: str) -> bool:
    """Delete an order."""
    return True


@mcp.tool()
def fetch_weather(city: str) -> str:
    """Fetch the weather for a city."""
    return city
