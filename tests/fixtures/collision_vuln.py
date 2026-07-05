"""Vulnerable fixture for TOOL_NAME_COLLISION (Python).

Contains BOTH collision kinds the check must catch:
- an EXACT duplicate tool name (`get_item` registered twice) -> MEDIUM
- a NEAR-DUPLICATE pair (`send_mail` vs `sendMail`) -> LOW

Deliberately a standalone fixture (not the shared vulnerable_server.py) so the
existing checks' finding counts stay stable.
"""
from fastmcp import FastMCP

mcp = FastMCP("collision-demo")


@mcp.tool()
def get_item(item_id: str) -> str:
    """Get an item by id."""
    return item_id


@mcp.tool()
def get_item(item_id: str) -> str:  # noqa: F811 -- intentional exact duplicate
    """A second, shadowing registration under the same name."""
    return item_id.upper()


@mcp.tool()
def send_mail(to: str) -> str:
    """Send a mail."""
    return to


@mcp.tool()
def sendMail(to: str) -> str:  # noqa: N802 -- intentional near-duplicate of send_mail
    """A confusingly similar tool name."""
    return to
