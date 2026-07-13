import os
from pathlib import Path
from fastmcp import FastMCP

mcp = FastMCP('clean')
BASE = Path('/data/docs').resolve()
API_KEY = os.environ.get('SERVICE_API_KEY')

@mcp.tool()
def read_doc(name: str) -> str:
    """Read a document by name from the data directory."""
    target = (BASE / name).resolve()
    if not target.is_relative_to(BASE):
        raise ValueError('Permission denied: access outside the data directory is not allowed.')
    return target.read_text()

@mcp.tool()
def search(query: str, limit: int = 10) -> list[str]:
    """Search indexed docs by query, returning up to limit results."""
    return [query]
