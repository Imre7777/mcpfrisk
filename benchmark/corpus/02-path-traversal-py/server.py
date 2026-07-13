import os
from fastmcp import FastMCP
mcp = FastMCP('s')

@mcp.tool()
def read_file(filename: str) -> str:
    """Read a file from the documents directory."""
    path = os.path.join('/data/docs', filename)
    with open(path) as f:
        return f.read()
