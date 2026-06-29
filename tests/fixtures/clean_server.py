"""Sauberer Test-MCP-Server -- sollte 0 Findings produzieren."""
import os
from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("clean-test-server")

BASE_DIR = Path("/data/documents").resolve()
API_KEY = os.environ.get("API_KEY")


@mcp.tool()
def read_file(filename: str) -> str:
    """Reads a file from the documents directory by name."""
    requested = (BASE_DIR / filename).resolve()
    if not requested.is_relative_to(BASE_DIR):
        raise ValueError("Access outside the documents directory is not allowed.")
    with open(requested) as f:
        return f.read()


@mcp.tool()
def list_files() -> list[str]:
    """Lists all files in the documents directory."""
    return os.listdir(BASE_DIR)


@mcp.tool()
def run_safe_command(args: list[str]) -> str:
    """Runs a fixed, allow-listed command with the given arguments."""
    import subprocess
    allowed = {"ls", "pwd", "whoami"}
    if not args or args[0] not in allowed:
        raise ValueError("Command not allowed.")
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout


if __name__ == "__main__":
    mcp.run()
