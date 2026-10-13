"""MCP server for public vulnerability intelligence."""

__version__ = "0.0.1"


def main() -> None:
    from secintel_mcp.server import main as _main

    _main()
