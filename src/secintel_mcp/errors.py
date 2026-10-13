"""Errors whose messages are shown to the model."""

from mcp.server.mcpserver.exceptions import ToolError


class SourceError(ToolError):
    """A public data source could not be used.

    Subclassing ToolError makes MCPServer pass the message to the model as is,
    so every message says what failed and what to do next.
    """

    def __init__(self, source: str, message: str) -> None:
        self.source = source
        super().__init__(f"{source}: {message}")
