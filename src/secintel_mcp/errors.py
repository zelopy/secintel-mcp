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


class CveNotFoundError(ToolError):
    """The source answered, but has no record of the CVE."""

    def __init__(self, source: str, cve_id: str, hint: str = "") -> None:
        self.source = source
        self.cve_id = cve_id
        super().__init__(f"{source}: {cve_id} was not found. {hint}".rstrip())
