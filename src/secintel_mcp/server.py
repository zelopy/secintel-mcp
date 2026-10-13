"""secintel-mcp server entry point.

Tool docstrings and argument descriptions are what the model reads to choose a
tool, so they say when to use each one.
"""

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from secintel_mcp import __version__
from secintel_mcp.models import CveIdBatch, KevResult
from secintel_mcp.sources import kev
from secintel_mcp.sources.http import make_client

mcp = MCPServer(
    name="secintel-mcp",
    version=__version__,
    instructions=(
        "Public vulnerability intelligence from NVD, OSV, FIRST EPSS, and CISA KEV. "
        "Use prioritize_cves to decide which CVEs to patch first; it returns the "
        "reasons for each priority."
    ),
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
READ_ONLY_EXTERNAL = ToolAnnotations(readOnlyHint=True, openWorldHint=True)


@mcp.tool(annotations=READ_ONLY)
def ping() -> str:
    """Check that the server is running. Calls no external API."""
    return f"pong (secintel-mcp {__version__})"


@mcp.tool(annotations=READ_ONLY_EXTERNAL)
async def check_kev(cve_ids: CveIdBatch) -> KevResult:
    """Check whether CVEs are in the CISA Known Exploited Vulnerabilities (KEV) catalog.

    A KEV listing means exploitation in the wild has been confirmed. Use this when
    the question is "is this actually being exploited?". To rank several CVEs for
    patching, use prioritize_cves instead; it already includes this check.

    Args:
        cve_ids: 1-100 CVE IDs such as CVE-2021-44228.
    """
    async with make_client() as client:
        catalog = await kev.fetch_catalog(client)
    return kev.lookup(catalog, cve_ids)


def main() -> None:
    mcp.run()  # stdio
