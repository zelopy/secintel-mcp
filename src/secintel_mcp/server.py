"""secintel-mcp server entry point.

Tool docstrings and argument descriptions are what the model reads to choose a
tool, so they say when to use each one.
"""

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from secintel_mcp import __version__, config
from secintel_mcp.models import CveDetail, CveId, CveIdBatch, EpssResult, KevResult
from secintel_mcp.sources import epss, kev, nvd
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
async def lookup_cve(cve_id: CveId) -> CveDetail:
    """Get NVD details for one CVE: description, CVSS score, CWEs, and references.

    Use this to explain what a vulnerability is. Recent CVEs are often scored only
    by the CNA (cvss.source_type is Secondary) because NVD analysis lags. A CVE
    with nvd_status Rejected is void, usually a duplicate; its description says
    which ID to use instead. For several CVEs, prefer prioritize_cves.

    Args:
        cve_id: A CVE ID such as CVE-2021-44228.
    """
    async with make_client() as client:
        return await nvd.fetch_cve(client, cve_id, config.nvd_api_key())


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


@mcp.tool(annotations=READ_ONLY_EXTERNAL)
async def get_epss(cve_ids: CveIdBatch) -> EpssResult:
    """Get FIRST EPSS scores: the probability that each CVE is exploited in the next 30 days.

    Use this when the question is "how likely is this to be exploited?". EPSS is a
    forecast; for confirmed exploitation use check_kev. To rank CVEs for patching,
    use prioritize_cves, which combines EPSS with KEV and CVSS.

    Args:
        cve_ids: 1-100 CVE IDs such as CVE-2021-44228.
    """
    async with make_client() as client:
        return await epss.fetch_scores(client, cve_ids)


def main() -> None:
    mcp.run()  # stdio
