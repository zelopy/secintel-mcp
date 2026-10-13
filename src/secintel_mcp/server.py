"""secintel-mcp 서버 진입점."""

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from secintel_mcp import __version__

mcp = MCPServer(
    name="secintel-mcp",
    version=__version__,
    instructions=(
        "공개 취약점 인텔리전스(NVD, OSV, FIRST EPSS, CISA KEV)를 조회하고 "
        "CVE 패치 우선순위를 판단 근거와 함께 반환한다."
    ),
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)


@mcp.tool(annotations=READ_ONLY)
def ping() -> str:
    """서버 연결 상태를 확인한다. 외부 API는 호출하지 않는다."""
    return f"pong (secintel-mcp {__version__})"


def main() -> None:
    mcp.run()  # stdio
