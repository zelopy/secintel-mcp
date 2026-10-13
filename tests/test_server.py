import pytest
from mcp import Client

from secintel_mcp.server import mcp

pytestmark = pytest.mark.anyio


async def test_ping_is_listed_as_read_only():
    async with Client(mcp) as client:
        tools = (await client.list_tools()).tools

    ping = next(t for t in tools if t.name == "ping")
    assert ping.annotations.read_only_hint is True


async def test_ping_returns_pong():
    async with Client(mcp) as client:
        result = await client.call_tool("ping", {})

    assert not result.is_error
    assert result.content[0].text.startswith("pong")
