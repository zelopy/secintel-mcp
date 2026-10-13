import copy
from datetime import UTC

import httpx
import pytest
import respx
from conftest import load_fixture
from mcp import Client

from secintel_mcp.errors import SourceError
from secintel_mcp.server import mcp
from secintel_mcp.sources import kev

FEED = load_fixture("kev.json")


# --- parsing ----------------------------------------------------------------


def test_parse_catalog_indexes_entries_by_cve_id():
    catalog = kev.parse_catalog(FEED)

    assert catalog.version == FEED["catalogVersion"]
    assert catalog.released.tzinfo == UTC
    assert set(catalog.entries) == {
        "CVE-2021-44228",
        "CVE-2022-22965",
        "CVE-2015-5477",
    }
    log4shell = catalog.entries["CVE-2021-44228"]
    assert log4shell.ransomware_use == "Known"
    assert str(log4shell.due_date) == "2021-12-24"


def test_malformed_entries_are_skipped():
    feed = copy.deepcopy(FEED)
    del feed["vulnerabilities"][0]["dueDate"]
    feed["vulnerabilities"][1]["knownRansomwareCampaignUse"] = "Maybe"

    catalog = kev.parse_catalog(feed)

    assert set(catalog.entries) == {"CVE-2015-5477"}


def test_missing_cwes_become_an_empty_list():
    feed = copy.deepcopy(FEED)
    del feed["vulnerabilities"][0]["cwes"]

    assert kev.parse_catalog(feed).entries["CVE-2021-44228"].cwes == []


@pytest.mark.parametrize("feed", [{}, {"catalogVersion": "x"}, [], "oops"])
def test_unrecognized_catalog_raises_source_error(feed):
    with pytest.raises(SourceError, match="CISA KEV: the catalog format"):
        kev.parse_catalog(feed)


# --- lookup -----------------------------------------------------------------


def test_lookup_splits_listed_and_unlisted_in_input_order():
    catalog = kev.parse_catalog(FEED)

    result = kev.lookup(catalog, ["CVE-2099-0001", "CVE-2022-22965", "CVE-2021-44228"])

    assert [e.cve_id for e in result.in_kev] == ["CVE-2022-22965", "CVE-2021-44228"]
    assert result.not_in_kev == ["CVE-2099-0001"]
    assert result.catalog_version == catalog.version


# --- check_kev tool ---------------------------------------------------------


@pytest.mark.anyio
@respx.mock
async def test_check_kev_tool_returns_structured_result():
    respx.get(kev.KEV_URL).respond(json=FEED)

    async with Client(mcp) as client:
        result = await client.call_tool(
            "check_kev", {"cve_ids": ["cve-2021-44228", "CVE-2099-0001"]}
        )

    assert not result.is_error
    data = result.structured_content
    assert [e["cve_id"] for e in data["in_kev"]] == ["CVE-2021-44228"]
    assert data["in_kev"][0]["ransomware_use"] == "Known"
    assert data["not_in_kev"] == ["CVE-2099-0001"]


@pytest.mark.anyio
@respx.mock
async def test_check_kev_sends_user_agent():
    route = respx.get(kev.KEV_URL).respond(json=FEED)

    async with Client(mcp) as client:
        await client.call_tool("check_kev", {"cve_ids": ["CVE-2021-44228"]})

    assert route.calls.last.request.headers["User-Agent"].startswith("secintel-mcp/")


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("mock", "message"),
    [
        (httpx.Response(503), "CISA KEV: returned HTTP 503"),
        (httpx.ConnectTimeout("slow"), "CISA KEV: the request timed out"),
        (httpx.ConnectError("down"), "CISA KEV: could not connect (ConnectError)"),
        (httpx.Response(200, text="<html>maintenance</html>"), "not valid JSON"),
    ],
)
@respx.mock
async def test_check_kev_reports_source_failures_to_the_model(mock, message):
    route = respx.get(kev.KEV_URL)
    if isinstance(mock, Exception):
        route.side_effect = mock
    else:
        route.return_value = mock

    async with Client(mcp) as client:
        result = await client.call_tool("check_kev", {"cve_ids": ["CVE-2021-44228"]})

    assert result.is_error
    assert message in result.content[0].text


@pytest.mark.anyio
async def test_check_kev_is_marked_read_only_and_external():
    async with Client(mcp) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}

    annotations = tools["check_kev"].annotations
    assert annotations.read_only_hint is True
    assert annotations.open_world_hint is True
    assert tools["check_kev"].input_schema["properties"]["cve_ids"]["maxItems"] == 100
