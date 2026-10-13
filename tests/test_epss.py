import copy
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx
from conftest import load_fixture
from mcp import Client

from secintel_mcp.errors import SourceError
from secintel_mcp.server import mcp
from secintel_mcp.sources import epss

RESPONSE = load_fixture("epss.json")  # CVE-2022-22965 and CVE-2021-44228


def ids(n: int, digits: int = 4) -> list[str]:
    return [f"CVE-2024-{10 ** (digits - 1) + i}" for i in range(n)]


def query(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(str(request.url)).query).items()}


# --- chunking ---------------------------------------------------------------


@pytest.mark.parametrize("n", [1, 99, 100, 101, 250])
def test_chunks_cover_every_id_once_in_order(n):
    cve_ids = ids(n, digits=7)
    chunks = list(epss.chunk_ids(cve_ids))

    assert [c for chunk in chunks for c in chunk] == cve_ids
    for chunk in chunks:
        assert len(chunk) <= epss.MAX_IDS_PER_REQUEST
        assert len(",".join(chunk)) <= epss.MAX_PARAM_CHARS


def test_long_ids_split_on_length_before_count():
    # 16-char IDs: 100 of them would be a 1,699-char parameter.
    chunks = list(epss.chunk_ids(ids(100, digits=7)))
    assert len(chunks) == 2


# --- parsing ----------------------------------------------------------------


def test_parse_scores_converts_strings_to_numbers():
    scores = {s.cve_id: s for s in epss.parse_scores(RESPONSE)}

    log4shell = scores["CVE-2021-44228"]
    assert log4shell.epss == pytest.approx(0.99999)
    assert log4shell.percentile == pytest.approx(1.0)
    assert str(log4shell.score_date) == "2026-10-12"


def test_truncated_response_is_an_error_not_missing_scores():
    truncated = copy.deepcopy(RESPONSE)
    truncated["total"] = 3

    with pytest.raises(SourceError, match="returned 2 of 3 scores"):
        epss.parse_scores(truncated)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(status="error"),
        lambda d: d.pop("data"),
        lambda d: d["data"][0].update(epss="n/a"),
    ],
)
def test_unrecognized_response_raises_source_error(mutate):
    bad = copy.deepcopy(RESPONSE)
    mutate(bad)

    with pytest.raises(SourceError, match="FIRST EPSS: the response format"):
        epss.parse_scores(bad)


# --- fetching ---------------------------------------------------------------


@pytest.mark.anyio
@respx.mock
async def test_fetch_keeps_input_order_and_reports_missing():
    route = respx.get(epss.EPSS_URL).respond(json=RESPONSE)

    async with httpx.AsyncClient() as client:
        result = await epss.fetch_scores(
            client, ["CVE-2099-0001", "CVE-2021-44228", "CVE-2022-22965"]
        )

    assert [s.cve_id for s in result.scores] == ["CVE-2021-44228", "CVE-2022-22965"]
    assert result.not_found == ["CVE-2099-0001"]
    sent = query(route.calls.last.request)
    assert sent["cve"] == "CVE-2099-0001,CVE-2021-44228,CVE-2022-22965"
    assert sent["limit"] == "3"


@pytest.mark.anyio
@respx.mock
async def test_fetch_splits_large_batches():
    def echo_none(request):
        return httpx.Response(200, json={"status": "OK", "total": 0, "data": []})

    route = respx.get(epss.EPSS_URL).mock(side_effect=echo_none)

    async with httpx.AsyncClient() as client:
        result = await epss.fetch_scores(client, ids(100, digits=7))

    assert route.call_count == 2
    for call in route.calls:
        sent = query(call.request)
        assert len(sent["cve"]) <= epss.MAX_PARAM_CHARS
        assert sent["limit"] == str(len(sent["cve"].split(",")))
    assert len(result.not_found) == 100


# --- get_epss tool ----------------------------------------------------------


@pytest.mark.anyio
@respx.mock
async def test_get_epss_tool_returns_structured_result():
    respx.get(epss.EPSS_URL).respond(json=RESPONSE)

    async with Client(mcp) as client:
        result = await client.call_tool(
            "get_epss", {"cve_ids": ["cve-2021-44228", "CVE-2099-0001"]}
        )

    assert not result.is_error
    data = result.structured_content
    assert data["scores"][0]["cve_id"] == "CVE-2021-44228"
    assert data["not_found"] == ["CVE-2099-0001"]


@pytest.mark.anyio
@respx.mock
async def test_get_epss_reports_source_failure():
    respx.get(epss.EPSS_URL).respond(502)

    async with Client(mcp) as client:
        result = await client.call_tool("get_epss", {"cve_ids": ["CVE-2021-44228"]})

    assert result.is_error
    assert "FIRST EPSS: returned HTTP 502" in result.content[0].text
