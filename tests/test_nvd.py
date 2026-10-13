import copy
from datetime import UTC

import httpx
import pytest
import respx
from conftest import load_fixture
from mcp import Client

from secintel_mcp.errors import CveNotFoundError, SourceError
from secintel_mcp.server import mcp
from secintel_mcp.sources import nvd


def cve_of(name: str) -> dict:
    return copy.deepcopy(load_fixture(name)["vulnerabilities"][0]["cve"])


def metric(source, score, *, type_="Secondary", version="3.1", severity="HIGH"):
    data = {"version": version, "baseScore": score, "vectorString": f"CVSS:{version}/x"}
    if version == "2.0":
        return {
            "source": source,
            "type": type_,
            "cvssData": data,
            "baseSeverity": severity,
        }
    return {
        "source": source,
        "type": type_,
        "cvssData": data | {"baseSeverity": severity},
    }


# --- CVSS selection ---------------------------------------------------------


def test_nvd_primary_beats_secondary_in_the_same_version():
    cve = cve_of("nvd_log4shell.json")  # NVD 10.0 Primary + CISA ADP Secondary

    score = nvd.select_cvss(cve)

    assert (score.source, score.source_type, score.base_score) == (
        "nvd@nist.gov",
        "Primary",
        10.0,
    )


def test_cna_beats_other_secondary_in_the_same_version():
    cve = {
        "sourceIdentifier": "cna@example.org",
        "metrics": {
            "cvssMetricV31": [
                metric("134c704f-9b21-4f2e-91b3-4a467353bcc0", 9.8),
                metric("cna@example.org", 6.5, severity="MEDIUM"),
            ]
        },
    }

    assert nvd.select_cvss(cve).source == "cna@example.org"


def test_v31_is_preferred_over_v40():
    # Real case: the same CNA scored v4.0 5.5 MEDIUM and v3.1 7.3 HIGH.
    score = nvd.select_cvss(cve_of("nvd_cna_only.json"))

    assert (score.version, score.base_score, score.severity) == ("3.1", 7.3, "HIGH")
    assert score.source == "cna@vuldb.com"


def test_v40_is_used_when_there_is_no_v31():
    cve = cve_of("nvd_cna_only.json")
    del cve["metrics"]["cvssMetricV31"]

    score = nvd.select_cvss(cve)

    assert (score.version, score.base_score) == ("4.0", 5.5)


def test_version_beats_scorer():
    # A CNA v3.1 score wins over an NVD v2.0 score.
    cve = {
        "sourceIdentifier": "cna@example.org",
        "metrics": {
            "cvssMetricV2": [
                metric("nvd@nist.gov", 9.3, type_="Primary", version="2.0")
            ],
            "cvssMetricV31": [metric("cna@example.org", 6.1, severity="MEDIUM")],
        },
    }

    assert nvd.select_cvss(cve).version == "3.1"


def test_adp_score_is_used_when_it_is_the_only_one():
    score = nvd.select_cvss(cve_of("nvd_adp_only.json"))

    assert score.source == "134c704f-9b21-4f2e-91b3-4a467353bcc0"
    assert score.source_type == "Secondary"


def test_v2_severity_is_read_from_the_metric_level():
    cve = {"metrics": {"cvssMetricV2": [metric("nvd@nist.gov", 9.3, version="2.0")]}}

    assert nvd.select_cvss(cve).severity == "HIGH"


def test_non_cvss_metrics_and_malformed_entries_are_ignored():
    cve = {
        "metrics": {
            "ssvcV203": [{"source": "cisa", "ssvcData": {"version": "2.0.3"}}],
            "cvssMetricV40": [{"source": "x", "type": "Secondary"}],  # no cvssData
            "cvssMetricV31": [
                {"source": "y", "cvssData": {"baseScore": 7.5}}
            ],  # no vector
        }
    }

    assert nvd.select_cvss(cve) is None


def test_missing_type_counts_as_secondary():
    cve = {"metrics": {"cvssMetricV31": [metric("cna@example.org", 7.5)]}}
    del cve["metrics"]["cvssMetricV31"][0]["type"]

    assert nvd.select_cvss(cve).source_type == "Secondary"


# --- parsing ----------------------------------------------------------------


def test_parse_log4shell():
    detail = nvd.parse_cve(cve_of("nvd_log4shell.json"))

    assert detail.cve_id == "CVE-2021-44228"
    assert detail.nvd_status == "Analyzed"
    assert detail.description.startswith("Apache Log4j2")
    assert detail.published.tzinfo == UTC
    assert detail.cwes == ["CWE-20", "CWE-400", "CWE-502", "CWE-917"]


def test_references_are_deduped_capped_and_useful_first():
    cve = cve_of("nvd_log4shell.json")
    raw = cve["references"]

    detail = nvd.parse_cve(cve)

    assert detail.references_total == len({r["url"] for r in raw}) < len(raw)
    assert len(detail.references) == nvd.MAX_REFERENCES
    assert all(set(r.tags) & set(nvd.USEFUL_TAGS) for r in detail.references), (
        "log4shell has more than 10 Exploit/Patch/Vendor Advisory links"
    )


def test_broken_links_go_last():
    cve = {
        "references": [
            {"url": "https://a", "tags": ["Exploit", "Broken Link"]},
            {"url": "https://b", "tags": []},
        ]
    }

    refs, _ = nvd._references(cve)

    assert [r.url for r in refs] == ["https://b", "https://a"]


def test_placeholder_cwes_are_dropped():
    cve = {
        "weaknesses": [
            {"description": [{"value": "NVD-CWE-Other"}, {"value": "CWE-79"}]},
            {"description": [{"value": "CWE-79"}, {"value": "NVD-CWE-noinfo"}]},
        ]
    }

    assert nvd._cwes(cve) == ["CWE-79"]


def test_rejected_cve_parses_without_a_score():
    detail = nvd.parse_cve(cve_of("nvd_rejected.json"))

    assert detail.nvd_status == "Rejected"
    assert detail.cvss is None
    assert detail.description.startswith("Rejected reason")


# --- fetching ---------------------------------------------------------------


@pytest.mark.anyio
@respx.mock
async def test_fetch_sends_api_key_only_when_set():
    route = respx.get(nvd.NVD_URL).respond(json=load_fixture("nvd_log4shell.json"))

    async with httpx.AsyncClient() as client:
        await nvd.fetch_cve(client, "CVE-2021-44228", "secret-key")
        await nvd.fetch_cve(client, "CVE-2021-44228", None)

    with_key, without_key = (c.request for c in route.calls)
    assert with_key.headers["apiKey"] == "secret-key"
    assert "apiKey" not in without_key.headers
    assert with_key.url.params["cveId"] == "CVE-2021-44228"


@pytest.mark.anyio
@respx.mock
async def test_unknown_cve_raises_not_found():
    respx.get(nvd.NVD_URL).respond(json=load_fixture("nvd_not_found.json"))

    async with httpx.AsyncClient() as client:
        with pytest.raises(CveNotFoundError, match="CVE-2099-0001 was not found"):
            await nvd.fetch_cve(client, "CVE-2099-0001", None)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("status", "headers", "has_key", "message"),
    [
        (404, {"message": "Invalid apiKey."}, True, "NVD_API_KEY was rejected"),
        (
            403,
            {},
            False,
            "rate limit reached. Wait 30 seconds and retry, or set NVD_API_KEY",
        ),
        (429, {}, True, "rate limit reached. Wait 30 seconds and retry."),
        (
            404,
            {"message": "Invalid cveId parameter."},
            False,
            "HTTP 404 (Invalid cveId parameter)",
        ),
        (500, {}, False, "returned HTTP 500. Try again later."),
    ],
)
@respx.mock
async def test_error_responses_are_explained(status, headers, has_key, message):
    respx.get(nvd.NVD_URL).respond(status, headers=headers)

    async with httpx.AsyncClient() as client:
        with pytest.raises(SourceError) as excinfo:
            await nvd.fetch_cve(client, "CVE-2021-44228", "k" if has_key else None)

    assert message in str(excinfo.value)


@pytest.mark.anyio
@respx.mock
async def test_unrecognized_response_raises_source_error():
    respx.get(nvd.NVD_URL).respond(json={"vulnerabilities": [{"cve": {"id": "x"}}]})

    async with httpx.AsyncClient() as client:
        with pytest.raises(SourceError, match="NVD: the response format"):
            await nvd.fetch_cve(client, "CVE-2021-44228", None)


# --- lookup_cve tool --------------------------------------------------------


@pytest.mark.anyio
@respx.mock
async def test_lookup_cve_tool(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "from-env")
    route = respx.get(nvd.NVD_URL).respond(json=load_fixture("nvd_log4shell.json"))

    async with Client(mcp) as client:
        result = await client.call_tool("lookup_cve", {"cve_id": " cve-2021-44228"})

    assert not result.is_error
    assert result.structured_content["cvss"]["base_score"] == 10.0
    assert route.calls.last.request.headers["apiKey"] == "from-env"
    assert route.calls.last.request.url.params["cveId"] == "CVE-2021-44228"


@pytest.mark.anyio
@respx.mock
async def test_lookup_cve_tool_reports_not_found(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    respx.get(nvd.NVD_URL).respond(json=load_fixture("nvd_not_found.json"))

    async with Client(mcp) as client:
        result = await client.call_tool("lookup_cve", {"cve_id": "CVE-2099-0001"})

    assert result.is_error
    assert "NVD: CVE-2099-0001 was not found" in result.content[0].text
