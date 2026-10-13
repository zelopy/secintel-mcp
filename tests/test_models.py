from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from secintel_mcp.models import (
    MAX_BATCH,
    MAX_PRIORITIZE,
    CveDetail,
    CveId,
    CveIdBatch,
    CveIdsToPrioritize,
    CvssScore,
    Ecosystem,
    KevEntry,
    PackageVulns,
    PrioritizationResult,
    Thresholds,
)

cve_id = TypeAdapter(CveId)
batch = TypeAdapter(CveIdBatch)
to_prioritize = TypeAdapter(CveIdsToPrioritize)


def ids(n: int) -> list[str]:
    return [f"CVE-2024-{i:05d}" for i in range(n)]


# --- CVE ID -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CVE-2021-44228", "CVE-2021-44228"),
        (" cve-2021-44228 ", "CVE-2021-44228"),
        ("CVE-2024-1234567", "CVE-2024-1234567"),
        ("CVE-2021-44228\n", "CVE-2021-44228"),
    ],
)
def test_cve_id_is_normalized(raw, expected):
    assert cve_id.validate_python(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "log4shell",
        "CVE-21-44228",
        "CVE-2021-123",
        "GHSA-jfh8-c2jp-5v3q",
        "CVE-２０２１-44228",  # fullwidth digits
    ],
)
def test_invalid_cve_id_error_shows_the_expected_form(raw):
    with pytest.raises(ValidationError, match="CVE-YYYY-NNNN"):
        cve_id.validate_python(raw)


# --- CVE ID lists -----------------------------------------------------------


def test_batch_dedupes_after_normalizing_and_keeps_order():
    raw = ["cve-2022-22965", "CVE-2021-44228", "CVE-2022-22965 "]
    assert batch.validate_python(raw) == ["CVE-2022-22965", "CVE-2021-44228"]


@pytest.mark.parametrize(
    ("adapter", "limit"), [(batch, MAX_BATCH), (to_prioritize, MAX_PRIORITIZE)]
)
def test_list_size_limits(adapter, limit):
    assert len(adapter.validate_python(ids(limit))) == limit
    with pytest.raises(ValidationError, match=f"at most {limit}"):
        adapter.validate_python(ids(limit + 1))
    with pytest.raises(ValidationError, match="at least 1"):
        adapter.validate_python([])


def test_list_limits_are_in_the_input_schema():
    schema = to_prioritize.json_schema()
    assert (schema["minItems"], schema["maxItems"]) == (1, MAX_PRIORITIZE)


# --- thresholds -------------------------------------------------------------


def test_threshold_names_match_prioritize_arguments():
    assert set(Thresholds.model_fields) == {
        "epss_threshold",
        "percentile_threshold",
        "cvss_threshold",
    }


@pytest.mark.parametrize(
    "bad",
    [
        {"epss_threshold": 1.5},
        {"percentile_threshold": -0.1},
        {"cvss_threshold": 11},
    ],
)
def test_thresholds_are_range_checked(bad):
    with pytest.raises(ValidationError):
        Thresholds(**bad)


# --- KEV ransomware flag ----------------------------------------------------


def kev_entry(**overrides) -> KevEntry:
    fields = {
        "cve_id": "CVE-2021-44228",
        "vendor_project": "Apache",
        "product": "Log4j2",
        "vulnerability_name": "Apache Log4j2 Remote Code Execution Vulnerability",
        "date_added": "2021-12-10",
        "due_date": "2021-12-24",
        "ransomware_use": "Known",
        "required_action": "Apply updates.",
        "short_description": "JNDI lookup RCE.",
        "cwes": ["CWE-502"],
    }
    return KevEntry(**fields | overrides)


@pytest.mark.parametrize("value", ["Known", "Unknown"])
def test_ransomware_use_keeps_cisa_value(value):
    assert kev_entry(ransomware_use=value).ransomware_use == value


@pytest.mark.parametrize("value", [False, True, "No"])
def test_ransomware_use_is_not_a_boolean(value):
    with pytest.raises(ValidationError):
        kev_entry(ransomware_use=value)


# --- timestamps -------------------------------------------------------------


def test_naive_nvd_timestamps_are_read_as_utc():
    detail = CveDetail(
        cve_id="CVE-2021-44228",
        description="Log4Shell",
        published="2021-12-10T10:15:09.143",
        last_modified="2026-08-11T19:33:44.513+00:00",
        nvd_status="Analyzed",
        cvss=None,
        cwes=[],
        references=[],
        references_total=0,
    )
    assert detail.published == datetime(2021, 12, 10, 10, 15, 9, 143000, tzinfo=UTC)
    assert detail.last_modified.tzinfo is not None


# --- descriptions the model relies on --------------------------------------


def test_secondary_cvss_is_not_described_as_cna_only():
    text = CvssScore.model_fields["source_type"].description
    assert "CNA" in text and "CISA ADP" in text


def test_result_order_description_covers_all_tiebreaks():
    text = PrioritizationResult.model_fields["results"].description
    assert "ransomware" in text
    assert "missing EPSS last" in text
    assert "P3 and P4" in text


def test_without_cve_counts_advisories_with_no_cve_id_at_all():
    text = PackageVulns.model_fields["without_cve"].description
    assert "no CVE ID" in text and "alias" not in text


def test_ecosystem_values_match_osv_names():
    assert Ecosystem("PyPI") is Ecosystem.PYPI
    assert Ecosystem("crates.io") is Ecosystem.CRATES_IO
