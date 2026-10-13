"""NVD CVE API 2.0."""

from typing import Any

import httpx
from pydantic import ValidationError

from secintel_mcp.errors import CveNotFoundError, SourceError
from secintel_mcp.models import CveDetail, CvssScore, Reference
from secintel_mcp.sources.http import get_json

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE = "NVD"
NVD_SOURCE_ID = "nvd@nist.gov"

# v3.1 first: nearly every CVE has one (192 of 200 published in early October
# 2026), so scores compare on one scale, and the same CNA can score far apart
# across versions (CVE-2026-105471: v4.0 5.5, v3.1 7.3). v4.0 is next, for CVEs
# scored only in v4. `metrics` also holds non-CVSS entries (e.g. CISA's
# ssvcV203), so only these keys are read.
CVSS_KEYS = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
MAX_REFERENCES = 10
USEFUL_TAGS = ("Exploit", "Patch", "Vendor Advisory")


def _scorer_rank(metric: dict[str, Any], cna_source: str | None) -> int:
    """0 = NVD's own analysis, 1 = the CNA, 2 = anyone else (e.g. CISA ADP)."""
    if metric.get("type") == "Primary" or metric.get("source") == NVD_SOURCE_ID:
        return 0
    if cna_source and metric.get("source") == cna_source:
        return 1
    return 2


def select_cvss(cve: dict[str, Any]) -> CvssScore | None:
    """Pick one score: version by CVSS_KEYS order, then NVD over the CNA over others."""
    metrics = cve.get("metrics") or {}
    cna_source = cve.get("sourceIdentifier")
    for key, version in CVSS_KEYS:
        candidates = []
        for metric in metrics.get(key) or []:
            data = metric.get("cvssData") or {}
            try:
                score = CvssScore(
                    version=version,
                    base_score=data["baseScore"],
                    severity=data.get("baseSeverity") or metric.get("baseSeverity"),
                    vector=data["vectorString"],
                    source=metric.get("source", "unknown"),
                    source_type=metric.get("type", "Secondary"),
                )
            except (KeyError, ValidationError):
                continue
            candidates.append((_scorer_rank(metric, cna_source), score))
        if candidates:
            return min(candidates, key=lambda c: c[0])[1]
    return None


def _description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _cwes(cve: dict[str, Any]) -> list[str]:
    # NVD also uses placeholders such as NVD-CWE-Other and NVD-CWE-noinfo.
    values = (
        d.get("value", "")
        for w in cve.get("weaknesses") or []
        for d in w.get("description") or []
    )
    return list(dict.fromkeys(v for v in values if v.startswith("CWE-")))


def _reference_rank(ref: dict[str, Any]) -> int:
    tags = ref.get("tags") or []
    if "Broken Link" in tags:
        return len(USEFUL_TAGS) + 1
    return min(
        (USEFUL_TAGS.index(t) for t in tags if t in USEFUL_TAGS),
        default=len(USEFUL_TAGS),
    )


def _references(cve: dict[str, Any]) -> tuple[list[Reference], int]:
    unique = list(
        {r["url"]: r for r in cve.get("references") or [] if r.get("url")}.values()
    )
    ranked = sorted(unique, key=_reference_rank)  # stable: NVD order within a rank
    picked = [Reference(url=r["url"], tags=r.get("tags") or []) for r in ranked]
    return picked[:MAX_REFERENCES], len(unique)


def parse_cve(cve: dict[str, Any]) -> CveDetail:
    references, references_total = _references(cve)
    return CveDetail(
        cve_id=cve["id"],
        description=_description(cve),
        published=cve["published"],
        last_modified=cve["lastModified"],
        nvd_status=cve.get("vulnStatus", "Unknown"),
        cvss=select_cvss(cve),
        cwes=_cwes(cve),
        references=references,
        references_total=references_total,
    )


def _explain_error(response: httpx.Response, has_key: bool) -> str | None:
    # NVD puts the reason in a `message` header, e.g. "Invalid apiKey." with a 404.
    detail = response.headers.get("message", "")
    if "apikey" in detail.lower():
        return "NVD_API_KEY was rejected as invalid. Fix it or remove it to use the public limit."
    if response.status_code in (403, 429):
        advice = "" if has_key else ", or set NVD_API_KEY for a 10x higher limit"
        return f"rate limit reached. Wait 30 seconds and retry{advice}."
    if detail:
        return f"returned HTTP {response.status_code} ({detail.rstrip('.')})."
    return None


async def fetch_cve(
    client: httpx.AsyncClient, cve_id: str, api_key: str | None
) -> CveDetail:
    data = await get_json(
        client,
        NVD_URL,
        source=SOURCE,
        params={"cveId": cve_id},
        headers={"apiKey": api_key} if api_key else None,
        explain_error=lambda r: _explain_error(r, has_key=bool(api_key)),
    )
    try:
        found = data["vulnerabilities"]
        if not found:
            raise CveNotFoundError(
                SOURCE,
                cve_id,
                "Check the ID. A CVE published in the last few hours may not be listed yet.",
            )
        return parse_cve(found[0]["cve"])
    except (KeyError, TypeError, IndexError, ValidationError) as exc:
        raise SourceError(
            SOURCE, "the response format was not recognized. Try again later."
        ) from exc
