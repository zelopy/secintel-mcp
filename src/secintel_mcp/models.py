"""Tool input/output models.

Field descriptions are part of each tool's output schema, so they are written
for the model that reads the results.
"""

import re
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, Field

# --- inputs -----------------------------------------------------------------

# [0-9] rather than \d, which also matches non-ASCII digits such as fullwidth ２.
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def _normalize_cve_id(value: str) -> str:
    cve_id = value.strip().upper()
    if not _CVE_RE.match(cve_id):
        raise ValueError(
            f"'{value}' is not a CVE ID. Use the form CVE-YYYY-NNNN (for example CVE-2021-44228)."
        )
    return cve_id


CveId = Annotated[str, AfterValidator(_normalize_cve_id)]

MAX_BATCH = 100
MAX_PRIORITIZE = 50


def _dedupe(ids: list[str]) -> list[str]:
    return list(dict.fromkeys(ids))


CveIdBatch = Annotated[
    list[CveId], Field(min_length=1, max_length=MAX_BATCH), AfterValidator(_dedupe)
]
CveIdsToPrioritize = Annotated[
    list[CveId], Field(min_length=1, max_length=MAX_PRIORITIZE), AfterValidator(_dedupe)
]


def _assume_utc(value: datetime) -> datetime:
    # NVD timestamps carry no offset but are UTC.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


UtcDatetime = Annotated[datetime, AfterValidator(_assume_utc)]


class Ecosystem(StrEnum):
    """OSV ecosystem names (case-sensitive in the OSV API)."""

    PYPI = "PyPI"
    NPM = "npm"
    MAVEN = "Maven"
    GO = "Go"
    CRATES_IO = "crates.io"
    RUBYGEMS = "RubyGems"
    NUGET = "NuGet"
    PACKAGIST = "Packagist"


# --- lookup_cve (NVD) -------------------------------------------------------


class CvssScore(BaseModel):
    version: Literal["4.0", "3.1", "3.0", "2.0"]
    base_score: float = Field(description="CVSS base score, 0.0-10.0.")
    severity: str | None = Field(description="Severity label such as CRITICAL or HIGH.")
    vector: str
    source: str = Field(
        description="Who scored it: nvd@nist.gov, the CNA, or another provider."
    )
    source_type: Literal["Primary", "Secondary"] = Field(
        description=(
            "Primary is NVD's own analysis. Secondary comes from the CNA or another "
            "provider such as CISA ADP."
        )
    )


class Reference(BaseModel):
    url: str
    tags: list[str] = Field(
        default_factory=list, description="NVD tags such as Patch or Exploit."
    )


class CveDetail(BaseModel):
    cve_id: str
    description: str = Field(description="English description from NVD.")
    published: UtcDatetime
    last_modified: UtcDatetime
    nvd_status: str = Field(
        description="NVD analysis status, e.g. Analyzed, Awaiting Analysis, or Rejected."
    )
    cvss: CvssScore | None = Field(
        description=(
            "Preferred score: CVSS v3.1 if any, else v4.0, v3.0, v2.0; within a version, "
            "NVD (Primary) first, then the CNA, then other providers. Null when unscored."
        )
    )
    cwes: list[str] = Field(description="CWE IDs, e.g. CWE-502.")
    references: list[Reference] = Field(
        description="Up to 10 references, Exploit/Patch/Vendor Advisory tags first."
    )
    references_total: int


# --- query_package_vulns (OSV) ----------------------------------------------


class PackageVuln(BaseModel):
    id: str = Field(description="OSV ID, often a GHSA or PYSEC ID.")
    cve_ids: list[str] = Field(
        description="CVE IDs of this advisory: its own ID if it is a CVE, plus CVE aliases."
    )
    summary: str | None
    severity: str | None = Field(
        description="Advisory severity label (e.g. CRITICAL, MODERATE) when the source gives one."
    )
    fixed_versions: list[str] = Field(
        description="Versions that fix it; empty if no fix is known."
    )
    published: UtcDatetime | None
    modified: UtcDatetime


class PackageVulns(BaseModel):
    ecosystem: Ecosystem
    package: str
    version: str | None = Field(description="Queried version; null means all versions.")
    vulns: list[PackageVuln]
    cve_ids: list[str] = Field(
        description="All distinct CVE IDs found, ready to pass to prioritize_cves."
    )
    without_cve: int = Field(
        description="Number of advisories with no CVE ID at all (cve_ids is empty)."
    )


# --- get_epss (FIRST EPSS) --------------------------------------------------


class EpssScore(BaseModel):
    cve_id: str
    epss: float = Field(
        description="Probability of exploitation in the next 30 days, 0-1."
    )
    percentile: float = Field(
        description="Share of scored CVEs with an equal or lower EPSS, 0-1."
    )
    score_date: date = Field(description="Date the score was published.")


class EpssResult(BaseModel):
    scores: list[EpssScore]
    not_found: list[str] = Field(
        description="CVE IDs EPSS has no score for (too new, rejected, or nonexistent)."
    )


# --- check_kev (CISA KEV) ---------------------------------------------------

RansomwareUse = Literal["Known", "Unknown"]


class KevEntry(BaseModel):
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date
    due_date: date = Field(description="Remediation deadline for US federal agencies.")
    ransomware_use: RansomwareUse = Field(
        description=(
            "Known: CISA has seen it used in ransomware campaigns. Unknown: no such "
            "evidence yet; it does not rule ransomware use out."
        )
    )
    required_action: str
    short_description: str
    cwes: list[str]


class KevResult(BaseModel):
    in_kev: list[KevEntry] = Field(
        description="CVEs confirmed as exploited in the wild."
    )
    not_in_kev: list[str] = Field(
        description="CVEs not in the catalog. This is not proof they are unexploited."
    )
    catalog_version: str
    catalog_released: UtcDatetime


# --- prioritize_cves --------------------------------------------------------

Priority = Literal["P1", "P2", "P3", "P4", "UNKNOWN"]


class Thresholds(BaseModel):
    """Names match the prioritize_cves arguments, so they can be passed back as is."""

    epss_threshold: float = Field(default=0.1, ge=0, le=1)
    percentile_threshold: float = Field(default=0.95, ge=0, le=1)
    cvss_threshold: float = Field(default=7.0, ge=0, le=10)


class PrioritizedCve(BaseModel):
    cve_id: str
    priority: Priority
    reasons: list[str] = Field(
        description="Why this priority was assigned, in rule order."
    )
    in_kev: bool
    ransomware_use: RansomwareUse | None = Field(
        description="CISA's ransomware flag (see check_kev); null when not in KEV."
    )
    kev_due_date: date | None
    epss: float | None
    epss_percentile: float | None
    cvss: CvssScore | None
    cvss_status: Literal["fetched", "skipped", "unavailable"] = Field(
        description=(
            "skipped: not needed because KEV or EPSS already decided the priority. "
            "unavailable: NVD failed, has no score, or rejected the CVE."
        )
    )


class PrioritizationResult(BaseModel):
    results: list[PrioritizedCve] = Field(
        description=(
            "Most urgent first: P1 to P4, then UNKNOWN. Within P1, known ransomware use "
            "first. Then higher EPSS (missing EPSS last), then higher CVSS; CVSS only "
            "breaks ties in P3 and P4 because P1 and P2 skip the NVD lookup."
        )
    )
    counts: dict[Priority, int]
    thresholds: Thresholds
    kev_catalog_version: str
    epss_date: date | None
    warnings: list[str] = Field(
        default_factory=list, description="Stale cache use or partial source failures."
    )
