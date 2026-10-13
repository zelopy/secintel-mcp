"""CISA Known Exploited Vulnerabilities (KEV) catalog."""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
from pydantic import ValidationError

from secintel_mcp.errors import SourceError
from secintel_mcp.models import KevEntry, KevResult
from secintel_mcp.sources.http import get_json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SOURCE = "CISA KEV"

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class KevCatalog:
    version: str
    released: datetime
    entries: dict[str, KevEntry]


def parse_catalog(data: Any) -> KevCatalog:
    """Index the feed by CVE ID. Malformed entries are skipped, not fatal."""
    try:
        version = data["catalogVersion"]
        released = datetime.fromisoformat(data["dateReleased"])
        raw_entries = data["vulnerabilities"]
    except (KeyError, TypeError, ValueError) as exc:
        raise SourceError(
            SOURCE, "the catalog format was not recognized. Try again later."
        ) from exc

    entries: dict[str, KevEntry] = {}
    skipped = 0
    for raw in raw_entries:
        try:
            entry = KevEntry(
                cve_id=raw["cveID"],
                vendor_project=raw["vendorProject"],
                product=raw["product"],
                vulnerability_name=raw["vulnerabilityName"],
                date_added=raw["dateAdded"],
                due_date=raw["dueDate"],
                ransomware_use=raw["knownRansomwareCampaignUse"],
                required_action=raw["requiredAction"],
                short_description=raw["shortDescription"],
                cwes=raw.get("cwes") or [],
            )
        except (KeyError, TypeError, ValidationError):
            skipped += 1
            continue
        entries[entry.cve_id.upper()] = entry
    if skipped:
        log.warning("Skipped %d malformed KEV entries", skipped)
    return KevCatalog(version=version, released=released, entries=entries)


async def fetch_catalog(client: httpx.AsyncClient) -> KevCatalog:
    return parse_catalog(await get_json(client, KEV_URL, source=SOURCE))


def lookup(catalog: KevCatalog, cve_ids: list[str]) -> KevResult:
    """Split CVE IDs (already normalized) into listed and unlisted, keeping order."""
    in_kev = [catalog.entries[c] for c in cve_ids if c in catalog.entries]
    not_in_kev = [c for c in cve_ids if c not in catalog.entries]
    return KevResult(
        in_kev=in_kev,
        not_in_kev=not_in_kev,
        catalog_version=catalog.version,
        catalog_released=catalog.released,
    )
