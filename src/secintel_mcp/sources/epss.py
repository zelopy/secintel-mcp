"""FIRST EPSS (Exploit Prediction Scoring System) scores."""

from collections.abc import Iterator
from typing import Any

import httpx
from pydantic import ValidationError

from secintel_mcp.errors import SourceError
from secintel_mcp.models import EpssResult, EpssScore
from secintel_mcp.sources.http import get_json

EPSS_URL = "https://api.first.org/data/v1/epss"
SOURCE = "FIRST EPSS"

# Two silent failure modes of the API, both checked on 2026-10-13:
# - only `limit` rows come back (default 100), however many CVEs match;
# - once the `cve` parameter passes roughly 2,000 characters, the API answers
#   200 OK with no rows at all.
# Requests are therefore split well below both limits.
MAX_IDS_PER_REQUEST = 100
MAX_PARAM_CHARS = 1500


def chunk_ids(cve_ids: list[str]) -> Iterator[list[str]]:
    chunk: list[str] = []
    length = 0
    for cve_id in cve_ids:
        added = len(cve_id) + (1 if chunk else 0)
        if chunk and (
            len(chunk) == MAX_IDS_PER_REQUEST or length + added > MAX_PARAM_CHARS
        ):
            yield chunk
            chunk, length, added = [], 0, len(cve_id)
        chunk.append(cve_id)
        length += added
    if chunk:
        yield chunk


def parse_scores(data: Any) -> list[EpssScore]:
    try:
        if data["status"] != "OK":
            raise ValueError(data["status"])
        rows = data["data"]
        total = int(data["total"])
        scores = [
            EpssScore(
                cve_id=row["cve"],
                epss=row["epss"],
                percentile=row["percentile"],
                score_date=row["date"],
            )
            for row in rows
        ]
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise SourceError(
            SOURCE, "the response format was not recognized. Try again later."
        ) from exc
    if len(scores) < total:
        raise SourceError(
            SOURCE,
            f"returned {len(scores)} of {total} scores. Ask for fewer CVEs at a time.",
        )
    return scores


async def fetch_scores(client: httpx.AsyncClient, cve_ids: list[str]) -> EpssResult:
    """Look up EPSS scores for normalized CVE IDs, keeping the input order."""
    found: dict[str, EpssScore] = {}
    for chunk in chunk_ids(cve_ids):
        data = await get_json(
            client,
            EPSS_URL,
            source=SOURCE,
            params={"cve": ",".join(chunk), "limit": str(len(chunk))},
        )
        for score in parse_scores(data):
            found[score.cve_id.upper()] = score
    return EpssResult(
        scores=[found[c] for c in cve_ids if c in found],
        not_found=[c for c in cve_ids if c not in found],
    )
