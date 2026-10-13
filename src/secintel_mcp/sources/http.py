"""Shared HTTP client settings and JSON fetching."""

from collections.abc import Callable
from typing import Any

import httpx

from secintel_mcp import __version__
from secintel_mcp.errors import SourceError

USER_AGENT = f"secintel-mcp/{__version__} (+https://github.com/zelopy/secintel-mcp)"
TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        follow_redirects=True,
    )


async def get_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    source: str,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    explain_error: Callable[[httpx.Response], str | None] | None = None,
) -> Any:
    """GET a JSON document, turning every failure into a SourceError.

    `explain_error` lets a source turn an error response into a specific message;
    returning None falls back to the generic one.
    """
    try:
        response = await client.get(url, params=params, headers=headers)
    except httpx.TimeoutException as exc:
        raise SourceError(source, "the request timed out. Try again shortly.") from exc
    except httpx.HTTPError as exc:
        raise SourceError(
            source, f"could not connect ({type(exc).__name__}). Try again shortly."
        ) from exc

    if response.status_code >= 400:
        message = explain_error(response) if explain_error else None
        raise SourceError(
            source,
            message or f"returned HTTP {response.status_code}. Try again later.",
        )
    try:
        # JSON is UTF-8 by spec; decoding the bytes avoids the locale codec (cp949 on
        # Korean Windows) that text-mode reads would use.
        return response.json()
    except ValueError as exc:
        raise SourceError(
            source, "returned a response that is not valid JSON."
        ) from exc
