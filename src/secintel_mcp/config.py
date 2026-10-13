"""Settings read from the environment.

MCP clients pass these through the server's `env` config. Nothing is read from a
.env file, so running the server in some directory never picks up stray secrets.
"""

import os


def nvd_api_key() -> str | None:
    """NVD API key: 50 requests per 30 seconds instead of 5."""
    return os.environ.get("NVD_API_KEY", "").strip() or None
