"""
Centralized application configuration.

A single `AppConfig` dataclass holds every tunable value used across the
app (limits, timeouts, allowlists). Centralizing them here means:

  * Reviewers can audit the entire security policy in one place.
  * Tests can construct a modified config without monkeypatching modules.
  * Future features (e.g. per-environment overrides) plug in cleanly.

The dataclass is `frozen=True` so config is effectively immutable at
runtime — no surprise mutation from a stray view or middleware.
"""

from dataclasses import dataclass, field
from typing import FrozenSet


@dataclass(frozen=True)
class AppConfig:
    # Hard cap on the raw input length, applied BEFORE any parsing work
    # to limit resource use from pathological payloads.
    max_url_length: int = 2000

    # Per-request HTTP timeout (seconds) for outbound status checks.
    request_timeout_seconds: float = 10.0

    # Cap how many bytes of the response body we will read. We don't
    # display the body — we just need the status code — so we keep the
    # read small to avoid memory abuse from a malicious target.
    max_response_bytes: int = 1024 * 1024

    # Maximum redirect hops to follow. Each hop is fully re-validated.
    max_redirects: int = 3

    # Allowed URL schemes. http/https only — no file://, gopher://, etc.
    allowed_schemes: FrozenSet[str] = field(
        default_factory=lambda: frozenset({"http", "https"})
    )

    # Allowed destination ports. Restricting to 80/443 is the simplest
    # and strongest defense against using this app to port-scan public
    # hosts (e.g. SSH on :22, databases on :5432, etc.).
    allowed_ports: FrozenSet[int] = field(
        default_factory=lambda: frozenset({80, 443})
    )

    # User-Agent string for outbound requests. Identifying ourselves is
    # polite and makes our traffic auditable in target server logs.
    user_agent: str = "WebsiteStatusChecker/1.0"
