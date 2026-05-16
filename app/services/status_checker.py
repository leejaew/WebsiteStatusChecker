"""
Website status checker service.

# Responsibility

Given a URL that has already been validated by `app.security.url_validator`,
make a single outbound HTTP request (manually following a bounded number
of redirects) and return a `StatusResult` describing what happened.

# Why a dataclass result instead of a magic string

The previous version returned strings like `"Operational"` and the template
checked `status == "Operational"` to pick a CSS class. That coupled the
template to copy text. `StatusResult.is_up` lets the template ask the
right question without caring about the wording.

# Redirect handling

We disable `requests`' built-in redirect handling and follow Location
headers ourselves so that EVERY hop is re-vetted by the same validator
the user input goes through. This stops a public page from redirecting us
to a private IP after we've already pinned the first hop.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import requests as http_requests

from app.config import AppConfig
from app.security.dns_pinning import pinned_ip
from app.security.url_validator import validate_url


@dataclass(frozen=True)
class StatusResult:
    """
    Outcome of a status check.

    `label` is the human-readable text shown to the user.
    `is_up` is True only for a clean 200 response — used by the template
    to choose colors without reading the label.
    """

    label: str
    is_up: bool

    @classmethod
    def operational(cls) -> "StatusResult":
        return cls(label="Operational", is_up=True)

    @classmethod
    def down(cls, reason: str = "Service status is DOWN") -> "StatusResult":
        return cls(label=reason, is_up=False)

    @classmethod
    def status_code(cls, code: int) -> "StatusResult":
        return cls(label=f"Returned status {code}", is_up=False)


class StatusChecker:
    """
    Performs HTTP HEAD/GET checks against vetted URLs.

    Implemented as a small class (rather than a free function) so the
    `AppConfig` is captured once at construction time instead of being
    threaded through every method call. This is a thin convenience —
    not an attempt to introduce a service-locator pattern.
    """

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def check(self, initial_url: str, initial_pinned_ip: str) -> StatusResult:
        """
        Fetch `initial_url`, following at most `config.max_redirects`
        hops. Each redirect target is re-validated through the same URL
        policy as user input.
        """
        current_url = initial_url
        current_ip: Optional[str] = initial_pinned_ip

        # +1 because the original request itself counts as one fetch.
        for _ in range(self._config.max_redirects + 1):
            try:
                response = self._do_pinned_get(current_url, current_ip)
            except http_requests.RequestException:
                # Network error, DNS failure, TLS failure, etc. — all
                # surface as "down" without leaking exception details
                # to the user.
                return StatusResult.down()

            try:
                if response.is_redirect or response.is_permanent_redirect:
                    next_url = self._extract_redirect_target(response, current_url)
                    response.close()
                    if next_url is None:
                        return StatusResult.down()

                    # Re-run the FULL policy on the redirect target.
                    # `allow_user_omit_scheme=False` because Location
                    # headers must be properly formed URLs.
                    revalidated = validate_url(
                        next_url,
                        self._config,
                        allow_user_omit_scheme=False,
                    )
                    if not revalidated.is_valid:
                        return StatusResult.down(
                            "Blocked redirect to disallowed target"
                        )
                    current_url = revalidated.safe_url  # type: ignore[assignment]
                    current_ip = revalidated.pinned_ip
                    continue

                code = response.status_code
                response.close()
                if code == 200:
                    return StatusResult.operational()
                return StatusResult.status_code(code)
            except Exception:
                # Defensive: any unexpected error during response
                # handling is treated as down rather than 500ing.
                try:
                    response.close()
                except Exception:
                    pass
                return StatusResult.down()

        return StatusResult.down("Too many redirects")

    # --- internals -------------------------------------------------------

    def _do_pinned_get(self, url: str, ip: Optional[str]):
        """
        Issue the GET with the socket-layer IP pin in effect.

        `stream=True` lets us cap how much body we actually pull off the
        wire — we don't need the body, only the status code.
        """
        with pinned_ip(ip):
            response = http_requests.get(
                url,
                timeout=self._config.request_timeout_seconds,
                allow_redirects=False,
                stream=True,
                headers={"User-Agent": self._config.user_agent},
            )

        # Drain a bounded amount so the server doesn't keep the
        # connection open waiting for us. Errors here are non-fatal —
        # we already have the status line.
        try:
            response.raw.read(self._config.max_response_bytes, decode_content=False)
        except Exception:
            pass
        return response

    @staticmethod
    def _extract_redirect_target(response, current_url: str) -> Optional[str]:
        """Resolve a possibly-relative Location header against the current URL."""
        location = response.headers.get("Location")
        if not location:
            return None
        return http_requests.compat.urljoin(current_url, location)
