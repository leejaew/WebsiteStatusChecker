"""
URL / host / IP / port policy validation.

# Responsibility

Given an untrusted URL string from the user (or from a redirect Location
header), decide whether it's safe for the app to fetch and, if so, return
a normalized URL plus the specific IP we resolved it to.

This module is **pure** — no I/O other than DNS lookups. It does not make
HTTP requests. Keeping validation pure makes it easy to reason about and
easy to test.

# Why a single ValidationResult dataclass

The previous shape was `(safe_url, pinned_ip, error)` tuples returned from
a function. Tuples make call sites read like noise (`r[0]`, `r[1]`...) and
encourage drift. A frozen dataclass with a `.is_valid` property documents
intent and gives static analyzers something to check.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from app.config import AppConfig

# RFC-1123 hostname regex, single source of truth.
# Permits standard DNS labels separated by dots, with a 2-63 char TLD.
# We deliberately do NOT support IDN/punycode here — it widens the parser
# attack surface for marginal user benefit in a status-checker.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)


@dataclass(frozen=True)
class ValidationResult:
    """
    Outcome of validating one URL against the app policy.

    Either `error` is set (validation failed) OR both `safe_url` and
    `pinned_ip` are set (validation passed). Use `.is_valid` instead of
    checking attributes directly so callers don't depend on this layout.
    """

    safe_url: Optional[str] = None
    pinned_ip: Optional[str] = None
    error: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        # Require BOTH outputs to be present so callers can rely on
        # `safe_url` and `pinned_ip` being non-None after this check.
        return (
            self.error is None
            and self.safe_url is not None
            and self.pinned_ip is not None
        )


def _is_public_ip(ip_str: str) -> bool:
    """
    Return True only for IPs we are willing to send traffic to.

    We use Python's `ip.is_global` as the *allowlist* (rather than a
    denylist of `is_private` etc.) because allowlists fail safe: any
    address class we forgot about is treated as not-allowed by default.

    IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) are unwrapped and
    re-checked against their embedded IPv4 to prevent that bypass.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # Unwrap IPv4-mapped IPv6 to catch e.g. ::ffff:127.0.0.1
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _is_public_ip(str(ip.ipv4_mapped))

    # Belt + suspenders: is_global SHOULD already exclude these,
    # but enumerating them defensively guards against version drift in
    # the stdlib's classification rules.
    return ip.is_global and not (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_private
    )


def _resolve_safe_ip(hostname: str) -> Optional[str]:
    """
    Resolve `hostname` and return a single IP only if EVERY answer is
    public. If even one A/AAAA record is private, the whole hostname is
    rejected — partial-trust is not a thing here.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return None
    if not infos:
        return None
    candidate: Optional[str] = None
    for info in infos:
        ip = info[4][0]
        if not _is_public_ip(ip):
            return None
        if candidate is None:
            candidate = ip
    return candidate


def validate_url(
    raw_url: str,
    config: AppConfig,
    *,
    allow_user_omit_scheme: bool = True,
) -> ValidationResult:
    """
    Run the full URL policy: length, scheme, hostname/IP class, port.

    `allow_user_omit_scheme` toggles the convenience that lets a human
    type "example.com" instead of "https://example.com". For redirect
    targets we set it to False — Location headers must be fully formed
    URLs, and silently re-prefixing them would mask classification bugs.
    """
    if not raw_url:
        return ValidationResult(error="Please enter a website URL.")

    raw_url = raw_url.strip()
    if len(raw_url) > config.max_url_length:
        return ValidationResult(error="URL is too long.")

    candidate = raw_url
    if "://" not in candidate and allow_user_omit_scheme:
        # Default to HTTPS — the safer scheme for the user.
        candidate = "https://" + candidate

    parsed = urlparse(candidate)

    if parsed.scheme not in config.allowed_schemes:
        return ValidationResult(error="Only http and https URLs are allowed.")

    hostname = parsed.hostname
    if not hostname:
        return ValidationResult(error="Could not parse a hostname from the URL.")
    hostname = hostname.lower()

    # `localhost` is special — it can resolve to 127.0.0.1 OR ::1 depending
    # on /etc/hosts and resolver behavior, so we reject it by name regardless
    # of what DNS would say.
    if hostname == "localhost":
        return ValidationResult(error="That hostname is not allowed.")

    # Port policy: if the URL omits a port, infer the scheme default.
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    if port not in config.allowed_ports:
        return ValidationResult(error="Only standard ports 80 and 443 are allowed.")

    # Branch on whether the hostname is already a literal IP.
    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        # Not a literal IP -> validate as a DNS hostname and resolve.
        if not _HOSTNAME_RE.match(hostname):
            return ValidationResult(
                error="Please enter a valid hostname (e.g. example.com)."
            )
        pinned = _resolve_safe_ip(hostname)
        if pinned is None:
            return ValidationResult(
                error="That hostname resolves to a disallowed address."
            )
    else:
        if not _is_public_ip(str(ip_obj)):
            return ValidationResult(
                error="Private or reserved IP addresses are not allowed."
            )
        pinned = str(ip_obj)

    # Reconstruct a canonical URL from the parts we vetted. We do NOT
    # echo the user's input verbatim into the outbound request — that
    # protects against weird userinfo/fragment payloads slipping past.
    safe_url = f"{parsed.scheme}://{hostname}"
    if parsed.port is not None:
        safe_url += f":{parsed.port}"
    safe_url += parsed.path or ""
    if parsed.query:
        safe_url += "?" + parsed.query

    return ValidationResult(safe_url=safe_url, pinned_ip=pinned)
