"""
DNS pinning to prevent DNS-rebinding SSRF.

# Why this module exists

Without pinning, our SSRF defense has a TOCTOU (time-of-check / time-of-use)
gap: we resolve a hostname, decide it's a public IP, then hand the URL to
`requests`. `requests`/urllib3 then resolves the hostname AGAIN at connect
time, and a malicious authoritative DNS server can return a different IP on
that second lookup — typically a private/internal address — turning a
"validated" request into an SSRF.

# How the fix works

`urllib3.util.connection.create_connection` is the single function urllib3
calls to open every TCP socket. We replace it with a wrapper that, when a
"pinned IP" is set in thread-local state, ignores the hostname in `address`
and connects directly to the IP we already vetted. SNI and TLS certificate
verification still use the original hostname from the URL (urllib3 takes
those from the URL, not from the socket peer), so HTTPS keeps working
correctly.

The pin is exposed as a context manager `pinned_ip(ip)` so callers can't
forget to clear it. Thread-local state keeps Flask's threaded dev server and
production threadpools safe.

# Scope / limits

This pin is process-global (it monkeypatches a module attribute). That is
intentional — every outbound `requests.get` in this process must go through
it. If a future feature needs unpinned outbound traffic, expose an explicit
opt-out rather than removing the patch.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator, Optional

import urllib3.util.connection as _urllib3_connection

# Thread-local storage so concurrent requests don't trample each other's pin.
_pin_state = threading.local()

# Capture the original create_connection ONCE at import time. Re-importing
# this module is a no-op because Python caches modules — but we still guard
# against double-installation below.
_ORIGINAL_CREATE_CONNECTION = _urllib3_connection.create_connection
_INSTALLED = False


def _patched_create_connection(address, *args, **kwargs):
    """
    urllib3-compatible create_connection that honors the thread-local pin.

    `address` is a (host, port) tuple. When a pin is active we substitute
    the host with the pre-validated IP, leaving the port untouched.
    """
    host, port = address
    pinned = getattr(_pin_state, "ip", None)
    if pinned is not None:
        address = (pinned, port)
    return _ORIGINAL_CREATE_CONNECTION(address, *args, **kwargs)


def install_dns_pin() -> None:
    """
    Install the urllib3 monkeypatch.

    Idempotent: safe to call multiple times (e.g. from `create_app` in
    tests). Must be called before any outbound HTTP traffic so the
    interception is active for the very first request.
    """
    global _INSTALLED
    if _INSTALLED:
        return
    _urllib3_connection.create_connection = _patched_create_connection
    _INSTALLED = True


@contextmanager
def pinned_ip(ip: Optional[str]) -> Iterator[None]:
    """
    Context manager that pins outbound socket connects to `ip`.

    Usage:

        with pinned_ip("203.0.113.42"):
            requests.get("https://example.com/")  # connects to .42

    Passing `None` is a no-op; this lets callers conditionally pin
    without branching on every call site.
    """
    previous = getattr(_pin_state, "ip", None)
    _pin_state.ip = ip
    try:
        yield
    finally:
        _pin_state.ip = previous
