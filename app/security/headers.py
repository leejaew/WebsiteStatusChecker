"""
HTTP response security headers.

Registered as a Flask `after_request` hook so EVERY response — including
errors and redirects — gets the same hardening, with no per-route opt-in
required. Centralizing the policy here means a security review can audit
the full response surface in one place.

# What each header buys us, in plain terms

  * Content-Security-Policy: The page renders zero JS by design. CSP
    `default-src 'none'` enforces that even if an XSS sneaks in, the
    browser refuses to execute or load anything. `style-src 'unsafe-inline'`
    is the one concession — our small inline <style> block uses it.
  * X-Content-Type-Options: nosniff — stops browsers from re-guessing
    content types and treating our HTML as something dangerous.
  * X-Frame-Options + frame-ancestors: blocks clickjacking via iframe.
  * Referrer-Policy: don't leak the form contents in a Referer header.
  * Permissions-Policy: disable powerful browser APIs we never use.
"""

from flask import Flask, Response

_CSP = (
    "default-src 'none'; "
    "style-src 'unsafe-inline'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)

_HEADERS = {
    "Content-Security-Policy": _CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


def register_security_headers(flask_app: Flask) -> None:
    """Attach the security-headers `after_request` hook to `flask_app`."""

    @flask_app.after_request
    def _apply(response: Response) -> Response:
        for name, value in _HEADERS.items():
            response.headers.setdefault(name, value)
        return response
