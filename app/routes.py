"""
HTTP layer: Flask view functions.

This module is intentionally thin. Its only job is to translate between
HTTP (form input, rendered templates) and the application services. All
real work happens in `app.security.url_validator` and
`app.services.status_checker`. Keeping views thin makes them easy to
read and lets the underlying logic be reused outside an HTTP context.
"""

from __future__ import annotations

from flask import Flask, render_template, request
from markupsafe import escape

from app.config import AppConfig
from app.security.url_validator import validate_url
from app.services.status_checker import StatusChecker, StatusResult


def register_routes(flask_app: Flask, config: AppConfig) -> None:
    """Attach all view functions to `flask_app`."""

    # One checker instance, reused across requests. It's stateless apart
    # from the config it holds, so this is safe and saves a tiny bit of
    # per-request work.
    checker = StatusChecker(config)

    @flask_app.route("/", methods=["GET", "POST"])
    def index():
        url_display = ""
        result: StatusResult | None = None
        error: str | None = None

        if request.method == "POST":
            raw = request.form.get("url", "")

            # Length check first, before any parsing — cheapest reject.
            if len(raw) > config.max_url_length:
                error = "URL is too long."
                # Truncate so we don't echo a 1MB string back into HTML.
                url_display = raw[: config.max_url_length]
            else:
                validation = validate_url(raw, config)
                if not validation.is_valid:
                    error = validation.error
                    url_display = raw[: config.max_url_length]
                else:
                    # safe_url and pinned_ip are guaranteed non-None
                    # when is_valid is True; the type ignores reflect
                    # that contract.
                    result = checker.check(
                        validation.safe_url,  # type: ignore[arg-type]
                        validation.pinned_ip,  # type: ignore[arg-type]
                    )
                    url_display = validation.safe_url  # type: ignore[assignment]

        # Jinja autoescapes by default for .html templates, but we wrap
        # `url_display` in `escape()` explicitly to make the safety
        # intent obvious at the call site.
        return render_template(
            "index.html",
            url=escape(url_display),
            result=result,
            error=error,
        )
