"""
Application package for the Website Status Checker.

This package uses the Flask **App Factory** pattern (`create_app`) so that the
Flask application can be instantiated with different configurations without
relying on import-time side effects. That makes the app trivial to wire up in
tests or alternate entry points later, without rewriting global state.

Module layout (kept intentionally flat — this is a small app):

    app/
      __init__.py           -> create_app() factory
      config.py             -> AppConfig dataclass with all tunables
      routes.py             -> Flask view functions (HTTP layer only)
      templates/index.html  -> Jinja template (HTML kept out of Python)
      security/
        dns_pinning.py      -> urllib3 socket-level IP pin (anti-rebinding)
        url_validator.py    -> URL/host/IP/port policy checks
        headers.py          -> Response security headers middleware
      services/
        status_checker.py   -> Outbound HTTP status-checking service
"""

from flask import Flask

from app.config import AppConfig
from app.routes import register_routes
from app.security.dns_pinning import install_dns_pin
from app.security.headers import register_security_headers


def create_app(config: AppConfig | None = None) -> Flask:
    """
    Construct and configure the Flask application.

    The factory does three things, in this order, on purpose:

    1. Install the DNS-pinning monkeypatch at the urllib3 socket layer.
       This MUST happen before any outbound HTTP client is used so that
       the SSRF defenses are in effect for every request the app makes.
    2. Build the Flask app with our chosen template folder.
    3. Register security headers (after_request) and route handlers.

    Passing a custom `AppConfig` lets tests or alternate entry points
    tweak limits (timeouts, allowed ports, max URL length) without
    monkeypatching module globals.
    """
    install_dns_pin()

    cfg = config or AppConfig()

    flask_app = Flask(
        __name__,
        template_folder="templates",
    )

    # Config is passed explicitly into the layers that need it rather
    # than stashed on `flask_app.config`. Explicit injection keeps the
    # dependency visible in function signatures and avoids hidden
    # coupling to Flask's global request context.
    register_security_headers(flask_app)
    register_routes(flask_app, cfg)

    return flask_app
