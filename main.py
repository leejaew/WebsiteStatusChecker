"""
Production entry point.

This file stays small on purpose: all wiring lives in `app.create_app()`
so the entry point can be swapped (e.g. gunicorn, a CLI, a test runner)
without touching application code.

Run locally:  `python3 main.py`
Deployed via the `[deployment]` section in `.replit` (vm target).
"""

from app import create_app

# Module-level `app` so WSGI servers (gunicorn, etc.) can import it as
# `main:app` if we ever switch off the built-in dev server.
app = create_app()


if __name__ == "__main__":
    # Bind 0.0.0.0 so the Replit proxy can reach us. Port 5000 is the
    # one wired to the webview preview in the workflow config.
    app.run(host="0.0.0.0", port=5000)
