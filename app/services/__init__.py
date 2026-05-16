"""
Application services — outbound work, separate from HTTP routing.

Keeping the actual status-checking logic in a service module (rather
than inline in a Flask view) lets the same logic be invoked from a CLI,
a scheduled job, or a test, without dragging Flask's request context.
"""
