"""
Security-related building blocks.

Splitting security concerns into focused modules keeps each concern
small and independently testable:

  * `dns_pinning` — mitigates DNS-rebinding TOCTOU at the socket layer.
  * `url_validator` — pure-function URL/host/IP/port policy checks.
  * `headers` — registers HTTP response hardening headers.
"""
