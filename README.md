# Website Status Checker

A small Flask web app that checks whether a public website is reachable
and reports its HTTP status, response time, and final URL after
redirects. Built with a focus on safe outbound HTTP — the checker is
hardened against SSRF, DNS rebinding, and redirect-based pivots into
internal networks.

## Features

- Submit any `http://` or `https://` URL through a simple form and get
  back the status code, reason, response time, and final redirected URL.
- Strict URL validation: scheme allowlist, hostname/IP allowlist
  (public IPs only), port allowlist, and re-validation on every redirect
  hop.
- DNS-rebinding-resistant outbound requests: the resolved IP is pinned
  at the socket layer so the host can't swap to an internal address
  mid-request.
- Response security headers (CSP, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`).
- Clean app-factory layout that's easy to extend or drop behind a
  production WSGI server.

## Project layout

```
.
├── main.py                       # Entry point — creates the app and runs it
├── requirements.txt              # Python dependencies
├── app/
│   ├── __init__.py               # create_app() application factory
│   ├── config.py                 # Config dataclass (limits, timeouts, allowlists)
│   ├── routes.py                 # Flask routes / form handling
│   ├── security/
│   │   ├── dns_pinning.py        # urllib3 socket-level IP pin (anti-DNS-rebinding)
│   │   ├── url_validator.py      # Scheme / host / IP / port validation
│   │   └── headers.py            # Response security headers
│   ├── services/
│   │   └── status_checker.py     # Performs the validated outbound check
│   └── templates/
│       └── index.html            # Single-page Jinja template
```

## Requirements

- Python 3.11+
- `pip` (or any installer that understands `requirements.txt`)

## Getting started

```bash
# 1. Create and activate a virtual environment (optional but recommended)
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the dev server
python3 main.py
```

The app listens on `http://0.0.0.0:5000` by default. Open
`http://localhost:5000` in a browser, enter a URL, and submit the form.

## Running in production

`main.py` exposes a module-level `app` object so any WSGI server can host it:

```bash
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:5000 main:app
```

## Security notes

The status checker accepts user-supplied URLs and makes outbound HTTP
requests on the server's behalf. To make this safe:

- Only `http` and `https` schemes are accepted.
- Hostnames must resolve to a **public** IP (no private, loopback,
  link-local, multicast, reserved, or IPv4-mapped IPv6 addresses).
- Only standard web ports are allowed (80, 443, and the common
  8000–8443 range — configurable in `app/config.py`).
- Every redirect hop is re-validated against the same allowlists, so a
  server can't redirect into an internal address.
- The resolved IP is pinned at socket creation, so the hostname can't
  rebind to a different address between resolution and connection.
- Response bodies are length-capped to avoid memory exhaustion.

If you adapt this project, keep these defenses in place — removing any
one of them re-opens an SSRF hole.

## License

Released under the [MIT License](LICENSE).
