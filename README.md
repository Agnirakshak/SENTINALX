# SENTINEL X — Unified Web Trust & Threat Intelligence

A hackathon prototype that combines public-website URL heuristics, HTTPS/TLS certificate validation, HTTP security-header checks, explainable risk scoring, scan history, and a community-submitted threat-report queue.

> **Important:** This is a defensive prototype, not a production security product. A low score does not prove a website is safe. Community reports are unverified. The current version does not include a trained ML model, commercial reputation feeds, full certificate-transparency history, browser rendering analysis, or attribution of threat actors.

## Features

- Public HTTP/HTTPS URL analysis with transparent heuristic findings.
- TLS handshake validation using the system trust store, hostname verification, issuer/subject, expiry, TLS version and cipher.
- HTTP security-header checks (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy).
- Explainable 0–100 risk indicator combining URL heuristics, header gaps, TLS validation and exact-host community reports.
- SQLite scan history and community report queue.
- JSON investigation report export.
- Basic SSRF protections: blocks non-global IP destinations, limits redirects, restricts schemes, and uses bounded timeouts.

## Run locally

Python 3.10+ is recommended.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```

Open <http://127.0.0.1:8000>. API health: <http://127.0.0.1:8000/api/health>.

## Environment

Copy `.env.example` to `.env` if you need to configure local environment values. The current prototype requires no API keys. Never commit real secrets.

## Safety and limitations

- Only scan public websites you are authorised to assess.
- Private, loopback, link-local, multicast and reserved IP targets are blocked by IP classification.
- This prototype does not perform exploit testing, port scanning, credential submission or destructive actions.
- DNS rebinding and complex proxy/network environments require stronger egress controls before production use. Deploy behind network-level egress restrictions.
- HTTP fetches are bounded and redirect destinations are revalidated, but a production service should pin DNS resolution to the connected address to eliminate rebinding risk.
- Certificate validation means the TLS handshake passed the local trust store and hostname checks; it does not mean the site operator is honest.
- Heuristic risk scoring is a prioritisation aid, not a probability of compromise or a definitive malicious/benign verdict.
- Community reports are user-submitted and unverified; they must not be represented as confirmed threats.

## Architecture

- `app.py`: FastAPI routes, SQLite persistence, URL validation, safe network checks, TLS inspection, header analysis and risk scoring.
- `static/index.html`: responsive single-page dashboard and browser-side interactions.
- `requirements.txt`: runtime dependencies.

## Competition disclosure

Disclose the use of AI coding assistants, libraries, public APIs, templates and other tools according to the event's rules. This implementation uses FastAPI, HTTPX, Pydantic, Python standard-library networking/TLS/SQLite modules, Google Fonts, and AI-assisted development. No external threat-intelligence API is currently integrated.

## Development log

Add genuine commits as work progresses during the permitted competition window. Do not backdate commits or present pre-round implementation code as competition work.

## Risk-scoring calibration update

- Legitimate brand domains and their subdomains are allowlisted for brand-name impersonation checks (for example, `google.com` and `www.google.com`). Similar brand strings on unrelated domains remain review signals.
- HTTP 401/403/429/503 responses are treated as limited inspection, not automatic evidence of phishing or missing application headers.
- Missing security headers contribute a small hardening score (maximum 5 points), not a large phishing penalty.
- TLS connection/inspection failures caused by timeouts or network restrictions are reported as unavailable and do not automatically add an invalid-certificate penalty. A completed certificate/hostname verification failure remains a high-severity finding.
