# ReconLab — Reconnaissance & Footprinting Workbench

Full-stack training dashboard based on the user's 49-page PDF extract of **Chapter 3: Reconnaissance and Footprinting** (book pp. 83–131). Built with **HTML/CSS/vanilla JavaScript** and **Python/FastAPI**.

## Quick start

```bash
cd recon-workbench
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
Open **http://127.0.0.1:8000**. The API documentation is at **http://127.0.0.1:8000/docs**.



## Features

- **DNS intelligence**: A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, with educational defensive observations.
- **Subdomain discovery**: passive names from certificate transparency (crt.sh). No host scanning; may be rate-limited.
- **RDAP**: public registration metadata via rdap.org. Not a guarantee of ownership or scope.
- **TLS inspector**: one authorized verified handshake to port 443, direct IP filtered for globally routable destinations, no certificate validation bypass.
- **Search builder**: safe domain-scoped operators; search opens in the browser.
- **Email header analyzer**: parse local header text and report mail relays and authorization flags; never send pasted email contents externally.
- **EXIF checker**: uploaded image parsed in RAM; display camera, timestamp, GPS and a map link if present.
- **Reports**: JSON export via the frontend.
- **External references**: Shodan, Censys, Netcraft, DNSDumpster, CVE, Internet Archive, Google Alerts, and optional CLIs.

## Safety & accuracy

Designed for **your own domains and explicitly authorized assets**. DNS and TLS endpoints require an explicit authorization checkbox. No exploitation, credential checks, service enumeration, bulk scanning, phishing, or social-engineering functions. Passive CT logs may contain stale names or names not operated by the entity being assessed. DNS is non-intrusive but still contacts infrastructure or a resolver. Do not send private emails to third-party analyzers without consent.

**Important:** This is a usable instructional prototype, not a certified security auditor. No finding by itself proves a vulnerability. The certificate-transparency endpoint is a third-party service; availability and rate limits are outside this project's control. This prototype has no login system; run only on loopback or add authentication and rate limiting before any shared deployment.

## Files

- `main.py` — FastAPI endpoints, input validation, analysis and services
- `static/index.html` — dashboard
- `static/style.css` — responsive dark UI
- `static/app.js` — UI interactions, fetch, rendering, report export
- `requirements.txt` — Python dependencies
