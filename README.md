# osint_ai_agent

A one-stop IOC reputation lookup tool. Submit a hash, IP, domain, URL, email
sender or process name and it fans out to multiple OSINT sources, returns a
normalized verdict per source plus an aggregate, and gives you the raw JSON for
your ticket.

Local analyst tool. Binds to `127.0.0.1` only.

## Run

```bash
.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Then open <http://127.0.0.1:8000>.

First-time setup, if the venv is missing:

```bash
python -m venv .venv && .venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Sources

Twelve sources. A missing key disables that source — it never breaks the app,
and the UI shows which were consulted.

| Source | IOC types | Key |
|---|---|---|
| VirusTotal | hash, ip, domain, url | `VT_API_KEY` |
| AbuseIPDB | ip | `ABUSEIPDB_API_KEY` |
| urlscan.io | url, domain, ip | `URLSCAN_API_KEY` |
| AlienVault OTX | hash, ip, domain, url | `OTX_API_KEY` |
| Google Safe Browsing | url, domain | `GOOGLE_SAFEBROWSING_API_KEY` |
| GreyNoise | ip | `GREYNOISE_API_KEY` |
| abuse.ch | hash, url, ip, domain | `ABUSECH_AUTH_KEY` |
| RDAP / WHOIS | domain, ip, email | none |
| Email Authentication | email | none (DNS) |
| Team Cymru MHR | hash (MD5/SHA-1) | none |
| Process Baseline | process | none (local JSON) |
| LOLBAS | process | none |
| GTFOBins | process | none |

Keys go in `.env` (gitignored). Copy `.env.example` and fill in what you have.

## Verdicts

Four states. `clean` must be **earned** — a source that errored, was rate
limited, or has never seen the indicator contributes nothing toward it.

- `malicious` — at least one source affirmatively flags it
- `suspicious` — at least one rates it suspicious, none malicious
- `clean` — at least one affirmatively reports clean, none flagged
- `no_data` — nothing affirmative came back. **Not the same as clean.**

Confidence drops when sources error or rate limit, because coverage is
incomplete.

## Process analysis

The one thing reputation APIs cannot answer: is this process running from the
right place? `data/windows_process_baseline.json` holds 45 Windows processes
with expected paths, parents, instance policies and homoglyph watchlists.

Submit a bare name (`svchost.exe`) for the expected values, or a full path
(`C:\Users\Public\svchost.exe`) to have it verified. Typosquats like
`scvhost.exe` are caught by edit distance and digit-substitution matching.

## Email sender analysis

Checks the sender domain's SPF, DKIM, DMARC and MX over DNS. No key needed.

**What it measures: spoofability, not intent.** A domain with perfect DMARC can
still send phishing; a small legitimate domain with no DMARC is forgeable, not
malicious. The verdict reflects how hard the domain is to impersonate.

- **SPF** — presence plus the `all` qualifier (`-all` hard fail, `~all` soft
  fail, `?all` neutral, `+all` broken)
- **DMARC** — presence plus the `p=` policy. `p=none` is monitor-only and does
  not stop spoofing
- **DKIM** — probes 12 common selectors. A `p=` with an empty value is a
  *revoked* key per RFC 6376 and is not counted. A deterministic control
  selector detects zones that wildcard `*._domainkey`, where probing is
  meaningless and the result is reported as inconclusive
- **MX** — a **null MX** (`.`, RFC 7505) means the owner declares the domain
  sends no mail at all, so any message claiming to come from it is forged.
  That grades `malicious` on its own

**DKIM limitation, stated plainly:** verifying a signature needs the message's
`DKIM-Signature` header, which supplies the selector. Without the message this
can only show whether the domain publishes DKIM keys — a bespoke selector will
be missed, so absence is not proof.

## Security posture

- **Keys never reach the browser.** All API calls happen server-side; the
  frontend only talks to localhost.
- **Strict CSP**, no `unsafe-inline` for scripts or styles. All CSS is in a
  stylesheet; the client builds DOM via `textContent` and never `innerHTML`.
- **Scheme allowlist** on every outbound link, enforced server-side *and*
  client-side. A `javascript:` URL from a hostile API response cannot become a
  clickable link.
- **Confidence is clamped** to an integer 0–100 before it reaches CSS.
- **Input hardening** — leading-zero IP octets rejected (octal ambiguity),
  private/loopback/link-local addresses refused so internal detail never leaks
  to a third-party API, IDN domains converted to punycode so homograph phishing
  domains are analysable, URL schemes restricted to http/https.
- **File upload is refused** (`/api/upload` returns 403). Uploading a sample to
  a public sandbox exposes it to other researchers and tips off the actor.
  Look files up by hash.
- **urlscan is passive search only** — submitting a scan would send the URL to a
  third party and can be publicly visible. Gated behind `URLSCAN_ACTIVE_SCAN`.
- **Clipboard failures surface** rather than silently reporting success.
- **Defanged copy** available on every indicator (`evil[.]com`) so a live IOC
  pasted into a ticket cannot be clicked by accident.

## Layout

```
backend/
  main.py        FastAPI app, SSE endpoint, static serving, security headers
  config.py      env loading; blank key = disabled source
  detect.py      IOC type detection + hardened validation
  sanitize.py    scheme allowlist, confidence clamp, defang
  aggregate.py   verdict + confidence logic
  enrich.py      type-specific detail panel, ATT&CK mapping
  cache.py       SQLite TTL cache
  ratelimit.py   per-source token buckets
  sources/       one module per source
frontend/
  index.html     structure + radar SVG
  styles.css     all styling (nothing inline)
  app.js         SSE client, DOM building
data/
  windows_process_baseline.json
```

## API

- `POST /api/lookup` — `{"ioc": "...", "type": "auto"}`, returns an SSE stream
  of `start` / `source` / `done` / `error` events
- `GET /api/health` — which sources are configured
- `POST /api/cache/purge` — drop expired cache entries
- `POST /api/upload` — always 403, by design

## Notes

VirusTotal's public API is non-commercial only. Fine for personal and portfolio
use; a commercial deployment needs a Premium licence.
