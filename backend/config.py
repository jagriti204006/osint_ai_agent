"""Configuration loaded from .env.

A blank key means the source is *disabled*, never an error. The app runs with
an empty .env using the four keyless sources.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")


def _opt(name: str) -> str | None:
    """Read an env var, treating blank/whitespace as absent."""
    return (os.environ.get(name) or "").strip() or None


VT_API_KEY = _opt("VT_API_KEY")
ABUSEIPDB_API_KEY = _opt("ABUSEIPDB_API_KEY")
ABUSECH_AUTH_KEY = _opt("ABUSECH_AUTH_KEY")
URLSCAN_API_KEY = _opt("URLSCAN_API_KEY")
OTX_API_KEY = _opt("OTX_API_KEY")
GREYNOISE_API_KEY = _opt("GREYNOISE_API_KEY")
GOOGLE_SAFEBROWSING_API_KEY = _opt("GOOGLE_SAFEBROWSING_API_KEY")
IPINFO_TOKEN = _opt("IPINFO_TOKEN")

CACHE_TTL = int(_opt("CACHE_TTL") or 3600)

# Uploading a sample to a public sandbox exposes it to every other researcher.
# Enforced server-side in main.py, not merely read here.
ALLOW_PUBLIC_FILE_UPLOAD = (_opt("ALLOW_PUBLIC_FILE_UPLOAD") or "false").lower() == "true"

# urlscan: submitting a scan sends the URL to a third party and may make it
# public. Passive search only unless deliberately changed.
URLSCAN_ACTIVE_SCAN = (_opt("URLSCAN_ACTIVE_SCAN") or "false").lower() == "true"

BASELINE_PATH = ROOT / "data" / "windows_process_baseline.json"
CACHE_PATH = ROOT / ".cache" / "osint.sqlite"
FRONTEND_DIR = ROOT / "frontend"

# OTX in particular is slow under load; 12s produced avoidable timeout faults.
HTTP_TIMEOUT = 20.0
USER_AGENT = "osint-ai-agent/1.0 (local analyst tool)"
