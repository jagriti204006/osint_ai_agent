"""Google Safe Browsing v4 — authoritative but binary: a match or nothing.

No match is genuinely weak evidence (the list covers known-bad only), so a
miss reports no_data rather than clean.
"""

import httpx

from .. import config
from ..detect import Indicator
from ..models import SourceResult
from .base import Source

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


class SafeBrowsing(Source):
    name = "Google Safe Browsing"
    supports = {"url", "domain"}
    needs_key = True

    def __init__(self) -> None:
        self.key = config.GOOGLE_SAFEBROWSING_API_KEY

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        target = ind.value if ind.type == "url" else f"http://{ind.value}/"
        payload = {
            "client": {"clientId": "osint-ai-agent", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target}],
            },
        }
        resp = await client.post(ENDPOINT, params={"key": self.key or ""}, json=payload)
        resp.raise_for_status()
        matches = resp.json().get("matches", []) or []

        link = "https://transparencyreport.google.com/safe-browsing/search"
        if not matches:
            return SourceResult(
                name=self.name,
                status="ok",
                verdict="no_data",
                score="No list match",
                fields={
                    "note": "not on any Safe Browsing list — this is not a clean verdict",
                    "lists_checked": str(len(THREAT_TYPES)),
                },
                link=link,
            )

        kinds = sorted({str(m.get("threatType", "UNKNOWN")) for m in matches})
        return SourceResult(
            name=self.name,
            status="ok",
            verdict="malicious",
            score=", ".join(k.replace("_", " ").title() for k in kinds),
            fields={
                "matches": str(len(matches)),
                "threat_types": ", ".join(kinds),
                "platform": str(matches[0].get("platformType", "ANY")),
            },
            link=link,
        )
