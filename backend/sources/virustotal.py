"""VirusTotal v3.

Public API terms are non-commercial. Free tier is roughly 4 req/min, 500/day.
"""

import base64

import httpx

from .. import config
from ..detect import Indicator
from ..models import SourceResult
from .base import Source

BASE = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"


def _url_id(url: str) -> str:
    """VT identifies URLs by unpadded base64url of the URL itself."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotal(Source):
    name = "VirusTotal"
    supports = {"hash", "ip", "domain", "url"}
    needs_key = True

    def __init__(self) -> None:
        self.key = config.VT_API_KEY

    def _endpoint(self, ind: Indicator) -> tuple[str, str]:
        if ind.type == "hash":
            return f"{BASE}/files/{ind.value}", f"{GUI}/file/{ind.value}"
        if ind.type == "ip":
            return f"{BASE}/ip_addresses/{ind.value}", f"{GUI}/ip-address/{ind.value}"
        if ind.type == "domain":
            return f"{BASE}/domains/{ind.value}", f"{GUI}/domain/{ind.value}"
        uid = _url_id(ind.value)
        return f"{BASE}/urls/{uid}", f"{GUI}/url/{uid}"

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        endpoint, link = self._endpoint(ind)
        resp = await client.get(endpoint, headers={"x-apikey": self.key or ""})

        if resp.status_code == 404:
            return SourceResult(
                name=self.name,
                status="ok",
                verdict="no_data",
                score="Not found",
                fields={"http_status": "404", "note": "never submitted to VirusTotal"},
                link=link,
            )
        resp.raise_for_status()

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        mal = int(stats.get("malicious", 0) or 0)
        sus = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = mal + sus + harmless + undetected

        if total == 0:
            verdict = "no_data"
            score = "No analysis on record"
        elif mal >= 3:
            verdict, score = "malicious", f"{mal} / {total} engines"
        elif mal >= 1 or sus >= 2:
            # Any outright malicious detection matters. A lone 'suspicious'
            # heuristic out of ~90 engines does not — that fired on public DNS
            # resolvers such as 9.9.9.9 and 208.67.222.222, which is noise.
            verdict, score = "suspicious", f"{mal} malicious, {sus} suspicious / {total}"
        else:
            verdict, score = "clean", f"{mal} / {total} engines"

        fields: dict[str, str] = {
            "malicious": str(mal),
            "suspicious": str(sus),
            "harmless": str(harmless),
            "undetected": str(undetected),
        }
        for key, label in (
            ("meaningful_name", "name"),
            ("type_description", "file_type"),
            ("reputation", "reputation"),
            ("as_owner", "as_owner"),
            ("country", "country"),
            ("creation_date", "created"),
        ):
            if key in attrs and attrs[key] not in (None, ""):
                fields[label] = str(attrs[key])

        return SourceResult(
            name=self.name,
            status="ok",
            verdict=verdict,
            score=score,
            fields=fields,
            link=link,
        )
