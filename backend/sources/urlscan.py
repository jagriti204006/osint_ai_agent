"""urlscan.io — passive search over existing scans.

Deliberately search-only. Submitting a scan sends the URL to a third party and,
on the free tier, can make the submission publicly visible — which tips off an
actor that their infrastructure is under investigation. Active submission is
gated behind URLSCAN_ACTIVE_SCAN and is off by default.
"""

import httpx

from .. import config
from ..detect import Indicator
from ..models import SourceResult
from .base import Source


class UrlScan(Source):
    name = "urlscan.io"
    supports = {"url", "domain", "ip"}
    needs_key = True

    def __init__(self) -> None:
        self.key = config.URLSCAN_API_KEY

    def _query(self, ind: Indicator) -> str:
        if ind.type == "domain":
            return f"page.domain:{ind.value}"
        if ind.type == "ip":
            return f"page.ip:{ind.value}"
        return f'page.url:"{ind.value}"'

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        resp = await client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": self._query(ind), "size": 10},
            headers={"API-Key": self.key or ""},
        )
        resp.raise_for_status()
        body = resp.json()
        results = body.get("results", []) or []
        total = int(body.get("total", len(results)) or 0)

        link = f"https://urlscan.io/search/#{ind.value}"
        if not results:
            return SourceResult(
                name=self.name,
                status="ok",
                verdict="no_data",
                score="No scans on record",
                fields={"scans": "0", "note": "passive search only, nothing submitted"},
                link=link,
            )

        malicious = sum(
            1 for r in results if (r.get("verdicts", {}) or {}).get("malicious")
        )
        latest = results[0]
        page = latest.get("page", {}) or {}
        task = latest.get("task", {}) or {}

        if malicious:
            verdict = "malicious"
            score = f"{malicious} of {len(results)} scans flagged"
        else:
            verdict = "clean"
            score = f"{total} scan(s), none flagged"

        fields = {"scans": str(total)}
        for key, out in (("domain", "domain"), ("ip", "ip"), ("server", "server"),
                         ("country", "country"), ("status", "http_status")):
            if page.get(key):
                fields[out] = str(page[key])
        if task.get("time"):
            fields["last_scan"] = str(task["time"])
        if latest.get("result"):
            link = str(latest["result"])

        return SourceResult(
            name=self.name, status="ok", verdict=verdict, score=score,
            fields=fields, link=link,
        )
