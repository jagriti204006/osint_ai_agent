"""abuse.ch — one Auth-Key covers MalwareBazaar, URLhaus and ThreatFox.

Dispatches to whichever service fits the indicator type. Disabled until
ABUSECH_AUTH_KEY is set; get one free at https://auth.abuse.ch.
"""

import httpx

from .. import config
from ..detect import Indicator
from ..models import SourceResult
from .base import Source


class AbuseCh(Source):
    name = "abuse.ch"
    supports = {"hash", "url", "ip", "domain"}
    needs_key = True

    def __init__(self) -> None:
        self.key = config.ABUSECH_AUTH_KEY

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        headers = {"Auth-Key": self.key or ""}
        if ind.type == "hash":
            return await self._bazaar(ind, client, headers)
        if ind.type == "url":
            return await self._urlhaus(ind, client, headers)
        return await self._threatfox(ind, client, headers)

    async def _bazaar(self, ind, client, headers) -> SourceResult:
        resp = await client.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": ind.value},
            headers=headers,
        )
        resp.raise_for_status()
        body = resp.json()
        link = f"https://bazaar.abuse.ch/browse.php?search={ind.value}"

        if body.get("query_status") != "ok" or not body.get("data"):
            return SourceResult(
                name=self.name, status="ok", verdict="no_data",
                score="Not in MalwareBazaar", fields={"samples": "0"}, link=link,
            )
        item = body["data"][0]
        fields = {"signature": str(item.get("signature") or "unlabelled"),
                  "file_type": str(item.get("file_type") or "?"),
                  "first_seen": str(item.get("first_seen") or "?")[:10]}
        if item.get("tags"):
            fields["tags"] = ", ".join(str(t) for t in item["tags"][:5])
        return SourceResult(
            name=self.name, status="ok", verdict="malicious",
            score=f"MalwareBazaar: {item.get('signature') or 'known sample'}",
            fields=fields, link=link,
        )

    async def _urlhaus(self, ind, client, headers) -> SourceResult:
        resp = await client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": ind.value},
            headers=headers,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("query_status") != "ok":
            return SourceResult(
                name=self.name, status="ok", verdict="no_data",
                score="Not in URLhaus", fields={"entries": "0"},
                link="https://urlhaus.abuse.ch/browse/",
            )
        status = str(body.get("url_status") or "unknown")
        return SourceResult(
            name=self.name, status="ok",
            verdict="malicious" if status == "online" else "suspicious",
            score=f"URLhaus: payload {status}",
            fields={"threat": str(body.get("threat") or "?"),
                    "url_status": status,
                    "date_added": str(body.get("date_added") or "?")[:10]},
            link=str(body.get("urlhaus_reference") or "https://urlhaus.abuse.ch/browse/"),
        )

    async def _threatfox(self, ind, client, headers) -> SourceResult:
        resp = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ind.value},
            headers=headers,
        )
        resp.raise_for_status()
        body = resp.json()
        link = "https://threatfox.abuse.ch/browse/"
        if body.get("query_status") != "ok" or not body.get("data"):
            return SourceResult(
                name=self.name, status="ok", verdict="no_data",
                score="Not in ThreatFox", fields={"iocs": "0"}, link=link,
            )
        item = body["data"][0]
        return SourceResult(
            name=self.name, status="ok", verdict="malicious",
            score=f"ThreatFox: {item.get('malware_printable') or 'listed IOC'}",
            fields={"malware": str(item.get("malware_printable") or "?"),
                    "threat_type": str(item.get("threat_type") or "?"),
                    "confidence": f"{item.get('confidence_level', '?')}%",
                    "first_seen": str(item.get("first_seen") or "?")[:10]},
            link=link,
        )
