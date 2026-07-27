"""GreyNoise Community — separates internet background noise from targeting.

The highest-value false-positive filter in the set: an IP that scans the entire
internet is not evidence that *you* were targeted. Disabled until
GREYNOISE_API_KEY is set.
"""

import httpx

from .. import config
from ..detect import Indicator
from ..models import SourceResult
from .base import Source


class GreyNoise(Source):
    name = "GreyNoise"
    supports = {"ip"}
    needs_key = True

    def __init__(self) -> None:
        self.key = config.GREYNOISE_API_KEY

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        resp = await client.get(
            f"https://api.greynoise.io/v3/community/{ind.value}",
            headers={"key": self.key or "", "Accept": "application/json"},
        )
        link = f"https://viz.greynoise.io/ip/{ind.value}"

        if resp.status_code == 404:
            return SourceResult(
                name=self.name, status="ok", verdict="no_data",
                score="Not observed scanning",
                fields={"note": "no scan activity on record — says nothing about "
                                "whether the IP is malicious"},
                link=link,
            )
        resp.raise_for_status()
        data = resp.json()

        classification = str(data.get("classification") or "unknown").lower()
        verdict = {
            "malicious": "malicious",
            "benign": "clean",
            "unknown": "no_data",
        }.get(classification, "no_data")

        fields = {
            "classification": classification,
            "internet_scanner": "Yes" if data.get("noise") else "No",
            "common_business_service": "Yes" if data.get("riot") else "No",
        }
        if data.get("name"):
            fields["actor"] = str(data["name"])
        if data.get("last_seen"):
            fields["last_seen"] = str(data["last_seen"])

        if data.get("noise") and classification != "malicious":
            fields["triage_note"] = (
                "Mass internet scanner — likely background noise, not targeting"
            )

        return SourceResult(
            name=self.name, status="ok", verdict=verdict,
            score=f"Classified: {classification}", fields=fields,
            link=str(data.get("link") or link),
        )
