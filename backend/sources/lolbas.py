"""LOLBAS — legitimate Windows binaries abused by attackers. No key.

Answers 'is this binary one attackers live off?' and returns the abuse
functions plus the project's own detection rules.
"""

import httpx

from ..detect import Indicator
from ..models import SourceResult
from . import feeds
from .base import Source

FEED = "https://lolbas-project.github.io/api/lolbas.json"


class LOLBAS(Source):
    name = "LOLBAS"
    supports = {"process"}
    needs_key = False
    cache_ttl = 86400

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        async def load():
            resp = await client.get(FEED)
            resp.raise_for_status()
            return resp.json()

        # One fetch per day for the whole process, not per indicator.
        feed = await feeds.get("lolbas", 86400, load)

        name = ind.value.lower()
        entry = next((e for e in feed if str(e.get("Name", "")).lower() == name), None)

        if entry is None:
            return SourceResult(
                name=self.name,
                status="ok",
                verdict="no_data",
                score="Not a LOLBAS entry",
                fields={"note": "not a known living-off-the-land binary"},
                link="https://lolbas-project.github.io/",
            )

        commands = entry.get("Commands") or []
        categories = sorted({str(c.get("Category", "")) for c in commands if c.get("Category")})
        mitre = sorted({str(c.get("MitreID", "")) for c in commands if c.get("MitreID")})
        paths = [str(p.get("Path", "")) for p in (entry.get("Full_Path") or [])]
        detections = entry.get("Detection") or []

        fields = {
            "abuse_functions": ", ".join(categories[:5]) or "see entry",
            "expected_paths": ", ".join(paths[:2]) or "n/a",
            "detection_rules_available": str(len(detections)),
        }
        if mitre:
            fields["mitre"] = ", ".join(mitre[:4])
        if entry.get("Description"):
            fields["description"] = str(entry["Description"])

        # Context, not a verdict. These binaries ship with Windows, so a LOLBAS
        # listing says the binary is *abusable*, not that this instance is
        # abused. Returning 'suspicious' here made a legitimate
        # C:\Windows\explorer.exe grade suspicious, since suspicious outranks
        # clean in aggregation. Path anomaly is Process Baseline's call; the
        # abuse detail still surfaces in the detail panel and as a flag chip.
        return SourceResult(
            name=self.name,
            status="ok",
            verdict="no_data",
            score=f"LOLBAS entry — {len(commands)} abuse technique(s)",
            fields=fields,
            link=str(entry.get("url") or "https://lolbas-project.github.io/"),
        )
