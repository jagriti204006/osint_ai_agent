"""GTFOBins — Unix binaries abused for privilege escalation and evasion.

GTFOBins publishes no JSON API, so the entry list comes from the repository
listing via the GitHub API. Cached for a day: unauthenticated GitHub allows
only ~60 requests an hour.
"""

import httpx

from ..detect import Indicator
from ..models import SourceResult
from . import feeds
from .base import Source

LISTING = "https://api.github.com/repos/GTFOBins/GTFOBins.github.io/contents/_gtfobins"


class GTFOBins(Source):
    name = "GTFOBins"
    supports = {"process"}
    needs_key = False
    cache_ttl = 86400

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        # Strip a Windows extension: GTFOBins entries are bare Unix binary names.
        name = ind.value.lower().rsplit(".", 1)[0] if "." in ind.value else ind.value.lower()

        async def load():
            resp = await client.get(
                LISTING, headers={"Accept": "application/vnd.github+json"}
            )
            resp.raise_for_status()
            listing = resp.json()
            if not isinstance(listing, list):
                raise ValueError("Unexpected response from the GitHub contents API.")
            return {str(e.get("name", "")).removesuffix(".md").lower() for e in listing}

        # Unauthenticated GitHub allows ~60 requests/hour, so this must be
        # fetched once per day for the process, not once per indicator.
        names = await feeds.get("gtfobins", 86400, load)
        if name not in names:
            return SourceResult(
                name=self.name,
                status="ok",
                verdict="no_data",
                score="Not a GTFOBins entry",
                fields={"entries_checked": str(len(names))},
                link="https://gtfobins.github.io/",
            )

        # Context, not a verdict - see the note in lolbas.py.
        return SourceResult(
            name=self.name,
            status="ok",
            verdict="no_data",
            score="GTFOBins entry — abusable Unix binary",
            fields={
                "binary": name,
                "note": "legitimate binary with documented abuse techniques",
                "entries_checked": str(len(names)),
            },
            link=f"https://gtfobins.github.io/gtfobins/{name}/",
        )
