"""AbuseIPDB — community abuse reports for IPv4/IPv6. ~1,000 checks/day free."""

import httpx

from .. import config
from ..detect import Indicator
from ..models import SourceResult
from .base import Source


class AbuseIPDB(Source):
    name = "AbuseIPDB"
    supports = {"ip"}
    needs_key = True

    def __init__(self) -> None:
        self.key = config.ABUSEIPDB_API_KEY

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ind.value, "maxAgeInDays": 90},
            headers={"Key": self.key or "", "Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        score = int(data.get("abuseConfidenceScore", 0) or 0)
        reports = int(data.get("totalReports", 0) or 0)

        if reports == 0:
            verdict, label = "no_data", "No reports on file"
        elif score >= 50:
            verdict, label = "malicious", f"{score}% abuse confidence"
        elif score >= 10:
            verdict, label = "suspicious", f"{score}% abuse confidence"
        else:
            verdict, label = "clean", f"{score}% abuse confidence"

        fields = {"reports": str(reports), "confidence": f"{score}%"}
        for key, out in (
            ("numDistinctUsers", "distinct_reporters"),
            ("lastReportedAt", "last_reported"),
            ("countryCode", "country"),
            ("usageType", "usage_type"),
            ("isp", "isp"),
            ("domain", "domain"),
        ):
            if data.get(key):
                fields[out] = str(data[key])
        if data.get("isTor"):
            fields["tor"] = "Yes"

        return SourceResult(
            name=self.name,
            status="ok",
            verdict=verdict,
            score=label,
            fields=fields,
            link=f"https://www.abuseipdb.com/check/{ind.value}",
        )
