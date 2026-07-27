"""AlienVault OTX (LevelBlue) — community 'pulses' give campaign context.

Pulse membership is a weaker signal than an engine detection: pulses include
benign and research indicators. Treated as suspicious rather than malicious
unless several pulses agree.
"""

import httpx

from .. import config
from ..detect import Indicator
from ..models import SourceResult
from .base import Source

BASE = "https://otx.alienvault.com/api/v1/indicators"

SECTION = {
    "ip": ("IPv4", "ip"),
    "domain": ("domain", "domain"),
    "url": ("url", "url"),
    "hash": ("file", "file"),
}


def _labels(pulses: list, key: str) -> list[str]:
    """Collect a pulse field that OTX returns as either strings or objects.

    malware_families arrives as [{'display_name': 'Emotet', ...}] on some
    endpoints and as ['Emotet'] on others.
    """
    out: set[str] = set()
    for pulse in pulses:
        for item in pulse.get(key) or []:
            if isinstance(item, dict):
                label = item.get("display_name") or item.get("name") or item.get("id")
            else:
                label = item
            if label:
                out.add(str(label))
    return sorted(out)


class OTX(Source):
    name = "AlienVault OTX"
    supports = {"ip", "domain", "url", "hash"}
    needs_key = True

    def __init__(self) -> None:
        self.key = config.OTX_API_KEY

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        kind, slug = SECTION[ind.type]
        if ind.type == "ip" and ind.extra.get("version") == 6:
            kind = "IPv6"

        resp = await client.get(
            f"{BASE}/{kind}/{ind.value}/general",
            headers={"X-OTX-API-KEY": self.key or ""},
        )
        link = f"https://otx.alienvault.com/indicator/{slug}/{ind.value}"

        if resp.status_code == 404:
            return SourceResult(
                name=self.name, status="ok", verdict="no_data",
                score="Not indexed", fields={"pulses": "0"}, link=link,
            )
        resp.raise_for_status()
        data = resp.json()

        info = data.get("pulse_info", {}) or {}
        count = int(info.get("count", 0) or 0)
        pulses = info.get("pulses", []) or []
        families = _labels(pulses, "malware_families")

        # OTX marks known-good infrastructure explicitly. Popular domains and
        # public resolvers carry markers like 'Whitelisted domain', 'Listed on
        # Alexa' or 'Known False Positive'. Honour those first.
        whitelist = [
            str(v.get("name")) for v in (data.get("validation") or []) if v.get("name")
        ]

        # OTX is corroboration and campaign context, not a detection engine.
        #
        # malware_families are attributes of a *pulse* — a curated collection —
        # not of the individual indicator inside it, so they leak across. The
        # all-zero SHA-256 placeholder picked up 'PUA:Win32/OpenCandy' purely by
        # sharing pulses with unrelated samples. Pulse counts were worse: popular
        # infrastructure sits in dozens of auto-generated pulses.
        #
        # So OTX only ever lowers suspicion (via OTX's own whitelist markers) or
        # stays silent. Everything useful still reaches the analyst through the
        # fields below. This cannot cause a miss: the other sources set the
        # verdict independently.
        if whitelist:
            verdict = "clean"
            score = "Whitelisted by OTX"
        elif count == 0:
            verdict, score = "no_data", "0 pulses"
        else:
            verdict = "no_data"
            score = f"{count} pulse(s) — context only"

        fields = {"pulses": str(count)}
        if whitelist:
            fields["whitelist"] = ", ".join(whitelist[:3])
        if families:
            fields["families"] = ", ".join(families[:4])
        tags = _labels(pulses, "tags")
        if tags:
            fields["tags"] = ", ".join(tags[:5])
        if pulses and pulses[0].get("created"):
            fields["first_pulse"] = str(pulses[0]["created"])[:10]
        for key, out in (("asn", "asn"), ("country_name", "country"),
                         ("whois", None), ("type_title", "kind")):
            if out and data.get(key):
                fields[out] = str(data[key])

        return SourceResult(
            name=self.name, status="ok", verdict=verdict, score=score,
            fields=fields, link=link,
        )
