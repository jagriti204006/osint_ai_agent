"""RDAP — registration data, no key required.

Domain age is the single strongest cheap signal in phishing triage: a domain
registered days ago and already in an email is suspicious regardless of what
any reputation engine says about it.
"""

from datetime import datetime, timezone

import httpx

from ..detect import Indicator
from ..models import SourceResult
from .base import Source

YOUNG_DAYS = 30
NEWISH_DAYS = 90


def _parse_when(value: str) -> datetime | None:
    raw = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class RDAP(Source):
    name = "RDAP / WHOIS"
    supports = {"domain", "ip", "email"}
    needs_key = False
    cache_ttl = 21600

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        target = ind.extra.get("domain") if ind.type == "email" else ind.value
        kind = "ip" if ind.type == "ip" else "domain"
        url = f"https://rdap.org/{kind}/{target}"

        resp = await client.get(url, headers={"Accept": "application/rdap+json"},
                                follow_redirects=True)
        if resp.status_code == 404:
            # Authoritative negative: the registry has no record, so the domain
            # is not registered. Flagged so aggregation can stop VirusTotal's
            # '0/91 harmless' on a non-existent domain reading as clean.
            return SourceResult(
                name=self.name, status="ok", verdict="no_data",
                score="Not registered",
                fields={
                    "registered": "No",
                    "note": f"no RDAP record for {target} — the domain does not exist",
                },
                link=url,
            )
        resp.raise_for_status()
        data = resp.json()

        events = {
            str(e.get("eventAction", "")).lower(): str(e.get("eventDate", ""))
            for e in (data.get("events") or [])
        }
        fields: dict[str, str] = {}
        verdict: str = "no_data"
        score = "Registration record"

        registered = events.get("registration") or events.get("last changed")
        age_days: int | None = None
        if registered:
            when = _parse_when(registered)
            if when:
                age_days = (datetime.now(timezone.utc) - when).days
                fields["created"] = registered[:10]
                fields["age_days"] = str(age_days)
        if events.get("expiration"):
            fields["expires"] = events["expiration"][:10]

        if kind == "domain":
            for ns in (data.get("nameservers") or [])[:2]:
                fields.setdefault("nameservers", "")
                nm = str(ns.get("ldhName", "")).lower()
                if nm:
                    fields["nameservers"] = (fields["nameservers"] + " " + nm).strip()
            for ent in (data.get("entities") or []):
                roles = [str(r).lower() for r in (ent.get("roles") or [])]
                if "registrar" in roles:
                    for item in (ent.get("vcardArray") or [None, []])[1]:
                        if isinstance(item, list) and item and item[0] == "fn":
                            fields["registrar"] = str(item[3])
                            break
            if age_days is not None:
                if age_days <= YOUNG_DAYS:
                    verdict = "suspicious"
                    score = f"Registered {age_days} day(s) ago"
                elif age_days <= NEWISH_DAYS:
                    verdict = "suspicious"
                    score = f"Registered {age_days} days ago"
                else:
                    verdict = "clean"
                    score = f"Registered {age_days // 365} year(s) ago"
        else:
            for key, out in (("name", "netname"), ("country", "country"),
                             ("handle", "handle"), ("startAddress", "range_start"),
                             ("endAddress", "range_end")):
                if data.get(key):
                    fields[out] = str(data[key])
            score = "Allocation record"

        return SourceResult(
            name=self.name, status="ok", verdict=verdict, score=score,
            fields=fields, link=url,
        )
