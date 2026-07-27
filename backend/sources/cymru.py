"""Team Cymru Malware Hash Registry — free hash lookup over DNS, no key.

A TXT record at <hash>.malware.hash.cymru.com returns "<last_seen> <detection%>".
NXDOMAIN means not known to the registry, which is no_data, not clean.
MD5 and SHA-1 only.
"""

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from ..detect import Indicator
from ..models import SourceResult
from .base import Source

ZONE = "malware.hash.cymru.com"


class CymruMHR(Source):
    name = "Team Cymru MHR"
    supports = {"hash"}
    needs_key = False
    cache_ttl = 21600

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        kind = ind.extra.get("kind")
        if kind not in ("md5", "sha1"):
            return SourceResult(
                name=self.name,
                status="ok",
                verdict="no_data",
                score="Not applicable",
                fields={"note": f"MHR indexes MD5 and SHA-1 only; this is {kind}"},
            )

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 6.0
        resolver.timeout = 3.0

        try:
            answer = await resolver.resolve(f"{ind.value}.{ZONE}", "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return SourceResult(
                name=self.name,
                status="ok",
                verdict="no_data",
                score="Not in registry",
                fields={"note": "unknown to MHR — absence of evidence, not clean"},
            )
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            # Surface as an error: a DNS failure must never read as 'clean'.
            return SourceResult(
                name=self.name,
                status="error",
                error=f"DNS lookup failed ({type(exc).__name__}). "
                      "Egress filtering may be blocking the query.",
            )

        txt = " ".join(part.decode() for part in answer[0].strings).strip('"').split()
        last_seen, rate = (txt + ["", ""])[:2]
        try:
            pct = int(rate)
        except ValueError:
            pct = 0

        verdict = "malicious" if pct >= 20 else "suspicious" if pct > 0 else "no_data"
        return SourceResult(
            name=self.name,
            status="ok",
            verdict=verdict,
            score=f"{pct}% AV detection",
            fields={"detection_rate": f"{pct}%", "last_seen_epoch": last_seen,
                    "hash_kind": kind},
        )
