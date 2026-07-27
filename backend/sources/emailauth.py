"""SPF / DKIM / DMARC posture for a sender domain, over DNS. No key required.

Scope, stated plainly: this measures how *spoofable* the sender domain is. It
does not and cannot tell you whether a specific message was malicious — that
needs the message headers. A domain with perfect DMARC can still send phishing;
a small legitimate domain with no DMARC is not malicious, merely forgeable.

DKIM has a further limit. Keys live at <selector>._domainkey.<domain> and the
selector is only known from a message's DKIM-Signature header. Without the
message we probe common selectors, which shows whether the domain publishes
DKIM at all — it never verifies a signature.
"""

import asyncio
import re

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from ..detect import Indicator
from ..models import SourceResult
from .base import Source

# Selectors used by the major mail platforms. A hit proves the domain publishes
# DKIM; a miss proves nothing, since the real selector may be bespoke.
COMMON_SELECTORS = (
    "google", "selector1", "selector2", "k1", "default",
    "dkim", "mail", "s1", "s2", "protonmail", "zoho", "mandrill",
)

SPF_QUALIFIER = {
    "-all": ("hard fail", "strong"),
    "~all": ("soft fail", "moderate"),
    "?all": ("neutral", "weak"),
    "+all": ("allow all", "broken"),
}


def _resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.lifetime = 6.0
    r.timeout = 3.0
    return r


async def _txt(resolver, name: str) -> list[str]:
    """Return TXT strings for `name`, or [] when absent. Raises on DNS failure."""
    try:
        answer = await resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [
        b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answer
    ]


# A DKIM record's p= tag holds a base64 public key. An empty p= is the RFC 6376
# way of saying the key is REVOKED — publishing it means the opposite of having
# DKIM. Require a plausible key length rather than the mere presence of 'p='.
KEY_RE = re.compile(r"\bp=([A-Za-z0-9+/=]*)")
MIN_KEY_LEN = 32

# Deterministic nonsense selector. If this resolves to a real key the zone
# wildcards *._domainkey, and every selector will appear to exist.
CONTROL_SELECTOR = "dc9f1e7b-control-probe"


async def _dkim_key(resolver, domain: str, selector: str) -> str | None:
    """Return the selector if it publishes a usable DKIM key, else None."""
    try:
        records = await _txt(resolver, f"{selector}._domainkey.{domain}")
    except dns.exception.DNSException:
        return None
    for rec in records:
        if "v=dkim1" not in rec.lower() and "k=rsa" not in rec.lower():
            continue
        match = KEY_RE.search(rec)
        if match and len(match.group(1)) >= MIN_KEY_LEN:
            return selector
    return None


class EmailAuth(Source):
    name = "Email Authentication"
    supports = {"email"}
    needs_key = False
    cache_ttl = 3600

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        domain = ind.extra.get("domain")
        if not domain:
            return SourceResult(
                name=self.name, status="error", error="No sender domain to check."
            )

        resolver = _resolver()
        try:
            spf_records, dmarc_records, mx = await asyncio.gather(
                _txt(resolver, domain),
                _txt(resolver, f"_dmarc.{domain}"),
                self._mx(resolver, domain),
            )
        except dns.exception.DNSException as exc:
            return SourceResult(
                name=self.name,
                status="error",
                error=f"DNS lookup failed ({type(exc).__name__}). "
                      "Cannot assess sender authentication.",
            )

        probes = await asyncio.gather(
            _dkim_key(resolver, domain, CONTROL_SELECTOR),
            *(_dkim_key(resolver, domain, s) for s in COMMON_SELECTORS),
        )
        wildcarded = probes[0] is not None
        selectors = [s for s in probes[1:] if s]

        fields: dict[str, str] = {}
        weaknesses: list[str] = []

        # ---- SPF ----
        spf = next((r for r in spf_records if r.lower().startswith("v=spf1")), None)
        if spf:
            qualifier = next(
                (q for q in SPF_QUALIFIER if q in spf.lower()), None
            )
            if qualifier:
                label, strength = SPF_QUALIFIER[qualifier]
                fields["SPF"] = f"present ({label})"
                if strength in ("weak", "broken"):
                    weaknesses.append(f"SPF policy is {label}")
            else:
                fields["SPF"] = "present (no explicit all mechanism)"
                weaknesses.append("SPF has no 'all' mechanism")
            fields["SPF record"] = spf
        else:
            fields["SPF"] = "absent"
            weaknesses.append("no SPF record")

        # ---- DMARC ----
        dmarc = next((r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None)
        if dmarc:
            policy = "none"
            for part in dmarc.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    policy = part[2:].strip().lower()
                    break
            fields["DMARC"] = f"present (p={policy})"
            fields["DMARC record"] = dmarc
            if policy == "none":
                weaknesses.append("DMARC is monitor-only (p=none), not enforced")
        else:
            fields["DMARC"] = "absent"
            weaknesses.append("no DMARC record")

        # ---- DKIM ----
        if wildcarded:
            fields["DKIM"] = "inconclusive — zone wildcards *._domainkey"
            fields["DKIM note"] = (
                "A nonsense control selector also resolved, so every selector "
                "appears to exist. Selector probing cannot be trusted for this "
                "domain; verify against the DKIM-Signature header instead."
            )
        elif selectors:
            fields["DKIM"] = f"published ({', '.join(selectors)})"
            fields["DKIM note"] = (
                f"probed {len(COMMON_SELECTORS)} common selectors; "
                "signature not verified"
            )
        else:
            fields["DKIM"] = "no common selector found"
            fields["DKIM note"] = (
                f"probed {len(COMMON_SELECTORS)} common selectors plus a control; "
                "a bespoke selector would be missed — absence is not proof"
            )

        # ---- MX ----
        null_mx = mx == ["."]
        if null_mx:
            fields["MX"] = "null MX (RFC 7505) — domain declares it sends no mail"
            weaknesses.append(
                "null MX: the domain owner declares this domain sends and receives "
                "no mail, so any message claiming to be from it is forged"
            )
        elif mx:
            fields["MX"] = ", ".join(mx[:2])
        else:
            fields["MX"] = "none"
            weaknesses.append("no MX record — domain cannot receive mail")

        verdict, score = self._grade(spf, dmarc, weaknesses, null_mx)
        if weaknesses:
            fields["Spoofing risk"] = "; ".join(weaknesses[:3])
        fields["Scope"] = "Measures domain spoofability, not message intent"

        return SourceResult(
            name=self.name,
            status="ok",
            verdict=verdict,
            score=score,
            fields=fields,
            link=f"https://mxtoolbox.com/SuperTool.aspx?action=spf%3a{domain}",
        )

    async def _mx(self, resolver, domain: str) -> list[str]:
        """Return MX hostnames. A single '.' is a null MX (RFC 7505) and is
        preserved as-is so the caller can distinguish it from having none."""
        try:
            answer = await resolver.resolve(domain, "MX")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        hosts = sorted(str(r.exchange) for r in answer)
        if hosts == ["."]:
            return ["."]
        return [h.rstrip(".") for h in hosts if h.rstrip(".")]

    def _grade(self, spf, dmarc, weaknesses, null_mx: bool = False) -> tuple[str, str]:
        """Grade the anti-spoofing posture.

        'clean' here means hard to spoof — never that the sender is trustworthy.
        """
        if null_mx:
            # The domain owner has explicitly declared no mail originates here.
            # A message from this sender cannot be genuine.
            return "malicious", "Null MX — domain sends no mail, sender is forged"
        if not spf and not dmarc:
            return "suspicious", "No SPF or DMARC — trivially spoofable"
        if any("allow all" in w for w in weaknesses):
            return "suspicious", "SPF +all — anyone may send as this domain"
        if not dmarc:
            return "suspicious", "SPF only, no DMARC enforcement"
        if any("monitor-only" in w for w in weaknesses):
            return "suspicious", "DMARC p=none — published but not enforced"
        if spf and dmarc and not weaknesses:
            return "clean", "SPF and DMARC enforced — hard to spoof"
        return "no_data", "Partial authentication configuration"
