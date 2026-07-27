"""Aggregate per-source verdicts into one answer.

The governing rule: `clean` must be *earned*. A source that errored, was rate
limited, or has never seen the indicator contributes nothing toward clean —
absence of evidence is not evidence of absence.
"""

from .models import LookupResult, SourceResult
from .sanitize import clamp_confidence


def _counts(sources: list[SourceResult]) -> dict[str, int]:
    tally = {"malicious": 0, "suspicious": 0, "clean": 0, "no_data": 0}
    for s in sources:
        if s.status == "ok" and s.verdict in tally:
            tally[s.verdict] += 1
    return tally


def _faults(sources: list[SourceResult]) -> int:
    return sum(1 for s in sources if s.status in ("error", "rate_limited"))


def _unregistered(sources: list[SourceResult]) -> bool:
    """True when RDAP authoritatively reports the domain does not exist."""
    for s in sources:
        if s.name == "RDAP / WHOIS" and s.status == "ok":
            if s.fields.get("registered") == "No":
                return True
    return False


def decide(sources: list[SourceResult]) -> tuple[str, int]:
    """Return (verdict, confidence)."""
    tally = _counts(sources)
    faults = _faults(sources)
    answered = sum(tally.values())

    if tally["malicious"]:
        verdict = "malicious"
        confidence = 60 + 12 * tally["malicious"]
    elif tally["suspicious"]:
        verdict = "suspicious"
        confidence = 40 + 10 * tally["suspicious"]
    elif tally["clean"]:
        # A domain that is not registered cannot be 'clean'. VirusTotal reports
        # 0/91 harmless for domains it has simply never seen, which otherwise
        # certifies a non-existent domain as safe.
        if _unregistered(sources):
            return "no_data", 0
        verdict = "clean"
        confidence = 55 + 10 * tally["clean"]
    else:
        # Nothing affirmative came back. Not clean — unknown.
        return "no_data", 0

    # Incomplete coverage means we are less sure, whichever way it went.
    if faults:
        confidence -= 10 * faults
    if answered <= 1:
        confidence -= 10

    return verdict, clamp_confidence(confidence)


def summarize(result: LookupResult) -> str:
    """One plain-language line an analyst can paste into a ticket."""
    tally = _counts(result.sources)
    faults = _faults(result.sources)
    label = {"ip": "address", "domain": "domain", "url": "URL", "hash": "file",
             "process": "process", "email": "sender"}.get(result.type, "indicator")

    if result.verdict == "no_data" and _unregistered(result.sources):
        base = (
            "This domain is not registered — the registry has no record of it. "
            "Engines reporting no detections are reporting on something that does "
            "not exist, which is not a clean verdict."
        )
    elif result.verdict == "no_data":
        base = (
            f"No queried source has ever observed this {label}. This is an absence "
            "of evidence, not a clean verdict — treat as unknown and escalate to "
            "sandbox detonation or manual analysis."
        )
    elif result.verdict == "malicious":
        base = (
            f"{tally['malicious']} of {len(result.sources)} sources flag this {label} "
            "as malicious."
        )
    elif result.verdict == "suspicious":
        base = (
            f"{tally['suspicious']} source(s) rate this {label} suspicious with no "
            "confirmed malicious verdict — review before actioning."
        )
    else:
        base = (
            f"{tally['clean']} source(s) affirmatively report this {label} as clean "
            "and none flagged it."
        )

    if faults:
        base += (
            f" {faults} source(s) did not answer (error or rate limit); coverage is "
            "incomplete and confidence is reduced accordingly."
        )
    return base
