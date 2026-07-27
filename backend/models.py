"""Normalized data contract shared by every source and the frontend."""

from dataclasses import dataclass, field, asdict
from typing import Any, Literal

Verdict = Literal["malicious", "suspicious", "clean", "no_data"]
Status = Literal["ok", "pending", "error", "rate_limited", "disabled"]

# Ordered most severe first. Aggregation relies on this ordering.
SEVERITY = ["malicious", "suspicious", "clean", "no_data"]

# 'file' is accepted as an alias for 'hash': file *content* is never submitted,
# so detect.build() normalizes it to 'hash' and rejects anything that is not a
# digest. No source is registered for 'file' and none should be.
IOC_TYPES = ("hash", "file", "domain", "ip", "url", "email", "process")


@dataclass
class SourceResult:
    name: str
    status: Status = "pending"
    verdict: Verdict | None = None
    score: str | None = None
    fields: dict[str, str] = field(default_factory=dict)
    link: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LookupResult:
    ioc: str
    type: str
    verdict: Verdict = "no_data"
    confidence: int = 0
    summary: str = ""
    first_seen: str | None = None
    last_seen: str | None = None
    sources: list[SourceResult] = field(default_factory=list)
    type_specific: dict[str, Any] = field(default_factory=dict)
    attack_techniques: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
