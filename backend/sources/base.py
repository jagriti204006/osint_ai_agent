"""Common source machinery.

Every source subclasses `Source` and implements `fetch`. The `run` wrapper —
not the subclass — owns caching, rate limiting, error containment, and output
sanitisation, so a new source physically cannot skip them.
"""

import abc

import httpx

from .. import cache, ratelimit
from ..detect import Indicator
from ..models import SourceResult
from ..sanitize import clean_text, safe_link


class Source(abc.ABC):
    name: str = "unnamed"
    supports: set[str] = set()
    key: str | None = None          # resolved API key, None when unconfigured
    needs_key: bool = False
    cache_ttl: int | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.key) if self.needs_key else True

    def handles(self, ioc_type: str) -> bool:
        return ioc_type in self.supports

    @abc.abstractmethod
    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        """Query the upstream API. May raise; `run` contains the failure."""

    async def run(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        if not self.enabled:
            return SourceResult(
                name=self.name,
                status="disabled",
                error="No API key configured for this source.",
            )

        cached = cache.get(self.name, ind.type, ind.value)
        if cached is not None:
            return SourceResult(**cached)

        try:
            await ratelimit.acquire(self.name)
        except ratelimit.RateLimited as exc:
            return SourceResult(name=self.name, status="rate_limited", error=str(exc))

        try:
            result = await self.fetch(ind, client)
        except httpx.TimeoutException:
            return SourceResult(
                name=self.name, status="error", error="Upstream timed out."
            )
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            if code in (429, 503):
                return SourceResult(
                    name=self.name,
                    status="rate_limited",
                    error=f"Upstream returned HTTP {code} (quota exhausted).",
                )
            if code in (401, 403):
                return SourceResult(
                    name=self.name,
                    status="error",
                    error=f"HTTP {code} — API key rejected or lacks permission.",
                )
            return SourceResult(
                name=self.name, status="error", error=f"Upstream returned HTTP {code}."
            )
        except Exception as exc:  # noqa: BLE001 - one bad source must not sink the query
            return SourceResult(
                name=self.name,
                status="error",
                error=f"{type(exc).__name__}: {clean_text(exc, 160)}",
            )

        result = self._sanitize(result)
        if result.status == "ok":
            cache.put(self.name, ind.type, ind.value, result.as_dict(), self.cache_ttl)
        return result

    def _sanitize(self, result: SourceResult) -> SourceResult:
        """Scrub untrusted upstream data before it can reach the browser."""
        result.name = self.name
        result.link = safe_link(result.link)
        result.score = clean_text(result.score, 120) if result.score is not None else None
        result.error = clean_text(result.error, 240) if result.error is not None else None
        result.fields = {
            clean_text(k, 48): clean_text(v, 200)
            for k, v in list(result.fields.items())[:12]
        }
        if result.verdict not in ("malicious", "suspicious", "clean", "no_data", None):
            result.verdict = None
        return result
