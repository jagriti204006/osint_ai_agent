"""Per-source async token buckets.

Free tiers are strict — VirusTotal's public API is roughly 4 requests a minute.
Exceeding it returns 429s that must surface as 'rate_limited', never as 'clean'.
"""

import asyncio
import time

# requests allowed per minute, per source
LIMITS = {
    "VirusTotal": 4,
    "AbuseIPDB": 40,
    "urlscan.io": 30,
    "AlienVault OTX": 60,
    "Google Safe Browsing": 100,
    "GreyNoise": 10,
    "abuse.ch": 60,
    "RDAP / WHOIS": 60,
    "Team Cymru MHR": 60,
    "Email Authentication": 30,
    "LOLBAS": 60,
    "GTFOBins": 30,
    # Local JSON, no network - should never be throttled.
    "Process Baseline": 100000,
}

DEFAULT_LIMIT = 30


class RateLimited(Exception):
    """Raised when a token could not be acquired in time."""


class _Bucket:
    def __init__(self, per_minute: int) -> None:
        self.capacity = float(per_minute)
        self.tokens = float(per_minute)
        self.rate = per_minute / 60.0
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self, wait: float) -> None:
        deadline = time.monotonic() + wait
        while True:
            async with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                shortfall = (1.0 - self.tokens) / self.rate
            if time.monotonic() + shortfall > deadline:
                raise RateLimited(
                    f"Local quota guard: would need to wait {shortfall:.0f}s for a slot."
                )
            await asyncio.sleep(min(shortfall, 1.0))


_buckets: dict[str, _Bucket] = {}
_buckets_lock = asyncio.Lock()


async def acquire(source: str, wait: float = 6.0) -> None:
    """Take a token for `source`, or raise RateLimited within `wait` seconds."""
    async with _buckets_lock:
        bucket = _buckets.get(source)
        if bucket is None:
            bucket = _Bucket(LIMITS.get(source, DEFAULT_LIMIT))
            _buckets[source] = bucket
    await bucket.acquire(wait)
