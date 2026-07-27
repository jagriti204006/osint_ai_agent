"""Process-lifetime cache for global reference feeds.

LOLBAS and GTFOBins publish one document covering every binary. The SQLite
cache is keyed per indicator, so caching there re-fetched the whole feed for
each distinct process name — 429 KB per lookup for LOLBAS, and a fresh GitHub
API call per lookup for GTFOBins, which burns the 60/hour unauthenticated
limit and produced 'Server disconnected' errors under load.

The feed is global data, so it belongs in a global cache.
"""

import asyncio
import time
from typing import Any, Awaitable, Callable

_entries: dict[str, tuple[float, Any]] = {}
_locks: dict[str, asyncio.Lock] = {}


async def get(key: str, ttl: float, loader: Callable[[], Awaitable[Any]]) -> Any:
    """Return the cached feed for `key`, loading it at most once per `ttl`.

    Concurrent lookups for the same feed wait on one loader rather than each
    firing their own request.
    """
    entry = _entries.get(key)
    if entry and (time.monotonic() - entry[0]) < ttl:
        return entry[1]

    lock = _locks.get(key)
    if lock is None:
        lock = _locks.setdefault(key, asyncio.Lock())

    async with lock:
        # Another waiter may have populated it while we queued.
        entry = _entries.get(key)
        if entry and (time.monotonic() - entry[0]) < ttl:
            return entry[1]
        data = await loader()
        _entries[key] = (time.monotonic(), data)
        return data


def clear() -> None:
    _entries.clear()
