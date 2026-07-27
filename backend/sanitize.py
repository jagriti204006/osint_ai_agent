"""Output sanitisation.

Everything a source returns is untrusted: it comes from a third-party API that
we do not control. These helpers run on the way *out*, so a hostile API
response cannot reach the browser as an active payload.

Closes the two findings from the design review:
  - javascript: URLs rendered into href
  - unclamped confidence flowing into a style attribute
"""

from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}

_DEFANG = (
    ("http://", "hxxp://"),
    ("https://", "hxxps://"),
    ("ftp://", "fxp://"),
)


def safe_link(url: str | None) -> str | None:
    """Return url only if it is a plain http(s) URL, else None.

    Rejects javascript:, data:, file:, vbscript: and anything else that could
    execute when an analyst clicks 'Full report'.
    """
    if not url or not isinstance(url, str):
        return None
    url = url.strip()
    if not url or any(c in url for c in "\r\n\t"):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return None
    if not parts.netloc:
        return None
    return url


def clamp_confidence(value: object) -> int:
    """Coerce anything to an int in 0..100.

    The frontend puts this into a CSS width, so a string like
    '0%; position:fixed' must never survive.
    """
    try:
        n = int(float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0
    return max(0, min(100, n))


def clean_text(value: object, limit: int = 400) -> str:
    """Flatten any value to a bounded single-line string.

    Strips control characters so a hostile field cannot inject terminal escapes
    or break log parsing. HTML is left intact — the frontend inserts via
    textContent, so it renders inert.
    """
    s = "Yes" if value is True else "No" if value is False else str(value)
    s = "".join(ch for ch in s if ch == " " or ch.isprintable())
    s = " ".join(s.split())
    return s[:limit]


def defang(value: str) -> str:
    """Neuter an indicator so it cannot be clicked from a ticket or email."""
    out = value
    for live, dead in _DEFANG:
        out = out.replace(live, dead)
    return out.replace(".", "[.]").replace("@", "[@]")
