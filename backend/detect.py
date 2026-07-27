"""IOC type detection and hardened validation.

Server-side and authoritative — the frontend's detection is a convenience only.

Closes the input-side findings from the design review:
  - leading-zero IP octets (010.1.1.1 reads as octal to some parsers)
  - private / loopback / reserved addresses leaking to third-party APIs
  - IDN homograph domains being unrepresentable
  - URL scheme allowlist
"""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna

HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.I)
# Auto-detect deliberately excludes '.com': it is a DOS executable extension but
# far more commonly a TLD, and treating 'google.com' as a process is the worse
# error. PROCESS_EXPLICIT_RE adds it back for when the analyst selects Process
# Name by hand, so a genuine .com binary is still reachable.
PROCESS_RE = re.compile(r"\.(exe|dll|sys|scr|ps1|psm1|bat|cmd|vbs|jar|msi)$", re.I)
PROCESS_EXPLICIT_RE = re.compile(
    r"\.(exe|dll|sys|scr|ps1|psm1|bat|cmd|vbs|jar|msi|com)$", re.I
)

ALLOWED_URL_SCHEMES = {"http", "https"}

HASH_KINDS = {32: "md5", 40: "sha1", 64: "sha256"}


class ValidationError(ValueError):
    """Raised when an indicator cannot be safely looked up."""


@dataclass
class Indicator:
    """A validated indicator, normalized for querying."""

    raw: str
    type: str
    value: str            # normalized form sent to APIs (punycode, lowercased)
    display: str          # what the analyst typed, for the UI
    extra: dict           # type-specific parse results (hash kind, url host, ...)


def _reject_special_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Refuse addresses that are meaningless or unsafe to send to a third party.

    Submitting an internal address to VirusTotal discloses your network layout
    to an external service, and no OSINT source has data on RFC1918 space.
    """
    if ip.is_private:
        raise ValidationError(
            f"{ip} is a private address. Looking it up would disclose internal "
            "network detail to third-party APIs, and no OSINT source has data on it."
        )
    for attr, label in (
        ("is_loopback", "loopback"),
        ("is_link_local", "link-local"),
        ("is_multicast", "multicast"),
        ("is_reserved", "reserved"),
        ("is_unspecified", "unspecified"),
    ):
        if getattr(ip, attr, False):
            raise ValidationError(f"{ip} is a {label} address and cannot be looked up.")


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    v = value.strip()
    if IPV4_RE.match(v):
        octets = v.split(".")
        # '010.1.1.1' is octal to some resolvers and decimal to others. Refuse
        # the ambiguity rather than pick an interpretation.
        for o in octets:
            if len(o) > 1 and o[0] == "0":
                raise ValidationError(
                    f"'{v}' has a leading zero in octet '{o}'. Leading zeros are "
                    "parsed inconsistently (octal vs decimal) — remove them."
                )
            if int(o) > 255:
                raise ValidationError(f"'{v}' has octet '{o}' above 255.")
        ip = ipaddress.ip_address(v)
    else:
        try:
            ip = ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValidationError(f"'{v}' is not a valid IP address.") from exc
    _reject_special_ip(ip)
    return ip


def parse_domain(value: str) -> str:
    """Return the punycode (A-label) form so IDN homographs are analysable."""
    v = value.strip().rstrip(".").lower()
    if not v or "/" in v or " " in v or "@" in v:
        raise ValidationError(f"'{value}' is not a valid domain.")
    try:
        encoded = idna.encode(v, uts46=True).decode("ascii")
    except idna.IDNAError:
        # Not IDN-encodable; fall back to strict ASCII validation below.
        encoded = v
    if len(encoded) > 253 or "." not in encoded:
        raise ValidationError(f"'{value}' is not a valid domain.")
    for label in encoded.split("."):
        if not LABEL_RE.match(label):
            raise ValidationError(f"'{value}' has an invalid label '{label}'.")
    return encoded


def parse_url(value: str) -> tuple[str, str]:
    """Validate a URL and return (normalized_url, host)."""
    v = value.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I):
        v = "http://" + v
    try:
        parts = urlsplit(v)
    except ValueError as exc:
        raise ValidationError(f"'{value}' is not a parseable URL.") from exc
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_URL_SCHEMES:
        raise ValidationError(
            f"Scheme '{scheme}:' is not allowed. Only http and https URLs can be "
            "looked up."
        )
    host = parts.hostname
    if not host:
        raise ValidationError(f"'{value}' has no host.")
    # A URL pointing at internal space must not be sent to a third party.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        parse_domain(host)
    else:
        _reject_special_ip(ip)
    return v, host


def parse_email(value: str) -> tuple[str, str]:
    v = value.strip().lower()
    if v.count("@") != 1:
        raise ValidationError(f"'{value}' is not a valid email address.")
    local, _, domain = v.partition("@")
    if not local or any(c.isspace() for c in local):
        raise ValidationError(f"'{value}' is not a valid email address.")
    return v, parse_domain(domain)


def parse_process(value: str) -> tuple[str, str | None]:
    """Return (image_name, observed_path or None).

    Accepts a bare name ('svchost.exe') or a full path
    ('C:\\Users\\Public\\svchost.exe').
    """
    v = value.strip().strip('"')
    if not v:
        raise ValidationError("Empty process name.")
    path = v if ("\\" in v or "/" in v) else None
    name = re.split(r"[\\/]", v)[-1]
    if not PROCESS_EXPLICIT_RE.search(name):
        raise ValidationError(
            f"'{value}' does not look like a process image name "
            "(expected an extension such as .exe, .dll or .ps1)."
        )
    return name.lower(), path


def detect_type(value: str) -> str | None:
    """Best-effort type inference. Returns None when the shape is unrecognised."""
    v = (value or "").strip()
    if not v:
        return None
    if HASH_RE.match(v):
        return "hash"
    if IPV4_RE.match(v) or (":" in v and "/" not in v and "@" not in v and _looks_ipv6(v)):
        return "ip"
    if "@" in v and "/" not in v:
        return "email"
    if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I) or "/" in v:
        return "url"
    if PROCESS_RE.search(v) or "\\" in v:
        return "process"
    if "." in v and " " not in v:
        return "domain"
    return None


def _looks_ipv6(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def build(value: str, forced_type: str | None = None) -> Indicator:
    """Validate `value` and return a normalized Indicator, or raise."""
    raw = (value or "").strip()
    if not raw:
        raise ValidationError("Enter an indicator to look up.")
    if len(raw) > 2048:
        raise ValidationError("Indicator is too long (max 2048 characters).")

    ioc_type = forced_type if forced_type and forced_type != "auto" else detect_type(raw)
    if not ioc_type:
        raise ValidationError(
            "Could not infer the indicator type from its shape. Choose a type "
            "from the selector."
        )

    if ioc_type in ("hash", "file"):
        if not HASH_RE.match(raw):
            raise ValidationError(
                f"'{raw}' is not an MD5, SHA-1 or SHA-256 hash. File content cannot "
                "be submitted — look the file up by hash instead."
            )
        v = raw.lower()
        return Indicator(raw, "hash", v, raw, {"kind": HASH_KINDS[len(v)]})

    if ioc_type == "ip":
        ip = parse_ip(raw)
        return Indicator(raw, "ip", str(ip), raw, {"version": ip.version})

    if ioc_type == "domain":
        d = parse_domain(raw)
        return Indicator(raw, "domain", d, raw, {"punycode": d != raw.lower().rstrip(".")})

    if ioc_type == "url":
        url, host = parse_url(raw)
        return Indicator(raw, "url", url, raw, {"host": host})

    if ioc_type == "email":
        addr, domain = parse_email(raw)
        return Indicator(raw, "email", addr, raw, {"domain": domain})

    if ioc_type == "process":
        name, path = parse_process(raw)
        return Indicator(raw, "process", name, raw, {"observed_path": path})

    raise ValidationError(f"Unsupported indicator type '{ioc_type}'.")
