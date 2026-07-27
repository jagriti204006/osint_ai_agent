"""Source registry.

A source with no configured key reports status 'disabled' rather than being
hidden, so the UI can show the analyst exactly what was and was not consulted.
"""

from .abusech import AbuseCh
from .abuseipdb import AbuseIPDB
from .base import Source
from .cymru import CymruMHR
from .emailauth import EmailAuth
from .greynoise import GreyNoise
from .gtfobins import GTFOBins
from .lolbas import LOLBAS
from .otx import OTX
from .process_baseline import ProcessBaseline
from .rdap import RDAP
from .safebrowsing import SafeBrowsing
from .urlscan import UrlScan
from .virustotal import VirusTotal


def all_sources() -> list[Source]:
    return [
        VirusTotal(),
        AbuseIPDB(),
        GreyNoise(),
        UrlScan(),
        SafeBrowsing(),
        OTX(),
        AbuseCh(),
        RDAP(),
        CymruMHR(),
        EmailAuth(),
        ProcessBaseline(),
        LOLBAS(),
        GTFOBins(),
    ]


def for_type(ioc_type: str) -> list[Source]:
    """Sources that handle this indicator type, enabled ones first."""
    matching = [s for s in all_sources() if s.handles(ioc_type)]
    return sorted(matching, key=lambda s: (not s.enabled, s.name))


def status() -> list[dict]:
    return [
        {"name": s.name, "enabled": s.enabled, "needs_key": s.needs_key,
         "supports": sorted(s.supports)}
        for s in all_sources()
    ]
