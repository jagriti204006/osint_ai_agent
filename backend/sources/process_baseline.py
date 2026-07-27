"""Local masquerading check against data/windows_process_baseline.json.

The only source here that answers the question reputation APIs cannot:
is this process running from the right place, under the right parent?
No network, no key.
"""

import fnmatch
import json
import re

import httpx

from .. import config
from ..detect import Indicator
from ..models import SourceResult
from .base import Source

EXPANSIONS = {
    "%systemroot%": "c:\\windows",
    "%systemdrive%": "c:",
    "%programfiles%": "c:\\program files",
    "%programfiles(x86)%": "c:\\program files (x86)",
    "%programdata%": "c:\\programdata",
    "%temp%": "c:\\users\\*\\appdata\\local\\temp",
    "%tmp%": "c:\\users\\*\\appdata\\local\\temp",
    "%appdata%": "c:\\users\\*\\appdata\\roaming",
    "%localappdata%": "c:\\users\\*\\appdata\\local",
    "%userprofile%": "c:\\users\\*",
    "%public%": "c:\\users\\public",
}

_cache: dict | None = None


def _baseline() -> dict:
    global _cache
    if _cache is None:
        _cache = json.loads(config.BASELINE_PATH.read_text(encoding="utf-8"))
    return _cache


def _norm(path: str) -> str:
    p = path.strip().strip('"').lower().replace("/", "\\")
    for var, real in EXPANSIONS.items():
        p = p.replace(var, real)
    return p


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _digit_swapped(a: str, b: str) -> bool:
    """True if the names differ only by look-alike digit/letter substitution."""
    table = str.maketrans({"0": "o", "1": "l", "5": "s", "3": "e", "$": "s"})
    return a.translate(table) == b.translate(table) and a != b


class ProcessBaseline(Source):
    name = "Process Baseline"
    supports = {"process"}
    needs_key = False
    cache_ttl = 0  # local and instant; caching would only hide edits to the JSON

    async def fetch(self, ind: Indicator, client: httpx.AsyncClient) -> SourceResult:
        data = _baseline()
        name = ind.value.lower()
        observed = ind.extra.get("observed_path")
        entry = next(
            (p for p in data["processes"] if p["name"].lower() == name), None
        )

        if entry is None:
            return self._unknown_name(data, name)

        fields: dict[str, str] = {
            "expected_path": entry["expected_paths"][0] if entry["expected_paths"] else "n/a (kernel)",
            "expected_parent": ", ".join(entry["expected_parents"]) or "none",
            "instance_policy": entry["instance_policy"],
            "category": entry["category"],
        }
        techniques = entry.get("attack_techniques", [])

        if not observed:
            fields["note"] = "No path supplied — submit the full image path to verify"
            return SourceResult(
                name=self.name, status="ok", verdict="no_data",
                score="Known system binary — path not verified",
                fields=fields,
            )

        obs = _norm(observed)
        fields["observed_path"] = observed

        allowed = [_norm(p) for p in entry["expected_paths"]]
        if entry.get("syswow64_ok"):
            allowed += [p.replace("system32", "syswow64") for p in allowed]
        matched = any(fnmatch.fnmatch(obs, pat) for pat in allowed)

        suspicious = next(
            (pat for pat in data["suspicious_path_patterns"]["patterns"]
             if fnmatch.fnmatch(obs, _norm(pat))),
            None,
        )

        if matched:
            return SourceResult(
                name=self.name, status="ok", verdict="clean",
                score="Path matches baseline",
                fields=fields | {"masquerading": "No — path is expected"},
            )

        fields["masquerading"] = "Yes — path does not match baseline"
        if suspicious:
            fields["suspicious_directory"] = suspicious
        return SourceResult(
            name=self.name,
            status="ok",
            verdict="malicious",
            score=f"Path mismatch ({entry['severity_if_mismatch']})",
            fields=fields,
        )

    def _unknown_name(self, data: dict, name: str) -> SourceResult:
        """Not a baseline process — check for a typosquat of one."""
        watch = data["homoglyph_watchlist"]["examples"]
        for real, fakes in watch.items():
            if name in [f.lower() for f in fakes]:
                return SourceResult(
                    name=self.name, status="ok", verdict="malicious",
                    score="Known typosquat",
                    fields={
                        "impersonates": real,
                        "masquerading": "Yes — listed homoglyph of a system binary",
                    },
                )

        for proc in data["processes"]:
            real = proc["name"].lower()
            if real == name:
                continue
            if _levenshtein(name, real) <= 1 or _digit_swapped(name, real):
                return SourceResult(
                    name=self.name, status="ok", verdict="suspicious",
                    score="Near-match to a system binary",
                    fields={
                        "resembles": proc["name"],
                        "masquerading": "Possible — name is one edit from a system binary",
                    },
                )

        return SourceResult(
            name=self.name, status="ok", verdict="no_data",
            score="Not a known system binary",
            fields={"note": "absent from the baseline — unknown, not clean"},
        )
