"""Derive the type-specific detail panel and ATT&CK mapping from source output."""

from .detect import Indicator
from .models import SourceResult

# Which source's fields feed the detail panel, per indicator type, and the
# label each field should carry in the UI.
DETAIL_MAP: dict[str, list[tuple[str, str, str]]] = {
    "ip": [
        ("AbuseIPDB", "isp", "ISP"),
        ("AbuseIPDB", "usage_type", "Usage type"),
        ("AbuseIPDB", "country", "Country"),
        ("AbuseIPDB", "tor", "Tor exit node"),
        ("AbuseIPDB", "domain", "Domain"),
        ("GreyNoise", "classification", "GreyNoise class"),
        ("GreyNoise", "internet_scanner", "Internet scanner"),
        ("GreyNoise", "actor", "Actor"),
        ("VirusTotal", "as_owner", "ASN owner"),
        ("RDAP / WHOIS", "netname", "Netname"),
        ("RDAP / WHOIS", "handle", "RIR handle"),
    ],
    "domain": [
        ("RDAP / WHOIS", "registrar", "Registrar"),
        ("RDAP / WHOIS", "created", "Created"),
        ("RDAP / WHOIS", "age_days", "Domain age (days)"),
        ("RDAP / WHOIS", "expires", "Expires"),
        ("RDAP / WHOIS", "nameservers", "Nameservers"),
        ("urlscan.io", "ip", "Resolved IP"),
        ("urlscan.io", "server", "Server"),
        ("VirusTotal", "reputation", "VT reputation"),
    ],
    "url": [
        ("urlscan.io", "domain", "Domain"),
        ("urlscan.io", "ip", "Hosting IP"),
        ("urlscan.io", "server", "Server"),
        ("urlscan.io", "http_status", "HTTP status"),
        ("urlscan.io", "last_scan", "Last scan"),
        ("Google Safe Browsing", "threat_types", "Safe Browsing lists"),
    ],
    "hash": [
        ("VirusTotal", "file_type", "File type"),
        ("VirusTotal", "name", "Known filename"),
        ("VirusTotal", "reputation", "VT reputation"),
        ("abuse.ch", "signature", "Malware family"),
        ("abuse.ch", "tags", "Tags"),
        ("abuse.ch", "first_seen", "First seen"),
        ("Team Cymru MHR", "detection_rate", "MHR detection rate"),
    ],
    "process": [
        ("Process Baseline", "expected_path", "Expected path"),
        ("Process Baseline", "observed_path", "Observed path"),
        ("Process Baseline", "expected_parent", "Expected parent"),
        ("Process Baseline", "instance_policy", "Instance policy"),
        ("Process Baseline", "masquerading", "Masquerading verdict"),
        ("Process Baseline", "impersonates", "Impersonates"),
        ("Process Baseline", "resembles", "Resembles"),
        ("Process Baseline", "suspicious_directory", "Suspicious directory"),
        ("LOLBAS", "abuse_functions", "LOLBAS abuse functions"),
        ("LOLBAS", "mitre", "LOLBAS MITRE IDs"),
        ("GTFOBins", "binary", "GTFOBins entry"),
    ],
    "email": [
        ("Email Authentication", "SPF", "SPF"),
        ("Email Authentication", "DKIM", "DKIM"),
        ("Email Authentication", "DMARC", "DMARC"),
        ("Email Authentication", "MX", "MX records"),
        ("Email Authentication", "Spoofing risk", "Spoofing risk"),
        ("Email Authentication", "SPF record", "SPF record"),
        ("Email Authentication", "DMARC record", "DMARC record"),
        ("Email Authentication", "DKIM note", "DKIM caveat"),
        ("Email Authentication", "Scope", "Scope"),
        ("RDAP / WHOIS", "registrar", "Sender domain registrar"),
        ("RDAP / WHOIS", "created", "Sender domain created"),
        ("RDAP / WHOIS", "age_days", "Sender domain age (days)"),
    ],
}

TECHNIQUE_NAMES = {
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1090.003": "Proxy: Multi-hop Proxy",
    "T1105": "Ingress Tool Transfer",
    "T1218": "System Binary Proxy Execution",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1047": "Windows Management Instrumentation",
    "T1490": "Inhibit System Recovery",
    "T1055": "Process Injection",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1585.002": "Establish Accounts: Email Accounts",
}


def _by_name(results: list[SourceResult]) -> dict[str, SourceResult]:
    return {r.name: r for r in results}


def type_specific(ind: Indicator, results: list[SourceResult]) -> dict[str, str]:
    index = _by_name(results)
    out: dict[str, str] = {}
    for source_name, key, label in DETAIL_MAP.get(ind.type, []):
        src = index.get(source_name)
        if src and src.status == "ok" and key in src.fields:
            out[label] = src.fields[key]

    if ind.type == "domain" and ind.extra.get("punycode"):
        out["Punycode"] = ind.value
        out["IDN warning"] = "Non-ASCII domain — check for homograph impersonation"
    if ind.type == "url":
        out["Host"] = ind.extra.get("host", "")
    if ind.type == "email":
        out["Sender domain"] = ind.extra.get("domain", "")
    if ind.type == "hash":
        out["Hash type"] = str(ind.extra.get("kind", "")).upper()
    return {k: v for k, v in out.items() if v}


def techniques(ind: Indicator, results: list[SourceResult]) -> list[dict[str, str]]:
    ids: set[str] = set()
    index = _by_name(results)

    baseline = index.get("Process Baseline")
    if baseline and baseline.status == "ok" and baseline.verdict in ("malicious", "suspicious"):
        ids.add("T1036.005")

    lol = index.get("LOLBAS")
    if lol and lol.status == "ok" and "mitre" in lol.fields:
        for part in lol.fields["mitre"].split(","):
            tid = part.strip()
            if tid.startswith("T"):
                ids.add(tid)

    if ind.type == "domain":
        rdap = index.get("RDAP / WHOIS")
        if rdap and rdap.status == "ok" and rdap.verdict == "suspicious":
            ids.update({"T1583.001", "T1566.002"})

    if ind.type == "email":
        auth = index.get("Email Authentication")
        if auth and auth.status == "ok" and auth.verdict in ("suspicious", "malicious"):
            # A forgeable sender domain is the precondition for spoofed phishing.
            ids.update({"T1566.001", "T1585.002"})

    return [
        {"id": tid, "name": TECHNIQUE_NAMES.get(tid, "See MITRE ATT&CK")}
        for tid in sorted(ids)
    ]
