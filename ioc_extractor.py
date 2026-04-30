"""
ioc_extractor.py — IOC extraction for ThreatCheck.

Extracts Indicators of Compromise from unstructured text (articles, PDFs, etc.).
Ported and trimmed from Threat-Intel-Nom-Nom with ThreatCheck-specific adjustments.

Extracted IOC types:
  - IPv4 addresses (public only — private/loopback filtered)
  - CVEs
  - Domains
  - URLs
  - MD5 / SHA1 / SHA256 hashes

Usage:
    from ioc_extractor import IOCExtractor
    iocs = IOCExtractor.extract(text)
    # Returns dict with only populated keys:
    # { "ipv4": [...], "cves": [...], "domains": [...], "urls": [...],
    #   "sha256": [...], "sha1": [...], "md5": [...] }
"""

import re
from typing import Dict, List, Any


class IOCExtractor:
    """Extract Indicators of Compromise from plain text."""

    # ── Patterns ────────────────────────────────────────────────────────────

    CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

    IPV4_RE = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
    )

    MD5_RE    = re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])')
    SHA1_RE   = re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])')
    SHA256_RE = re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])')

    URL_RE = re.compile(r'https?://[^\s<>"\')\]]+')

    DOMAIN_RE = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|io|gov|edu|mil|info|biz|co|us|uk|de|fr|ru|cn|'
        r'xyz|top|onion|cc|me|tv|in|jp|br|au|ca|nl|it|es|se|no|fi|dk|'
        r'pl|cz|sk|hu|ro|bg|hr|si|ua|kz|by|lt|lv|ee|pt|gr|ie|ch|at|be)\b',
        re.IGNORECASE
    )

    # ── False-positive filters ───────────────────────────────────────────────

    # Domains that appear in reports as sources/references, not as IOCs
    _DOMAIN_WHITELIST = {
        # Government / CERT
        "cisa.dhs.gov", "cisa.gov", "us-cert.gov", "ncsc.gov.uk",
        "ncsc.gov", "nist.gov", "nvd.nist.gov", "cve.mitre.org",
        "mitre.org", "dhs.gov", "fbi.gov", "nsa.gov", "cyber.gc.ca",
        "cert.gov", "ic3.gov", "report.ncsc.gov.uk", "hq.doe.gov",
        # Security vendors / research
        "virustotal.com", "abuseipdb.com", "greynoise.io", "shodan.io",
        "mandiant.com", "crowdstrike.com", "recordedfuture.com",
        "unit42.paloaltonetworks.com", "paloaltonetworks.com",
        "secureworks.com", "sentinelone.com", "microsoft.com",
        "security.microsoft.com", "symantec.com", "broadcom.com",
        "trendmicro.com", "kaspersky.com", "eset.com", "mcafee.com",
        "fireeye.com", "cylance.com", "carbonblack.com",
        "thedfirreport.com", "redcanary.com", "sans.org", "isc.sans.edu",
        "bleepingcomputer.com", "thehackernews.com", "krebsonsecurity.com",
        "darkreading.com", "securityweek.com", "exploit-db.com",
        # ICS/OT vendors commonly cited in advisories
        "rockwellautomation.com", "siemens.com", "schneider-electric.com",
        "honeywellprocess.com", "ge.com", "emerson.com", "abb.com",
        "unitronics.com", "aveva.com", "ptc.com", "inductive-automation.com",
        # Common reference domains
        "github.com", "githubusercontent.com", "attack.mitre.org",
        "owasp.org", "nvd.nist.gov",
    }

    # Hash patterns that are almost certainly not real IOCs
    _HASH_EXCLUDE = re.compile(
        r'^0{8,}$|^f{8,}$|^a{8,}$|^1234|^abcd',
        re.IGNORECASE
    )

    # Private / reserved / loopback IP ranges
    _IP_PRIVATE = re.compile(
        r'^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|'
        r'169\.254\.|224\.|240\.|255\.)'
    )

    # ── Public API ───────────────────────────────────────────────────────────

    @staticmethod
    def extract(text: str) -> Dict[str, Any]:
        """
        Extract IOCs from text. Returns two buckets:
          - "iocs":       threat indicators (IPs, CVEs, hashes, unknown domains)
          - "references": whitelisted domains/URLs (vendors, gov sites, cited sources)

        Args:
            text: Raw text to extract from (handles defanged IPs like 1.2.3[.]4)

        Returns:
            {
                "iocs": {
                    "ipv4": [...], "cves": [...], "domains": [...],
                    "urls": [...], "sha256": [...], "sha1": [...], "md5": [...]
                },
                "references": {
                    "domains": [...],  # whitelisted domains found in text
                    "urls":    [...],  # whitelisted URLs found in text
                }
            }
        """
        # Normalize defanged IPs: 1.2.3[.]4 → 1.2.3.4
        text = re.sub(r'\[\.?\]', '.', text)
        # hXXp → http
        text = re.sub(r'hXXps?://', lambda m: m.group(0).replace('XX', 'tt'), text, flags=re.IGNORECASE)

        iocs: Dict[str, Any]       = {}
        references: Dict[str, Any] = {}

        # ── CVEs ────────────────────────────────────────────────────────────
        cves = sorted(set(IOCExtractor.CVE_RE.findall(text)))
        if cves:
            iocs["cves"] = [c.upper() for c in cves]

        # ── IPv4 — public only ───────────────────────────────────────────────
        ips = sorted(set(
            ip for ip in IOCExtractor.IPV4_RE.findall(text)
            if not IOCExtractor._IP_PRIVATE.match(ip)
        ))
        if ips:
            iocs["ipv4"] = ips

        # ── URLs ─────────────────────────────────────────────────────────────
        all_urls = sorted(set(IOCExtractor.URL_RE.findall(text)))
        threat_urls = []
        ref_urls    = []
        for u in all_urls:
            if any(w in u.lower() for w in IOCExtractor._DOMAIN_WHITELIST):
                ref_urls.append(u)
            else:
                threat_urls.append(u)
        if threat_urls:
            iocs["urls"] = threat_urls[:20]
        if ref_urls:
            references["urls"] = ref_urls[:20]

        # ── Domains ──────────────────────────────────────────────────────────
        url_text = " ".join(all_urls)
        threat_domains = []
        ref_domains    = []
        for d in sorted(set(
            d.lower() for d in IOCExtractor.DOMAIN_RE.findall(text)
            if d.lower() not in url_text.lower()
            and len(d) > 4
        )):
            if d in IOCExtractor._DOMAIN_WHITELIST:
                ref_domains.append(d)
            else:
                threat_domains.append(d)
        if threat_domains:
            iocs["domains"] = threat_domains[:20]
        if ref_domains:
            references["domains"] = ref_domains[:20]

        # ── Hashes — SHA256 first ────────────────────────────────────────────
        sha256 = sorted(set(
            h for h in IOCExtractor.SHA256_RE.findall(text)
            if not IOCExtractor._HASH_EXCLUDE.match(h)
        ))
        if sha256:
            iocs["sha256"] = sha256[:10]

        remaining = text
        for h in sha256:
            remaining = remaining.replace(h, "")

        sha1 = sorted(set(
            h for h in IOCExtractor.SHA1_RE.findall(remaining)
            if not IOCExtractor._HASH_EXCLUDE.match(h)
        ))
        if sha1:
            iocs["sha1"] = sha1[:10]

        for h in sha1:
            remaining = remaining.replace(h, "")

        md5 = sorted(set(
            h for h in IOCExtractor.MD5_RE.findall(remaining)
            if not IOCExtractor._HASH_EXCLUDE.match(h)
        ))
        if md5:
            iocs["md5"] = md5[:10]

        return {"iocs": iocs, "references": references}

    @staticmethod
    def extract_ips_only(text: str) -> List[str]:
        """
        Convenience method — returns only public IPv4 addresses.
        Used for batch file generation from news feed / PDF.
        """
        text = re.sub(r'\[\.?\]', '.', text)
        return sorted(set(
            ip for ip in IOCExtractor.IPV4_RE.findall(text)
            if not IOCExtractor._IP_PRIVATE.match(ip)
        ))

    @staticmethod
    def format_for_display(result: Dict[str, Any], indent: int = 4) -> str:
        """
        Format extracted IOCs and references for terminal display.
        Shows threat IOCs prominently and reference mentions separately.
        Returns empty string if nothing found.

        Args:
            result: Return value from extract() — dict with 'iocs' and 'references' keys
        """
        # Handle legacy callers passing raw iocs dict directly
        if "iocs" not in result:
            result = {"iocs": result, "references": {}}

        iocs       = result.get("iocs", {})
        references = result.get("references", {})

        if not iocs and not references:
            return ""

        pad = " " * indent
        labels = {
            "ipv4":    "IPs    ",
            "cves":    "CVEs   ",
            "urls":    "URLs   ",
            "domains": "Domains",
            "sha256":  "SHA256 ",
            "sha1":    "SHA1   ",
            "md5":     "MD5    ",
        }

        lines = []

        # ── Threat IOCs ──────────────────────────────────────────────────────
        if iocs:
            total = sum(len(v) for v in iocs.values())
            lines.append(f"{pad}┌─ Threat IOCs ({total}) ──────────────────────────")
            for key in ("ipv4", "cves", "sha256", "sha1", "md5", "domains", "urls"):
                if key not in iocs:
                    continue
                label  = labels.get(key, key)
                values = iocs[key]
                lines.append(f"{pad}│  {label} : {values[0]}")
                for v in values[1:]:
                    lines.append(f"{pad}│           {v}")

        # ── Reference mentions ───────────────────────────────────────────────
        if references:
            ref_domains = references.get("domains", [])
            ref_urls    = references.get("urls", [])
            ref_items   = ref_domains + ref_urls
            if ref_items:
                if iocs:
                    lines.append(f"{pad}├─ Reference Mentions (not IOCs) ────────────")
                else:
                    lines.append(f"{pad}┌─ Reference Mentions (not IOCs) ────────────")
                for d in ref_domains:
                    lines.append(f"{pad}│  {d}")
                for u in ref_urls[:5]:   # cap URLs in reference display
                    lines.append(f"{pad}│  {u}")

        lines.append(f"{pad}└────────────────────────────────────────────")
        return "\n".join(lines)
