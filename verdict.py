"""
verdict.py — Multi-source verdict correlation engine for ThreatCheck.

Weighting rationale (must sum to 1.0):
  AbuseIPDB  35% — direct community abuse reports
  VirusTotal 35% — AV engine consensus, malware/phishing signal
  GreyNoise  20% — noise vs targeted classification (answers "is this targeting ME?")
  IPInfo      10% — context/geo only, not a threat feed
"""

from typing import Optional

SOURCE_WEIGHTS = {
    "abuseipdb":  0.35,
    "virustotal": 0.35,
    "greynoise":  0.20,
    "ipinfo":     0.10,
}

STATUS_SCORES = {
    "Malicious":  100,
    "Suspicious":  50,
    "Clean":        0,
    "OK":           0,
    "Unknown":      0,   # GreyNoise "Unknown" = not in dataset, not a threat signal
    "Skipped":     -1,   # Excluded from scoring
    "Auth Error":  -1,
    "Rate Limit":  -1,
    "HTTP Error":  -1,
    "Not Found":   -1,
    "Connection Error": -1,
    "API Error":   -1,
}

# --------------------------------------------------------------------------- #
#  Tag derivation
# --------------------------------------------------------------------------- #

USAGE_TYPE_TAGS = {
    "Data Center/Web Hosting/Transit": "HOSTING",
    "ISP":                             "ISP",
    "University/College/School":       "EDUCATION",
    "Organization":                    "ORGANIZATION",
    "Government":                      "GOVERNMENT",
    "Military":                        "MILITARY",
    "Library":                         "LIBRARY",
    "Content Delivery Network":        "CDN",
    "Fixed Line ISP":                  "ISP",
    "Mobile ISP":                      "MOBILE_ISP",
    "Search Engine Spider":            "SCANNER",
    "Reserved":                        "RESERVED",
}

TAG_KEYWORDS = {
    "TOR_EXIT":    ["tor", "torproject", "tor exit"],
    "VPN":         ["vpn", "virtual private", "nordvpn", "expressvpn", "protonvpn",
                    "mullvad", "ipvanish", "hidemyass", "purevpn"],
    "PROXY":       ["proxy", "anonymous proxy", "open proxy"],
    "SCANNER":     ["shodan", "censys", "masscan", "nmap", "scanner", "scanning",
                    "internet scanner", "research scan"],
    "CDN":         ["cloudflare", "akamai", "fastly", "cdn", "content delivery"],
    "HOSTING":     ["hosting", "datacenter", "data center", "vps", "digitalocean",
                    "linode", "vultr", "hetzner", "ovh", "amazon", "aws", "azure",
                    "google cloud", "gcp"],
    "BOTNET":      ["botnet", "bot ", "zombie"],
    "SPAM":        ["spam", "spammer", "bulk mail"],
    "BRUTE_FORCE": ["brute", "bruteforce", "brute force", "ssh attack", "rdp attack"],
    "MALWARE_C2":  ["c2", "command and control", "c&c", "malware"],
    "PHISHING":    ["phish", "phishing"],
}


def _derive_tags(enrichment_results: dict) -> list:
    tags = set()

    abuse = enrichment_results.get("abuseipdb", {})
    usage = (abuse.get("usage_type") or "").strip()
    tag = USAGE_TYPE_TAGS.get(usage)
    if tag:
        tags.add(tag)

    raw = abuse.get("raw_data") or {}
    for report in (raw.get("reports") or []):
        cats = report.get("categories") or []
        if 14 in cats: tags.add("SCANNER")
        if 18 in cats: tags.add("BRUTE_FORCE")
        if  4 in cats: tags.add("SPAM")

    vt          = enrichment_results.get("virustotal", {})
    vt_cats     = (vt.get("raw_data") or {}).get("categories") or {}
    vt_text     = " ".join(str(v).lower() for v in vt_cats.values())

    ipinfo      = enrichment_results.get("ipinfo", {})
    org_text    = (ipinfo.get("org") or "").lower()

    gn          = enrichment_results.get("greynoise", {})
    gn_name     = (gn.get("name") or "").lower()

    # GreyNoise-specific tags
    if gn.get("noise"):
        tags.add("SCANNER")   # Actively scanning the internet
    if gn.get("riot"):
        tags.add("KNOWN_BENIGN")
    elif (gn.get("classification") or "").lower() == "benign":
        tags.add("KNOWN_BENIGN")  # Benign noise actor (e.g. Censys, Shodan)

    combined = f"{usage.lower()} {vt_text} {org_text} {gn_name}"
    combined += f" {(abuse.get('isp') or '').lower()}"
    combined += f" {(vt.get('as_owner') or '').lower()}"

    for tag_name, keywords in TAG_KEYWORDS.items():
        for kw in keywords:
            if kw in combined:
                tags.add(tag_name)
                break

    return sorted(tags)


# --------------------------------------------------------------------------- #
#  Scoring
# --------------------------------------------------------------------------- #

def _weighted_score(enrichment_results: dict) -> Optional[float]:
    active = {}
    for source, weight in SOURCE_WEIGHTS.items():
        result  = enrichment_results.get(source, {})
        status  = result.get("status", "Unknown")
        numeric = STATUS_SCORES.get(status, -1)
        if numeric >= 0:
            active[source] = (weight, numeric)

    if not active:
        return None

    total_weight = sum(w for w, _ in active.values())
    score = sum((w / total_weight) * s for w, s in active.values())
    return round(score, 1)


def _count_verdicts(enrichment_results: dict) -> dict:
    counts = {"Malicious": 0, "Suspicious": 0, "Clean": 0, "active": 0}
    for source in SOURCE_WEIGHTS:
        result = enrichment_results.get(source, {})
        status = result.get("status", "Unknown")
        if STATUS_SCORES.get(status, -1) >= 0:
            counts["active"] += 1
            if status == "Malicious":   counts["Malicious"]  += 1
            elif status == "Suspicious": counts["Suspicious"] += 1
            elif status in ("Clean", "OK", "Unknown"): counts["Clean"] += 1
    return counts


# --------------------------------------------------------------------------- #
#  Main verdict function
# --------------------------------------------------------------------------- #

def correlate(enrichment_results: dict) -> dict:
    score  = _weighted_score(enrichment_results)
    counts = _count_verdicts(enrichment_results)
    tags   = _derive_tags(enrichment_results)

    source_verdicts = {
        src: enrichment_results.get(src, {}).get("status", "Skipped")
        for src in SOURCE_WEIGHTS
    }

    active_count = counts["active"]

    # GreyNoise override logic — benign/noise actors should not be MALICIOUS
    # even if AbuseIPDB and VT flag them heavily (they scan everyone, not just you).
    gn = enrichment_results.get("greynoise", {})
    gn_classification = (gn.get("classification") or "").lower()
    gn_noise          = gn.get("noise", False)
    gn_riot           = gn.get("riot", False)
    gn_name           = gn.get("name", "unknown")
    gn_active         = gn.get("status") not in ("Skipped", "Auth Error", "Rate Limit",
                                                   "Connection Error", "HTTP Error", None)

    if gn_active and gn_riot:
        # RIOT = definitively known benign service (Google, Cloudflare, etc.)
        verdict    = "CLEAN"
        confidence = "HIGH"
        summary    = f"IP belongs to {gn_name} (GreyNoise RIOT — known benign service)."
    elif gn_active and gn_classification == "benign" and gn_noise:
        # Benign scanner (Censys, Shodan, etc.) — high report volume is expected,
        # not evidence of targeted malicious activity against you specifically.
        # Cap at SUSPICIOUS so analysts still review, but don't call it MALICIOUS.
        verdict    = "SUSPICIOUS"
        confidence = "MEDIUM"
        summary    = (f"GreyNoise identifies {gn_name} as a benign internet scanner "
                      f"(noise: True). High AbuseIPDB/VT scores reflect mass scanning "
                      f"activity, not targeted attacks. Verify if this IP contacted you.")
    elif score is None:
        verdict    = "UNKNOWN"
        confidence = "LOW"
        summary    = "All sources failed or were skipped — result is inconclusive."
    elif score >= 50:
        verdict = "MALICIOUS"
        confidence = "HIGH"   if counts["Malicious"] >= 2 else "MEDIUM"
        summary    = (f"Flagged as malicious by {counts['Malicious']}/{active_count} sources (score: {score}/100)."
                      if counts["Malicious"] >= 1
                      else f"Composite score indicates malicious activity (score: {score}/100).")
    elif score >= 10:
        verdict    = "SUSPICIOUS"
        confidence = "MEDIUM" if counts["Suspicious"] >= 2 else "LOW"
        summary    = (f"Multiple sources report suspicious activity (score: {score}/100)."
                      if counts["Suspicious"] >= 2
                      else f"Low-level suspicious signal (score: {score}/100). Monitor or investigate.")
    else:
        verdict    = "CLEAN"
        confidence = "HIGH" if active_count >= 2 else "MEDIUM"
        summary    = (f"No threat signal across {active_count} sources (score: {score}/100)."
                      if active_count >= 2
                      else f"No threat signal (score: {score}/100), only {active_count} source checked.")

    if tags:
        summary += f" Tags: {', '.join(tags)}."

    return {
        "verdict":         verdict,
        "confidence":      confidence,
        "score":           score if score is not None else "N/A",
        "tags":            tags,
        "summary":         summary,
        "source_verdicts": source_verdicts,
    }


# --------------------------------------------------------------------------- #
#  Pretty printer
# --------------------------------------------------------------------------- #

VERDICT_ICONS = {
    "MALICIOUS":  "🔴",
    "SUSPICIOUS": "🟡",
    "CLEAN":      "🟢",
    "UNKNOWN":    "⚪",
}

CONFIDENCE_ICONS = {
    "HIGH":   "███",
    "MEDIUM": "██░",
    "LOW":    "█░░",
}


def print_verdict(verdict_result: dict, ip_str: str):
    v         = verdict_result["verdict"]
    c         = verdict_result["confidence"]
    s         = verdict_result["score"]
    icon      = VERDICT_ICONS.get(v, "⚪")
    conf_bar  = CONFIDENCE_ICONS.get(c, "░░░")

    print()
    print(f"  ╔══════════════════════════════════════════════╗")
    print(f"  ║  VERDICT  {icon}  {v:<10}  [{conf_bar}] {c:<6}     ║")
    ip_display = (ip_str[:20] + "..") if len(ip_str) > 22 else ip_str
    print(f"  ║  Score  : {str(s):>5}/100   IP: {ip_display:<22}  ║")
    print(f"  ╚══════════════════════════════════════════════╝")

    sv = verdict_result["source_verdicts"]
    print(f"  Sources │ AbuseIPDB: {sv.get('abuseipdb','?'):<12} "
          f"VT: {sv.get('virustotal','?'):<12} "
          f"GN: {sv.get('greynoise','?'):<10} "
          f"IPInfo: {sv.get('ipinfo','?')}")

    tags = verdict_result["tags"]
    if tags:
        print(f"  Tags    │ {', '.join(tags)}")

    print(f"  Summary │ {verdict_result['summary']}")
    print()