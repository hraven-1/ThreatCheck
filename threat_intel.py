"""
threat_intel.py — Threat Intelligence News Feed for ThreatCheck.

Features:
  - Concurrent RSS/Atom fetching (ThreadPoolExecutor)
  - Published date parsing and display
  - Severity tagging: 🚨 critical / ⚠️  notable keywords auto-flagged
  - Date-based filtering: --since 24 (hours) or --since 7d (days), default 24h
    Articles without a date always show (no date = can't filter)
  - Keyword filtering
  - HTML digest export
  - Lenient XML parser with control-char sanitization fallback

Sources:
  GENERAL      : The Hacker News, BleepingComputer
  GOVERNMENT   : CISA Advisories, CISA KEV, MSRC, Google TAG
  TECHNICAL    : DFIR Report, Red Canary, Unit 42, Mandiant
  VULNS        : NVD Recent CVEs, SANS ISC, Exploit-DB
  THREAT_FEEDS : Feodo Tracker C2
"""

import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
import ssl
import json
import os
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.utils import parsedate_to_datetime
import ioc_extractor as ioc_module

# --------------------------------------------------------------------------- #
#  Config
# --------------------------------------------------------------------------- #

DEFAULT_MAX_ITEMS  = 3
DEFAULT_SINCE_HRS  = 24    # Default lookback window in hours
FETCH_TIMEOUT      = 10
MAX_WORKERS        = 10

CRITICAL_KEYWORDS = [
    "zero-day", "0-day", "0day", "actively exploited", "in the wild",
    "emergency", "critical patch", "remote code execution", "rce",
    "ransomware", "nation-state", "apt", "supply chain attack",
    "cobalt strike", "emotet", "lockbit", "blackcat", "cl0p",
]

NOTABLE_KEYWORDS = [
    "critical", "high severity", "cvss 9", "cvss 10", "patch tuesday",
    "data breach", "backdoor", "rootkit", "phishing campaign",
    "malware", "trojan", "infostealer", "keylogger", "botnet",
    "privilege escalation", "authentication bypass", "command injection",
    "sql injection", "vulnerability", "exploit",
]

# --------------------------------------------------------------------------- #
#  Sources
# --------------------------------------------------------------------------- #

SOURCES = [
    # name, url (or sentinel), category
    ("The Hacker News",     "https://feeds.feedburner.com/TheHackersNews",                  "GENERAL"),
    ("BleepingComputer",    "https://www.bleepingcomputer.com/feed/",                       "GENERAL"),
    ("CISA Advisories",     "https://www.cisa.gov/cybersecurity-advisories/all.xml",        "GOVERNMENT"),
    ("CISA KEV",            "CISA_KEV",                                                     "GOVERNMENT"),
    # MSRC feed removed — contains invalid XML characters that survive sanitization
    ("Google TAG",          "https://blog.google/threat-analysis-group/rss/",              "GOVERNMENT"),
    ("The DFIR Report",     "https://thedfirreport.com/feed/",                             "TECHNICAL"),
    ("Red Canary",          "https://redcanary.com/feed/",                                 "TECHNICAL"),
    ("Palo Alto Unit 42",   "https://unit42.paloaltonetworks.com/feed/",                   "TECHNICAL"),
    ("Mandiant",            "https://www.mandiant.com/resources/blog/rss.xml",             "TECHNICAL"),
    ("NVD Recent CVEs",     "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml", "VULNS"),
    ("SANS ISC",            "https://isc.sans.edu/rssfeed.xml",                            "VULNS"),
    ("Exploit-DB",          "https://www.exploit-db.com/rss.xml",                         "VULNS"),
    ("Feodo Tracker C2",    "FEODO",                                                       "THREAT_FEEDS"),
]

CATEGORY_HEADERS = {
    "GENERAL":      "GENERAL AWARENESS",
    "GOVERNMENT":   "GOVERNMENT & ADVISORIES",
    "TECHNICAL":    "DEEP TECHNICAL / THREAT HUNTING",
    "VULNS":        "VULNERABILITIES & EXPLOITS",
    "THREAT_FEEDS": "LIVE THREAT FEEDS",
}

# --------------------------------------------------------------------------- #
#  SSL
# --------------------------------------------------------------------------- #

def _ssl_ctx():
    ctx = ssl.create_default_context()
    try:
        ctx.check_hostname = True
        ctx.verify_mode    = ssl.CERT_REQUIRED
    except Exception:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    return ctx

# --------------------------------------------------------------------------- #
#  Severity
# --------------------------------------------------------------------------- #

def _severity(title):
    t = title.lower()
    for kw in CRITICAL_KEYWORDS:
        if kw in t:
            return "CRITICAL"
    for kw in NOTABLE_KEYWORDS:
        if kw in t:
            return "NOTABLE"
    return "NORMAL"

# --------------------------------------------------------------------------- #
#  Date parsing
# --------------------------------------------------------------------------- #

def _parse_dt(date_str):
    """
    Parse a date string from an RSS/Atom feed into a timezone-aware datetime.
    Returns None if parsing fails.
    """
    if not date_str:
        return None
    date_str = date_str.strip()

    # RFC 2822 (standard RSS pubDate)
    try:
        dt = parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass

    # ISO 8601 variants — use explicit slice lengths, not len(fmt)
    for fmt, length in (
        ("%Y-%m-%dT%H:%M:%S%z", 25),
        ("%Y-%m-%dT%H:%M:%SZ",  20),
        ("%Y-%m-%dT%H:%M:%S",   19),
        ("%Y-%m-%d",            10),
    ):
        try:
            dt = datetime.strptime(date_str[:length], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass

    return None


def _format_dt(dt):
    """Returns a short display string like '2026-03-11 14:32'."""
    if dt is None:
        return None
    try:
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return None


def _parse_since(since_str):
    """
    Parse a --since value into a cutoff datetime.
    Accepts: integer hours (e.g. '24'), or Nd (e.g. '7d').
    Returns a timezone-aware datetime.
    """
    if since_str is None:
        return datetime.now(timezone.utc) - timedelta(hours=DEFAULT_SINCE_HRS)

    since_str = str(since_str).strip().lower()
    try:
        if since_str.endswith("d"):
            hours = int(since_str[:-1]) * 24
        else:
            hours = int(since_str)
        return datetime.now(timezone.utc) - timedelta(hours=hours)
    except ValueError:
        print(f"[!] Invalid --since value '{since_str}', defaulting to 24h")
        return datetime.now(timezone.utc) - timedelta(hours=DEFAULT_SINCE_HRS)

# --------------------------------------------------------------------------- #
#  HTTP helper
# --------------------------------------------------------------------------- #

def _get(url, timeout=FETCH_TIMEOUT):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 ThreatCheck/1.0"
    })
    with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
        return r.read()

# --------------------------------------------------------------------------- #
#  XML parser with sanitizing fallback
# --------------------------------------------------------------------------- #

def _parse_xml(raw):
    """Parse XML bytes, falling back to control-char sanitization on failure."""
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        cleaned = raw.decode("utf-8", errors="replace")
        cleaned = "".join(
            c for c in cleaned
            if c in ("\t", "\n", "\r")
            or ("\x20" <= c <= "\ud7ff")
            or ("\ue000" <= c <= "\ufffd")
        )
        try:
            return ET.fromstring(cleaned.encode("utf-8"))
        except ET.ParseError as e:
            raise ET.ParseError(f"Unrecoverable XML: {e}")

# --------------------------------------------------------------------------- #
#  Article filtering (date + keywords)
# --------------------------------------------------------------------------- #

def _filter(articles, keywords, cutoff, max_items):
    """
    Filter articles by keyword and date cutoff.
    Articles with no date are always included (can't determine age).
    """
    if keywords:
        kws      = [k.lower().strip() for k in keywords]
        articles = [a for a in articles
                    if any(kw in a["title"].lower() for kw in kws)]

    if cutoff is not None:
        kept = []
        for a in articles:
            dt = a.get("_dt")
            if dt is None:
                kept.append(a)         # no date — always show
            elif dt >= cutoff:
                kept.append(a)
        articles = kept

    return articles[:max_items]

# --------------------------------------------------------------------------- #
#  Fetchers
# --------------------------------------------------------------------------- #

def _fetch_rss(url, max_items, keywords, cutoff):
    root  = _parse_xml(_get(url))
    items = root.findall(".//item")
    if not items:
        items = root.findall(".//{http://www.w3.org/2005/Atom}entry")

    articles = []
    for item in items:
        # Title — explicit is-not-None checks (XML elements are falsy when empty)
        te = item.find("title")
        if te is None:
            te = item.find("{http://www.w3.org/2005/Atom}title")
        title = (te.text or "").strip() if te is not None else ""
        title = title or "No Title"

        # Link
        link = ""
        le   = item.find("link")
        if le is not None:
            link = (le.text or "").strip() or le.get("href", "")
        if not link:
            ale = item.find("{http://www.w3.org/2005/Atom}link")
            if ale is not None:
                link = ale.get("href", "")
        if not link:
            ge = item.find("guid")
            if ge is not None and (ge.text or "").startswith("http"):
                link = (ge.text or "").strip()
        link = link or "No Link"

        # Date
        de = item.find("pubDate")
        if de is None:
            de = item.find("published")
        if de is None:
            de = item.find("{http://www.w3.org/2005/Atom}published")
        if de is None:
            de = item.find("{http://www.w3.org/2005/Atom}updated")
        dt   = _parse_dt(de.text if de is not None else None)
        date = _format_dt(dt)

        articles.append({"title": title, "link": link, "date": date, "_dt": dt})

    return _filter(articles, keywords, cutoff, max_items)


def _fetch_cisa_kev(max_items, keywords, cutoff):
    data  = json.loads(_get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ))
    vulns = sorted(data.get("vulnerabilities", []),
                   key=lambda v: v.get("dateAdded", ""), reverse=True)
    articles = []
    for v in vulns:
        cve   = v.get("cveID", "")
        title = f"{cve} — {v.get('vendorProject','')}: {v.get('vulnerabilityName','')}"
        link  = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve}"
        dt    = _parse_dt(v.get("dateAdded", ""))
        articles.append({"title": title, "link": link,
                         "date": _format_dt(dt), "_dt": dt})
    return _filter(articles, keywords, cutoff, max_items)


def _fetch_feodo(max_items, keywords, cutoff):
    text  = _get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt").decode("utf-8")
    lines = [l.strip() for l in text.splitlines()
             if l.strip() and not l.startswith("#")]
    # Feodo has no dates — always shown, no date filter applied
    articles = [
        {"title": f"Active C2: {ip}",
         "link":  f"https://feodotracker.abuse.ch/browse/host/{ip}/",
         "date":  None, "_dt": None}
        for ip in lines
    ]
    if keywords:
        kws      = [k.lower().strip() for k in keywords]
        articles = [a for a in articles
                    if any(kw in a["title"].lower() for kw in kws)]
    return articles[:max_items]


def _fetch_source(name, url, category, max_items, keywords, cutoff):
    try:
        if url == "CISA_KEV":
            articles = _fetch_cisa_kev(max_items, keywords, cutoff)
        elif url == "FEODO":
            articles = _fetch_feodo(max_items, keywords, cutoff)
        else:
            # Exploit-DB entries are always relevant regardless of age
            _cutoff = None if "exploit-db.com" in url else cutoff
            articles = _fetch_rss(url, max_items, keywords, _cutoff)
        return name, category, articles, None
    except urllib.error.URLError as e:
        return name, category, [], f"Network error: {e.reason}"
    except ET.ParseError as e:
        return name, category, [], f"Feed parse error: {e}"
    except Exception as e:
        return name, category, [], f"Error: {e}"

# --------------------------------------------------------------------------- #
#  Display
# --------------------------------------------------------------------------- #

SEV_PREFIX = {
    "CRITICAL": "🚨",
    "NOTABLE":  "⚠️ ",
    "NORMAL":   "   ",
}


def display_news(max_items=DEFAULT_MAX_ITEMS, keywords=None,
                 since=None, save_path=None,
                 extract_iocs=False, to_batch=None, enrich_callback=None):
    """
    Fetch and display threat intel news.

    Args:
        max_items       : Articles per source
        keywords        : List of keyword strings to filter on (None = no filter)
        since           : Hours lookback as int, or string like '7d'. None = 24h.
                          Pass 0 or 'all' to disable date filtering entirely.
        save_path       : If set, write an HTML digest to this path
        extract_iocs    : If True, extract and display IOCs from each article title
        to_batch        : If set, write all extracted IPs to this file path
        enrich_callback : If set, called with list of IPs after batch file is written
    """
    # Build cutoff datetime
    if since == 0 or str(since).lower() == "all":
        cutoff    = None
        since_str = "all time"
    else:
        cutoff    = _parse_since(since)
        hrs       = int(str(since).replace("d","")) * (24 if str(since).endswith("d") else 1) if since else DEFAULT_SINCE_HRS
        since_str = f"last {hrs}h" if hrs < 48 else f"last {hrs//24}d"

    filter_str = f" │ filter: {', '.join(keywords)}" if keywords else ""

    print(f"\n{'='*54}")
    print(f"  THREAT INTELLIGENCE BRIEFING")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M')} │ {since_str}{filter_str}")
    print(f"{'='*54}\n")
    print(f"[-] Fetching {len(SOURCES)} sources concurrently...\n")

    ordered_results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_idx = {
            executor.submit(_fetch_source, name, url, cat, max_items, keywords, cutoff): i
            for i, (name, url, cat) in enumerate(SOURCES)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                ordered_results[idx] = future.result()
            except Exception as e:
                name, _, cat = SOURCES[idx]
                ordered_results[idx] = (name, cat, [], str(e))

    all_for_save     = []
    total_shown      = 0
    current_category = None
    all_extracted_ips = []   # collected across all articles for --to-batch

    for i in range(len(SOURCES)):
        name, category, articles, error = ordered_results.get(
            i, (SOURCES[i][0], SOURCES[i][2], [], "No result")
        )

        if category != current_category:
            current_category = category
            header = CATEGORY_HEADERS.get(category, category)
            print(f"\n  ── {header} {'─' * max(0, 44 - len(header))}")

        if error:
            print(f"\n  [{name}]  [!] {error}")
            continue

        if not articles:
            print(f"\n  [{name}]")
            print(f"    (no articles in window)")
            continue

        print(f"\n  [{name}]")
        for article in articles:
            title  = article["title"]
            link   = article["link"]
            date   = article.get("date") or ""
            prefix = SEV_PREFIX.get(_severity(title), "   ")
            date_s = f"  [{date}]" if date else ""

            try:
                print(f"  {prefix} {title}{date_s}")
                print(f"       {link}")
            except UnicodeEncodeError:
                clean = title.encode("ascii", "ignore").decode("ascii")
                print(f"  {prefix} {clean}{date_s}")
                print(f"       {link}")

            # IOC extraction — runs on title text
            if extract_iocs or to_batch:
                result = ioc_module.IOCExtractor.extract(title)
                iocs   = result.get("iocs", {})
                refs   = result.get("references", {})
                if iocs or refs:
                    print(ioc_module.IOCExtractor.format_for_display(result, indent=7))
                if to_batch and iocs.get("ipv4"):
                    all_extracted_ips.extend(iocs["ipv4"])

            total_shown += 1
            all_for_save.append((name, category, article))

    print(f"\n{'='*54}")
    print(f"  {total_shown} article(s) in window")
    print(f"{'='*54}\n")

    # Write extracted IPs to batch file
    if to_batch and all_extracted_ips:
        unique_ips    = sorted(set(all_extracted_ips))
        dupe_count    = len(all_extracted_ips) - len(unique_ips)
        try:
            os.makedirs(os.path.dirname(to_batch) if os.path.dirname(to_batch) else ".", exist_ok=True)
            with open(to_batch, "w", encoding="utf-8") as f:
                f.write(f"# ThreatCheck IOC Batch — extracted from news feed\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# {len(all_extracted_ips)} total IPs "
                        f"({len(unique_ips)} unique, {dupe_count} dupes kept for cache coverage)\n\n")
                for ip in all_extracted_ips:   # dupes kept intentionally
                    f.write(ip + "\n")
            print(f"[-] Extracted {len(all_extracted_ips)} IPs "
                  f"({len(unique_ips)} unique) → {to_batch}")
        except IOError as e:
            print(f"[!] Error writing batch file: {e}")

        if enrich_callback and all_extracted_ips:
            print(f"[-] Starting enrichment on extracted IPs...\n")
            enrich_callback(all_extracted_ips)

    elif to_batch and not all_extracted_ips:
        print(f"[-] No public IPs found in article titles — batch file not written.")

    if save_path and all_for_save:
        _save_digest(all_for_save, save_path, keywords, since_str)

# --------------------------------------------------------------------------- #
#  HTML digest
# --------------------------------------------------------------------------- #

def _save_digest(articles_with_source, path, keywords=None, since_str=""):
    from collections import defaultdict
    now    = datetime.now().strftime("%Y-%m-%d %H:%M")
    by_cat = defaultdict(list)
    for name, cat, article in articles_with_source:
        by_cat[cat].append((name, article))

    sev_badge = {
        "CRITICAL": '<span style="background:#c0392b;color:#fff;padding:1px 6px;border-radius:3px;font-size:0.72em;margin-right:6px">🚨 CRITICAL</span>',
        "NOTABLE":  '<span style="background:#e67e22;color:#fff;padding:1px 6px;border-radius:3px;font-size:0.72em;margin-right:6px">⚠️ NOTABLE</span>',
        "NORMAL":   "",
    }

    rows = []
    for cat in ["GENERAL", "GOVERNMENT", "TECHNICAL", "VULNS", "THREAT_FEEDS"]:
        if cat not in by_cat:
            continue
        header = CATEGORY_HEADERS.get(cat, cat)
        rows.append(f'<tr><td colspan="3" style="background:#1a1a2e;color:#61dafb;'
                    f'padding:10px 12px;font-weight:600;font-size:0.82em;'
                    f'letter-spacing:0.05em">{header}</td></tr>')
        for name, article in by_cat[cat]:
            title = article["title"]
            link  = article["link"]
            date  = article.get("date") or ""
            badge = sev_badge.get(_severity(title), "")
            rows.append(
                f'<tr style="border-bottom:1px solid #1a1a2e">'
                f'<td style="padding:6px 12px;color:#555;font-size:0.75em;white-space:nowrap">{date}</td>'
                f'<td style="padding:6px 8px;color:#888;font-size:0.78em;white-space:nowrap">{name}</td>'
                f'<td style="padding:6px 12px;font-size:0.83em">{badge}'
                f'<a href="{link}" target="_blank" '
                f'style="color:#e0e0e0;text-decoration:none">{title}</a></td>'
                f'</tr>'
            )

    filter_note = f" — filter: {', '.join(keywords)}" if keywords else ""
    since_note  = f" — {since_str}" if since_str else ""
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ThreatCheck Digest — {now}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
        background:#0d0d1a;color:#e0e0e0;padding:24px;font-size:14px}}
  h1{{color:#61dafb;font-size:1.3em;margin-bottom:4px}}
  .meta{{color:#555;font-size:0.8em;margin-bottom:20px}}
  table{{width:100%;border-collapse:collapse}}
  tr:hover td{{background:rgba(97,218,251,0.04)}}
  a:hover{{color:#61dafb!important;text-decoration:underline!important}}
</style>
</head><body>
<h1>🛡 ThreatCheck — Intelligence Digest</h1>
<div class="meta">Generated: {now}{since_note}{filter_note} &nbsp;|&nbsp; {len(articles_with_source)} articles</div>
<table>
<thead><tr style="border-bottom:2px solid #333">
  <th style="text-align:left;padding:8px 12px;color:#444;font-size:0.75em">Date</th>
  <th style="text-align:left;padding:8px 8px;color:#444;font-size:0.75em">Source</th>
  <th style="text-align:left;padding:8px 12px;color:#444;font-size:0.75em">Article</th>
</tr></thead>
<tbody>{"".join(rows)}</tbody>
</table></body></html>"""

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[-] News digest saved to: {path}")
    except IOError as e:
        print(f"[!] Error saving digest: {e}")


# --------------------------------------------------------------------------- #
#  Standalone entry point
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ThreatCheck News Feed")
    parser.add_argument("--filter",  metavar="KEYWORDS",
                        help="Comma-separated keywords to filter on")
    parser.add_argument("--since",   metavar="N",      default=None,
                        help="Lookback window: hours (e.g. 24) or days (e.g. 7d). Default: 24h. Use 'all' for no filter.")
    parser.add_argument("--save",    metavar="FILE",
                        help="Save digest as HTML file")
    parser.add_argument("--max",     type=int, default=DEFAULT_MAX_ITEMS,
                        help="Max articles per source (default: 3)")
    args = parser.parse_args()

    kws = [k.strip() for k in args.filter.split(",")] if args.filter else None
    display_news(
        max_items=args.max,
        keywords=kws,
        since=args.since,
        save_path=args.save,
    )
