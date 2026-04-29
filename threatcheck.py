"""
threatcheck.py — ThreatCheck CLI
Multi-source IP reputation checker.

Sources  : AbuseIPDB · VirusTotal · GreyNoise · IPInfo · Shodan (InternetDB)
Features : CIDR expansion · batch processing · delta tracking ·
           HTML reports · IOC export · defang · pipe-friendly JSON mode ·
           local SQLite cache
"""

import argparse
import ipaddress
import json
import os
import csv
import sys
import tempfile
import urllib.request
import urllib.parse
from datetime import datetime

import threat_intel
import enrichment
import verdict   as verdict_module
import cache     as cache_module
import delta     as delta_module
import report    as report_module

API_CONFIG_FILE = "config.json"


# --------------------------------------------------------------------------- #
#  Config
# --------------------------------------------------------------------------- #

def load_config():
    if os.path.exists(API_CONFIG_FILE):
        try:
            with open(API_CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def save_config(config):
    dir_name = os.path.dirname(API_CONFIG_FILE) or "."
    try:
        fd, tmp = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(config, f, indent=4)
        os.replace(tmp, API_CONFIG_FILE)
        return True
    except Exception as e:
        _err(f"Error saving config: {e}")
        return False


def load_api_keys():
    cfg = load_config()
    return {
        "abuseipdb":  cfg.get("abuseipdb_key"),
        "virustotal": cfg.get("virustotal_key"),
        "greynoise":  cfg.get("greynoise_key"),
        "ipinfo":     cfg.get("ipinfo_token"),
        "shodan":     cfg.get("shodan_key"),
    }


def save_api_key(name, value):
    field_map = {
        "abuseipdb":  "abuseipdb_key",
        "virustotal": "virustotal_key",
        "greynoise":  "greynoise_key",
        "ipinfo":     "ipinfo_token",
        "shodan":     "shodan_key",
    }
    cfg = load_config()
    cfg[field_map[name]] = value
    if save_config(cfg):
        _log(f"{name} key saved to {API_CONFIG_FILE}")


# --------------------------------------------------------------------------- #
#  Output helpers  (quiet mode suppresses these)
# --------------------------------------------------------------------------- #

_QUIET = False


def _log(msg):
    if not _QUIET:
        print(f"[-] {msg}")


def _err(msg):
    print(f"[!] {msg}", file=sys.stderr)


def _out(msg):
    """Always prints — used for JSON output in pipe mode."""
    print(msg)


# --------------------------------------------------------------------------- #
#  IP helpers
# --------------------------------------------------------------------------- #

def classify_ip(ip_obj):
    if ip_obj.is_loopback:   return "loopback"
    if ip_obj.is_link_local: return "link-local"
    if ip_obj.is_multicast:  return "multicast"
    if ip_obj.is_reserved:   return "reserved"
    if ip_obj.is_private:    return "private"
    if ip_obj.is_global:     return "public"
    return "unknown"


def defang(ip):
    """Returns defanged IP: 1.2.3[.]4"""
    return ip.replace(".", "[.]") if ip else ip


def expand_cidr(cidr_str):
    """
    Expands a CIDR range to a list of host IP strings.
    Caps at 256 hosts to avoid accidental /8 explosions.
    Returns (list_of_ips, warning_message_or_None).
    """
    MAX_HOSTS = 256
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        hosts   = list(network.hosts())
        if not hosts:
            # Handle /32 (single host) — .hosts() returns empty for /32
            hosts = [network.network_address]
        if len(hosts) > MAX_HOSTS:
            return (
                [str(h) for h in hosts[:MAX_HOSTS]],
                f"CIDR {cidr_str} has {len(hosts)} hosts — capped at {MAX_HOSTS}. Use a smaller range or split manually."
            )
        return [str(h) for h in hosts], None
    except ValueError as e:
        return [], str(e)


def is_cidr(s):
    return "/" in s


# --------------------------------------------------------------------------- #
#  Core processor
# --------------------------------------------------------------------------- #

def process_ip(ip_str, keys, max_age_days=90, use_cache=True, cache_ttl=21600):
    """Validates, classifies, enriches, deltas, and verdicts a single IP."""
    ip_str = ip_str.strip().replace("[", "").replace("]", "")

    result = {
        "timestamp":          datetime.now().isoformat(),
        "input_ip":           ip_str,
        "ip_type":            "unknown",
        "is_valid":           False,
        "enrichment_results": {},
        "verdict":            None,
        "error":              None,
        "_delta":             None,   # internal — stripped before JSON output
    }

    if not ip_str:
        result["error"] = "Empty input"
        return result

    try:
        ip      = ipaddress.ip_address(ip_str)
        ip_type = classify_ip(ip)
        result["is_valid"] = True
        result["ip_type"]  = ip_type

        if ip_type != "public":
            if not _QUIET:
                print(f"\n[-] {ip_str}")
                print(f"    Type : {ip_type.capitalize()} IP — skipping external check.")
            return result

        if not _QUIET:
            print(f"\n[+] Enriching {ip_str}...")

        enrichment_results = enrichment.enrich(
            ip_str, keys,
            max_age_days=max_age_days,
            use_cache=use_cache,
            cache_ttl=cache_ttl
        )
        result["enrichment_results"] = enrichment_results

        if not _QUIET:
            _print_enrichment_details(enrichment_results)

        verd = verdict_module.correlate(enrichment_results)
        result["verdict"] = verd

        # Delta tracking — compare against last known result
        previous = delta_module.get_last_result(ip_str)
        d = delta_module.compute_delta(result, previous)
        result["_delta"] = d

        if not _QUIET:
            verdict_module.print_verdict(verd, ip_str)
            if d:
                delta_module.print_delta(d)

    except ValueError:
        result["error"] = "Invalid IP address format"
        _err(f"'{ip_str}' is not a valid IP address.")

    return result


def _print_enrichment_details(enrichment_results):
    abuse = enrichment_results.get("abuseipdb", {})
    if abuse.get("status") not in ("Skipped", "Unknown", None):
        print()
        print("  ── AbuseIPDB ─────────────────────────────────")
        if abuse.get("error") and abuse["status"] not in ("Clean", "Suspicious", "Malicious"):
            print(f"    [!] {abuse['error']}")
        else:
            print(f"    Score        : {abuse.get('risk_score','?')}%  ({abuse.get('status','?')})")
            print(f"    Reports      : {abuse.get('total_reports','?')}")
            print(f"    Last Reported: {abuse.get('last_reported_at','?')}")
            print(f"    ISP          : {abuse.get('isp','?')}")
            print(f"    Country      : {abuse.get('country_code','?')}")
            print(f"    Whitelisted  : {abuse.get('is_whitelisted','?')}")
            print(f"    Usage Type   : {abuse.get('usage_type','?')}")

    vt = enrichment_results.get("virustotal", {})
    if vt.get("status") not in ("Skipped", "Unknown", None):
        print()
        print("  ── VirusTotal ────────────────────────────────")
        if vt.get("error") and vt["status"] not in ("Clean", "Suspicious", "Malicious"):
            print(f"    [!] {vt['error']}")
        else:
            mal   = vt.get("malicious_count") or 0
            sus   = vt.get("suspicious_count") or 0
            total = vt.get("total_engines") or 0
            print(f"    Status       : {vt.get('status','?')}")
            print(f"    Detections   : {mal} malicious, {sus} suspicious / {total} engines")
            print(f"    AS Owner     : {vt.get('as_owner','?')}")
            print(f"    Country      : {vt.get('country','?')}")
            if vt.get("reputation") is not None:
                print(f"    Reputation   : {vt.get('reputation')}")

    gn = enrichment_results.get("greynoise", {})
    if gn.get("status") not in ("Skipped", None):
        print()
        print("  ── GreyNoise ─────────────────────────────────")
        if gn.get("error") and gn["status"] not in ("Clean","Suspicious","Malicious","Unknown"):
            print(f"    [!] {gn['error']}")
        else:
            print(f"    Status       : {gn.get('status','?')}")
            print(f"    Classification: {gn.get('classification','?')}")
            print(f"    Noise        : {gn.get('noise','?')}  (scanning internet background)")
            print(f"    RIOT         : {gn.get('riot','?')}  (known benign service)")
            print(f"    Name         : {gn.get('name','?')}")
            if gn.get("last_seen"):
                print(f"    Last Seen    : {gn.get('last_seen')}")
            if gn.get("message"):
                print(f"    Message      : {gn.get('message')}")

    shodan = enrichment_results.get("shodan", {})
    if shodan.get("status") not in ("Skipped", "Unknown", None):
        print()
        print("  ── Shodan (InternetDB) ───────────────────────")
        if shodan.get("error") and shodan["status"] not in ("OK",):
            print(f"    [!] {shodan['error']}")
        else:
            ports     = shodan.get("ports")     or []
            vulns     = shodan.get("vulns")     or []
            tags      = shodan.get("tags")      or []
            cpes      = shodan.get("cpes")      or []
            hostnames = shodan.get("hostnames") or []
            print(f"    Open Ports   : {', '.join(str(p) for p in ports) if ports else 'None'}")
            print(f"    Hostnames    : {', '.join(hostnames) if hostnames else 'None'}")
            print(f"    Tags         : {', '.join(tags) if tags else 'None'}")
            print(f"    CPEs         : {', '.join(cpes) if cpes else 'None'}")
            print(f"    Vulns (CVEs) : {', '.join(vulns) if vulns else 'None'}")

    ipinfo = enrichment_results.get("ipinfo", {})
    if ipinfo.get("status") not in ("Unknown", None):
        print()
        print("  ── IPInfo ────────────────────────────────────")
        if ipinfo.get("error") and ipinfo["status"] != "OK":
            print(f"    [!] {ipinfo['error']}")
        else:
            print(f"    Hostname     : {ipinfo.get('hostname','?')}")
            print(f"    Location     : {ipinfo.get('city','?')}, "
                  f"{ipinfo.get('region','?')}, {ipinfo.get('country','?')}")
            print(f"    Org / ASN    : {ipinfo.get('org','?')}")
            print(f"    Timezone     : {ipinfo.get('timezone','?')}")


# --------------------------------------------------------------------------- #
#  Logging
# --------------------------------------------------------------------------- #

def log_result_atomic(data, log_dir="logs", log_file="threat_log.json"):
    os.makedirs(log_dir, exist_ok=True)
    file_path = os.path.join(log_dir, log_file)

    logs = []
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as f:
                logs = json.load(f)
        except json.JSONDecodeError:
            _err("Log file was corrupt. Starting fresh.")

    # Strip internal _delta key before persisting
    def clean(r):
        c = dict(r)
        c.pop("_delta", None)
        return c

    if isinstance(data, list):
        logs.extend(clean(r) for r in data)
    else:
        logs.append(clean(data))

    dir_name = os.path.dirname(file_path) or "."
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(logs, f, indent=4)
        os.replace(tmp_path, file_path)
    except Exception as e:
        _err(f"Error writing log: {e}")
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        return None

    return file_path


# --------------------------------------------------------------------------- #
#  CSV export
# --------------------------------------------------------------------------- #

def export_csv(results, export_path):
    rows = []
    for r in results:
        verd  = r.get("verdict") or {}
        abuse = (r.get("enrichment_results") or {}).get("abuseipdb") or {}
        vt    = (r.get("enrichment_results") or {}).get("virustotal") or {}
        gn    = (r.get("enrichment_results") or {}).get("greynoise") or {}
        info  = (r.get("enrichment_results") or {}).get("ipinfo") or {}
        shodan = (r.get("enrichment_results") or {}).get("shodan") or {}
        d     = r.get("_delta") or {}
        rows.append({
            "timestamp":           r.get("timestamp", ""),
            "input_ip":            r.get("input_ip", ""),
            "defanged_ip":         defang(r.get("input_ip", "")),
            "ip_type":             r.get("ip_type", ""),
            "verdict":             verd.get("verdict", ""),
            "confidence":          verd.get("confidence", ""),
            "score":               verd.get("score", ""),
            "tags":                "|".join(verd.get("tags") or []),
            "summary":             verd.get("summary", ""),
            "delta_changes":       "|".join(d.get("highlights") or []),
            "abuse_status":        abuse.get("status", ""),
            "abuse_score":         abuse.get("risk_score", ""),
            "abuse_reports":       abuse.get("total_reports", ""),
            "abuse_country":       abuse.get("country_code", ""),
            "abuse_isp":           abuse.get("isp", ""),
            "abuse_last_reported": abuse.get("last_reported_at", ""),
            "vt_status":           vt.get("status", ""),
            "vt_malicious":        vt.get("malicious_count", ""),
            "vt_suspicious":       vt.get("suspicious_count", ""),
            "vt_total_engines":    vt.get("total_engines", ""),
            "vt_as_owner":         vt.get("as_owner", ""),
            "gn_status":           gn.get("status", ""),
            "gn_classification":   gn.get("classification", ""),
            "gn_noise":            gn.get("noise", ""),
            "gn_riot":             gn.get("riot", ""),
            "gn_name":             gn.get("name", ""),
            "shodan_ports":        "|".join(str(p) for p in (shodan.get("ports") or [])),
            "shodan_vulns":        "|".join(shodan.get("vulns") or []),
            "shodan_tags":         "|".join(shodan.get("tags") or []),
            "shodan_cpes":         "|".join(shodan.get("cpes") or []),
            "shodan_hostnames":    "|".join(shodan.get("hostnames") or []),
            "hostname":            info.get("hostname", ""),
            "city":                info.get("city", ""),
            "region":              info.get("region", ""),
            "country":             info.get("country", ""),
            "org":                 info.get("org", ""),
            "asn":                 info.get("asn", ""),
            "error":               r.get("error", ""),
        })

    if not rows:
        _err("No results to export.")
        return

    try:
        with open(export_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        _log(f"CSV exported to: {export_path}")
    except IOError as e:
        _err(f"Error writing CSV: {e}")


# --------------------------------------------------------------------------- #
#  IOC export (defanged, malicious only)
# --------------------------------------------------------------------------- #

def export_iocs(results, ioc_path):
    """Writes a defanged IOC list of all MALICIOUS IPs."""
    malicious = [
        r["input_ip"] for r in results
        if (r.get("verdict") or {}).get("verdict") == "MALICIOUS"
        and r.get("input_ip")
    ]

    if not malicious:
        _log("No malicious IPs to export as IOCs.")
        return

    try:
        with open(ioc_path, "w", encoding="utf-8") as f:
            f.write(f"# ThreatCheck IOC Export — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# {len(malicious)} malicious IP(s) — defanged for safe sharing\n\n")
            for ip in malicious:
                f.write(defang(ip) + "\n")
        _log(f"IOC list exported to: {ioc_path} ({len(malicious)} entries)")
    except IOError as e:
        _err(f"Error writing IOC file: {e}")


# --------------------------------------------------------------------------- #
#  Interactive setup
# --------------------------------------------------------------------------- #

def interactive_key_setup(keys):
    """Prompts only for keys that are not yet configured."""
    prompts = [
        ("abuseipdb",  "[!] AbuseIPDB API Key not found (required for abuse checks).",
                       "    Enter AbuseIPDB key (or Enter to skip): "),
        ("virustotal", "[?] VirusTotal API Key not found (optional but recommended).",
                       "    Enter VirusTotal key (or Enter to skip): "),
        ("greynoise",  "[?] GreyNoise API Key not found (optional - free tier at greynoise.io).",
                       "    Enter GreyNoise key (or Enter to skip): "),
        ("shodan",     "[?] Shodan API Key not found (optional - free at shodan.io, used for future full-host lookups).",
                       "    Enter Shodan key (or Enter to skip): "),
    ]

    any_prompted = False
    for name, notice, prompt in prompts:
        if not keys.get(name):
            if not any_prompted:
                print("\n[~] One-time API key setup - press Enter to skip any key.\n")
                any_prompted = True
            print(notice)
            val = input(prompt).strip()
            if val:
                keys[name] = val
                save_api_key(name, val)

    if not keys.get("abuseipdb") and not keys.get("virustotal"):
        _err("No threat-feed keys configured. Only IPInfo (geo) checks will run.")

    return keys


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def main():
    global _QUIET

    parser = argparse.ArgumentParser(
        description="ThreatCheck: Multi-source IP reputation checker.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python threatcheck.py 8.8.8.8
  python threatcheck.py 8.8.8.8 --defang
  python threatcheck.py 192.168.1.0/24
  python threatcheck.py --batch ips.txt --report report.html
  python threatcheck.py --batch ips.txt --ioc iocs.txt --export results.csv
  python threatcheck.py 8.8.8.8 --quiet --json
  python threatcheck.py --news
  python threatcheck.py --cache-stats
        """
    )

    # Positional
    parser.add_argument("ip",              nargs="?",            help="Single IP or CIDR range to check")

    # Input modes
    parser.add_argument("--batch",         metavar="FILE",       help="File with one IP/CIDR per line")

    # Output modes
    parser.add_argument("--export",        metavar="FILE",       help="Export results to CSV")
    parser.add_argument("--report",        metavar="FILE",       help="Generate HTML report")
    parser.add_argument("--ioc",           metavar="FILE",       help="Export defanged malicious IOC list")
    parser.add_argument("--defang",        action="store_true",  help="Print IPs in defanged format (1.2.3[.]4)")
    parser.add_argument("--json",          action="store_true",  help="Output results as JSON to stdout (pipe mode)")
    parser.add_argument("--quiet",         action="store_true",  help="Suppress all output except --json")

    # News
    parser.add_argument("--news",          action="store_true",  help="Display latest threat intel feeds")
    parser.add_argument("--news-filter",   metavar="KEYWORDS",   help="Comma-separated keywords to filter news (e.g. 'ransomware,CVE')")
    parser.add_argument("--news-since",    metavar="N",          help="Lookback window: hours (e.g. 24) or days (e.g. 7d). Default 24h. Use 'all' for no filter.")
    parser.add_argument("--news-save",     metavar="FILE",       help="Save news digest as HTML file")
    parser.add_argument("--news-max",      type=int, default=3,  help="Articles per source (default: 3)")

    # API options
    parser.add_argument("--days",          type=int, default=90, help="AbuseIPDB lookback window in days (default: 90)")
    parser.add_argument("--no-cache",      action="store_true",  help="Bypass cache, force fresh API calls")
    parser.add_argument("--cache-ttl",     type=int, default=21600,
                                                                 help="Cache TTL in seconds (default: 21600 = 6h)")
    parser.add_argument("--cache-stats",   action="store_true",  help="Show cache statistics and exit")
    parser.add_argument("--cache-purge",   action="store_true",  help="Purge expired cache entries and exit")

    # Key overrides (ephemeral — not saved)
    parser.add_argument("--abuse-key",     metavar="KEY",        help="AbuseIPDB API key override")
    parser.add_argument("--vt-key",        metavar="KEY",        help="VirusTotal API key override")
    parser.add_argument("--gn-key",        metavar="KEY",        help="GreyNoise API key override")
    parser.add_argument("--ipinfo-token",  metavar="TOKEN",      help="IPInfo token override")
    parser.add_argument("--shodan-key",    metavar="KEY",        help="Shodan API key override")

    args = parser.parse_args()

    # --- Quiet / JSON mode ---
    if args.quiet or args.json:
        _QUIET = True

    # --- Utility commands ---
    if args.cache_stats:
        s = cache_module.stats()
        print("\n[Cache Stats]")
        print(f"  Total entries : {s.get('total_entries','?')}")
        for src, count in (s.get("by_source") or {}).items():
            print(f"  {src:<14}: {count}")
        print()
        return

    if args.cache_purge:
        cache_module.purge_expired(ttl=args.cache_ttl)
        print("[-] Expired cache entries purged.")
        return

    if args.news:
        kws = [k.strip() for k in args.news_filter.split(",")] if args.news_filter else None
        threat_intel.display_news(
            max_items=args.news_max,
            keywords=kws,
            since=args.news_since,
            save_path=args.news_save,
        )
        return

    if not args.ip and not args.batch:
        parser.print_help()
        return

    # --- API keys ---
    keys = load_api_keys()
    if args.abuse_key:    keys["abuseipdb"]  = args.abuse_key
    if args.vt_key:       keys["virustotal"] = args.vt_key
    if args.gn_key:       keys["greynoise"]  = args.gn_key
    if args.ipinfo_token: keys["ipinfo"]     = args.ipinfo_token
    if args.shodan_key:   keys["shodan"]     = args.shodan_key

    # Prompt for any missing keys — runs even if AbuseIPDB is already configured
    missing = [k for k in ("abuseipdb", "virustotal", "greynoise", "shodan") if not keys.get(k)]
    if missing and not _QUIET:
        keys = interactive_key_setup(keys)

    use_cache = not args.no_cache

    # --- Collect IPs (with CIDR expansion) ---
    ips_to_check = []

    def add_ip_or_cidr(s):
        s = s.strip()
        if not s or s.startswith("#"):
            return
        if is_cidr(s):
            expanded, warn = expand_cidr(s)
            if warn:
                _err(warn)
            if expanded:
                if not _QUIET:
                    print(f"[-] Expanded {s} → {len(expanded)} hosts")
                ips_to_check.extend(expanded)
            else:
                _err(f"Could not expand CIDR '{s}'")
        else:
            ips_to_check.append(s)

    if args.ip:
        add_ip_or_cidr(args.ip)

    if args.batch:
        if not os.path.exists(args.batch):
            _err(f"Batch file not found: {args.batch}")
            return
        with open(args.batch, "r") as f:
            for line in f:
                add_ip_or_cidr(line.strip())
        if not _QUIET:
            print(f"[-] Loaded {len(ips_to_check)} IPs from {args.batch}")

    if not ips_to_check:
        _err("No IPs to check.")
        return

    # --- Process ---
    results = []
    total   = len(ips_to_check)
    for i, ip_str in enumerate(ips_to_check, 1):
        if not _QUIET and total > 1:
            print(f"\n{'─'*52}")
            print(f"[{i}/{total}]  {ip_str}")
        result = process_ip(
            ip_str, keys,
            max_age_days=args.days,
            use_cache=use_cache,
            cache_ttl=args.cache_ttl,
        )

        # Defang display
        if args.defang and not _QUIET and result.get("input_ip"):
            print(f"  Defanged: {defang(result['input_ip'])}")

        results.append(result)

    # --- Log ---
    log_path = log_result_atomic(results if len(results) > 1 else results[0])
    if log_path and not _QUIET:
        print(f"\n[-] Results logged to: {log_path}")

    # --- Outputs ---
    if args.export:
        export_csv(results, args.export)

    if args.ioc:
        export_iocs(results, args.ioc)

    if args.report:
        # Attach delta to each result for the report
        report_module.generate(results, args.report)

    if args.json:
        # Strip internal keys, output clean JSON
        clean_results = []
        for r in results:
            c = dict(r)
            c.pop("_delta", None)
            clean_results.append(c)
        _out(json.dumps(clean_results, indent=2))

    # --- Defang-only summary (no full output) ---
    if args.defang and _QUIET:
        for r in results:
            ip = r.get("input_ip", "")
            v  = (r.get("verdict") or {}).get("verdict", "?")
            _out(f"{defang(ip)}\t{v}")

    # --- Batch summary ---
    if total > 1 and not _QUIET:
        tally = {}
        for r in results:
            v = (r.get("verdict") or {}).get("verdict") or r.get("ip_type", "skipped")
            tally[v] = tally.get(v, 0) + 1

        print(f"\n{'─'*52}")
        print("  BATCH SUMMARY")
        print(f"{'─'*52}")
        order = ["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN",
                 "private", "loopback", "reserved", "skipped"]
        icons = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟡", "CLEAN": "🟢"}
        for status in order:
            if status in tally:
                icon = icons.get(status, "⚪")
                print(f"  {icon}  {status:<20} {tally[status]}")
        print(f"{'─'*52}\n")


if __name__ == "__main__":
    main()
