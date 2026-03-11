# ThreatCheck

A multi-source IP reputation and threat intelligence tool. Correlates data from AbuseIPDB, VirusTotal, GreyNoise, and IPInfo into a single weighted verdict with confidence scoring, IOC tagging, delta tracking, and a daily news briefing pulled from 13 live threat intelligence feeds.

---

## Requirements

- Python 3.8+
- AbuseIPDB API key (free at abuseipdb.com — required)
- VirusTotal API key (free at virustotal.com — recommended)
- GreyNoise API key (free community tier at greynoise.io — recommended)

---

## Quick Start

Double-click `run_threatcheck.bat` to launch the interactive prompt, or run directly:

```bash
python threatcheck.py 8.8.8.8
```

On first run you will be prompted to enter your API keys. They are saved locally to `config.json` and never need to be entered again.

---

## Files

| File | Purpose |
|------|---------|
| `threatcheck.py` | Main entry point and CLI |
| `enrichment.py` | Queries AbuseIPDB, VirusTotal, IPInfo |
| `greynoise.py` | GreyNoise Community API source |
| `verdict.py` | Weighted scoring and verdict correlation engine |
| `cache.py` | SQLite-backed local cache (default 6h TTL) |
| `delta.py` | Tracks changes between checks for the same IP |
| `threat_intel.py` | Threat intelligence news feed aggregator |
| `report.py` | HTML report generator |
| `run_threatcheck.bat` | Windows interactive launcher |

---

## IP Checks

### Single IP
```bash
python threatcheck.py 8.8.8.8
```

### CIDR Range (up to 256 hosts)
```bash
python threatcheck.py 192.168.1.0/24
```

### Batch File
```bash
python threatcheck.py --batch ips.txt
```
One IP or CIDR per line. Lines starting with `#` are ignored.

### Private / Reserved IPs
Private, loopback, link-local, and reserved IPs are detected and skipped automatically — no API calls are made.

---

## Verdict Engine

Each IP is scored across up to 4 sources with weighted contributions:

| Source | Weight | Notes |
|--------|--------|-------|
| AbuseIPDB | 35% | Community abuse reports |
| VirusTotal | 35% | AV engine consensus |
| GreyNoise | 20% | Noise vs targeted classification |
| IPInfo | 10% | Geo/ASN context only |

Verdicts: `MALICIOUS` / `SUSPICIOUS` / `CLEAN` / `UNKNOWN`
Confidence: `HIGH` / `MEDIUM` / `LOW`

GreyNoise overrides apply — if an IP is classified as a known benign internet scanner (e.g. Censys, Shodan), the verdict is capped at `SUSPICIOUS` regardless of AbuseIPDB and VirusTotal scores, with an explanation in the summary.

---

## IOC Tags

Automatically derived from source data:

`SCANNER` `KNOWN_BENIGN` `TOR_EXIT` `VPN` `PROXY` `CDN` `HOSTING` `BOTNET` `SPAM` `BRUTE_FORCE` `MALWARE_C2` `PHISHING`

---

## Output Options

```bash
# Export results to CSV
python threatcheck.py --batch ips.txt --export results.csv

# Generate HTML report (dark theme, sortable, filterable)
python threatcheck.py --batch ips.txt --report report.html

# Export defanged malicious IPs as IOC list
python threatcheck.py --batch ips.txt --ioc iocs.txt

# Print IPs in defanged format (1.2.3[.]4)
python threatcheck.py 1.2.3.4 --defang

# JSON output for piping
python threatcheck.py 1.2.3.4 --quiet --json | jq '.[] | select(.verdict.verdict=="MALICIOUS")'
```

---

## News Briefing

Fetches from 13 concurrent threat intelligence feeds with severity tagging and date filtering.

### From the interactive launcher
```
n          → last 24 hours (default)
n 48       → last 48 hours
n 7d       → last 7 days
n all      → no date filter
```

### From the command line
```bash
python threatcheck.py --news
python threatcheck.py --news --news-since 7d
python threatcheck.py --news --news-filter "ransomware,CVE"
python threatcheck.py --news --news-save briefing.html
python threatcheck.py --news --news-max 5
```

### Sources
**General:** The Hacker News, BleepingComputer  
**Government:** CISA Advisories, CISA KEV, Google TAG  
**Technical:** The DFIR Report, Red Canary, Palo Alto Unit 42, Mandiant  
**Vulns:** NVD Recent CVEs, SANS ISC, Exploit-DB  
**Live Feeds:** Feodo Tracker C2

### Severity Tags
- 🚨 `CRITICAL` — zero-day, actively exploited, ransomware, nation-state, RCE
- ⚠️ `NOTABLE` — critical severity, data breach, malware, exploit, vulnerability

---

## Cache

Results are cached locally in `cache/threatcheck_cache.db` (default TTL: 6 hours).

```bash
python threatcheck.py --cache-stats     # Show cache statistics
python threatcheck.py --cache-purge     # Remove expired entries
python threatcheck.py --no-cache        # Bypass cache, force fresh queries
python threatcheck.py --cache-ttl 3600  # Set custom TTL in seconds
```

---

## Delta Tracking

When an IP is checked more than once, ThreatCheck compares the new result against the last log entry and surfaces meaningful changes:

- Verdict escalation or de-escalation
- Composite score shift (≥5 points)
- New or removed IOC tags
- AbuseIPDB score change
- VirusTotal engine count change
- GreyNoise classification change

---

## Logs

All results are saved to `logs/threat_log.json`.

---

## API Key Overrides (ephemeral, not saved)

```bash
python threatcheck.py 8.8.8.8 --abuse-key KEY --vt-key KEY --gn-key KEY
```

---

## Security Note

`config.json` contains your API keys. Do not share it. If you share ThreatCheck with others, share only the source files — not your `config.json`.
