================================================================================
  THREATCHECK — README
================================================================================

A multi-source IP reputation and threat intelligence tool. Checks IPs against
AbuseIPDB, VirusTotal, GreyNoise, and IPInfo, then combines the results into
a single verdict with confidence scoring, IOC tags, delta tracking, and a
daily news briefing from 13 live threat intel feeds.


--------------------------------------------------------------------------------
  REQUIREMENTS
--------------------------------------------------------------------------------

  - Python 3.8 or newer
  - AbuseIPDB API key  (free at abuseipdb.com — required)
  - VirusTotal API key (free at virustotal.com — recommended)
  - GreyNoise API key  (free community tier at greynoise.io — recommended)


--------------------------------------------------------------------------------
  QUICK START
--------------------------------------------------------------------------------

  Double-click run_threatcheck.bat to open the interactive prompt.

  Or from the command line:
    python threatcheck.py 8.8.8.8

  On first run you will be asked for your API keys. They are saved to
  config.json and never need to be entered again.


--------------------------------------------------------------------------------
  FILES
--------------------------------------------------------------------------------

  threatcheck.py      Main entry point and CLI
  enrichment.py       Queries AbuseIPDB, VirusTotal, IPInfo
  greynoise.py        GreyNoise Community API source
  verdict.py          Weighted scoring and verdict engine
  cache.py            SQLite-backed local cache (default 6h TTL)
  delta.py            Tracks changes between checks for the same IP
  threat_intel.py     Threat intelligence news feed aggregator
  report.py           HTML report generator
  run_threatcheck.bat Windows interactive launcher


--------------------------------------------------------------------------------
  IP CHECKS
--------------------------------------------------------------------------------

  Single IP:
    python threatcheck.py 8.8.8.8

  CIDR range (up to 256 hosts):
    python threatcheck.py 192.168.1.0/24

  Batch file (one IP or CIDR per line, # for comments):
    python threatcheck.py --batch ips.txt

  Private, loopback, and reserved IPs are detected and skipped automatically.


--------------------------------------------------------------------------------
  VERDICT ENGINE
--------------------------------------------------------------------------------

  Each IP is scored across up to 4 sources:

    AbuseIPDB   35%  — community abuse reports
    VirusTotal  35%  — AV engine consensus
    GreyNoise   20%  — noise vs targeted classification
    IPInfo      10%  — geo/ASN context only

  Verdicts   : MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN
  Confidence : HIGH / MEDIUM / LOW

  GreyNoise overrides apply. If an IP is a known benign internet scanner
  (e.g. Censys, Shodan), the verdict is capped at SUSPICIOUS regardless of
  AbuseIPDB and VirusTotal scores, with an explanation in the summary.


--------------------------------------------------------------------------------
  IOC TAGS
--------------------------------------------------------------------------------

  Automatically derived from source data:

  SCANNER  KNOWN_BENIGN  TOR_EXIT  VPN  PROXY  CDN  HOSTING
  BOTNET   SPAM  BRUTE_FORCE  MALWARE_C2  PHISHING


--------------------------------------------------------------------------------
  OUTPUT OPTIONS
--------------------------------------------------------------------------------

  Export to CSV:
    python threatcheck.py --batch ips.txt --export results.csv

  Generate HTML report (dark theme, sortable, filterable):
    python threatcheck.py --batch ips.txt --report report.html

  Export defanged malicious IPs as IOC list:
    python threatcheck.py --batch ips.txt --ioc iocs.txt

  Defanged output (1.2.3[.]4):
    python threatcheck.py 1.2.3.4 --defang

  JSON output for piping:
    python threatcheck.py 1.2.3.4 --quiet --json


--------------------------------------------------------------------------------
  NEWS BRIEFING
--------------------------------------------------------------------------------

  From the interactive launcher:
    n          last 24 hours (default)
    n 48       last 48 hours
    n 7d       last 7 days
    n all      no date filter

  From the command line:
    python threatcheck.py --news
    python threatcheck.py --news --news-since 7d
    python threatcheck.py --news --news-filter "ransomware,CVE"
    python threatcheck.py --news --news-save briefing.html
    python threatcheck.py --news --news-max 5

  Sources:
    General    : The Hacker News, BleepingComputer
    Government : CISA Advisories, CISA KEV, Google TAG
    Technical  : The DFIR Report, Red Canary, Unit 42, Mandiant
    Vulns      : NVD Recent CVEs, SANS ISC, Exploit-DB
    Live Feeds : Feodo Tracker C2

  Severity tags fire automatically on keywords:
    CRITICAL — zero-day, actively exploited, ransomware, nation-state, RCE
    NOTABLE  — critical severity, data breach, malware, exploit, vulnerability


--------------------------------------------------------------------------------
  CACHE
--------------------------------------------------------------------------------

  Results cache locally in cache/threatcheck_cache.db (default TTL: 6 hours).

    python threatcheck.py --cache-stats     Show cache statistics
    python threatcheck.py --cache-purge     Remove expired entries
    python threatcheck.py --no-cache        Bypass cache, force fresh queries
    python threatcheck.py --cache-ttl 3600  Set custom TTL in seconds


--------------------------------------------------------------------------------
  DELTA TRACKING
--------------------------------------------------------------------------------

  When an IP is checked more than once, ThreatCheck compares results against
  the last log entry and surfaces meaningful changes:

    - Verdict escalation or de-escalation
    - Composite score shift (5+ points)
    - New or removed IOC tags
    - AbuseIPDB score change
    - VirusTotal engine count change
    - GreyNoise classification change


--------------------------------------------------------------------------------
  LOGS
--------------------------------------------------------------------------------

  All results are saved to logs/threat_log.json.


--------------------------------------------------------------------------------
  SECURITY CHECKLIST
--------------------------------------------------------------------------------

  config.json contains your API keys. DO NOT SHARE IT.

  If sharing ThreatCheck with others, share only the source .py files and
  the .bat launcher — never your config.json.

  Keep a personal copy renamed so you know which one has your keys in it.
  The version you share should have no config.json included.

================================================================================
