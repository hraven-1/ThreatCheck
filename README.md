# ThreatCheck

A multi-source IP reputation and threat intelligence CLI tool. Checks public IPs against five enrichment sources and produces verdicts, HTML reports, CSV exports, and defanged IOC lists. Includes IOC extraction from news feeds, PDFs, and TAXII threat intelligence collections.

## Sources

| Source | Data | Key Required |
|---|---|---|
| AbuseIPDB | Abuse reports, confidence score, ISP, country | Yes |
| VirusTotal | AV engine detections, AS owner, reputation | Yes |
| GreyNoise | Internet noise classification, RIOT, last seen | Yes (free tier available) |
| Shodan (InternetDB) | Open ports, CVEs, tags, CPEs, hostnames | No |
| IPInfo | Geolocation, ASN, org, hostname, timezone | No (token optional) |

## Requirements

- Python 3.7+
- No required dependencies — stdlib only for core features

Optional dependencies for extended features:

```bash
pip install pdfplumber    # PDF IOC extraction (--pdf)
pip install taxii2-client # TAXII feed integration (--taxii)
```

## Setup

1. Copy `config.json.example` to `config.json`
2. Add your API keys to `config.json`
3. Run it

API keys are saved automatically on first run if `config.json` is not present.

## Usage

```bash
# Single IP
python threatcheck.py 8.8.8.8

# CIDR range (auto-expanded, capped at 256 hosts)
python threatcheck.py 192.168.1.0/24

# Batch file (one IP or CIDR per line)
python threatcheck.py --batch ips.txt

# Batch with full outputs
python threatcheck.py --batch ips.txt --report report.html --export results.csv --ioc iocs.txt

# Pipe-friendly JSON output
python threatcheck.py 8.8.8.8 --quiet --json

# Defanged output
python threatcheck.py 8.8.8.8 --defang

# Threat intel news feed
python threatcheck.py --news
python threatcheck.py --news --ioc-extract
python threatcheck.py --news --news-filter "ransomware,CVE" --news-since 48

# News feed to batch to enrichment pipeline
python threatcheck.py --news --ioc-extract --to-batch leads.txt
python threatcheck.py --news --ioc-extract --to-batch leads.txt --enrich
python threatcheck.py --news --ioc-extract --to-batch leads.txt --enrich --export results.csv

# PDF IOC extraction
python threatcheck.py --pdf advisory.pdf
python threatcheck.py --pdf advisory.pdf --to-batch leads.txt
python threatcheck.py --pdf advisory.pdf --to-batch leads.txt --enrich --export results.csv

# TAXII feed integration
python threatcheck.py --taxii
python threatcheck.py --taxii --to-batch taxii_leads.txt
python threatcheck.py --taxii --to-batch taxii_leads.txt --enrich
python threatcheck.py --taxii --taxii-since 2026-04-29T00:00:00.000Z --to-batch leads.txt --enrich

# Cache management
python threatcheck.py --cache-stats
python threatcheck.py --cache-purge
```

## IOC Extraction

ThreatCheck extracts Indicators of Compromise from news article titles, PDF documents, and TAXII collections. Extracted IOCs are split into two categories:

- **Threat IOCs** — IPs, CVEs, hashes, and unknown domains that may be malicious infrastructure
- **Reference Mentions** — whitelisted domains (vendors, government agencies, cited sources) that appear in reports but are not IOCs

Handles defanged indicators automatically (`1.2.3[.]4` and `hXXps://`).

## Output Modes

| Flag | Description |
|---|---|
| `--report FILE` | HTML report with verdict summary |
| `--export FILE` | CSV with all enrichment fields per IP |
| `--ioc FILE` | Defanged IOC list of malicious IPs only |
| `--json` | Clean JSON to stdout for piping |
| `--defang` | Print IPs in 1.2.3[.]4 format |
| `--to-batch FILE` | Write IPs extracted from news/PDF/TAXII to batch file |
| `--enrich` | Immediately enrich IPs written to --to-batch |

## Options

```
--batch FILE          File with one IP/CIDR per line
--pdf FILE            Extract IOCs from a PDF file
--taxii               Pull IP indicators from configured TAXII collections
--taxii-since TIME    Only fetch indicators added after this ISO timestamp
--days N              AbuseIPDB lookback window in days (default: 90)
--no-cache            Bypass cache, force fresh API calls
--cache-ttl N         Cache TTL in seconds (default: 21600 = 6h)
--quiet               Suppress terminal output (use with --json)
--ioc-extract         Extract and display IOCs from news article titles
--to-batch FILE       Write extracted IPs to batch file
--enrich              Immediately enrich IPs from --to-batch
--abuse-key KEY       AbuseIPDB key override (not saved)
--vt-key KEY          VirusTotal key override (not saved)
--gn-key KEY          GreyNoise key override (not saved)
--shodan-key KEY      Shodan key override (not saved)
--ipinfo-token TOK    IPInfo token override (not saved)
```

## Config

Keys and TAXII server configurations are stored in `config.json`. See `config.json.example` for the full structure including the `taxii_servers` block.

> ⚠️ **Never commit your `config.json`** — it contains your live API keys. It is excluded via `.gitignore`.

## Logs

Results are automatically saved to `logs/threat_log.json`.

## License

MIT
