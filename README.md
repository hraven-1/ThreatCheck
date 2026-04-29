# ThreatCheck

A multi-source IP reputation and threat intelligence CLI tool. Checks public IPs against five enrichment sources and produces verdicts, HTML reports, CSV exports, and defanged IOC lists.

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
- No external dependencies — stdlib only

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
python threatcheck.py --news --news-filter "ransomware,CVE" --news-since 48

# Cache management
python threatcheck.py --cache-stats
python threatcheck.py --cache-purge
```

## Output Modes

| Flag | Description |
|---|---|
| `--report FILE` | HTML report with verdict summary |
| `--export FILE` | CSV with all enrichment fields per IP |
| `--ioc FILE` | Defanged IOC list of malicious IPs only |
| `--json` | Clean JSON to stdout for piping |
| `--defang` | Print IPs in 1.2.3[.]4 format |

## Options

```
--batch FILE        File with one IP/CIDR per line
--days N            AbuseIPDB lookback window in days (default: 90)
--no-cache          Bypass cache, force fresh API calls
--cache-ttl N       Cache TTL in seconds (default: 21600 = 6h)
--quiet             Suppress terminal output (use with --json)
--abuse-key KEY     AbuseIPDB key override (not saved)
--vt-key KEY        VirusTotal key override (not saved)
--gn-key KEY        GreyNoise key override (not saved)
--shodan-key KEY    Shodan key override (not saved)
--ipinfo-token TOK  IPInfo token override (not saved)
```

## Config

Keys are stored in `config.json` in the tool directory. See `config.json.example` for the expected structure.

> ⚠️ **Never commit your `config.json`** — it contains your live API keys. It is excluded via `.gitignore`.

## Logs

Results are automatically saved to `logs/threat_log.json`.

## License

MIT
