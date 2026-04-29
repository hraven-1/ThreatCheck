"""
enrichment_shodan.py — Shodan InternetDB enrichment for ThreatCheck

Uses the free InternetDB API (https://internetdb.shodan.io/{ip}).
No API key required — key stored in config.json for future full-host
lookups if the user upgrades to a paid plan.

Returns:
    {
        "status":    "OK" | "Not Found" | "Error" | "Skipped",
        "ports":     [22, 80, 443, ...],
        "hostnames": ["host.example.com", ...],
        "tags":      ["vpn", "honeypot", ...],
        "cpes":      ["cpe:/a:openbsd:openssh:7.4", ...],
        "vulns":     ["CVE-2017-15906", ...],
        "error":     None | "error message",
        "source":    "internetdb",
    }
"""

import json
import urllib.request
import urllib.error

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
TIMEOUT        = 8   # seconds


def enrich(ip_str: str, api_key: str = None) -> dict:
    """
    Fetch InternetDB data for a single public IP.
    api_key is accepted for signature compatibility but not used —
    InternetDB is keyless. Reserved for future full-host API upgrade.
    """
    base = {
        "status":    "Unknown",
        "ports":     [],
        "hostnames": [],
        "tags":      [],
        "cpes":      [],
        "vulns":     [],
        "error":     None,
        "source":    "internetdb",
    }

    url = INTERNETDB_URL.format(ip=ip_str)

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ThreatCheck/1.0 (threat-intel-tool)"},
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")

        data = json.loads(raw)

        base["status"]    = "OK"
        base["ports"]     = data.get("ports")     or []
        base["hostnames"] = data.get("hostnames")  or []
        base["tags"]      = data.get("tags")       or []
        base["cpes"]      = data.get("cpes")       or []
        base["vulns"]     = data.get("vulns")      or []

        return base

    except urllib.error.HTTPError as e:
        if e.code == 404:
            # InternetDB returns 404 for IPs with no data — not an error
            base["status"] = "Not Found"
            return base
        base["status"] = "Error"
        base["error"]  = f"HTTP {e.code}: {e.reason}"
        return base

    except urllib.error.URLError as e:
        base["status"] = "Error"
        base["error"]  = f"Connection error: {e.reason}"
        return base

    except (json.JSONDecodeError, KeyError) as e:
        base["status"] = "Error"
        base["error"]  = f"Parse error: {e}"
        return base

    except Exception as e:
        base["status"] = "Error"
        base["error"]  = f"Unexpected error: {e}"
        return base
