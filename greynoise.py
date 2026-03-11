"""
greynoise.py — GreyNoise enrichment source for ThreatCheck.

GreyNoise answers the critical question other sources don't:
  "Is this IP scanning the entire internet (noise), or targeting ME specifically?"

Classifications:
  - benign     : Known good actor (Google, Shodan, etc.)
  - malicious  : Known bad actor actively attacking infrastructure
  - unknown    : Not in GreyNoise dataset (not necessarily clean)

Free Community API: https://www.greynoise.io/
  - 50 lookups/day, no credit card required
  - Endpoint: https://api.greynoise.io/v3/community/{ip}

Paid API unlocks full context (tags, CVEs, actor names, raw scan data).
"""

import json
import urllib.request
import urllib.error
import ssl
import cache as cache_module


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED
    return ctx


def check_greynoise(ip_str, api_key, use_cache=True, cache_ttl=21600):
    """
    Queries the GreyNoise Community API for an IP.
    Returns a normalised result dict.

    GreyNoise statuses:
      "noise"   — IP is actively scanning the internet (background noise)
      "riot"    — IP belongs to a known benign service (Google, Cloudflare, etc.)
      "unknown" — IP has no GreyNoise data
    """
    SOURCE = "greynoise"

    if use_cache:
        cached = cache_module.get(ip_str, SOURCE, ttl=cache_ttl)
        if cached:
            print(f"    [cache] GreyNoise result for {ip_str} served from cache.")
            return cached

    print(f"[-] GreyNoise  : querying {ip_str}...")

    result = {
        "source":        SOURCE,
        "noise":         None,   # True = actively scanning internet
        "riot":          None,   # True = known benign service
        "classification": None,  # "malicious" / "benign" / "unknown"
        "name":          None,   # Actor/org name if known
        "link":          None,   # GreyNoise profile URL
        "last_seen":     None,
        "message":       None,
        "status":        "Unknown",
        "error":         None,
        "raw_data":      None,
    }

    url = f"https://api.greynoise.io/v3/community/{ip_str}"
    headers = {
        "Accept":    "application/json",
        "key":       api_key,
        "User-Agent": "ThreatCheck/1.0"
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))

        result["noise"]          = data.get("noise", False)
        result["riot"]           = data.get("riot", False)
        result["classification"] = data.get("classification", "unknown")
        result["name"]           = data.get("name", "Unknown")
        result["link"]           = data.get("link", None)
        result["last_seen"]      = data.get("last_seen", None)
        result["message"]        = data.get("message", None)
        result["raw_data"]       = data

        classification = result["classification"]
        noise          = result["noise"]
        riot           = result["riot"]

        if classification == "malicious":
            result["status"] = "Malicious"
        elif riot:
            # Known benign service — treat as clean with context
            result["status"] = "Clean"
        elif noise and classification == "benign":
            result["status"] = "Clean"
        elif noise:
            # Scanning internet but not classified — suspicious
            result["status"] = "Suspicious"
        else:
            # Not in dataset
            result["status"] = "Unknown"

    except urllib.error.HTTPError as e:
        if e.code == 404:
            # 404 from GreyNoise = IP not in their dataset = unknown
            result["status"]  = "Unknown"
            result["message"] = "IP not found in GreyNoise dataset"
        elif e.code == 401:
            result["error"]  = "Invalid or missing GreyNoise API key"
            result["status"] = "Auth Error"
        elif e.code == 429:
            result["error"]  = "GreyNoise daily limit reached (50/day on free tier)"
            result["status"] = "Rate Limit"
        else:
            result["error"]  = f"HTTP {e.code}: {e.reason}"
            result["status"] = "HTTP Error"
    except Exception as e:
        result["error"]  = str(e)
        result["status"] = "Connection Error"

    if use_cache and result["status"] not in ("Auth Error", "Rate Limit", "Connection Error"):
        cache_module.set(ip_str, SOURCE, result)

    return result
