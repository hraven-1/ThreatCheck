"""
enrichment.py — Multi-source IP enrichment for ThreatCheck.

Sources:
  - AbuseIPDB   : Abuse reports and confidence score        (requires API key)
  - VirusTotal  : Malware/phishing detections by AV engines (requires API key)
  - GreyNoise   : Internet noise vs targeted threat context (requires API key)
  - IPInfo      : Geolocation, ASN, org, hostname           (free tier, no key required)
"""

import json
import urllib.request
import urllib.parse
import urllib.error
import ssl
import cache as cache_module
import greynoise as greynoise_module

# --------------------------------------------------------------------------- #
#  Shared helpers
# --------------------------------------------------------------------------- #

def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED
    return ctx


def _get_json(url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


# --------------------------------------------------------------------------- #
#  AbuseIPDB
# --------------------------------------------------------------------------- #

ABUSEIPDB_THRESHOLD_SUSPICIOUS = 1
ABUSEIPDB_THRESHOLD_MALICIOUS  = 25


def check_abuseipdb(ip_str, api_key, max_age_days=90,
                    threshold_suspicious=ABUSEIPDB_THRESHOLD_SUSPICIOUS,
                    threshold_malicious=ABUSEIPDB_THRESHOLD_MALICIOUS,
                    use_cache=True, cache_ttl=21600):
    SOURCE = "abuseipdb"
    if use_cache:
        cached = cache_module.get(ip_str, SOURCE, ttl=cache_ttl)
        if cached:
            print(f"    [cache] AbuseIPDB result for {ip_str} served from cache.")
            return cached

    print(f"[-] AbuseIPDB  : querying {ip_str} (last {max_age_days}d)...")

    result = {
        "source": SOURCE, "risk_score": None, "total_reports": None,
        "usage_type": None, "domain": None, "isp": None,
        "country_code": None, "is_whitelisted": None,
        "last_reported_at": None, "status": "Unknown",
        "error": None, "raw_data": None,
    }

    url = (
        "https://api.abuseipdb.com/api/v2/check?"
        + urllib.parse.urlencode({"ipAddress": ip_str, "maxAgeInDays": str(max_age_days)})
    )

    try:
        data = _get_json(url, headers={"Accept": "application/json", "Key": api_key})
        if "data" in data:
            d = data["data"]
            result.update({
                "risk_score":       d.get("abuseConfidenceScore", 0),
                "total_reports":    d.get("totalReports", 0),
                "usage_type":       d.get("usageType", "Unknown"),
                "domain":           d.get("domain", "Unknown"),
                "isp":              d.get("isp", "Unknown"),
                "country_code":     d.get("countryCode", "Unknown"),
                "is_whitelisted":   d.get("isWhitelisted", False),
                "last_reported_at": d.get("lastReportedAt", "Never"),
                "raw_data":         d,
            })
            score = result["risk_score"]
            result["status"] = (
                "Malicious"  if score >= threshold_malicious  else
                "Suspicious" if score >= threshold_suspicious else
                "Clean"
            )
        else:
            result["status"] = "API Error"
            result["error"]  = "Unexpected response format"
    except urllib.error.HTTPError as e:
        result["error"]  = f"HTTP {e.code}: {e.reason}"
        result["status"] = ("Auth Error" if e.code == 401 else
                            "Rate Limit" if e.code == 429 else "HTTP Error")
    except Exception as e:
        result["error"]  = str(e)
        result["status"] = "Connection Error"

    if use_cache and result["status"] not in ("Auth Error", "Rate Limit", "Connection Error"):
        cache_module.set(ip_str, SOURCE, result)
    return result


# --------------------------------------------------------------------------- #
#  VirusTotal
# --------------------------------------------------------------------------- #

VT_THRESHOLD_SUSPICIOUS = 1
VT_THRESHOLD_MALICIOUS  = 3


def check_virustotal(ip_str, api_key,
                     threshold_suspicious=VT_THRESHOLD_SUSPICIOUS,
                     threshold_malicious=VT_THRESHOLD_MALICIOUS,
                     use_cache=True, cache_ttl=21600):
    SOURCE = "virustotal"
    if use_cache:
        cached = cache_module.get(ip_str, SOURCE, ttl=cache_ttl)
        if cached:
            print(f"    [cache] VirusTotal result for {ip_str} served from cache.")
            return cached

    print(f"[-] VirusTotal : querying {ip_str}...")

    result = {
        "source": SOURCE, "malicious_count": None, "suspicious_count": None,
        "harmless_count": None, "undetected_count": None, "total_engines": None,
        "as_owner": None, "country": None, "last_analysis_date": None,
        "reputation": None, "status": "Unknown", "error": None, "raw_data": None,
    }

    try:
        data  = _get_json(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip_str}",
            headers={"x-apikey": api_key}
        )
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result.update({
            "malicious_count":    stats.get("malicious", 0),
            "suspicious_count":   stats.get("suspicious", 0),
            "harmless_count":     stats.get("harmless", 0),
            "undetected_count":   stats.get("undetected", 0),
            "total_engines":      sum(stats.values()) if stats else 0,
            "as_owner":           attrs.get("as_owner", "Unknown"),
            "country":            attrs.get("country", "Unknown"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "reputation":         attrs.get("reputation", 0),
            "raw_data":           attrs,
        })
        mal = result["malicious_count"]
        sus = result["suspicious_count"]
        result["status"] = (
            "Malicious"  if mal >= threshold_malicious  else
            "Suspicious" if (mal >= threshold_suspicious or sus >= threshold_suspicious) else
            "Clean"
        )
    except urllib.error.HTTPError as e:
        result["error"]  = f"HTTP {e.code}: {e.reason}"
        result["status"] = ("Auth Error" if e.code == 401 else
                            "Not Found"  if e.code == 404 else
                            "Rate Limit" if e.code == 429 else "HTTP Error")
    except Exception as e:
        result["error"]  = str(e)
        result["status"] = "Connection Error"

    if use_cache and result["status"] not in ("Auth Error", "Rate Limit", "Connection Error"):
        cache_module.set(ip_str, SOURCE, result)
    return result


# --------------------------------------------------------------------------- #
#  IPInfo
# --------------------------------------------------------------------------- #

def check_ipinfo(ip_str, api_token=None, use_cache=True, cache_ttl=21600):
    SOURCE = "ipinfo"
    if use_cache:
        cached = cache_module.get(ip_str, SOURCE, ttl=cache_ttl)
        if cached:
            print(f"    [cache] IPInfo result for {ip_str} served from cache.")
            return cached

    print(f"[-] IPInfo     : querying {ip_str}...")

    result = {
        "source": SOURCE, "hostname": None, "city": None,
        "region": None, "country": None, "org": None,
        "asn": None, "timezone": None, "status": "Unknown",
        "error": None, "raw_data": None,
    }

    url = f"https://ipinfo.io/{ip_str}/json"
    if api_token:
        url += f"?token={api_token}"

    try:
        data = _get_json(url)
        result.update({
            "hostname": data.get("hostname", "Unknown"),
            "city":     data.get("city",     "Unknown"),
            "region":   data.get("region",   "Unknown"),
            "country":  data.get("country",  "Unknown"),
            "org":      data.get("org",      "Unknown"),
            "timezone": data.get("timezone", "Unknown"),
            "raw_data": data,
        })
        org = result["org"] or ""
        result["asn"]    = org.split(" ")[0] if org.startswith("AS") else "Unknown"
        result["status"] = "OK"
    except urllib.error.HTTPError as e:
        result["error"]  = f"HTTP {e.code}: {e.reason}"
        result["status"] = "Rate Limit" if e.code == 429 else "HTTP Error"
    except Exception as e:
        result["error"]  = str(e)
        result["status"] = "Connection Error"

    if use_cache and result["status"] not in ("Rate Limit", "Connection Error"):
        cache_module.set(ip_str, SOURCE, result)
    return result


# --------------------------------------------------------------------------- #
#  Run all enabled sources
# --------------------------------------------------------------------------- #

def enrich(ip_str, keys, max_age_days=90, use_cache=True, cache_ttl=21600):
    """
    Runs all configured enrichment sources for a single IP.

    keys:
        "abuseipdb"  -> AbuseIPDB API key     (required for abuse checks)
        "virustotal" -> VirusTotal API key     (optional, recommended)
        "greynoise"  -> GreyNoise API key      (optional, free community tier)
        "ipinfo"     -> IPInfo token           (optional, free tier works)
    """
    results = {}

    results["abuseipdb"] = (
        check_abuseipdb(ip_str, keys["abuseipdb"],
                        max_age_days=max_age_days,
                        use_cache=use_cache, cache_ttl=cache_ttl)
        if keys.get("abuseipdb")
        else {"source": "abuseipdb", "status": "Skipped", "error": "No API key"}
    )

    results["virustotal"] = (
        check_virustotal(ip_str, keys["virustotal"],
                         use_cache=use_cache, cache_ttl=cache_ttl)
        if keys.get("virustotal")
        else {"source": "virustotal", "status": "Skipped", "error": "No API key"}
    )

    results["greynoise"] = (
        greynoise_module.check_greynoise(ip_str, keys["greynoise"],
                                         use_cache=use_cache, cache_ttl=cache_ttl)
        if keys.get("greynoise")
        else {"source": "greynoise", "status": "Skipped", "error": "No API key"}
    )

    # IPInfo always runs — free tier, no key required
    results["ipinfo"] = check_ipinfo(
        ip_str, api_token=keys.get("ipinfo"),
        use_cache=use_cache, cache_ttl=cache_ttl
    )

    return results
