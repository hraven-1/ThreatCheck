"""
taxii_source.py — TAXII 2.1 feed integration for ThreatCheck.

Pulls STIX 2.1 indicator objects from configured TAXII collections,
extracts IPv4 addresses from indicator patterns, and returns them
as a list ready for ThreatCheck batch enrichment.

Requires:
    pip install taxii2-client

Supported pattern formats:
    [ipv4-addr:value = '1.2.3.4']
    [ipv4-addr:value = '1.2.3.4/32']
    [network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '1.2.3.4']

Configuration in config.json:
    {
        "taxii_servers": [
            {
                "name": "My TAXII Server",
                "url": "https://example.com/taxii2/",
                "collection_id": "my-collection-id",
                "username": "",
                "password": "",
                "api_key": "",
                "api_key_header": "Authorization",
                "enabled": true,
                "added_after": null
            }
        ]
    }

Notes:
    - username/password for Basic auth
    - api_key for Bearer token auth (api_key_header defaults to "Authorization")
    - added_after: ISO timestamp for incremental pulls (null = last 24h)
    - Set enabled: false to skip a server without removing its config
"""

import re
import json
import os
import urllib.request
import urllib.parse
import urllib.error
import ssl
import base64
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

try:
    from taxii2client.v21 import Server, Collection
    _TAXII_CLIENT_AVAILABLE = True
    try:
        from taxii2client.common import TokenAuth, BasicAuth
    except ImportError:
        TokenAuth = None
        BasicAuth = None
except ImportError:
    _TAXII_CLIENT_AVAILABLE = False
    Server     = None
    Collection = None
    TokenAuth  = None
    BasicAuth  = None


# ── IPv4 pattern extraction ─────────────────────────────────────────────────

# Matches ipv4-addr values inside STIX patterns
_IPV4_PATTERN_RE = re.compile(
    r"ipv4-addr(?::value)?\s*=\s*['\"]"
    r"((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))"
    r"(?:/\d{1,2})?['\"]",
    re.IGNORECASE
)

# Private/reserved ranges to exclude
_IP_PRIVATE_RE = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|"
    r"169\.254\.|224\.|240\.|255\.)"
)


def _extract_ipv4_from_pattern(pattern: str) -> List[str]:
    """Extract public IPv4 addresses from a STIX indicator pattern string."""
    if not pattern:
        return []
    matches = _IPV4_PATTERN_RE.findall(pattern)
    return [ip for ip in matches if not _IP_PRIVATE_RE.match(ip)]


# ── Fallback raw TAXII client (stdlib only, no taxii2-client) ───────────────

def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED
    return ctx


def _raw_taxii_get(url: str, headers: Dict[str, str], timeout: int = 15) -> Dict:
    """Minimal stdlib TAXII GET — used when taxii2-client not installed."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 406:
            # Server rejected Accept header — try common alternatives
            for accept in [
                "application/json",
                "application/taxii+json; version=2.1",
                "application/vnd.oasis.taxii+json; version=2.1",
            ]:
                alt_headers = dict(headers)
                alt_headers["Accept"] = accept
                try:
                    req2 = urllib.request.Request(url, headers=alt_headers)
                    with urllib.request.urlopen(req2, context=_ssl_ctx(), timeout=timeout) as r:
                        return json.loads(r.read().decode("utf-8"))
                except urllib.error.HTTPError:
                    continue
        raise


def _build_headers(server_cfg: Dict) -> Dict[str, str]:
    """Build HTTP headers for a server config entry."""
    # Try TAXII media type first; _raw_taxii_get will fall back to application/json
    # if the server returns 406
    accept = server_cfg.get("accept_header", "application/taxii+json;version=2.1")
    headers = {
        "Accept":     accept,
        "User-Agent": "ThreatCheck/1.0 TAXII-Client",
    }
    username = server_cfg.get("username", "")
    password = server_cfg.get("password", "")
    api_key  = server_cfg.get("api_key", "")

    if api_key:
        header_name = server_cfg.get("api_key_header", "Authorization")
        # If the header is Authorization and the key doesn't look like a full
        # scheme already, prepend Bearer
        if header_name.lower() == "authorization" and not api_key.lower().startswith("bearer "):
            headers[header_name] = f"Bearer {api_key}"
        else:
            headers[header_name] = api_key
    elif username:
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {creds}"

    return headers


# ── Core fetcher ─────────────────────────────────────────────────────────────

def fetch_collection(server_cfg: Dict[str, Any],
                     added_after: Optional[str] = None,
                     limit: int = 500,
                     verbose: bool = True) -> Dict[str, Any]:
    """
    Fetch STIX objects from a single TAXII collection.

    Args:
        server_cfg  : A server config dict (from config.json taxii_servers list)
        added_after : ISO 8601 timestamp. Only objects added after this time
                      are returned. Defaults to 24h ago if None.
        limit       : Max objects per page (server may cap lower)
        verbose     : Print progress to terminal

    Returns:
        {
            "name":       server name,
            "url":        collection URL,
            "ips":        [list of extracted public IPv4s],
            "objects":    total STIX objects fetched,
            "indicators": total indicator objects found,
            "error":      None or error string,
        }
    """
    result = {
        "name":       server_cfg.get("name", "Unknown"),
        "url":        server_cfg.get("url", ""),
        "ips":        [],
        "objects":    0,
        "indicators": 0,
        "error":      None,
    }

    if not server_cfg.get("enabled", True):
        result["error"] = "Skipped (disabled)"
        return result

    url           = server_cfg.get("url", "").rstrip("/")
    collection_id = server_cfg.get("collection_id", "")

    if not url or not collection_id:
        result["error"] = "Missing url or collection_id in server config"
        return result

    # Resolve added_after
    if added_after is None:
        added_after = server_cfg.get("added_after")
    if not added_after:
        cutoff      = datetime.now(timezone.utc) - timedelta(hours=24)
        added_after = cutoff.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    if verbose:
        print(f"[-] TAXII  : {result['name']} — fetching indicators since {added_after}")

    # Build objects endpoint URL
    objects_url = f"{url}/{collection_id}/objects/"

    headers = _build_headers(server_cfg)
    all_ips = []
    total_objects    = 0
    total_indicators = 0

    try:
        # ── Prefer taxii2-client if available ───────────────────────────────
        if _TAXII_CLIENT_AVAILABLE:
            _fetch_with_client(
                server_cfg, collection_id, added_after, limit,
                all_ips, result
            )
        else:
            # ── Stdlib fallback — manual pagination ──────────────────────────
            params = {
                "added_after": added_after,
                "limit":       str(limit),
            }
            next_token = None

            while True:
                if next_token:
                    params["next"] = next_token

                full_url = objects_url + "?" + urllib.parse.urlencode(params)
                data = _raw_taxii_get(full_url, headers)

                objects = data.get("objects", [])
                total_objects += len(objects)

                for obj in objects:
                    if obj.get("type") == "indicator":
                        total_indicators += 1
                        ips = _extract_ipv4_from_pattern(obj.get("pattern", ""))
                        all_ips.extend(ips)

                # Pagination
                if data.get("more") and data.get("next"):
                    next_token = data["next"]
                    params["next"] = next_token
                else:
                    break

            result["objects"]    = total_objects
            result["indicators"] = total_indicators

    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        result["error"] = f"Connection error: {e.reason}"
    except Exception as e:
        result["error"] = f"Error: {e}"

    result["ips"] = sorted(set(all_ips))

    if verbose and not result["error"]:
        print(f"    Objects: {result['objects']} | "
              f"Indicators: {result['indicators']} | "
              f"IPs extracted: {len(result['ips'])}")

    return result


def _fetch_with_stdlib(server_cfg, collection_id, added_after, limit,
                       all_ips, result):
    """Pure stdlib TAXII fetch — used when taxii2client.common auth classes unavailable."""
    url     = server_cfg.get("url", "").rstrip("/")
    headers = _build_headers(server_cfg)
    params  = {
        "added_after": added_after,
        "limit":       str(limit),
    }

    objects_url  = f"{url}/{collection_id}/objects/"
    total_objects    = 0
    total_indicators = 0

    while True:
        full_url = objects_url + "?" + urllib.parse.urlencode(params)
        data = _raw_taxii_get(full_url, headers)

        objects = data.get("objects", [])
        total_objects += len(objects)

        for obj in objects:
            if obj.get("type") == "indicator":
                total_indicators += 1
                ips = _extract_ipv4_from_pattern(obj.get("pattern", ""))
                all_ips.extend(ips)

        if data.get("more") and data.get("next"):
            params["next"] = data["next"]
        else:
            break

    result["objects"]    = total_objects
    result["indicators"] = total_indicators


def _fetch_with_client(server_cfg, collection_id, added_after, limit,
                       all_ips, result):
    """taxii2-client backed fetch — cleaner auth and pagination handling."""
    url      = server_cfg.get("url", "").rstrip("/")
    username = server_cfg.get("username", "")
    password = server_cfg.get("password", "")
    api_key  = server_cfg.get("api_key", "")

    # Build auth object only if the classes are available
    auth = None
    if api_key and TokenAuth is not None:
        auth = TokenAuth(key=api_key)
    elif api_key and TokenAuth is None:
        # taxii2client.common not available — fall back to stdlib fetch
        _fetch_with_stdlib(server_cfg, collection_id, added_after, limit,
                           all_ips, result)
        return
    elif username and BasicAuth is not None:
        auth = BasicAuth(username=username, password=password)
    elif username and BasicAuth is None:
        _fetch_with_stdlib(server_cfg, collection_id, added_after, limit,
                           all_ips, result)
        return

    server = Server(url, auth=auth, verify=True)

    # Find matching collection
    target_collection = None
    for api_root in server.api_roots:
        for col in api_root.collections:
            if col.id == collection_id or col.title == collection_id:
                target_collection = col
                break
        if target_collection:
            break

    if not target_collection:
        col_url = f"{url}/{collection_id}/"
        target_collection = Collection(col_url, auth=auth, verify=True)

    total_objects    = 0
    total_indicators = 0

    for bundle in target_collection.get_objects(
        added_after=added_after,
        per_request=limit
    ):
        objects = bundle.get("objects", [])
        total_objects += len(objects)
        for obj in objects:
            if obj.get("type") == "indicator":
                total_indicators += 1
                ips = _extract_ipv4_from_pattern(obj.get("pattern", ""))
                all_ips.extend(ips)

    result["objects"]    = total_objects
    result["indicators"] = total_indicators


# ── Multi-server fetch ────────────────────────────────────────────────────────

def fetch_all(config: Dict[str, Any],
              added_after: Optional[str] = None,
              verbose: bool = True) -> Dict[str, Any]:
    """
    Fetch IPs from all enabled TAXII servers in config.

    Args:
        config      : Full config dict (from config.json)
        added_after : Optional ISO timestamp override for all servers
        verbose     : Print progress

    Returns:
        {
            "servers":    [list of per-server result dicts],
            "all_ips":    [deduplicated IPs across all servers],
            "total_ips":  count,
        }
    """
    servers = config.get("taxii_servers", [])

    if not servers:
        if verbose:
            print("[!] No TAXII servers configured. Add entries to taxii_servers in config.json.")
        return {"servers": [], "all_ips": [], "total_ips": 0}

    results  = []
    all_ips  = []

    for srv_cfg in servers:
        r = fetch_collection(srv_cfg, added_after=added_after, verbose=verbose)
        results.append(r)
        if not r["error"]:
            all_ips.extend(r["ips"])

    deduped = sorted(set(all_ips))

    return {
        "servers":   results,
        "all_ips":   deduped,
        "total_ips": len(deduped),
    }


# ── Batch file writer ─────────────────────────────────────────────────────────

def write_batch_file(ips: List[str], path: str,
                     source_label: str = "TAXII") -> bool:
    """
    Write extracted IPs to a batch file for ThreatCheck enrichment.

    Args:
        ips          : List of IP strings
        path         : Output file path
        source_label : Label written into the file header comment

    Returns:
        True on success, False on error
    """
    try:
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# ThreatCheck TAXII Batch — {source_label}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# {len(ips)} IP(s) extracted from TAXII indicators\n\n")
            for ip in ips:
                f.write(ip + "\n")
        return True
    except IOError as e:
        print(f"[!] Error writing batch file: {e}")
        return False


# ── Config helpers ─────────────────────────────────────────────────────────────

def get_example_server_config() -> Dict:
    """Returns an example server config dict for documentation/setup."""
    return {
        "name":             "My TAXII Server",
        "url":              "https://example.com/taxii2/api-root/",
        "collection_id":    "my-collection-id",
        "username":         "",
        "password":         "",
        "api_key":          "",
        "api_key_header":   "Authorization",
        "enabled":          True,
        "added_after":      None,
    }


def check_dependency() -> bool:
    """Returns True if taxii2-client is installed, False otherwise."""
    return _TAXII_CLIENT_AVAILABLE


# ── Display ───────────────────────────────────────────────────────────────────

def display_results(fetch_result: Dict[str, Any]) -> None:
    """Print TAXII fetch summary to terminal in ThreatCheck style."""
    print(f"\n{'='*54}")
    print(f"  TAXII FEED RESULTS")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*54}\n")

    for srv in fetch_result.get("servers", []):
        name  = srv.get("name", "?")
        error = srv.get("error")
        ips   = srv.get("ips", [])

        if error:
            print(f"  [!] {name}: {error}")
        else:
            print(f"  [{name}]")
            print(f"      Objects fetched : {srv.get('objects', 0)}")
            print(f"      Indicators found: {srv.get('indicators', 0)}")
            print(f"      IPs extracted   : {len(ips)}")
            if ips:
                for ip in ips[:10]:
                    print(f"        {ip}")
                if len(ips) > 10:
                    print(f"        ... and {len(ips) - 10} more")
        print()

    total = fetch_result.get("total_ips", 0)
    print(f"{'='*54}")
    print(f"  Total unique IPs: {total}")
    print(f"{'='*54}\n")
