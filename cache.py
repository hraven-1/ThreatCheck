"""
cache.py — Local SQLite cache for ThreatCheck.

Stores enrichment results per IP keyed by source name.
Cache entries expire after a configurable TTL (default: 6 hours).
This prevents redundant API calls during batch runs and protects
free-tier rate limits across AbuseIPDB, VirusTotal, and IPInfo.
"""

import sqlite3
import json
import os
import time

CACHE_DIR  = "cache"
CACHE_FILE = os.path.join(CACHE_DIR, "threatcheck_cache.db")

# Default time-to-live in seconds (6 hours)
DEFAULT_TTL = 6 * 60 * 60


def _get_conn():
    """Opens (and if needed, initialises) the SQLite cache database."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    conn = sqlite3.connect(CACHE_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            ip          TEXT    NOT NULL,
            source      TEXT    NOT NULL,
            data        TEXT    NOT NULL,
            cached_at   REAL    NOT NULL,
            PRIMARY KEY (ip, source)
        )
    """)
    conn.commit()
    return conn


def get(ip, source, ttl=DEFAULT_TTL):
    """
    Returns cached data dict for (ip, source) if it exists and is fresh.
    Returns None if the entry is missing or has expired.
    """
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT data, cached_at FROM cache WHERE ip=? AND source=?",
            (ip, source)
        ).fetchone()
        conn.close()

        if row is None:
            return None

        data_json, cached_at = row
        age = time.time() - cached_at

        if age > ttl:
            return None  # Expired

        return json.loads(data_json)

    except Exception as e:
        print(f"[cache] Read error for {ip}/{source}: {e}")
        return None


def set(ip, source, data):
    """
    Stores data dict for (ip, source) with the current timestamp.
    Overwrites any existing entry for the same (ip, source) pair.
    """
    try:
        conn = _get_conn()
        conn.execute(
            """
            INSERT OR REPLACE INTO cache (ip, source, data, cached_at)
            VALUES (?, ?, ?, ?)
            """,
            (ip, source, json.dumps(data), time.time())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[cache] Write error for {ip}/{source}: {e}")


def invalidate(ip, source=None):
    """
    Deletes cache entries for an IP.
    If source is given, only that source's entry is removed.
    If source is None, all entries for the IP are removed.
    """
    try:
        conn = _get_conn()
        if source:
            conn.execute("DELETE FROM cache WHERE ip=? AND source=?", (ip, source))
        else:
            conn.execute("DELETE FROM cache WHERE ip=?", (ip,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[cache] Invalidate error: {e}")


def purge_expired(ttl=DEFAULT_TTL):
    """Removes all entries older than ttl seconds. Call periodically to keep DB tidy."""
    try:
        cutoff = time.time() - ttl
        conn = _get_conn()
        conn.execute("DELETE FROM cache WHERE cached_at < ?", (cutoff,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[cache] Purge error: {e}")


def stats():
    """Returns a dict with basic cache statistics."""
    try:
        conn = _get_conn()
        total    = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
        by_src   = conn.execute(
            "SELECT source, COUNT(*) FROM cache GROUP BY source"
        ).fetchall()
        conn.close()
        return {"total_entries": total, "by_source": dict(by_src)}
    except Exception as e:
        return {"error": str(e)}
