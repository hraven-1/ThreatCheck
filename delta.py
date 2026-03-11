"""
delta.py — Historic delta tracking for ThreatCheck.

Compares a fresh result against the most recent prior result for the same IP
stored in the log file. Surfaces meaningful changes so analysts don't have to
manually diff JSON.

Tracked changes:
  - Verdict escalation / de-escalation  (CLEAN → MALICIOUS, etc.)
  - Composite score change              (± points)
  - New or removed IOC tags
  - AbuseIPDB score change
  - VirusTotal malicious engine count change
  - GreyNoise classification change
"""

import json
import os
from datetime import datetime

LOG_DIR  = "logs"
LOG_FILE = os.path.join(LOG_DIR, "threat_log.json")

# Verdict severity order for escalation detection
VERDICT_ORDER = ["UNKNOWN", "CLEAN", "SUSPICIOUS", "MALICIOUS"]


def _verdict_level(v):
    try:
        return VERDICT_ORDER.index(v)
    except ValueError:
        return -1


def load_log(log_file=LOG_FILE):
    """Loads the full log. Returns empty list on missing/corrupt file."""
    if not os.path.exists(log_file):
        return []
    try:
        with open(log_file, "r") as f:
            data = json.load(f)
            return data if isinstance(data, list) else [data]
    except (json.JSONDecodeError, IOError):
        return []


def get_last_result(ip_str, log_file=LOG_FILE):
    """
    Returns the most recent prior log entry for ip_str,
    or None if this is the first time the IP has been checked.
    """
    logs = load_log(log_file)
    matches = [
        entry for entry in logs
        if entry.get("input_ip") == ip_str and entry.get("is_valid")
    ]
    return matches[-1] if matches else None


def compute_delta(current, previous):
    """
    Compares current result dict against previous result dict.
    Returns a delta dict describing what changed, or None if nothing notable changed.

    Both dicts should be full result dicts as produced by process_ip().
    """
    if previous is None:
        return None  # First time seeing this IP — no delta to compute

    changes = []
    highlights = []

    # --- Verdict change ---
    cur_verdict  = (current.get("verdict")  or {}).get("verdict",  "UNKNOWN")
    prev_verdict = (previous.get("verdict") or {}).get("verdict",  "UNKNOWN")
    cur_level    = _verdict_level(cur_verdict)
    prev_level   = _verdict_level(prev_verdict)

    if cur_verdict != prev_verdict:
        direction = "↑ ESCALATED" if cur_level > prev_level else "↓ DE-ESCALATED"
        changes.append({
            "field":    "verdict",
            "previous": prev_verdict,
            "current":  cur_verdict,
            "direction": direction,
        })
        highlights.append(f"Verdict {direction}: {prev_verdict} → {cur_verdict}")

    # --- Composite score change ---
    cur_score  = (current.get("verdict")  or {}).get("score")
    prev_score = (previous.get("verdict") or {}).get("score")
    if isinstance(cur_score, (int, float)) and isinstance(prev_score, (int, float)):
        diff = round(cur_score - prev_score, 1)
        if abs(diff) >= 5:  # Only surface meaningful score shifts
            arrow = "↑" if diff > 0 else "↓"
            changes.append({
                "field":    "composite_score",
                "previous": prev_score,
                "current":  cur_score,
                "delta":    diff,
            })
            highlights.append(f"Score {arrow} {prev_score} → {cur_score} ({diff:+})")

    # --- Tag changes ---
    cur_tags  = set((current.get("verdict")  or {}).get("tags") or [])
    prev_tags = set((previous.get("verdict") or {}).get("tags") or [])
    new_tags     = cur_tags  - prev_tags
    removed_tags = prev_tags - cur_tags
    if new_tags:
        changes.append({"field": "tags_added",   "tags": sorted(new_tags)})
        highlights.append(f"New tags: {', '.join(sorted(new_tags))}")
    if removed_tags:
        changes.append({"field": "tags_removed", "tags": sorted(removed_tags)})
        highlights.append(f"Removed tags: {', '.join(sorted(removed_tags))}")

    # --- AbuseIPDB score change ---
    cur_abuse  = (current.get("enrichment_results")  or {}).get("abuseipdb")  or {}
    prev_abuse = (previous.get("enrichment_results") or {}).get("abuseipdb") or {}
    cur_ascore  = cur_abuse.get("risk_score")
    prev_ascore = prev_abuse.get("risk_score")
    if isinstance(cur_ascore, (int, float)) and isinstance(prev_ascore, (int, float)):
        diff = cur_ascore - prev_ascore
        if abs(diff) >= 5:
            arrow = "↑" if diff > 0 else "↓"
            changes.append({
                "field":    "abuseipdb_score",
                "previous": prev_ascore,
                "current":  cur_ascore,
                "delta":    diff,
            })
            highlights.append(f"AbuseIPDB {arrow} {prev_ascore}% → {cur_ascore}% ({diff:+})")

    # --- VirusTotal malicious engine count ---
    cur_vt  = (current.get("enrichment_results")  or {}).get("virustotal")  or {}
    prev_vt = (previous.get("enrichment_results") or {}).get("virustotal") or {}
    cur_mal  = cur_vt.get("malicious_count")
    prev_mal = prev_vt.get("malicious_count")
    if isinstance(cur_mal, int) and isinstance(prev_mal, int) and cur_mal != prev_mal:
        diff  = cur_mal - prev_mal
        arrow = "↑" if diff > 0 else "↓"
        changes.append({
            "field":    "vt_malicious_engines",
            "previous": prev_mal,
            "current":  cur_mal,
            "delta":    diff,
        })
        highlights.append(f"VT engines {arrow} {prev_mal} → {cur_mal} ({diff:+})")

    # --- GreyNoise classification change ---
    cur_gn  = (current.get("enrichment_results")  or {}).get("greynoise")  or {}
    prev_gn = (previous.get("enrichment_results") or {}).get("greynoise") or {}
    cur_gnc  = cur_gn.get("classification")
    prev_gnc = prev_gn.get("classification")
    if cur_gnc and prev_gnc and cur_gnc != prev_gnc:
        changes.append({
            "field":    "greynoise_classification",
            "previous": prev_gnc,
            "current":  cur_gnc,
        })
        highlights.append(f"GreyNoise: {prev_gnc} → {cur_gnc}")

    if not changes:
        return None  # Nothing meaningful changed

    prev_ts = previous.get("timestamp", "unknown")
    try:
        prev_dt = datetime.fromisoformat(prev_ts)
        cur_dt  = datetime.fromisoformat(current.get("timestamp", prev_ts))
        age_str = _format_age(cur_dt, prev_dt)
    except Exception:
        age_str = "unknown"

    return {
        "ip":            current.get("input_ip"),
        "previous_check": prev_ts,
        "age":           age_str,
        "change_count":  len(changes),
        "highlights":    highlights,
        "changes":       changes,
    }


def _format_age(now, then):
    """Returns a human-readable age string like '2d 4h ago'."""
    diff = now - then
    total_seconds = int(diff.total_seconds())
    if total_seconds < 0:
        return "future?"
    days    = total_seconds // 86400
    hours   = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600)  // 60
    if days > 0:
        return f"{days}d {hours}h ago"
    if hours > 0:
        return f"{hours}h {minutes}m ago"
    return f"{minutes}m ago"


def print_delta(delta):
    """Prints a formatted delta block to stdout."""
    if delta is None:
        return

    print(f"\n  ── Delta (last checked: {delta['age']}) {'─'*18}")
    for h in delta["highlights"]:
        print(f"    ⚡ {h}")
    print()
