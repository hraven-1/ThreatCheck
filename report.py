"""
report.py — HTML report generator for ThreatCheck.

Produces a single self-contained .html file with:
  - Summary stats bar (malicious / suspicious / clean counts)
  - Color-coded, sortable results table
  - Verdict badges and tag pills per row
  - Per-IP expandable source detail panel
  - Delta change indicators
  - IOC export button (defanged, malicious-only)
  - Fully offline — no CDN dependencies, all CSS/JS inline
"""

import json
import os
from datetime import datetime


VERDICT_COLORS = {
    "MALICIOUS":  ("#ff4444", "#fff"),
    "SUSPICIOUS": ("#ffaa00", "#000"),
    "CLEAN":      ("#00cc66", "#fff"),
    "UNKNOWN":    ("#888888", "#fff"),
}

VERDICT_EMOJI = {
    "MALICIOUS":  "🔴",
    "SUSPICIOUS": "🟡",
    "CLEAN":      "🟢",
    "UNKNOWN":    "⚪",
}


def _defang(ip):
    """Returns defanged IP string: 1.2.3[.]4"""
    return ip.replace(".", "[.]") if ip else ip


def _badge(text, bg, fg="#fff"):
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 8px;'
        f'border-radius:4px;font-size:0.78em;font-weight:600;'
        f'white-space:nowrap">{text}</span>'
    )


def _tag_pill(tag):
    tag_colors = {
        "MALWARE_C2":  "#c0392b",
        "BOTNET":      "#c0392b",
        "PHISHING":    "#e67e22",
        "BRUTE_FORCE": "#e67e22",
        "SPAM":        "#e67e22",
        "SCANNER":     "#8e44ad",
        "TOR_EXIT":    "#2980b9",
        "VPN":         "#2980b9",
        "PROXY":       "#2980b9",
        "HOSTING":     "#27ae60",
        "CDN":         "#27ae60",
        "ISP":         "#7f8c8d",
    }
    color = tag_colors.get(tag, "#555")
    return (
        f'<span style="background:{color};color:#fff;padding:1px 6px;'
        f'border-radius:3px;font-size:0.72em;margin:1px;display:inline-block">'
        f'{tag}</span>'
    )


def _source_detail_html(enrichment, delta):
    """Builds the expandable source detail panel HTML for one IP."""
    parts = []

    abuse = (enrichment or {}).get("abuseipdb") or {}
    vt    = (enrichment or {}).get("virustotal") or {}
    info  = (enrichment or {}).get("ipinfo") or {}
    gn    = (enrichment or {}).get("greynoise") or {}

    def row(label, value):
        return f'<tr><td style="color:#aaa;padding:2px 8px 2px 0;white-space:nowrap">{label}</td><td>{value}</td></tr>'

    if abuse.get("status") not in ("Skipped", None):
        parts.append('<div style="margin-bottom:10px"><strong style="color:#61dafb">AbuseIPDB</strong><table style="font-size:0.82em;margin-top:4px">')
        parts.append(row("Score",         f'{abuse.get("risk_score","?")}% ({abuse.get("status","?")})'))
        parts.append(row("Reports",       abuse.get("total_reports", "?")))
        parts.append(row("Last Reported", abuse.get("last_reported_at", "?")))
        parts.append(row("ISP",           abuse.get("isp", "?")))
        parts.append(row("Country",       abuse.get("country_code", "?")))
        parts.append(row("Whitelisted",   str(abuse.get("is_whitelisted", "?"))))
        parts.append(row("Usage Type",    abuse.get("usage_type", "?")))
        parts.append('</table></div>')

    if vt.get("status") not in ("Skipped", None):
        total = vt.get("total_engines") or 0
        mal   = vt.get("malicious_count") or 0
        sus   = vt.get("suspicious_count") or 0
        parts.append('<div style="margin-bottom:10px"><strong style="color:#61dafb">VirusTotal</strong><table style="font-size:0.82em;margin-top:4px">')
        parts.append(row("Status",     vt.get("status", "?")))
        parts.append(row("Detections", f'{mal} malicious, {sus} suspicious / {total} engines'))
        parts.append(row("AS Owner",   vt.get("as_owner", "?")))
        parts.append(row("Country",    vt.get("country", "?")))
        parts.append(row("Reputation", str(vt.get("reputation", "?"))))
        parts.append('</table></div>')

    if gn.get("status") not in ("Skipped", None):
        parts.append('<div style="margin-bottom:10px"><strong style="color:#61dafb">GreyNoise</strong><table style="font-size:0.82em;margin-top:4px">')
        parts.append(row("Classification", gn.get("classification", "?")))
        parts.append(row("Noise",          str(gn.get("noise", "?"))))
        parts.append(row("RIOT",           str(gn.get("riot", "?"))))
        parts.append(row("Name",           gn.get("name", "?")))
        parts.append(row("Last Seen",      gn.get("last_seen", "?")))
        if gn.get("link"):
            parts.append(row("Profile", f'<a href="{gn["link"]}" target="_blank" style="color:#61dafb">{gn["link"]}</a>'))
        parts.append('</table></div>')

    if info.get("status") not in (None,):
        parts.append('<div style="margin-bottom:10px"><strong style="color:#61dafb">IPInfo</strong><table style="font-size:0.82em;margin-top:4px">')
        parts.append(row("Hostname",  info.get("hostname", "?")))
        parts.append(row("Location",  f'{info.get("city","?")}, {info.get("region","?")}, {info.get("country","?")}'))
        parts.append(row("Org / ASN", info.get("org", "?")))
        parts.append(row("Timezone",  info.get("timezone", "?")))
        parts.append('</table></div>')

    if delta and delta.get("highlights"):
        parts.append('<div style="margin-bottom:10px"><strong style="color:#f39c12">⚡ Changes Since Last Check</strong>')
        parts.append(f'<div style="font-size:0.78em;color:#aaa;margin-bottom:4px">Last checked: {delta.get("age","?")}</div>')
        parts.append('<ul style="margin:4px 0;padding-left:16px;font-size:0.82em">')
        for h in delta["highlights"]:
            parts.append(f'<li>{h}</li>')
        parts.append('</ul></div>')

    return "".join(parts)


def generate(results, output_path, title="ThreatCheck Report"):
    """
    Generates a self-contained HTML report from a list of result dicts.
    Writes to output_path.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build summary counts
    tally = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0, "UNKNOWN": 0, "SKIPPED": 0}
    for r in results:
        v = (r.get("verdict") or {}).get("verdict")
        if v in tally:
            tally[v] += 1
        elif r.get("ip_type") and r["ip_type"] != "public":
            tally["SKIPPED"] += 1
        else:
            tally["UNKNOWN"] += 1

    total = len(results)

    # Build table rows
    rows_html = []
    malicious_ips = []

    for idx, r in enumerate(results):
        ip       = r.get("input_ip", "")
        ip_type  = r.get("ip_type", "unknown")
        verd     = r.get("verdict") or {}
        verdict  = verd.get("verdict", "UNKNOWN")
        score    = verd.get("score", "N/A")
        conf     = verd.get("confidence", "")
        tags     = verd.get("tags") or []
        summary  = verd.get("summary", "")
        ts       = r.get("timestamp", "")[:19].replace("T", " ")
        delta    = r.get("_delta")
        enrichment = r.get("enrichment_results") or {}

        bg, fg = VERDICT_COLORS.get(verdict, ("#888", "#fff"))
        emoji  = VERDICT_EMOJI.get(verdict, "⚪")

        badge_html = _badge(f"{emoji} {verdict}", bg, fg)
        tags_html  = "".join(_tag_pill(t) for t in tags)
        delta_html = "⚡" if delta and delta.get("highlights") else ""

        if verdict == "MALICIOUS":
            malicious_ips.append(ip)

        abuse = enrichment.get("abuseipdb") or {}
        vt    = enrichment.get("virustotal") or {}
        gn    = enrichment.get("greynoise") or {}

        abuse_score = abuse.get("risk_score", "")
        vt_mal      = vt.get("malicious_count", "")
        gn_class    = gn.get("classification", "")

        detail_html = _source_detail_html(enrichment, delta)
        detail_id   = f"detail_{idx}"

        row_style = ""
        if verdict == "MALICIOUS":
            row_style = 'style="background:rgba(255,68,68,0.08)"'
        elif verdict == "SUSPICIOUS":
            row_style = 'style="background:rgba(255,170,0,0.06)"'

        rows_html.append(f"""
        <tr {row_style} class="ip-row" data-verdict="{verdict}">
          <td style="font-family:monospace;font-size:0.9em">{ip}</td>
          <td>{badge_html}</td>
          <td style="text-align:center">{score}</td>
          <td style="text-align:center;font-size:0.85em">{conf}</td>
          <td style="text-align:center">{abuse_score}</td>
          <td style="text-align:center">{vt_mal}</td>
          <td style="font-size:0.8em;color:#aaa">{gn_class}</td>
          <td>{tags_html}</td>
          <td style="font-size:0.78em;color:#aaa">{ts}</td>
          <td style="text-align:center">
            {delta_html}
            <button onclick="toggleDetail('{detail_id}')"
              style="background:#333;color:#ccc;border:1px solid #555;
                     padding:2px 8px;border-radius:3px;cursor:pointer;font-size:0.78em">
              Details
            </button>
          </td>
        </tr>
        <tr id="{detail_id}" style="display:none">
          <td colspan="10" style="background:#1a1a2e;padding:12px 20px;border-bottom:1px solid #333">
            {detail_html}
            <div style="font-size:0.75em;color:#555;margin-top:8px">{summary}</div>
          </td>
        </tr>
        """)

    rows_str = "\n".join(rows_html)

    # Defanged IOC list for export button
    ioc_list = "\n".join(_defang(ip) for ip in malicious_ips)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0d0d1a;
    color: #e0e0e0;
    padding: 24px;
    font-size: 14px;
  }}
  h1 {{ font-size: 1.4em; color: #61dafb; margin-bottom: 4px; }}
  .meta {{ color: #666; font-size: 0.82em; margin-bottom: 20px; }}
  .stats {{
    display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap;
  }}
  .stat-card {{
    background: #1a1a2e; border: 1px solid #333; border-radius: 8px;
    padding: 12px 20px; min-width: 110px; text-align: center;
  }}
  .stat-card .num {{ font-size: 2em; font-weight: 700; }}
  .stat-card .lbl {{ font-size: 0.75em; color: #aaa; margin-top: 2px; }}
  .controls {{
    display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; align-items: center;
  }}
  .controls input {{
    background: #1a1a2e; border: 1px solid #444; color: #e0e0e0;
    padding: 6px 12px; border-radius: 4px; font-size: 0.85em; width: 200px;
  }}
  .filter-btn {{
    background: #1a1a2e; border: 1px solid #444; color: #aaa;
    padding: 5px 12px; border-radius: 4px; cursor: pointer; font-size: 0.82em;
  }}
  .filter-btn.active {{ border-color: #61dafb; color: #61dafb; }}
  .ioc-btn {{
    background: #c0392b; border: none; color: #fff;
    padding: 5px 14px; border-radius: 4px; cursor: pointer; font-size: 0.82em;
    margin-left: auto;
  }}
  table {{
    width: 100%; border-collapse: collapse; font-size: 0.85em;
  }}
  th {{
    background: #1a1a2e; color: #888; text-align: left;
    padding: 8px 10px; border-bottom: 1px solid #333;
    cursor: pointer; user-select: none; white-space: nowrap;
  }}
  th:hover {{ color: #61dafb; }}
  th .sort-arrow {{ font-size: 0.7em; margin-left: 4px; opacity: 0.5; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid #222; vertical-align: middle; }}
  tr.ip-row:hover td {{ background: rgba(97,218,251,0.04); }}
  #ioc-modal {{
    display:none; position:fixed; top:0; left:0; width:100%; height:100%;
    background:rgba(0,0,0,0.75); z-index:100; align-items:center; justify-content:center;
  }}
  #ioc-modal.open {{ display:flex; }}
  .modal-box {{
    background:#1a1a2e; border:1px solid #444; border-radius:8px;
    padding:24px; max-width:500px; width:90%;
  }}
  .modal-box h3 {{ color:#61dafb; margin-bottom:12px; }}
  .modal-box textarea {{
    width:100%; height:160px; background:#0d0d1a; color:#e0e0e0;
    border:1px solid #444; border-radius:4px; padding:8px;
    font-family:monospace; font-size:0.9em; resize:vertical;
  }}
  .modal-actions {{ display:flex; gap:8px; margin-top:12px; justify-content:flex-end; }}
  .modal-actions button {{
    padding:6px 16px; border-radius:4px; cursor:pointer; font-size:0.85em; border:none;
  }}
  .btn-copy {{ background:#61dafb; color:#000; }}
  .btn-close {{ background:#333; color:#ccc; }}
</style>
</head>
<body>

<h1>🛡 {title}</h1>
<div class="meta">Generated: {now} &nbsp;|&nbsp; {total} IPs checked</div>

<div class="stats">
  <div class="stat-card">
    <div class="num" style="color:#ff4444">{tally['MALICIOUS']}</div>
    <div class="lbl">🔴 Malicious</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#ffaa00">{tally['SUSPICIOUS']}</div>
    <div class="lbl">🟡 Suspicious</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#00cc66">{tally['CLEAN']}</div>
    <div class="lbl">🟢 Clean</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#888">{tally['UNKNOWN']}</div>
    <div class="lbl">⚪ Unknown</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#555">{tally['SKIPPED']}</div>
    <div class="lbl">— Skipped</div>
  </div>
</div>

<div class="controls">
  <input type="text" id="search" placeholder="🔍 Filter IPs or tags..." oninput="applyFilters()">
  <button class="filter-btn active" data-filter="ALL" onclick="setFilter(this)">All</button>
  <button class="filter-btn" data-filter="MALICIOUS" onclick="setFilter(this)">🔴 Malicious</button>
  <button class="filter-btn" data-filter="SUSPICIOUS" onclick="setFilter(this)">🟡 Suspicious</button>
  <button class="filter-btn" data-filter="CLEAN" onclick="setFilter(this)">🟢 Clean</button>
  <button class="ioc-btn" onclick="showIOC()">📋 Export IOCs ({len(malicious_ips)})</button>
</div>

<table id="results-table">
  <thead>
    <tr>
      <th onclick="sortTable(0)">IP <span class="sort-arrow">⇅</span></th>
      <th onclick="sortTable(1)">Verdict <span class="sort-arrow">⇅</span></th>
      <th onclick="sortTable(2)">Score <span class="sort-arrow">⇅</span></th>
      <th onclick="sortTable(3)">Confidence <span class="sort-arrow">⇅</span></th>
      <th onclick="sortTable(4)">AbuseIPDB% <span class="sort-arrow">⇅</span></th>
      <th onclick="sortTable(5)">VT Engines <span class="sort-arrow">⇅</span></th>
      <th onclick="sortTable(6)">GreyNoise <span class="sort-arrow">⇅</span></th>
      <th>Tags</th>
      <th onclick="sortTable(8)">Checked <span class="sort-arrow">⇅</span></th>
      <th></th>
    </tr>
  </thead>
  <tbody id="results-body">
    {rows_str}
  </tbody>
</table>

<!-- IOC Modal -->
<div id="ioc-modal">
  <div class="modal-box">
    <h3>📋 Malicious IP IOCs (Defanged)</h3>
    <p style="font-size:0.8em;color:#888;margin-bottom:10px">
      {len(malicious_ips)} malicious IP(s) — safe for copy/paste into reports or tickets.
    </p>
    <textarea id="ioc-text" readonly>{ioc_list}</textarea>
    <div class="modal-actions">
      <button class="btn-copy" onclick="copyIOC()">Copy All</button>
      <button class="btn-close" onclick="closeIOC()">Close</button>
    </div>
  </div>
</div>

<script>
  let activeFilter = 'ALL';
  let sortDir = {{}};

  function toggleDetail(id) {{
    const el = document.getElementById(id);
    el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
  }}

  function setFilter(btn) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.filter;
    applyFilters();
  }}

  function applyFilters() {{
    const query = document.getElementById('search').value.toLowerCase();
    document.querySelectorAll('tr.ip-row').forEach(row => {{
      const verdict  = row.dataset.verdict;
      const text     = row.innerText.toLowerCase();
      const matchV   = activeFilter === 'ALL' || verdict === activeFilter;
      const matchQ   = !query || text.includes(query);
      const detailId = row.querySelector('button[onclick]')
                          .getAttribute('onclick').match(/'([^']+)'/)[1];
      const detailRow = document.getElementById(detailId);
      row.style.display = (matchV && matchQ) ? '' : 'none';
      if (detailRow && (!matchV || !matchQ)) detailRow.style.display = 'none';
    }});
  }}

  function sortTable(col) {{
    const tbody = document.getElementById('results-body');
    const rows  = Array.from(tbody.querySelectorAll('tr.ip-row'));
    const dir   = sortDir[col] === 1 ? -1 : 1;
    sortDir[col] = dir;

    rows.sort((a, b) => {{
      const aVal = a.cells[col].innerText.trim();
      const bVal = b.cells[col].innerText.trim();
      const aNum = parseFloat(aVal);
      const bNum = parseFloat(bVal);
      if (!isNaN(aNum) && !isNaN(bNum)) return (aNum - bNum) * dir;
      return aVal.localeCompare(bVal) * dir;
    }});

    rows.forEach(row => {{
      tbody.appendChild(row);
      const btn = row.querySelector('button[onclick]');
      if (btn) {{
        const id = btn.getAttribute('onclick').match(/'([^']+)'/)[1];
        const detail = document.getElementById(id);
        if (detail) tbody.appendChild(detail);
      }}
    }});
  }}

  function showIOC() {{
    document.getElementById('ioc-modal').classList.add('open');
  }}
  function closeIOC() {{
    document.getElementById('ioc-modal').classList.remove('open');
  }}
  function copyIOC() {{
    const ta = document.getElementById('ioc-text');
    ta.select();
    document.execCommand('copy');
    const btn = document.querySelector('.btn-copy');
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = 'Copy All', 1500);
  }}

  document.getElementById('ioc-modal').addEventListener('click', function(e) {{
    if (e.target === this) closeIOC();
  }});
</script>

</body>
</html>"""

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[-] HTML report saved to: {output_path}")
    except IOError as e:
        print(f"[!] Error writing report: {e}")
