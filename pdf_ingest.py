"""
pdf_ingest.py — PDF text extraction for ThreatCheck IOC pipeline.

Extracts all text from a PDF file and passes it through IOCExtractor.
Supports standard text-layer PDFs. Scanned/image PDFs require OCR
(pytesseract + pdf2image) which is not included by default.

Requires:
    pip install pdfplumber

Usage:
    from pdf_ingest import extract_iocs_from_pdf
    result = extract_iocs_from_pdf("report.pdf")
    # Returns:
    # {
    #   "path":       "report.pdf",
    #   "pages":      12,
    #   "iocs":       { "ipv4": [...], "cves": [...], ... },
    #   "raw_text":   "...",   # full extracted text
    #   "error":      None,
    # }
"""

import os
from typing import Dict, Any

try:
    import pdfplumber
    _PDFPLUMBER_AVAILABLE = True
except ImportError:
    _PDFPLUMBER_AVAILABLE = False

import ioc_extractor as ioc_module


def _check_dependency():
    if not _PDFPLUMBER_AVAILABLE:
        raise ImportError(
            "pdfplumber is required for PDF support.\n"
            "Install it with: pip install pdfplumber"
        )


def extract_text(pdf_path: str) -> Dict[str, Any]:
    """
    Extract all text from a PDF file.

    Args:
        pdf_path: Path to the PDF file

    Returns:
        dict with keys: text (str), pages (int), error (str|None)
    """
    _check_dependency()

    result = {"text": "", "pages": 0, "error": None}

    if not os.path.exists(pdf_path):
        result["error"] = f"File not found: {pdf_path}"
        return result

    try:
        with pdfplumber.open(pdf_path) as pdf:
            result["pages"] = len(pdf.pages)
            parts = []
            for i, page in enumerate(pdf.pages):
                text = page.extract_text()
                if text:
                    parts.append(f"[Page {i + 1}]\n{text}")
            result["text"] = "\n\n".join(parts)

        if not result["text"].strip():
            result["error"] = (
                "No text extracted — PDF may be scanned/image-based. "
                "OCR support (pytesseract) is not currently enabled."
            )

    except Exception as e:
        result["error"] = f"PDF read error: {e}"

    return result


def extract_iocs_from_pdf(pdf_path: str) -> Dict[str, Any]:
    """
    Extract text from a PDF and run IOC extraction on the full content.

    Args:
        pdf_path: Path to the PDF file

    Returns:
        dict with keys: path, pages, iocs, raw_text, error
    """
    result = {
        "path":     pdf_path,
        "pages":    0,
        "iocs":     {},
        "raw_text": "",
        "error":    None,
    }

    text_result = extract_text(pdf_path)
    result["pages"]    = text_result["pages"]
    result["raw_text"] = text_result["text"]
    result["error"]    = text_result["error"]

    if text_result["text"]:
        extraction       = ioc_module.IOCExtractor.extract(text_result["text"])
        result["iocs"]   = extraction          # full two-bucket result
        result["threat_iocs"] = extraction.get("iocs", {})      # flat threat IOCs only

    return result


def display_pdf_iocs(result: Dict[str, Any]) -> None:
    """
    Print extracted IOC results to terminal in ThreatCheck style.
    Shows threat IOCs and reference mentions as separate sections.
    """
    path  = result.get("path", "?")
    pages = result.get("pages", 0)
    raw   = result.get("iocs", {})
    error = result.get("error")

    # Handle both old flat format and new two-bucket format
    if "iocs" in raw and "references" in raw:
        iocs       = raw["iocs"]
        references = raw["references"]
    else:
        iocs       = raw
        references = {}

    print(f"\n{'='*54}")
    print(f"  PDF IOC EXTRACTION")
    print(f"  {os.path.basename(path)}  ({pages} page{'s' if pages != 1 else ''})")
    print(f"{'='*54}\n")

    if error and not iocs:
        print(f"  [!] {error}\n")
        return

    if error:
        print(f"  [!] Warning: {error}")

    if not iocs and not references:
        print("  No IOCs found in document.\n")
        return

    labels = {
        "ipv4":    ("IPv4 Addresses", "🔵"),
        "cves":    ("CVEs",           "🔴"),
        "sha256":  ("SHA256 Hashes",  "🟣"),
        "sha1":    ("SHA1 Hashes",    "🟣"),
        "md5":     ("MD5 Hashes",     "🟣"),
        "domains": ("Domains",        "🟡"),
        "urls":    ("URLs",           "⚪"),
    }

    # ── Threat IOCs ──────────────────────────────────────────────────────────
    if iocs:
        total = sum(len(v) for v in iocs.values())
        print(f"  Found {total} threat IOC(s):\n")
        for key in ("ipv4", "cves", "sha256", "sha1", "md5", "domains", "urls"):
            if key not in iocs:
                continue
            label, icon = labels.get(key, (key, "•"))
            values = iocs[key]
            print(f"  {icon}  {label} ({len(values)})")
            for v in values:
                print(f"       {v}")
            print()

    # ── Reference mentions ───────────────────────────────────────────────────
    ref_domains = references.get("domains", [])
    ref_urls    = references.get("urls", [])
    if ref_domains or ref_urls:
        print(f"  📋  Reference Mentions (not IOCs — vendors/gov/cited sources)")
        for d in ref_domains:
            print(f"       {d}")
        for u in ref_urls[:5]:
            print(f"       {u}")
        print()
