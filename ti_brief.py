"""ti_brief - aggregate IOC feed data into a daily threat brief (zero dependencies).

Reads a CSV feed of indicators (type,value,malware,first_seen,source) and produces a
markdown brief: volume by type/source, top malware families, and the newest indicators.

Usage:
    python ti_brief.py [feed.csv] [--date 2026-06-28] [--out brief.md]
"""
from __future__ import annotations

import argparse
import csv
import os
import urllib.request
from collections import Counter
from typing import Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_FEED = os.path.join(HERE, "samples", "feed.csv")


FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"


def load_feed(path: str) -> List[Dict]:
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    except FileNotFoundError:
        raise SystemExit(f"error: feed file not found: {path}")


def fetch_feed(url: str = FEODO_URL, limit: int = 50) -> List[Dict]:
    """Pull a REAL live IOC feed (abuse.ch Feodo Tracker botnet C2 IP blocklist)."""
    req = urllib.request.Request(url, headers={"User-Agent": "ti-brief/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        text = resp.read().decode("utf-8", errors="ignore")
    data_lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    rows: List[Dict] = []
    for r in csv.DictReader(data_lines):
        ip = (r.get("dst_ip") or "").strip()
        if not ip:
            continue
        rows.append({
            "type": "ip",
            "value": ip,
            "malware": (r.get("malware") or "unknown").strip(),
            "first_seen": (r.get("first_seen_utc") or "")[:10],
            "source": "feodo",
        })
        if len(rows) >= limit:
            break
    return rows


def summarize(rows: List[Dict]) -> Dict:
    return {
        "total": len(rows),
        "by_type": dict(Counter(r["type"] for r in rows)),
        "by_source": dict(Counter(r["source"] for r in rows)),
        "by_malware": dict(Counter(r["malware"] for r in rows)),
    }


def top_malware(rows: List[Dict], n: int = 5):
    return Counter(r["malware"] for r in rows).most_common(n)


def newest(rows: List[Dict], n: int = 10):
    return sorted(rows, key=lambda r: r["first_seen"], reverse=True)[:n]


def build_brief(rows: List[Dict], date_label: str = "latest") -> str:
    s = summarize(rows)
    by_type = ", ".join(f"{k}={v}" for k, v in sorted(s["by_type"].items()))
    lines = [f"# Daily Threat Brief - {date_label}", ""]
    lines.append(f"**{s['total']} indicators** ingested across {len(s['by_source'])} sources.")
    lines.append(f"By type: {by_type}")
    lines.append("")
    lines.append("## Top malware families")
    for fam, c in top_malware(rows):
        lines.append(f"- **{fam}** - {c} indicators")
    lines.append("")
    lines.append("## Newest indicators")
    lines.append("| first_seen | type | value | malware | source |")
    lines.append("|------------|------|-------|---------|--------|")
    for r in newest(rows):
        lines.append(f"| {r['first_seen']} | {r['type']} | {r['value']} | {r['malware']} | {r['source']} |")
    lines.append("")
    lines.append("> Tip: pipe the indicator values through `iocsift` to enrich/refang them, and feed "
                 "the C2 IPs into the detection pipeline (project 07).")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ti_brief", description="Generate a daily threat brief from an IOC feed.")
    ap.add_argument("feed", nargs="?", default=DEFAULT_FEED)
    ap.add_argument("--fetch", action="store_true",
                    help="pull a REAL live feed (abuse.ch Feodo Tracker) instead of the bundled sample")
    ap.add_argument("--date", default="latest")
    ap.add_argument("--out", default=os.path.join(HERE, "reports", "daily-brief.md"))
    args = ap.parse_args(argv)

    rows = fetch_feed() if args.fetch else load_feed(args.feed)
    brief = build_brief(rows, args.date)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(brief)

    s = summarize(rows)
    print(f"Wrote {args.out}")
    print(f"{s['total']} IOCs | types {s['by_type']} | top {top_malware(rows, 3)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
