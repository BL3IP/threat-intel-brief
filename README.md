# 09 — Threat Intelligence Automation (Daily Brief)

Aggregates IOC feed data into an automated **daily threat brief** — volume by type/source, top
malware families, and the newest indicators — the kind of summary a CTI analyst sends each morning.

## Goal
Automate the repetitive part of threat intel: ingest indicator feeds and produce a consistent,
shareable brief, ready to feed enrichment + detection pipelines.

## What's inside
| Path | What it is |
|------|-----------|
| [`ti_brief.py`](./ti_brief.py) | Feed parser + brief generator (zero dependencies) |
| [`samples/feed.csv`](./samples/feed.csv) | Sample IOC feed (type, value, malware, first_seen, source) |
| [`reports/daily-brief.md`](./reports/daily-brief.md) | The generated brief (proof) |

## Exact Setup Commands
```powershell
cd C:\Users\banlv\cyber\09-threat-intel
& "C:\Users\banlv\AppData\Local\Programs\Python\Python312\python.exe" -m venv .venv
.\.venv\Scripts\python.exe -m pip install pytest
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe ti_brief.py --date 2026-06-28
```

## Proof It Works
**4/4 tests pass.** Generated brief summary:
```
15 IOCs | types {'url': 4, 'domain': 4, 'ip': 4, 'sha256': 2, 'md5': 1}
top [('AgentTesla', 4), ('Qakbot', 3), ('CobaltStrike', 3)]
```
The brief ([`reports/daily-brief.md`](./reports/daily-brief.md)) ranks malware families and lists
the newest indicators with source attribution.

## Screenshots
See [`./screenshots/`](./screenshots). Add: the rendered `daily-brief.md` and the tool summary line.

## My Custom Extensions
- **Reproducible, data-driven** briefs (swap the CSV, regenerate) — not a one-off report.
- Source attribution + malware-family ranking, mirroring real CTI feeds (URLhaus, Feodo, MalwareBazaar, OTX).
- Designed to chain: indicator values → `iocsift` (enrich/refang) → detection pipeline (project 07).

## Resume Bullet Points
- Built a **threat-intelligence automation** tool that aggregates multi-source IOC feeds into a
  ranked daily brief (malware families, indicator types, newest IOCs) with a tested parser.
- Structured output to integrate with IOC enrichment and detection-as-code pipelines.
- Modeled real CTI feed formats (URLhaus / Feodo / MalwareBazaar / OTX) for realistic triage.

## Next-Level Ideas
- Live-fetch free feeds (URLhaus/Feodo CSV) on a schedule; de-dupe against history.
- Add a local-LLM (or Groq) narrative summary of the day's threats.
- Push to MISP/OpenCTI (Docker) and email/Slack the brief automatically.

---
status: ✅ complete & tested
```
✅ PROJECT COMPLETE & FULLY TESTED in its isolated folder. All works. Ready for portfolio.
```
