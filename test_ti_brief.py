import os

from ti_brief import DEFAULT_FEED, build_brief, load_feed, summarize, top_malware

ROWS = load_feed(DEFAULT_FEED)


def test_feed_loaded():
    assert len(ROWS) == 15


def test_type_breakdown():
    s = summarize(ROWS)
    assert s["by_type"] == {"url": 4, "domain": 4, "ip": 4, "sha256": 2, "md5": 1}


def test_top_malware():
    top = top_malware(ROWS, 1)
    assert top[0] == ("AgentTesla", 4)


def test_brief_renders():
    brief = build_brief(ROWS, "2026-06-28")
    assert "Daily Threat Brief - 2026-06-28" in brief
    assert "AgentTesla" in brief
    assert "| first_seen |" in brief
