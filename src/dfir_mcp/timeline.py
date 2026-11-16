"""Merge events from several artifacts into one UTC-ordered timeline."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from . import browser, evtx
from .evidence import EvidenceError, check_allowed, detect_type, hashes, in_window, parse_iso, resolve

FIELDS = ["time", "source", "type", "summary", "ref", "evidence_sha256"]


def build(
    paths: list[str],
    start: str | None = None,
    end: str | None = None,
    out_csv: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Timeline across EVTX logs and browser history databases.

    Returns the first `limit` rows; with `out_csv` the full timeline is written there.
    """
    rows: list[dict[str, Any]] = []
    used, skipped = [], []
    for raw in paths:
        try:
            p = resolve(raw)
            check_allowed(p)
            kind = detect_type(p)
            if kind == "evtx":
                source = evtx.timeline_rows(str(p))
            elif kind == "sqlite":
                source = browser.timeline_rows(str(p))
            else:
                skipped.append({"path": raw, "reason": f"no timeline parser for type '{kind}'"})
                continue
            digest = hashes(p)["sha256"]
            count = 0
            for row in source:
                if in_window(row["time"], start, end):
                    row["evidence_sha256"] = digest
                    rows.append(row)
                    count += 1
            used.append({"path": str(p), "type": kind, "sha256": digest, "events": count})
        except EvidenceError as exc:
            skipped.append({"path": raw, "reason": str(exc)})

    rows.sort(key=lambda r: parse_iso(r["time"]))
    written = None
    if out_csv:
        out = Path(out_csv).expanduser()
        if out.exists():
            raise EvidenceError(f"{out} already exists; refusing to overwrite")
        with open(out, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        written = str(out.resolve())
    return {
        "inputs": used,
        "skipped": skipped,
        "total_events": len(rows),
        "first_utc": rows[0]["time"] if rows else None,
        "last_utc": rows[-1]["time"] if rows else None,
        "returned": min(limit, len(rows)),
        "events": rows[:limit],
        "csv": written,
        "limitations": [
            "Sources keep time with different clocks; ordering across machines assumes those clocks agreed.",
            "Registry hives are not placed on the timeline in this version.",
        ],
    }
