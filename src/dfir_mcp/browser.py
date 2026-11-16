"""Browser history from Chromium-family 'History' and Firefox 'places.sqlite' databases."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote

from .evidence import (
    EvidenceError, check_allowed, detect_type, evidence_block, in_window, prtime, resolve, webkit_time,
)


def _connect(path: Path) -> sqlite3.Connection:
    # mode=ro + immutable=1: SQLite takes no locks and writes nothing, not even a journal.
    con = sqlite3.connect(f"file:{quote(str(path))}?mode=ro&immutable=1", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _open(path: str) -> tuple[Path, sqlite3.Connection, str]:
    p = resolve(path)
    check_allowed(p)
    if detect_type(p) != "sqlite":
        raise EvidenceError(f"{p.name} is not an SQLite database")
    con = _connect(p)
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.DatabaseError as exc:
        con.close()
        raise EvidenceError(f"{p.name} could not be read as SQLite: {exc}") from exc
    if {"urls", "visits"} <= tables:
        return p, con, "chromium"
    if {"moz_places", "moz_historyvisits"} <= tables:
        return p, con, "firefox"
    con.close()
    raise EvidenceError(
        f"{p.name} is SQLite but not a browser history database "
        "(expected Chromium 'urls'+'visits' or Firefox 'moz_places'+'moz_historyvisits')"
    )


def _visits(con: sqlite3.Connection, family: str) -> Iterator[dict[str, Any]]:
    if family == "chromium":
        sql = ("SELECT v.visit_time AS t, u.url, u.title, u.visit_count FROM visits v "
               "JOIN urls u ON u.id = v.url ORDER BY v.visit_time")
        convert = webkit_time
    else:
        sql = ("SELECT v.visit_date AS t, p.url, p.title, p.visit_count FROM moz_historyvisits v "
               "JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date")
        convert = prtime
    for row in con.execute(sql):
        yield {"time": convert(row["t"]), "url": row["url"], "title": row["title"],
               "visit_count": row["visit_count"]}


def _downloads(con: sqlite3.Connection, family: str) -> list[dict[str, Any]]:
    if family != "chromium":
        return []
    try:
        rows = con.execute(
            "SELECT target_path, tab_url, start_time, total_bytes, danger_type, mime_type FROM downloads "
            "ORDER BY start_time"
        ).fetchall()
    except sqlite3.DatabaseError:
        return []
    return [
        {"time": webkit_time(r["start_time"]), "target_path": r["target_path"], "from_url": r["tab_url"],
         "bytes": r["total_bytes"], "danger_type": r["danger_type"], "mime_type": r["mime_type"]}
        for r in rows
    ]


def history(
    path: str,
    start: str | None = None,
    end: str | None = None,
    contains: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Visits (oldest first) filtered by UTC time window and URL/title text, plus downloads."""
    p, con, family = _open(path)
    needle = contains.lower() if contains else None
    try:
        out, total = [], 0
        for v in _visits(con, family):
            if not in_window(v["time"], start, end):
                continue
            if needle and needle not in f"{v['url']} {v['title'] or ''}".lower():
                continue
            total += 1
            if total > offset and len(out) < limit:
                out.append(v)
        downloads = [
            d for d in _downloads(con, family)
            if in_window(d["time"], start, end)
            and (not needle or needle in f"{d['target_path']} {d['from_url']}".lower())
        ]
    finally:
        con.close()
    limits = [
        "Only history still in the database is shown; cleared or expired entries are not recovered.",
        "Opened immutable: entries still in an unmerged -wal file beside the database are not included.",
        "A visit shows the browser loaded the URL, not who was at the keyboard.",
    ]
    if family == "firefox":
        limits.append("Firefox downloads are not parsed in this version.")
    return {
        "evidence": evidence_block(p, f"sqlite ({family})"),
        "browser_family": family,
        "total_matches": total,
        "returned": len(out),
        "offset": offset,
        "visits": out,
        "downloads": downloads[:limit],
        "limitations": limits,
    }


def timeline_rows(path: str) -> Iterator[dict[str, Any]]:
    p, con, family = _open(path)
    try:
        for v in _visits(con, family):
            if v["time"]:
                yield {"time": v["time"], "source": p.name, "type": f"browser:{family}:visit",
                       "summary": v["url"], "ref": v["title"] or ""}
        for d in _downloads(con, family):
            if d["time"]:
                yield {"time": d["time"], "source": p.name, "type": f"browser:{family}:download",
                       "summary": d["target_path"] or "", "ref": d["from_url"] or ""}
    finally:
        con.close()
