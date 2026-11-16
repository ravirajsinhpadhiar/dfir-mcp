"""MCP server exposing the parsers as tools. All tools are read-only on evidence."""
from __future__ import annotations

from typing import Any, Callable

from . import browser, evidence, evtx, registry, timeline

try:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

server = _Server(
    "dfir-mcp",
    instructions=(
        "Forensic artifact parsers. Evidence is opened read-only. Every result has an "
        "'evidence' block with the file's SHA-256 and a 'limitations' list: quote both when "
        "you report a finding, and do not claim more than the limitations allow. "
        "Start with file_info on an unknown file."
    ),
)


def _safe(fn: Callable[..., dict[str, Any]], *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return fn(*args, **kwargs)
    except evidence.EvidenceError as exc:
        return {"error": str(exc)}


@server.tool()
def file_info(path: str) -> dict[str, Any]:
    """Hash a file (MD5, SHA-1, SHA-256), detect its artifact type and say which tool to use next."""
    def run() -> dict[str, Any]:
        p = evidence.resolve(path)
        evidence.check_allowed(p)
        return evidence.file_info(str(p))
    return _safe(run)


@server.tool()
def evtx_summary(path: str) -> dict[str, Any]:
    """Overview of a Windows .evtx log: record count, time span, channels and a count
    per event ID, with security-relevant IDs (logons, log clearing, new services) called out."""
    return _safe(evtx.summary, path)


@server.tool()
def evtx_query(
    path: str,
    event_ids: list[int] | None = None,
    start: str | None = None,
    end: str | None = None,
    contains: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Records from a .evtx log filtered by event IDs, UTC time window (ISO 8601) and
    case-insensitive text in the event data. Page with limit/offset."""
    return _safe(evtx.query, path, event_ids, start, end, contains, limit, offset)


@server.tool()
def browser_history(
    path: str,
    start: str | None = None,
    end: str | None = None,
    contains: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Visits and downloads from a Chromium-family 'History' file (Chrome, Edge, Brave)
    or Firefox 'places.sqlite', filtered by UTC time window and URL/title text."""
    return _safe(browser.history, path, start, end, contains, limit, offset)


@server.tool()
def registry_key(path: str, key_path: str, max_items: int = 200) -> dict[str, Any]:
    """Values, subkeys and last-written time of one key in an offline registry hive.
    key_path is relative to the hive root."""
    return _safe(registry.key, path, key_path, max_items)


@server.tool()
def registry_autoruns(path: str) -> dict[str, Any]:
    """Autostart entries from the Run, RunOnce and Winlogon keys of an NTUSER.DAT or SOFTWARE hive."""
    return _safe(registry.autoruns, path)


@server.tool()
def build_timeline(
    paths: list[str],
    start: str | None = None,
    end: str | None = None,
    out_csv: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """One UTC-ordered timeline from several .evtx logs and browser history databases.
    Each row carries the SHA-256 of the file it came from. out_csv writes the full timeline
    to a new file (never overwrites)."""
    return _safe(timeline.build, paths, start, end, out_csv, limit)


def run() -> None:
    server.run()
