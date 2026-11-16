"""Evidence handling shared by every parser.

Two rules hold across the package:
1. Evidence files are opened read-only and never modified.
2. Every result carries an `evidence` block (path, size, SHA-256, parser) so a
   finding can be tied back to the exact bytes it came from.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import __version__

MAGIC = {
    b"ElfFile\x00": "evtx",
    b"regf": "registry_hive",
    b"SQLite format 3\x00": "sqlite",
}


class EvidenceError(Exception):
    """Raised for problems the caller can fix (wrong path, wrong file type)."""


def resolve(path: str) -> Path:
    p = Path(path).expanduser()
    if not p.exists():
        raise EvidenceError(f"no such file: {path}")
    if not p.is_file():
        raise EvidenceError(f"not a regular file: {path}")
    return p.resolve()


@lru_cache(maxsize=256)
def _hash_cached(path: str, size: int, mtime_ns: int) -> dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1024 * 1024):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def hashes(path: Path) -> dict[str, str]:
    st = path.stat()
    return _hash_cached(str(path), st.st_size, st.st_mtime_ns)


def detect_type(path: Path) -> str:
    with open(path, "rb") as fh:
        head = fh.read(16)
    for magic, kind in MAGIC.items():
        if head.startswith(magic):
            return kind
    return "unknown"


def evidence_block(path: Path, parser: str) -> dict[str, Any]:
    st = path.stat()
    return {
        "path": str(path),
        "size": st.st_size,
        "sha256": hashes(path)["sha256"],
        "parser": parser,
        "tool": f"dfir-mcp {__version__}",
        "examined_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def file_info(path: str) -> dict[str, Any]:
    """Hashes, size, timestamps and detected artifact type for one file."""
    p = resolve(path)
    st = p.stat()
    kind = detect_type(p)
    return {
        "path": str(p),
        "size": st.st_size,
        "type": kind,
        **hashes(p),
        "modified_utc": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(timespec="seconds"),
        "limitations": [
            "File-system timestamps describe this copy, not necessarily the original on the suspect system.",
        ],
        "next": {
            "evtx": "evtx_summary, then evtx_query",
            "registry_hive": "registry_autoruns or registry_key",
            "sqlite": "browser_history (if this is a Chrome 'History' or Firefox 'places.sqlite')",
        }.get(kind, "no parser for this type"),
    }


WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def webkit_time(microseconds: int | None) -> str | None:
    """Chrome/WebKit and Windows FILETIME-style: microseconds since 1601-01-01 UTC."""
    if not microseconds:
        return None
    try:
        return (WEBKIT_EPOCH + timedelta(microseconds=int(microseconds))).isoformat()
    except (OverflowError, ValueError):
        return None


def prtime(microseconds: int | None) -> str | None:
    """Firefox PRTime: microseconds since the Unix epoch."""
    if not microseconds:
        return None
    try:
        return (UNIX_EPOCH + timedelta(microseconds=int(microseconds))).isoformat()
    except (OverflowError, ValueError):
        return None


def in_window(ts: str | None, start: str | None, end: str | None) -> bool:
    """True when ISO timestamp `ts` lies in [start, end]. Missing bounds are open."""
    if not (start or end):
        return True
    if ts is None:
        return False
    t = parse_iso(ts)
    return (not start or t >= parse_iso(start)) and (not end or t <= parse_iso(end))


def parse_iso(text: str) -> datetime:
    try:
        dt = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"'{text}' is not an ISO 8601 time") from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def env_root() -> str | None:
    """Optional jail: when DFIR_MCP_ROOT is set, only files under it may be read."""
    return os.environ.get("DFIR_MCP_ROOT")


def check_allowed(path: Path) -> None:
    root = env_root()
    if root and not path.is_relative_to(Path(root).expanduser().resolve()):
        raise EvidenceError(f"{path} is outside DFIR_MCP_ROOT ({root})")
