"""CLI: the same parsers without an agent. JSON out."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, browser, evidence, evtx, registry, timeline


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dfir-mcp", description="Forensic artifact parsers for AI agents and analysts.")
    p.add_argument("--version", action="version", version=f"dfir-mcp {__version__}")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("serve", help="run the MCP server over stdio (default)")

    s = sub.add_parser("info", help="hashes and detected type of a file")
    s.add_argument("path")

    s = sub.add_parser("evtx-summary", help="overview of an .evtx log")
    s.add_argument("path")

    s = sub.add_parser("evtx-query", help="filter records of an .evtx log")
    s.add_argument("path")
    s.add_argument("--id", type=int, action="append", dest="event_ids", help="event ID (repeatable)")
    s.add_argument("--start")
    s.add_argument("--end")
    s.add_argument("--contains")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--offset", type=int, default=0)

    s = sub.add_parser("browser", help="browser history from History / places.sqlite")
    s.add_argument("path")
    s.add_argument("--start")
    s.add_argument("--end")
    s.add_argument("--contains")
    s.add_argument("--limit", type=int, default=100)

    s = sub.add_parser("reg-key", help="one key of an offline registry hive")
    s.add_argument("path")
    s.add_argument("key_path")

    s = sub.add_parser("autoruns", help="Run-key autostart entries of NTUSER.DAT or SOFTWARE")
    s.add_argument("path")

    s = sub.add_parser("timeline", help="merged timeline of several artifacts")
    s.add_argument("paths", nargs="+")
    s.add_argument("--start")
    s.add_argument("--end")
    s.add_argument("--csv", help="write the full timeline to this new file")
    s.add_argument("--limit", type=int, default=200)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in (None, "serve"):
        from .server import run

        run()
        return 0
    try:
        result = {
            "info": lambda: evidence.file_info(args.path),
            "evtx-summary": lambda: evtx.summary(args.path),
            "evtx-query": lambda: evtx.query(args.path, args.event_ids, args.start, args.end,
                                             args.contains, args.limit, args.offset),
            "browser": lambda: browser.history(args.path, args.start, args.end, args.contains, args.limit),
            "reg-key": lambda: registry.key(args.path, args.key_path),
            "autoruns": lambda: registry.autoruns(args.path),
            "timeline": lambda: timeline.build(args.paths, args.start, args.end, args.csv, args.limit),
        }[args.command]()
    except evidence.EvidenceError as exc:
        print(f"dfir-mcp: {exc}", file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, indent=2, ensure_ascii=False, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
