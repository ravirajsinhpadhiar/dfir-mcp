# dfir-mcp

Digital forensics for AI agents. An MCP server (and a plain CLI) that parses Windows event logs, registry hives and browser history **read-only**, and attaches a file hash and a list of limitations to every result.

Example session, using the sample log in `tests/data`:

```text
You:    What happened on this machine around the time the new account appeared?
Agent:  → file_info(security.evtx)        sha256 5f29a03c…
        → evtx_summary(security.evtx)     2,261 records, two 4720 "User account created"
        → evtx_query(event_ids=[4720, 4732])
        → build_timeline([security.evtx, History])
```

## Why

A general-purpose AI agent cannot read an `.evtx` file or an offline registry hive, and when it guesses it gives no way to check the answer. `dfir-mcp` gives the agent real parsers and makes each answer traceable:

- **`evidence` block on every result**: path, size, SHA-256, parser and tool version, examination time.
- **`limitations` on every result**: what the artifact cannot prove (cleared logs, per-key timestamps, unmerged WAL files).
- **Evidence is never written to.** SQLite databases are opened `mode=ro&immutable=1`; hives and logs are opened for reading only. A test checks that bytes, mtime and the surrounding folder are unchanged after parsing.

## Tools

| Tool | Artifact | What it returns |
|---|---|---|
| `file_info` | any file | MD5, SHA-1, SHA-256, detected type, which tool to use next |
| `evtx_summary` | Windows `.evtx` | record count, time span, channels, count per event ID, notable IDs called out |
| `evtx_query` | Windows `.evtx` | records filtered by event ID, UTC window and text, with paging |
| `browser_history` | Chrome/Edge/Brave `History`, Firefox `places.sqlite` | visits and (Chromium) downloads |
| `registry_key` | offline hive | values, subkeys and last-written time of one key |
| `registry_autoruns` | `NTUSER.DAT`, `SOFTWARE` | Run, RunOnce and Winlogon autostart entries |
| `build_timeline` | several of the above | one UTC-ordered timeline, optional CSV, each row tagged with its source hash |

## Install

```bash
pip install git+https://github.com/ravirajsinhpadhiar/dfir-mcp
```

Python 3.10 or newer.

## Connect an agent

Claude Code:

```bash
claude mcp add dfir -- dfir-mcp serve
```

Any MCP client:

```json
{
  "mcpServers": {
    "dfir": {
      "command": "dfir-mcp",
      "args": ["serve"],
      "env": { "DFIR_MCP_ROOT": "/cases/2026-014" }
    }
  }
}
```

`DFIR_MCP_ROOT` is optional but recommended: when set, the server refuses to read anything outside that folder.

## Use without an agent

```bash
dfir-mcp info security.evtx
dfir-mcp evtx-summary security.evtx
dfir-mcp evtx-query security.evtx --id 4624 --id 4625 --start 2016-07-08T18:00:00Z --limit 20
dfir-mcp browser History --contains download
dfir-mcp autoruns NTUSER.DAT
dfir-mcp reg-key NTUSER.DAT 'Software\Microsoft\Windows\CurrentVersion\Run'
dfir-mcp timeline security.evtx History --csv timeline.csv
```

## Working practice

Work on forensic copies, not originals, and keep your own chain-of-custody record. The hashes this tool reports identify the file it read; they do not replace acquisition hashes taken with a write blocker.

## Limits

- **Coverage is deliberately narrow in 0.1.** Not yet parsed: Prefetch, Amcache, ShimCache, SRUM, `$MFT`, LNK files, jump lists, Linux and macOS artifacts.
- Registry transaction logs (`.LOG1`, `.LOG2`) are not replayed.
- Browser databases are read without their `-wal` file, so the most recent activity may be missing.
- Deleted records are not carved.
- EVTX parsing is pure Python: roughly 200 to 300 records per second, so very large logs take minutes.
- Autoruns covers registry Run-style keys only, not services, scheduled tasks or WMI persistence.

## Develop

```bash
git clone https://github.com/ravirajsinhpadhiar/dfir-mcp && cd dfir-mcp
pip install -e ".[dev]"
pytest
```

EVTX and registry tests run against real public sample artifacts; see [`tests/data/README.md`](tests/data/README.md) for their origin.

## Credits

Built on [python-evtx](https://github.com/williballenthin/python-evtx) and [regipy](https://github.com/mkorman90/regipy).

## Licence

MIT.
