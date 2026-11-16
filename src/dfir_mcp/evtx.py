"""Windows Event Log (.evtx) parsing on top of python-evtx."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

import Evtx.Evtx as _evtx

from .evidence import EvidenceError, check_allowed, detect_type, evidence_block, in_window, resolve

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Event IDs an analyst usually wants to see first. Descriptions follow Microsoft's
# audit-event documentation.
NOTABLE = {
    104: "Event log cleared (System)",
    1102: "Security audit log cleared",
    4104: "PowerShell script block logged",
    4624: "Account logged on",
    4625: "Account failed to log on",
    4634: "Account logged off",
    4648: "Logon attempted with explicit credentials",
    4672: "Special privileges assigned to new logon",
    4688: "Process created",
    4697: "Service installed on the system",
    4698: "Scheduled task created",
    4702: "Scheduled task updated",
    4720: "User account created",
    4722: "User account enabled",
    4724: "Password reset attempted",
    4726: "User account deleted",
    4728: "Member added to security-enabled global group",
    4732: "Member added to security-enabled local group",
    4740: "User account locked out",
    4756: "Member added to security-enabled universal group",
    4768: "Kerberos TGT requested",
    4769: "Kerberos service ticket requested",
    4776: "NTLM credential validation attempted",
    7045: "Service installed (System)",
}


def _open(path: str) -> Path:
    p = resolve(path)
    check_allowed(p)
    if detect_type(p) != "evtx":
        raise EvidenceError(f"{p.name} is not an EVTX file (missing 'ElfFile' signature)")
    return p


def _records(path: Path) -> Iterator[dict[str, Any]]:
    """Yield parsed records. A record that fails to parse is yielded as {'_error': ...}."""
    with _evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except Exception as exc:  # corrupt or carved records must not stop the run
                yield {"_error": f"{type(exc).__name__}: {exc}"}
                continue
            system = root.find(f"{NS}System")
            if system is None:
                yield {"_error": "record has no System element"}
                continue

            def text(tag: str) -> str | None:
                el = system.find(f"{NS}{tag}")
                return el.text if el is not None else None

            created = system.find(f"{NS}TimeCreated")
            provider = system.find(f"{NS}Provider")
            ts = created.get("SystemTime") if created is not None else None
            data: dict[str, str] = {}
            for section in ("EventData", "UserData"):
                node = root.find(f"{NS}{section}")
                if node is None:
                    continue
                for i, el in enumerate(node.iter()):
                    if el is node or not (el.text and el.text.strip()):
                        continue
                    name = el.get("Name") or el.tag.replace(NS, "") + (f"_{i}" if el.get("Name") is None and el.tag == f"{NS}Data" else "")
                    data[name] = el.text.strip()
            try:
                event_id = int(text("EventID") or -1)
            except ValueError:
                event_id = -1
            yield {
                "record_id": int(text("EventRecordID") or 0),
                "time": ts.replace(" ", "T") if ts else None,
                "event_id": event_id,
                "provider": provider.get("Name") if provider is not None else None,
                "channel": text("Channel"),
                "computer": text("Computer"),
                "data": data,
            }


def summary(path: str) -> dict[str, Any]:
    """Record count, time span, channels and a count per event ID."""
    p = _open(path)
    ids: Counter[int] = Counter()
    channels: Counter[str] = Counter()
    computers: Counter[str] = Counter()
    first = last = None
    total = errors = 0
    for rec in _records(p):
        if "_error" in rec:
            errors += 1
            continue
        total += 1
        ids[rec["event_id"]] += 1
        channels[rec["channel"] or "?"] += 1
        computers[rec["computer"] or "?"] += 1
        if rec["time"]:
            first = min(first, rec["time"]) if first else rec["time"]
            last = max(last, rec["time"]) if last else rec["time"]
    return {
        "evidence": evidence_block(p, "python-evtx"),
        "records": total,
        "unparsed_records": errors,
        "first_event_utc": first,
        "last_event_utc": last,
        "channels": dict(channels),
        "computers": dict(computers),
        "event_ids": [
            {"event_id": eid, "count": n, "meaning": NOTABLE.get(eid)} for eid, n in ids.most_common()
        ],
        "notable_present": {
            str(eid): {"count": ids[eid], "meaning": NOTABLE[eid]} for eid in sorted(NOTABLE) if ids.get(eid)
        },
        "limitations": [
            "Counts cover records still present in the file; cleared or overwritten events are gone.",
            "A gap in time does not by itself prove tampering; check 1102/104 and record-id continuity.",
        ],
    }


def query(
    path: str,
    event_ids: list[int] | None = None,
    start: str | None = None,
    end: str | None = None,
    contains: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Records filtered by event id, UTC time window and a case-insensitive text match."""
    p = _open(path)
    wanted = set(event_ids or [])
    needle = contains.lower() if contains else None
    matched: list[dict[str, Any]] = []
    total = 0
    for rec in _records(p):
        if "_error" in rec:
            continue
        if wanted and rec["event_id"] not in wanted:
            continue
        if not in_window(rec["time"], start, end):
            continue
        if needle and needle not in " ".join(
            [str(rec["provider"]), *rec["data"].keys(), *rec["data"].values()]
        ).lower():
            continue
        total += 1
        if total > offset and len(matched) < limit:
            rec["meaning"] = NOTABLE.get(rec["event_id"])
            matched.append(rec)
    return {
        "evidence": evidence_block(p, "python-evtx"),
        "filter": {"event_ids": sorted(wanted), "start": start, "end": end, "contains": contains},
        "total_matches": total,
        "returned": len(matched),
        "offset": offset,
        "records": matched,
        "limitations": ["Times are UTC as stored in the log; the source system's clock may have been wrong."],
    }


def timeline_rows(path: str) -> Iterator[dict[str, Any]]:
    p = _open(path)
    for rec in _records(p):
        if "_error" in rec or not rec["time"]:
            continue
        label = NOTABLE.get(rec["event_id"], rec["provider"] or "event")
        who = rec["data"].get("TargetUserName") or rec["data"].get("SubjectUserName")
        yield {
            "time": rec["time"],
            "source": p.name,
            "type": f"evtx:{rec['event_id']}",
            "summary": f"{label}" + (f" [{who}]" if who else ""),
            "ref": f"record {rec['record_id']}",
        }
