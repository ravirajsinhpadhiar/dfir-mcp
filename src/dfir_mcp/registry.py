"""Windows registry hive parsing on top of regipy."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

from .evidence import EvidenceError, check_allowed, detect_type, evidence_block, resolve

# Autostart locations, relative to the hive root. Source: MITRE ATT&CK T1547.001
# (Registry Run Keys / Startup Folder) and T1547.004 (Winlogon Helper DLL).
RUN_KEYS = {
    "ntuser": [
        r"\Software\Microsoft\Windows\CurrentVersion\Run",
        r"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"\Software\Microsoft\Windows NT\CurrentVersion\Windows",
    ],
    "software": [
        r"\Microsoft\Windows\CurrentVersion\Run",
        r"\Microsoft\Windows\CurrentVersion\RunOnce",
        r"\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        r"\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ],
}
# In Winlogon / Windows keys only these values launch programs.
LAUNCH_VALUES = {"shell", "userinit", "load", "run", "taskman"}


def _open(path: str) -> tuple[Path, RegistryHive]:
    p = resolve(path)
    check_allowed(p)
    if detect_type(p) != "registry_hive":
        raise EvidenceError(f"{p.name} is not a registry hive (missing 'regf' signature)")
    try:
        return p, RegistryHive(str(p))
    except Exception as exc:
        raise EvidenceError(f"{p.name} could not be parsed as a hive: {exc}") from exc


def _stamp(key: Any) -> str | None:
    try:
        return convert_wintime(key.header.last_modified, as_json=True)
    except Exception:
        return None


def _value(v: Any) -> dict[str, Any]:
    val = v.value
    if isinstance(val, (bytes, bytearray)):
        val = val[:256].hex() + ("..." if len(val) > 256 else "")
    return {"name": v.name, "type": v.value_type, "value": val}


def _normalise(key_path: str) -> str:
    key_path = key_path.strip().replace("/", "\\")
    return key_path if key_path.startswith("\\") else "\\" + key_path


def key(path: str, key_path: str, max_items: int = 200) -> dict[str, Any]:
    """Values and subkey names of one key. `key_path` is relative to the hive root,
    e.g. \\Software\\Microsoft\\Windows\\CurrentVersion\\Run for an NTUSER.DAT hive."""
    p, hive = _open(path)
    kp = _normalise(key_path)
    try:
        k = hive.get_key(kp)
    except RegistryKeyNotFoundException:
        raise EvidenceError(f"key not found in {p.name}: {kp}") from None
    values = [_value(v) for v in k.iter_values()]
    subkeys = [{"name": s.name, "last_written_utc": _stamp(s)} for s in k.iter_subkeys()]
    return {
        "evidence": evidence_block(p, "regipy"),
        "hive_type": hive.hive_type,
        "key": kp,
        "last_written_utc": _stamp(k),
        "values": values[:max_items],
        "subkeys": subkeys[:max_items],
        "truncated": len(values) > max_items or len(subkeys) > max_items,
        "limitations": [
            "Last-written time is per key, not per value: it shows when anything in the key last changed.",
            "Transaction logs (.LOG1/.LOG2) are not replayed, so very recent changes may be missing.",
        ],
    }


def autoruns(path: str) -> dict[str, Any]:
    """Programs set to start automatically, from the Run-style keys of an NTUSER.DAT or SOFTWARE hive."""
    p, hive = _open(path)
    hive_type = (hive.hive_type or "").lower()
    if hive_type not in RUN_KEYS:
        raise EvidenceError(
            f"{p.name} is a '{hive_type or 'unknown'}' hive; autoruns needs NTUSER.DAT or SOFTWARE"
        )
    entries, checked, absent = [], [], []
    for kp in RUN_KEYS[hive_type]:
        try:
            k = hive.get_key(kp)
        except RegistryKeyNotFoundException:
            absent.append(kp)
            continue
        checked.append(kp)
        selective = kp.endswith(("Winlogon", r"CurrentVersion\Windows"))
        for v in k.iter_values():
            if selective and (v.name or "").lower() not in LAUNCH_VALUES:
                continue
            if v.value in (None, ""):
                continue
            entries.append({"key": kp, "key_last_written_utc": _stamp(k), **_value(v)})
    return {
        "evidence": evidence_block(p, "regipy"),
        "hive_type": hive_type,
        "entries": entries,
        "keys_checked": checked,
        "keys_absent": absent,
        "limitations": [
            "Covers registry Run-style keys only. Services, scheduled tasks, startup folders, "
            "WMI subscriptions and other persistence are not examined.",
            "An entry here is a fact about configuration, not a verdict: most autoruns are legitimate.",
            "Transaction logs (.LOG1/.LOG2) are not replayed.",
        ],
    }
