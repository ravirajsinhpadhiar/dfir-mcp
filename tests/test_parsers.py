"""Tests run against real public sample artifacts (see tests/data/README.md) for EVTX and
registry, and against small SQLite databases built here with the real browser schemas."""
import csv
import lzma
import sqlite3
from pathlib import Path

import pytest

from dfir_mcp import browser, evidence, evtx, registry, timeline
from dfir_mcp.cli import main
from dfir_mcp.evidence import EvidenceError

DATA = Path(__file__).parent / "data"
EVTX_SHA256 = "5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d"
NTUSER_SHA256 = "6a38fcea924113963e4931725cc4c2f4f10e1240234cb1867d101a1cd92cd439"


def _unpack(name: str, dest: Path) -> Path:
    out = dest / name
    out.write_bytes(lzma.decompress((DATA / f"{name}.xz").read_bytes()))
    return out


@pytest.fixture(scope="session")
def samples(tmp_path_factory):
    d = tmp_path_factory.mktemp("evidence")
    return {"evtx": _unpack("security.evtx", d), "ntuser": _unpack("NTUSER.DAT", d), "dir": d}


@pytest.fixture(scope="session")
def evtx_summary(samples):
    return evtx.summary(str(samples["evtx"]))


def webkit(us_since_unix: int) -> int:
    return us_since_unix + 11_644_473_600_000_000


@pytest.fixture()
def chrome_db(tmp_path):
    p = tmp_path / "History"
    con = sqlite3.connect(p)
    con.executescript(
        """
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, start_time INTEGER,
                               total_bytes INTEGER, danger_type INTEGER, mime_type TEXT);
        """
    )
    # 2024-01-01T00:00:00Z = 1704067200 s
    t0 = 1_704_067_200_000_000
    con.execute("INSERT INTO urls VALUES (1,'https://example.com/login','Login',2,?)", (webkit(t0 + 60_000_000),))
    con.execute("INSERT INTO urls VALUES (2,'https://files.example.net/tool.zip','',1,?)", (webkit(t0 + 120_000_000),))
    con.executemany("INSERT INTO visits VALUES (?,?,?,0)", [
        (1, 1, webkit(t0)), (2, 1, webkit(t0 + 60_000_000)), (3, 2, webkit(t0 + 120_000_000))])
    con.execute("INSERT INTO downloads VALUES (1,'C:\\Users\\a\\Downloads\\tool.zip',"
                "'https://files.example.net/tool.zip',?,2048,0,'application/zip')", (webkit(t0 + 125_000_000),))
    con.commit()
    con.close()
    return p


@pytest.fixture()
def firefox_db(tmp_path):
    p = tmp_path / "places.sqlite"
    con = sqlite3.connect(p)
    con.executescript(
        """
        CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
        CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
        """
    )
    con.execute("INSERT INTO moz_places VALUES (1,'https://mozilla.example/','Home',1)")
    con.execute("INSERT INTO moz_historyvisits VALUES (1,1,1704067200000000,1)")
    con.commit()
    con.close()
    return p


# ---------------------------------------------------------------- evidence
def test_file_info_hashes_and_detects(samples):
    info = evidence.file_info(str(samples["evtx"]))
    assert info["type"] == "evtx" and info["sha256"] == EVTX_SHA256
    assert evidence.file_info(str(samples["ntuser"]))["type"] == "registry_hive"


def test_missing_file_and_wrong_type(samples, tmp_path):
    with pytest.raises(EvidenceError, match="no such file"):
        evtx.summary(str(tmp_path / "nope.evtx"))
    with pytest.raises(EvidenceError, match="not an EVTX"):
        evtx.summary(str(samples["ntuser"]))
    with pytest.raises(EvidenceError, match="not a registry hive"):
        registry.autoruns(str(samples["evtx"]))


def test_root_jail(samples, tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_MCP_ROOT", str(tmp_path))
    with pytest.raises(EvidenceError, match="outside DFIR_MCP_ROOT"):
        registry.autoruns(str(samples["ntuser"]))


def test_time_conversions():
    assert evidence.webkit_time(webkit(1_704_067_200_000_000)) == "2024-01-01T00:00:00+00:00"
    assert evidence.prtime(1_704_067_200_000_000) == "2024-01-01T00:00:00+00:00"
    assert evidence.webkit_time(0) is None
    assert evidence.in_window("2024-01-01T00:00:00+00:00", "2023-12-31T00:00:00Z", None)
    assert not evidence.in_window(None, "2023-12-31T00:00:00Z", None)


# -------------------------------------------------------------------- evtx
def test_evtx_summary_on_real_log(evtx_summary):
    s = evtx_summary
    assert s["evidence"]["sha256"] == EVTX_SHA256
    assert s["records"] == 2261 and s["unparsed_records"] == 0
    assert s["channels"] == {"Security": 2261}
    assert s["first_event_utc"].startswith("2016-07-08T18:12:51")
    assert s["notable_present"]["4624"]["count"] == 583
    assert s["notable_present"]["4720"]["meaning"] == "User account created"
    assert "1102" not in s["notable_present"]


def test_evtx_query_filters_and_pages(samples):
    r = evtx.query(str(samples["evtx"]), event_ids=[4720, 4732], limit=3, offset=1)
    assert r["total_matches"] == 8 and r["returned"] == 3
    assert all(rec["event_id"] in (4720, 4732) for rec in r["records"])
    assert "TargetUserName" in r["records"][0]["data"]
    times = [rec["time"] for rec in r["records"]]
    assert times == sorted(times)


def test_evtx_query_time_window_and_text(samples):
    r = evtx.query(str(samples["evtx"]), event_ids=[4624], end="2016-07-08T18:12:52Z", contains="system")
    assert r["total_matches"] >= 1
    assert all(rec["time"] <= "2016-07-08T18:12:52" for rec in r["records"])
    with pytest.raises(EvidenceError, match="not an ISO 8601"):
        evtx.query(str(samples["evtx"]), start="yesterday")


# ---------------------------------------------------------------- registry
def test_autoruns_on_real_hive(samples):
    r = registry.autoruns(str(samples["ntuser"]))
    assert r["hive_type"] == "ntuser" and r["evidence"]["sha256"] == NTUSER_SHA256
    names = {e["name"]: e for e in r["entries"]}
    assert names["Sidebar"]["value"].endswith("Sidebar.exe /autoRun")
    assert names["Sidebar"]["key_last_written_utc"].startswith("2012-04-03T21:19:54")
    assert any(k.endswith(r"Policies\Explorer\Run") for k in r["keys_absent"])


def test_registry_key_accepts_loose_paths(samples):
    r = registry.key(str(samples["ntuser"]), "Software/Microsoft/Windows/CurrentVersion")
    assert "Run" in {s["name"] for s in r["subkeys"]}
    with pytest.raises(EvidenceError, match="key not found"):
        registry.key(str(samples["ntuser"]), r"\Software\NoSuchVendor")


# ----------------------------------------------------------------- browser
def test_chromium_history_and_downloads(chrome_db):
    r = browser.history(str(chrome_db))
    assert r["browser_family"] == "chromium" and r["total_matches"] == 3
    assert r["visits"][0] == {"time": "2024-01-01T00:00:00+00:00", "url": "https://example.com/login",
                              "title": "Login", "visit_count": 2}
    assert r["downloads"][0]["target_path"].endswith("tool.zip") and r["downloads"][0]["bytes"] == 2048
    only = browser.history(str(chrome_db), contains="TOOL.ZIP")
    assert only["total_matches"] == 1
    window = browser.history(str(chrome_db), start="2024-01-01T00:00:30Z", end="2024-01-01T00:01:30Z")
    assert window["total_matches"] == 1 and window["downloads"] == []


def test_firefox_history(firefox_db):
    r = browser.history(str(firefox_db))
    assert r["browser_family"] == "firefox" and r["visits"][0]["time"] == "2024-01-01T00:00:00+00:00"
    assert any("Firefox downloads" in note for note in r["limitations"])


def test_evidence_is_not_modified(chrome_db):
    before = (evidence.hashes(chrome_db)["sha256"], chrome_db.stat().st_mtime_ns, sorted(chrome_db.parent.iterdir()))
    browser.history(str(chrome_db))
    evidence._hash_cached.cache_clear()
    after = (evidence.hashes(chrome_db)["sha256"], chrome_db.stat().st_mtime_ns, sorted(chrome_db.parent.iterdir()))
    assert before == after  # same bytes, same mtime, no -journal/-wal left beside it


def test_non_history_sqlite_is_rejected(tmp_path):
    p = tmp_path / "other.db"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE t(x)")
    con.commit()
    con.close()
    with pytest.raises(EvidenceError, match="not a browser history"):
        browser.history(str(p))


# ---------------------------------------------------------------- timeline
def test_timeline_merges_sorts_and_writes_csv(chrome_db, firefox_db, samples, tmp_path):
    out = tmp_path / "timeline.csv"
    r = timeline.build([str(chrome_db), str(firefox_db), str(samples["ntuser"]), "/no/such/file"],
                       out_csv=str(out))
    assert r["total_events"] == 5
    assert [s["reason"].split(" for")[0] for s in r["skipped"]] == ["no timeline parser", "no such file: /no/such/file"]
    times = [e["time"] for e in r["events"]]
    assert times == sorted(times)
    assert {e["type"] for e in r["events"]} == {
        "browser:chromium:visit", "browser:chromium:download", "browser:firefox:visit"}
    rows = list(csv.DictReader(out.open()))
    assert len(rows) == 5 and len(rows[0]["evidence_sha256"]) == 64
    with pytest.raises(EvidenceError, match="refusing to overwrite"):
        timeline.build([str(chrome_db)], out_csv=str(out))


def test_cli_exit_codes(chrome_db, capsys):
    assert main(["browser", str(chrome_db), "--limit", "1"]) == 0
    assert '"browser_family": "chromium"' in capsys.readouterr().out
    assert main(["info", "/no/such/file"]) == 1
