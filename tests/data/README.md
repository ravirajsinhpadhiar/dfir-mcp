# Test artifacts

Real, publicly distributed sample artifacts, stored xz-compressed and unpacked to a temporary folder by the tests. They are not from any case of mine.

| File | Origin | Licence of origin repo | SHA-256 (uncompressed) |
|---|---|---|---|
| `security.evtx.xz` | [williballenthin/python-evtx](https://github.com/williballenthin/python-evtx), `tests/data/security.evtx` | Apache-2.0 | `5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d` |
| `NTUSER.DAT.xz` | [mkorman90/regipy](https://github.com/mkorman90/regipy), `regipy_tests/data/NTUSER.DAT.xz` | MIT | `6a38fcea924113963e4931725cc4c2f4f10e1240234cb1867d101a1cd92cd439` |

Browser history is tested against small SQLite databases that the tests create with the real Chromium and Firefox table layouts.
