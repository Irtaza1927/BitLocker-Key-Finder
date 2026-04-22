# BitLocker Key Finder — v1.1

**Semester 6 Project — Digital Forensics**
**FAST-NUCES Islamabad**

| Member | Roll No |
|---|---|
| Irtaza Zahid   | 23i-2096 |
| Ammar Shahid   | 23I-2125 |
| Usman Khan     | 23I-2069 |
| Shaheer Shaban | 23I-2040 |

---

## 1. Scope

Two-mode forensic utility for BitLocker recovery-password recovery:

| Mode | Status | Theme |
|---|---|---|
| **Option 1 — Live RAM Extraction**     | Phase 2 stub  | Amber terminal aesthetic (isolated `RAM_T`) |
| **Option 2 — Partition / Folder Scan** | **Complete**  | Navy/blue professional aesthetic (isolated `T`) |

The two modes use **fully isolated theme dictionaries** (`T` vs `RAM_T`) and distinct fonts (Segoe UI vs Consolas) so the operator is never uncertain which subsystem is active.

---

## 2. Folder Structure

```
DFProject/
├── main.py
├── requirements.txt
├── README.md
├── modules/
│   ├── __init__.py
│   ├── partition_scan.py      ← core engine (Part B)
│   └── live_ram.py            ← Phase 2 stub (Part A)
├── ui/
│   ├── __init__.py
│   └── interface.py           ← GUI (splash, menu, scan, RAM)
└── tests/
    └── sample_keys.txt        ← verified test data
```

---

## 3. Fixes in v1.1 (Part B)

| # | Defect | Resolution |
|---|---|---|
| F1 | Size filter set via `_ACTIVE_MIN_BYTES / _ACTIVE_MAX_BYTES` was never read by parsers — GUI input ignored. | Filter now enforced in `scan_partition()` via `_size_allowed()` before parser dispatch. |
| F2 | Extension filter `_ACTIVE_EXTS` set by GUI was never applied — all mapped extensions scanned regardless. | `scan_partition()` now skips files whose extension is not in the active set. |
| F3 | Module-level `now = datetime.datetime.now()` froze the timestamp at import; consecutive reports collided. | Timestamp recomputed inside `save_report()` per call. |
| F4 | `parse_bek()` contained a binary-GUID regex (`[\x00-\xff]{16}`) that matched any 16 bytes — dead code. | Removed; BEK identifier extracted via text-decode + `ID_PATTERN`. |
| F5 | Multiple keys in a single file all received `ids[0]` — wrong attribution. | Closest-offset pairing: each key matched to the `ID_PATTERN` whose regex start is nearest. |
| F6 | **No structural validation** — any 48-digit dashed string was reported as a BitLocker key. | **Mod-11 validator added** (Microsoft BitLocker invariant: `block % 11 == 0` and `block // 11 ≤ 0xFFFF` for each of 8 blocks). Pattern-only matches are still reported but labelled for forensic traceability — evidence is annotated, not discarded. |

---

## 4. Key Validation Semantics

Every result now carries a **Validation** field with one of three values:

| Label | Meaning | Table colour |
|---|---|---|
| `Valid (mod-11)`   | 48-digit key passes both Microsoft invariants — very high confidence this is a genuine BitLocker recovery password. | Green |
| `Pattern-only`     | Matches `\d{6}(-\d{6}){7}` but fails mod-11 — likely random data, test decoy, or corrupted key. Reported for manual review. | Amber |
| `N/A`              | Record is not a 48-digit key (e.g. `.bek` binary container, file-name-only hit). | Neutral |

Reference: dislocker source `src/accesses/rp/recovery_password.c`; libbde documentation.

---

## 5. Setup

```bash
python --version       # 3.9+
pip install -r requirements.txt
python main.py
```

---

## 6. Verification — Deterministic Test

Point the scanner at `tests/sample_keys.txt`. Expected output:

| # | Validation | Key | ID |
|---|---|---|---|
| 1 | Valid (mod-11) | 258016-...-720885 | A1B2C3D4-... |
| 2 | Valid (mod-11) | 122221-...-399993 | 11111111-... |
| 3 | Pattern-only   | 123456-...-666666 | DEADBEEF-... |
| 4 | Pattern-only   | 258016-...-720886 | 99999999-... |

If the output matches the above row-for-row, all six fixes (F1–F6) are functioning.

To additionally exercise F1 (size filter), drop a >20 MB file into `tests/` and set **Max Size = 10 MB** in the GUI — that file must not appear in results.

---

## 7. Output Files

```
BitLocker_Report_YYYYMMDD_HHMMSS.csv
BitLocker_Report_YYYYMMDD_HHMMSS.pdf
```

CSV columns: `# | Validation | BitLocker Key | Recovery Key ID | Source | File Path`
PDF: team header, scan metadata, keys table with validation-coloured rows, per-key file-content dump.

---

## 8. Troubleshooting

- **Permission errors on `C:\`** — run VS Code / terminal as Administrator.
- **`ModuleNotFoundError`** — re-run `pip install -r requirements.txt`.
- **Scan too slow** — uncheck *Binary Data Carving* and/or lower *Max Size*.
- **GUI won't launch** — verify tkinter: `python -m tkinter` should open a small test window.
