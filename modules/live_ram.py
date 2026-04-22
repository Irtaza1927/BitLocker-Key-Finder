"""
live_ram.py
─────────────────────────────────────────────────────────────────────────────
BitLocker Key Finder — Part A: RAM Acquisition & Scanning Engine
FAST-NUCES Islamabad | Digital Forensics | Semester 6

Sub-modes:
  A1 — Live RAM Acquisition (winpmem) + auto-scan
  A2 — Load existing dump file + scan

Scan strategies:
  · Full dump
  · First N MB / KB (triage)
  · Custom byte-offset range

Key types extracted:
  · 48-digit recovery password  (regex + mod-11 validation)
  · VMK / FVEK via Volatility3  (if installed + enabled)

Large-file handling:
  · Reads in 64 MB chunks with 100-byte overlap
  · Never loads entire dump into memory at once
"""

from __future__ import annotations

import os
import re
import sys
import csv
import subprocess
import threading
import datetime
from pathlib import Path

from modules.partition_scan import (
    validate_bitlocker_key,
    KEY_PATTERN,
    ID_PATTERN,
)

# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
WINPMEM_PATH  = str(_PROJECT_ROOT / "assets" / "winpmem.exe")

CHUNK_SIZE   = 64 * 1024 * 1024   # 64 MB chunks
OVERLAP_SIZE = 100                  # byte overlap between chunks

RAM_SIZE_OPTIONS = {
    "Full RAM": None,
    "32 GB":    32 * 1024,
    "16 GB":    16 * 1024,
    "8 GB":      8 * 1024,
    "4 GB":      4 * 1024,
    "2 GB":      2 * 1024,
    "Custom":   "custom",
}

SCAN_DEPTH_OPTIONS = {
    "Full Dump":    None,
    "First 50 MB":  50  * 1024 * 1024,
    "First 512 KB": 512 * 1024,
    "Custom":       "custom",
}

_ASCII_KEY_PAT = re.compile(
    rb"\b\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}\b"
)

FAST_ENCS = ("utf-8", "utf-16-le", "utf-16-be")
ALL_ENCS  = ("utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be", "latin-1")


# ═════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════════
def _make_record(key_str, rid, offset, encoding, source, is_valid, key_type="Recovery Password"):
    return {
        "File Path":       source,
        "Recovery Key ID": rid or "Unknown",
        "BitLocker Key":   key_str,
        "Validation":      "Valid (mod-11)" if is_valid else "Pattern-only",
        "Memory Offset":   f"0x{offset:016X}" if offset is not None else "N/A",
        "Key Type":        key_type,
        "Encoding":        encoding,
        "Source":          "RAM — Recovery Password",
    }


def _dedup(results, key_str, filepath):
    return any(
        r["BitLocker Key"] == key_str and r["File Path"] == filepath
        for r in results
    )


def check_winpmem() -> bool:
    return os.path.isfile(WINPMEM_PATH)


def check_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def check_volatility3() -> bool:
    try:
        import volatility3
        return True
    except ImportError:
        return False


# ═════════════════════════════════════════════════════════════════════════════
#  CORE SCANNER  (chunk-based)
# ═════════════════════════════════════════════════════════════════════════════
def scan_dump_file(
    dump_path:     str,
    results:       list,
    log_fn=None,
    progress_fn=None,
    stop_flag=None,
    max_bytes:     int | None = None,
    encoding_mode: str = "fast",
):
    """
    Scan a RAM dump for BitLocker recovery passwords.
    Reads in 64 MB chunks — safe for multi-GB dumps.
    """
    if not os.path.isfile(dump_path):
        if log_fn:
            log_fn(f"[ERROR] File not found: {dump_path}", "error")
        return

    file_size  = os.path.getsize(dump_path)
    scan_limit = min(file_size, max_bytes) if max_bytes else file_size
    label      = os.path.basename(dump_path)
    encs       = FAST_ENCS if encoding_mode == "fast" else ALL_ENCS

    if log_fn:
        log_fn(f"[RAM SCAN] File: {label}", "info")
        log_fn(f"[RAM SCAN] Total size : {file_size/(1024**2):.1f} MB", "info")
        log_fn(f"[RAM SCAN] Scanning   : {scan_limit/(1024**2):.1f} MB", "info")
        log_fn(f"[RAM SCAN] Encoding   : {encoding_mode}  "
               f"({', '.join(encs)})", "dim")

    bytes_done  = 0
    chunk_start = 0

    try:
        with open(dump_path, "rb") as f:
            carry = b""

            while chunk_start < scan_limit:
                if stop_flag and stop_flag.is_set():
                    if log_fn:
                        log_fn("[RAM SCAN] Stopped by user.", "warning")
                    return

                read_size = min(CHUNK_SIZE, scan_limit - chunk_start)
                chunk_raw = f.read(read_size)
                if not chunk_raw:
                    break

                data = carry + chunk_raw

                # ── ASCII byte-pattern pass ───────────────────────────────
                for m in _ASCII_KEY_PAT.finditer(data):
                    key_str = m.group().decode("ascii")
                    abs_off = chunk_start - len(carry) + m.start()
                    if _dedup(results, key_str, dump_path):
                        continue
                    is_valid = validate_bitlocker_key(key_str)
                    rec = _make_record(key_str, None, abs_off, "ASCII",
                                       dump_path, is_valid)
                    results.append(rec)
                    if log_fn:
                        tag = "success" if is_valid else "warning"
                        log_fn(f"[{'VALID' if is_valid else 'PATTERN'}] "
                               f"{key_str}  |  offset: 0x{abs_off:X}", tag)

                # ── Encoding decode passes ────────────────────────────────
                for enc in encs:
                    try:
                        text = data.decode(enc, errors="replace")
                        id_matches = list(ID_PATTERN.finditer(text))
                        for km in KEY_PATTERN.finditer(text):
                            key_str = km.group()
                            if _dedup(results, key_str, dump_path):
                                continue
                            rid = (
                                min(id_matches,
                                    key=lambda im: abs(im.start() - km.start())
                                    ).group()
                                if id_matches else None
                            )
                            is_valid = validate_bitlocker_key(key_str)
                            rec = _make_record(key_str, rid, None, enc,
                                               dump_path, is_valid)
                            results.append(rec)
                            if log_fn:
                                tag = "success" if is_valid else "warning"
                                log_fn(
                                    f"[{'VALID' if is_valid else 'PATTERN'}] "
                                    f"{key_str}  |  enc: {enc}  "
                                    f"|  ID: {rid or 'Unknown'}", tag
                                )
                    except Exception:
                        continue

                carry       = chunk_raw[-OVERLAP_SIZE:]
                chunk_start += read_size
                bytes_done  += read_size

                if progress_fn:
                    progress_fn(bytes_done, scan_limit)

    except PermissionError:
        if log_fn:
            log_fn(f"[PERMISSION DENIED] {dump_path} — run as Administrator",
                   "error")
    except Exception as e:
        if log_fn:
            log_fn(f"[ERROR] Scan failed: {e}", "error")
        return

    if log_fn:
        valid   = sum(1 for r in results if r.get("Validation") == "Valid (mod-11)")
        pattern = sum(1 for r in results if r.get("Validation") == "Pattern-only")
        log_fn(f"[RAM SCAN COMPLETE] Total: {len(results)}  "
               f"|  Valid: {valid}  |  Pattern-only: {pattern}", "success")


# ═════════════════════════════════════════════════════════════════════════════
#  VOLATILITY3
# ═════════════════════════════════════════════════════════════════════════════
def run_volatility3(dump_path: str, results: list, log_fn=None):
    """
    Run Volatility3 windows.bitlocker plugin to extract VMK/FVEK keys.
    Tries 'vol' command first (standard CLI), falls back gracefully if unavailable.
    """
    if log_fn:
        log_fn("[VOLATILITY3] Launching BitLocker plugin...", "info")
    
    try:
        # First, try the standard 'vol' command (most reliable)
        cmd_vol = ["vol", "-f", dump_path, "windows.bitlocker.BitLocker"]
        try:
            proc = subprocess.run(cmd_vol, capture_output=True, text=True, 
                                 timeout=300)
            if proc.returncode == 0:
                _parse_vol_output(proc.stdout, dump_path, results, log_fn)
                return
        except FileNotFoundError:
            pass  # vol command not in PATH, try Python module

        # Fall back to Python module invocation
        if log_fn:
            log_fn("[VOLATILITY3] Using Python module invocation...", "dim")
        
        cmd_py = [sys.executable, "-m", "volatility3.cli",
                  "-f", dump_path, "windows.bitlocker.BitLocker"]
        proc = subprocess.run(cmd_py, capture_output=True, text=True, timeout=300)
        
        if proc.returncode != 0:
            if log_fn:
                err_msg = proc.stderr.strip()
                # Extract meaningful error lines
                for line in err_msg.splitlines()[-3:]:
                    if line.strip():
                        log_fn(f"[VOL3] {line}", "error")
                log_fn("[VOL3 TIP] Ensure volatility3 is installed: "
                       "pip install --upgrade volatility3", "dim")
            return
        
        _parse_vol_output(proc.stdout, dump_path, results, log_fn)

    except subprocess.TimeoutExpired:
        if log_fn:
            log_fn("[VOLATILITY3] Plugin timed out (>5 min).", "error")
    except Exception as e:
        if log_fn:
            log_fn(f"[VOLATILITY3] Unexpected error: {type(e).__name__}: {e}", "error")


def _parse_vol_output(output_str, dump_path, results, log_fn):
    """Parse volatility3 output and extract keys."""
    found = 0
    for line in output_str.strip().splitlines():
        if not line or line.startswith("#") or "BitLocker" in line:
            continue
        parts = [p.strip() for p in line.split("\t")]
        if len(parts) < 2 or not parts[1]:
            continue
        key_type = parts[0] if parts[0] else "BitLocker Key"
        key_hex  = parts[1]
        results.append({
            "File Path":       dump_path,
            "Recovery Key ID": parts[2] if len(parts) > 2 else "N/A",
            "BitLocker Key":   key_hex,
            "Validation":      "Volatility3 Extract",
            "Memory Offset":   "N/A",
            "Key Type":        key_type,
            "Encoding":        "Binary (AES)",
            "Source":          "RAM — Volatility3",
        })
        found += 1
        if log_fn:
            log_fn(f"[VOL3 KEY] {key_type}: {key_hex[:48]}", "success")
    
    if log_fn:
        log_fn(f"[VOLATILITY3] Done — {found} key(s) extracted.", 
               "success" if found > 0 else "dim")


# ═════════════════════════════════════════════════════════════════════════════
#  LIVE ACQUISITION (winpmem)
# ═════════════════════════════════════════════════════════════════════════════
def acquire_live_ram(output_path, size_mb, log_fn, stop_flag, progress_fn):
    # Ensure output directory exists
    output_abs = os.path.abspath(output_path)  # ← CRITICAL
    output_dir = os.path.dirname(output_abs)
    os.makedirs(output_dir, exist_ok=True)
    
    if not check_winpmem():
        if log_fn:
            log_fn(f"[ERROR] winpmem.exe not found: {WINPMEM_PATH}", "error")
            log_fn("[ERROR] Download: github.com/Velocidex/WinPmem/releases",
                   "error")
        return False

    if not check_admin():
        if log_fn:
            log_fn("[ERROR] Administrator privileges required.", "error")
            log_fn("[ERROR] Restart VS Code as Administrator.", "error")
        return False

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    cmd = [WINPMEM_PATH, "acquire", output_path]

    if log_fn:
        log_fn(f"[ACQUIRE] winpmem acquire command starting", "info")
        log_fn(f"[ACQUIRE] Output: {output_path}", "dim")
        log_fn("[ACQUIRE] This may take several minutes...", "warning")

    try:
        import time
        import psutil  # Get actual system RAM size
        
        # Detect actual physical RAM
        total_system_ram = psutil.virtual_memory().total
        
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )

        # Monitor file size in background for progress bar
        def monitor_and_report():
            while proc.poll() is None:  # While process running
                if stop_flag and stop_flag.is_set():
                    proc.terminate()
                    return
                try:
                    if os.path.isfile(output_path):
                        acquired = os.path.getsize(output_path)
                        # Use actual system RAM as total (fixed, not moving)
                        if progress_fn and acquired > 0:
                            progress_fn(acquired, total_system_ram)
                except Exception:
                    pass
                time.sleep(0.25)  # Update every 250ms

        monitor = threading.Thread(target=monitor_and_report, daemon=True)
        monitor.start()

        # Stream winpmem output
        for line in proc.stdout:
            if stop_flag and stop_flag.is_set():
                proc.terminate()
                if log_fn:
                    log_fn("[ACQUIRE] Stopped by user.", "warning")
                return False
            line = line.strip()
            if line and log_fn:
                log_fn(f"[winpmem] {line}", "dim")
        
        proc.wait()

        if proc.returncode not in (0, 1, 143):  # 143 = SIGTERM (our termination)
            if log_fn:
                log_fn(f"[ACQUIRE] winpmem exit code {proc.returncode}", "warning")
            # Don't fail - dump was still acquired

        # Final progress update
        if os.path.isfile(output_path):
            final_size = os.path.getsize(output_path)
            if progress_fn:
                progress_fn(final_size, final_size)
            size_mb_actual = final_size / (1024**2)
            if log_fn:
                log_fn(f"[ACQUIRE] Done — {size_mb_actual:.1f} MB acquired", "success")
        return True

    except Exception as e:
        if log_fn:
            log_fn(f"[ACQUIRE] Error: {e}", "error")
        return False


# ═════════════════════════════════════════════════════════════════════════════
#  FULL A1 PIPELINE
# ═════════════════════════════════════════════════════════════════════════════
def run_live_pipeline(
    output_path:    str,
    size_mb:        int | None,
    results:        list,
    log_fn=None,
    stop_flag=None,
    progress_fn=None,
    scan_max_bytes: int | None = None,
    encoding_mode:  str = "fast",
    use_volatility: bool = False,
    keep_dump:      bool = False,
):
    """A1 full pipeline: acquire → scan → (optional) volatility3 → (optional) cleanup."""
    ok = acquire_live_ram(output_path, size_mb, log_fn, stop_flag, progress_fn)
    if not ok or (stop_flag and stop_flag.is_set()):
        return

    scan_dump_file(
        dump_path=output_path,
        results=results,
        log_fn=log_fn,
        progress_fn=progress_fn,
        stop_flag=stop_flag,
        max_bytes=scan_max_bytes,
        encoding_mode=encoding_mode,
    )

    if use_volatility and not (stop_flag and stop_flag.is_set()):
        run_volatility3(output_path, results, log_fn)

    if not keep_dump and os.path.isfile(output_path):
        try:
            os.remove(output_path)
            if log_fn:
                log_fn(f"[CLEANUP] Dump deleted: {output_path}", "dim")
        except Exception as e:
            if log_fn:
                log_fn(f"[CLEANUP] Could not delete dump: {e}", "warning")


# ═════════════════════════════════════════════════════════════════════════════
#  CSV REPORT
# ═════════════════════════════════════════════════════════════════════════════
def save_ram_report(results: list, output_folder: str) -> str:
    os.makedirs(output_folder, exist_ok=True)
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_folder, f"RAM_Report_{ts}.csv")
    fields = ["File Path", "Recovery Key ID", "BitLocker Key",
              "Validation", "Key Type", "Memory Offset", "Encoding", "Source"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in results:
            w.writerow({k: row.get(k, "") for k in fields})
    return path