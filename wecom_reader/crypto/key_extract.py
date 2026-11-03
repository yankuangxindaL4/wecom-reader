"""Extract WeCom database keys from Windows or Linux/Wine process memory.

Two scanning strategies: SQL hex key literals, then wxSQLite3 cipher structs.
All process access is read-only and requires memory read permission.
"""

import os
import re
import struct
import sys
import time
from typing import Optional

from .decrypt import is_wxsqlite3_aes128_page1, verify_key
from .process_memory import (
    close_process,
    enum_memory_regions,
    get_wxwork_pids,
    open_process,
    read_process_memory,
)


SCAN_CHUNK_SIZE = 4 * 1024 * 1024
SCAN_OVERLAP = 256  # Covers both a hex literal and a cipher struct at a boundary.


def _auto_detect_db_dir() -> Optional[str]:
    """Find the most recently modified Documents/WXWork/*/Data directory."""
    profile = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    docs = os.path.join(profile, "Documents", "WXWork")
    if not os.path.isdir(docs):
        return None

    candidates = []
    for name in os.listdir(docs):
        data_dir = os.path.join(docs, name, "Data")
        if not os.path.isdir(data_dir):
            continue
        for fname in os.listdir(data_dir):
            if not fname.endswith(".db"):
                continue
            with open(os.path.join(data_dir, fname), "rb") as f:
                page1 = f.read(4096)
            if is_wxsqlite3_aes128_page1(page1):
                candidates.append(data_dir)
                break

    return max(candidates, key=os.path.getmtime) if candidates else None


def _collect_db_files(db_dir: str) -> tuple[list, dict]:
    """Collect wxSQLite3 databases and their first pages without modifying them."""
    db_files = []
    salt_to_dbs = {}
    for root, dirs, files in os.walk(db_dir):
        dirs[:] = [d for d in dirs if d != "-journal"]
        for name in files:
            if not name.endswith(".db"):
                continue
            path = os.path.join(root, name)
            size = os.path.getsize(path)
            if size < 4096:
                continue
            with open(path, "rb") as f:
                page1 = f.read(4096)
            if not is_wxsqlite3_aes128_page1(page1):
                continue
            rel = os.path.relpath(path, db_dir)
            salt_hex = page1[:16].hex()
            db_files.append((rel, path, size, salt_hex, page1))
            salt_to_dbs.setdefault(salt_hex, []).append(rel)
    return db_files, salt_to_dbs


def _memory_chunks(handle, regions, deadline):
    """Bound both memory consumption and time, retaining boundary-spanning keys."""
    for base, size in regions:
        for offset in range(0, size, SCAN_CHUNK_SIZE):
            if time.monotonic() >= deadline:
                return
            data = read_process_memory(
                handle, base + offset, min(SCAN_CHUNK_SIZE + SCAN_OVERLAP, size - offset)
            )
            if data:
                yield base + offset, data


def _read_u32(handle, addr):
    data = read_process_memory(handle, addr, 4)
    return struct.unpack("<I", data)[0] if data and len(data) == 4 else None


def extract_key(
    db_dir: Optional[str] = None,
    timeout: int = 120,
    verbose: bool = False,
) -> dict[str, str]:
    """Read WXWork.exe memory and return a salt -> key map plus "_db_dir".

    "timeout" bounds both scanning strategies together, per process.
    Progress goes to stderr; key values are never printed.
    """
    if timeout <= 0:
        raise ValueError("Memory scan timeout must be greater than zero")
    if db_dir is None:
        db_dir = _auto_detect_db_dir()
    if not db_dir or not os.path.isdir(db_dir):
        raise RuntimeError("Cannot find WeCom data directory. Set --db-dir to the Data directory.")

    db_files, salt_to_dbs = _collect_db_files(db_dir)
    if not db_files:
        raise RuntimeError(f"No encrypted wxSQLite3 databases found in {db_dir}")

    pids = get_wxwork_pids()
    if not pids:
        raise RuntimeError("WXWork.exe is not running or is not visible to this process")

    key_map = {}
    remaining_salts = set(salt_to_dbs)
    pages = {salt: page1 for _, _, _, salt, page1 in db_files}
    tried_keys = set()
    denied_pids = []
    timed_out = False
    hex_re = re.compile(rb"x'([0-9a-fA-F]{32,192})'")
    # The existing wxSQLite3 cipher layout has two 32-bit flags, a 16-byte
    # key at +8, and a 32-bit page-size pointer chain at +0x30.
    cipher_re = re.compile(
        rb"(?=[\x01\x02]\x00\x00\x00(?:[\x01\x02]\x00\x00\x00|\x00[\x10\x20\x40]\x00\x00))"
    )
    page_sizes = {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}

    def try_key(key):
        if key in tried_keys:
            return
        tried_keys.add(key)
        # WeCom commonly shares one key across databases. Verify it against
        # every remaining first page immediately instead of rescanning memory.
        for salt in list(remaining_salts):
            if verify_key(key, pages[salt]):
                key_map[salt] = key.hex()
                remaining_salts.remove(salt)

    for pid, _ in pids:
        try:
            handle = open_process(pid)
        except PermissionError:
            denied_pids.append(pid)
            continue
        except OSError:
            # A Wine subprocess may exit between discovery and opening it.
            continue

        try:
            regions = enum_memory_regions(handle)
            deadline = time.monotonic() + timeout
            if verbose:
                print(f"[*] Scanning WXWork.exe PID {pid} ({len(regions)} readable regions)", file=sys.stderr)

            for _, data in _memory_chunks(handle, regions, deadline):
                for match in hex_re.finditer(data):
                    if time.monotonic() >= deadline:
                        break
                    value = match.group(1)
                    if len(value) in (32, 64, 96):
                        try_key(bytes.fromhex(value[:32].decode("ascii")))
                    if not remaining_salts:
                        break
                if not remaining_salts:
                    break

            if remaining_salts:
                for base, data in _memory_chunks(handle, regions, deadline):
                    for match in cipher_re.finditer(data):
                        if time.monotonic() >= deadline:
                            break
                        off = match.start()
                        if (base + off) % 4 or off + 0x34 > len(data):
                            continue
                        holder = struct.unpack_from("<I", data, off + 0x30)[0]
                        if not holder:
                            continue
                        obj = _read_u32(handle, holder + 4)
                        if not obj or _read_u32(handle, obj + 0x24) not in page_sizes:
                            continue
                        key = data[off + 8:off + 24]
                        if len(set(key)) >= 6:
                            try_key(key)
                        if not remaining_salts:
                            break
                    if not remaining_salts:
                        break
            timed_out |= time.monotonic() >= deadline
        except PermissionError:
            denied_pids.append(pid)
        except ProcessLookupError:
            continue
        finally:
            close_process(handle)

        if not remaining_salts:
            break

    if not key_map:
        if denied_pids:
            raise RuntimeError(
                f"Permission denied reading WXWork.exe memory (PIDs: {', '.join(map(str, denied_pids))}). "
                "On Linux/Wine, ptrace restrictions may require running this command with sudo "
                "using the same virtualenv Python. On Windows, run as administrator. "
                "No process or system settings were changed."
            )
        detail = " (scan timeout reached)" if timed_out else ""
        raise RuntimeError(f"Failed to extract any decryption keys from WXWork.exe{detail}")

    if verbose:
        print(f"[*] Found keys for {len(key_map)} database headers", file=sys.stderr)
    key_map["_db_dir"] = db_dir
    return key_map
