"""Read-only process access for Windows and Linux/Wine."""

import ctypes
import os
from pathlib import Path
import subprocess
import sys


PROC_ROOT = Path("/proc")
_kernel32 = None


def _windows_api():
    """Load Windows APIs only when needed, preserving pointer-sized handles."""
    global _kernel32
    if _kernel32 is None:
        from ctypes import wintypes as wt

        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        api.OpenProcess.restype = wt.HANDLE
        api.CloseHandle.argtypes = [wt.HANDLE]
        api.CloseHandle.restype = wt.BOOL
        api.ReadProcessMemory.argtypes = [
            wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]
        api.ReadProcessMemory.restype = wt.BOOL
        api.VirtualQueryEx.argtypes = [
            wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ]
        api.VirtualQueryEx.restype = ctypes.c_size_t
        _kernel32 = api
    return _kernel32


class _WindowsProcessMemory:
    @staticmethod
    def get_wxwork_pids() -> list[tuple[int, int]]:
        pids = []
        import csv

        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq WXWork.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, check=True,
        )
        for row in csv.reader(result.stdout.splitlines()):
            if len(row) >= 5 and row[0].lower() == "wxwork.exe":
                memory = "".join(c for c in row[4] if c.isdecimal())
                pids.append((int(row[1]), int(memory or "0")))
        return sorted(pids, key=lambda item: item[1], reverse=True)

    @staticmethod
    def open_process(pid: int):
        handle = _windows_api().OpenProcess(0x0010 | 0x0400, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    @staticmethod
    def close_process(handle):
        _windows_api().CloseHandle(handle)

    @staticmethod
    def read_process_memory(handle, addr: int, size: int):
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        _windows_api().ReadProcessMemory(handle, addr, buf, size, ctypes.byref(read))
        return buf.raw[:read.value] if read.value else None

    @staticmethod
    def enum_memory_regions(handle) -> list[tuple[int, int]]:
        regions = []
        from ctypes import wintypes as wt

        class MBI(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD),
                ("Protect", wt.DWORD),
                ("Type", wt.DWORD),
            ]

        api = _windows_api()
        mbi = MBI()
        addr = 0
        while api.VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base = mbi.BaseAddress or 0
            if mbi.State == 0x1000 and mbi.Protect in {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}:
                if mbi.RegionSize:
                    regions.append((base, mbi.RegionSize))
            next_addr = base + mbi.RegionSize
            if next_addr <= addr:
                break
            addr = next_addr
        return regions


class _LinuxProcessMemory:
    @staticmethod
    def get_wxwork_pids() -> list[tuple[int, int]]:
        pids = []
        for proc in PROC_ROOT.iterdir():
            if not proc.name.isdigit():
                continue
            try:
                # Wine's comm can be UIThread. argv[0] identifies the actual
                # executable, without also matching shell launchers or Web.exe.
                argv0 = (proc / "cmdline").read_bytes().split(b"\0", 1)[0]
                name = argv0.replace(b"\\", b"/").rsplit(b"/", 1)[-1]
                if name.lower() != b"wxwork.exe":
                    continue
                memory = 0
                for line in (proc / "status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        memory = int(line.split()[1])
                        break
                pids.append((int(proc.name), memory))
            except (OSError, ValueError):
                # A process can exit while /proc is being enumerated.
                continue
        return sorted(pids, key=lambda item: item[1], reverse=True)

    @staticmethod
    def open_process(pid: int):
        return (PROC_ROOT / str(pid) / "mem").open("rb", buffering=0)

    @staticmethod
    def close_process(handle):
        handle.close()

    @staticmethod
    def read_process_memory(handle, addr: int, size: int):
        try:
            return os.pread(handle.fileno(), size, addr)
        except (OSError, OverflowError):
            return None

    @staticmethod
    def enum_memory_regions(handle) -> list[tuple[int, int]]:
        regions = []
        with Path(handle.name).with_name("maps").open() as maps:
            for line in maps:
                fields = line.split()
                if len(fields) < 2 or not fields[1].startswith("r"):
                    continue
                start, end = (int(value, 16) for value in fields[0].split("-"))
                if end > start:
                    regions.append((start, end - start))
        return regions


def _get_backend():
    """Select the platform implementation without loading Windows APIs on Linux."""
    match sys.platform:
        case "win32":
            return _WindowsProcessMemory
        case "linux":
            return _LinuxProcessMemory
        case _:
            raise RuntimeError("Memory key extraction supports Windows or Linux with Wine")


def get_wxwork_pids() -> list[tuple[int, int]]:
    """Find WXWork.exe processes, sorted by resident memory in KiB."""
    return _get_backend().get_wxwork_pids()


def open_process(pid: int):
    return _get_backend().open_process(pid)


def close_process(handle):
    _get_backend().close_process(handle)


def read_process_memory(handle, addr: int, size: int):
    return _get_backend().read_process_memory(handle, addr, size)


def enum_memory_regions(handle) -> list[tuple[int, int]]:
    """Enumerate readable mappings without attaching or suspending the process."""
    return _get_backend().enum_memory_regions(handle)
