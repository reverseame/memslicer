"""Regression: investigation-mode system-table bits must reach the on-disk
file-header CapBitmap.

The header is hashed into the BLAKE3 chain when written and cannot be patched
afterwards, so the CapBitmap must be complete *before* the header is created.
A past bug set those bits on the in-memory header object only, after it had
already been serialized, so they never reached disk.
"""
import struct

from memslicer.acquirer.bridge import MemoryRange, ModuleInfo, PlatformInfo
from memslicer.acquirer.engine import AcquisitionEngine
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.constants import ArchType, CapBit, OSType
from memslicer.msl.types import (
    ConnectionEntry, ConnectivityTable, HandleEntry, ProcessEntry,
)


class _Bridge:
    def connect(self): pass
    def disconnect(self): pass
    def get_platform_info(self):
        return PlatformInfo(arch=ArchType.x86_64, os=OSType.Linux, pid=1234, page_size=4096)
    def enumerate_ranges(self):
        return [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]
    def enumerate_modules(self):
        return [ModuleInfo(name="libc.so", path="/usr/lib/libc.so", base=0x400000, size=0x1000)]
    def enumerate_threads(self):
        return []
    def read_memory(self, address, size):
        return b"\xAA" * size if address == 0x10000 else None


class _Collector:
    def __init__(self, empty):
        self._empty = empty
    def collect_process_identity(self, pid, **kwargs):
        return TargetProcessInfo(ppid=500, exe_path="/opt/app/server")
    def collect_system_info(self):
        return TargetSystemInfo(boot_time=1, hostname="h", domain="d", os_detail="os")
    def collect_process_table(self, target_pid):
        return [] if self._empty else [ProcessEntry(pid=1, exe_name="init")]
    def collect_connection_table(self):
        return [] if self._empty else [ConnectionEntry(pid=1, local_port=22)]
    def collect_handle_table(self, pid):
        return [] if self._empty else [HandleEntry(pid=1, fd=3, path="/etc/passwd")]
    def collect_connectivity_table(self):
        return ConnectivityTable()


def _acquire_cap_bitmap(tmp_path, *, empty):
    out = tmp_path / "inv.msl"
    engine = AcquisitionEngine(_Bridge(), investigation=True, collector=_Collector(empty))
    engine.acquire(out)
    raw = out.read_bytes()
    return struct.unpack_from("<Q", raw, 0x10)[0]   # CapBitmap @ offset 0x10


def test_system_table_bits_reach_header(tmp_path):
    cap = _acquire_cap_bitmap(tmp_path, empty=False)
    assert cap & (1 << CapBit.SystemContext)
    assert cap & (1 << CapBit.SystemProcessTable)
    assert cap & (1 << CapBit.SystemNetworkTable)
    assert cap & (1 << CapBit.SystemHandleTable)


def test_empty_system_tables_not_advertised(tmp_path):
    cap = _acquire_cap_bitmap(tmp_path, empty=True)
    assert cap & (1 << CapBit.SystemContext)              # always in investigation
    assert not (cap & (1 << CapBit.SystemProcessTable))
    assert not (cap & (1 << CapBit.SystemNetworkTable))
    assert not (cap & (1 << CapBit.SystemHandleTable))
