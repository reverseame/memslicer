"""Parse an MSL slice into an in-memory image for emulation.

Reuses :func:`memslicer.msl.iterator.iterate_blocks`; extracts Memory Region
(``0x0001``) and Thread Context (``0x0011``) blocks plus the architecture/OS
from the file header. No Unicorn/Capstone dependency lives here.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from memslicer.msl.constants import (
    ArchType, BlockType, OSType, PageState, REG_FLAG_PC, REG_FLAG_SP,
)
from memslicer.msl.iterator import iterate_blocks
from memslicer.utils.padding import pad8

_REGION_HDR = "<QQBBB5sQ"   # BaseAddr, RegionSize, Protection, RegionType, PageSizeLog2, rsv, Timestamp
_TC_HDR = "<QQHBBIH6s"       # ThreadID, StartTime, Flags, State, rsv, RegCount, NameLen, rsv
_THREAD_FLAG_CURRENT = 0x1


@dataclass
class EmuReg:
    """A single captured register."""
    name: str
    value: int
    width: int
    is_pc: bool = False
    is_sp: bool = False


@dataclass
class EmuThread:
    """A captured thread: identifier and register file."""
    tid: int
    is_current: bool
    registers: list[EmuReg] = field(default_factory=list)

    @property
    def pc(self) -> int | None:
        for r in self.registers:
            if r.is_pc:
                return r.value
        return None

    def as_dict(self) -> dict[str, int]:
        return {r.name: r.value for r in self.registers}


@dataclass
class EmuRegion:
    """A captured memory region. ``pages`` maps a page address to its bytes;
    only Captured pages are present (Failed/Unmapped pages are absent)."""
    base: int
    size: int
    protection: int
    page_size: int
    pages: dict[int, bytes] = field(default_factory=dict)


@dataclass
class SliceImage:
    """Everything needed to emulate a slice."""
    arch: ArchType
    os: OSType
    regions: list[EmuRegion] = field(default_factory=list)
    threads: list[EmuThread] = field(default_factory=list)

    @property
    def current_thread(self) -> EmuThread | None:
        for t in self.threads:
            if t.is_current:
                return t
        return self.threads[0] if self.threads else None

    @property
    def entry(self) -> int | None:
        t = self.current_thread
        return t.pc if t else None


def _page_state(psm: bytes, i: int) -> int:
    return (psm[i >> 2] >> (6 - (i & 3) * 2)) & 3


def _parse_region(payload: bytes) -> EmuRegion:
    base, size, prot, _rt, psl, _r, _ts = struct.unpack(_REGION_HDR, payload[:32])
    page_size = 1 << psl
    npages = size >> psl
    psm_len = pad8((npages + 3) // 4)
    psm = payload[32:32 + psm_len]
    data = payload[32 + psm_len:]
    pages: dict[int, bytes] = {}
    captured = 0
    for i in range(npages):
        if _page_state(psm, i) == PageState.CAPTURED:
            off = captured * page_size
            pages[base + i * page_size] = data[off:off + page_size]
            captured += 1
    return EmuRegion(base=base, size=size, protection=prot,
                     page_size=page_size, pages=pages)


def _parse_thread(payload: bytes) -> EmuThread:
    tid, _st, flags, _state, _r, regcount, namelen, _r2 = struct.unpack(
        _TC_HDR, payload[:32]
    )
    off = 32 + pad8(namelen)
    regs: list[EmuReg] = []
    for _ in range(regcount):
        rnamelen, width, rflags, _ = struct.unpack("<BBHI", payload[off:off + 8])
        name = payload[off + 8:off + 8 + rnamelen - 1].decode("utf-8", "replace")
        voff = off + 8 + pad8(rnamelen)
        value = int.from_bytes(payload[voff:voff + width], "little")
        regs.append(EmuReg(
            name=name, value=value, width=width,
            is_pc=bool(rflags & REG_FLAG_PC),
            is_sp=bool(rflags & REG_FLAG_SP),
        ))
        off = voff + pad8(width)
    return EmuThread(tid=tid, is_current=bool(flags & _THREAD_FLAG_CURRENT),
                     registers=regs)


def load_slice(path: str) -> SliceImage:
    """Load *path* (an ``.msl`` file) into a :class:`SliceImage`."""
    with open(path, "rb") as f:
        header = f.read(0x34)
        if header[:8] != b"MEMSLICE":
            raise ValueError(f"{path}: not a Memory Slice file")
        os_code, arch_code = struct.unpack("<HH", header[0x30:0x34])
        try:
            os_type = OSType(os_code)
        except ValueError:
            os_type = OSType.Unknown
        try:
            arch = ArchType(arch_code)
        except ValueError:
            arch = ArchType.Unknown

        image = SliceImage(arch=arch, os=os_type)
        f.seek(0)
        for blk in iterate_blocks(f):
            if blk.block_type == BlockType.MemoryRegion:
                image.regions.append(_parse_region(blk.payload))
            elif blk.block_type == BlockType.ThreadContext:
                image.threads.append(_parse_thread(blk.payload))
    return image
