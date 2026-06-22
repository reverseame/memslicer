"""Minimal PE export-table parser for resolving call targets to API names.

Reads the export directory straight from captured module memory (the PE image
pages of a slice) and returns ``{absolute_address: export_name}``. Only the
fields needed for by-name export resolution are parsed; anything missing or
unmapped yields an empty / partial result rather than an error.
"""
from __future__ import annotations


def _u16(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _u32(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _cstr(mem_read, addr: int, limit: int = 256) -> str:
    try:
        raw = mem_read(addr, limit)
    except Exception:  # noqa: BLE001
        return ""
    nul = raw.find(b"\x00")
    raw = raw if nul < 0 else raw[:nul]
    return raw.decode("ascii", "replace")


def parse_pe_exports(mem_read, base: int) -> dict[int, str]:
    """Return ``{addr: name}`` for the exports of the PE image at *base*.

    ``mem_read(addr, size) -> bytes`` reads from the (mapped) image memory.
    """
    try:
        dos = mem_read(base, 0x40)
        if dos[:2] != b"MZ":
            return {}
        e_lfanew = _u32(dos[0x3C:0x40])
        if mem_read(base + e_lfanew, 4) != b"PE\x00\x00":
            return {}
        opt_off = base + e_lfanew + 24      # past PE sig (4) + COFF header (20)
        magic = _u16(mem_read(opt_off, 2))
        if magic == 0x20B:        # PE32+
            dd_off = opt_off + 112
        elif magic == 0x10B:      # PE32
            dd_off = opt_off + 96
        else:
            return {}
        dd0 = mem_read(dd_off, 8)
        exp_rva, _exp_size = _u32(dd0[:4]), _u32(dd0[4:8])
        if not exp_rva:
            return {}
        ed = mem_read(base + exp_rva, 40)
        n_names = _u32(ed[0x18:0x1C])
        aof = _u32(ed[0x1C:0x20])   # AddressOfFunctions
        aon = _u32(ed[0x20:0x24])   # AddressOfNames
        aono = _u32(ed[0x24:0x28])  # AddressOfNameOrdinals
        out: dict[int, str] = {}
        for i in range(n_names):
            name_rva = _u32(mem_read(base + aon + 4 * i, 4))
            name = _cstr(mem_read, base + name_rva)
            if not name:
                continue
            ordinal = _u16(mem_read(base + aono + 2 * i, 2))
            func_rva = _u32(mem_read(base + aof + 4 * ordinal, 4))
            out[base + func_rva] = name
        return out
    except Exception:  # noqa: BLE001 - tolerate truncated / unmapped images
        return {}
