"""Minimal ELF dynamic-symbol + PLT/GOT parser for API name resolution.

The Linux analogue of PE export resolution, read straight from captured module
memory. Two maps come out:

* **defined symbols** -- ``.dynsym`` entries with a value (the library's own
  exported functions), ``{addr: name}`` for this module.
* **PLT/GOT imports** -- for each ``.rela.plt`` relocation, the imported symbol
  name plus the *bound* target read from its GOT slot (a captured live process
  has an already-resolved GOT), ``{resolved_addr: name}``. So a ``call func@plt``
  whose effective target is the bound address resolves to the right name even
  when the relocation's own module doesn't define it.

64-bit ELF only; 32-bit and malformed/unmapped images yield empty results
rather than raising.
"""
from __future__ import annotations

# Dynamic tags
_DT_NULL = 0
_DT_PLTRELSZ = 2
_DT_STRTAB = 5
_DT_SYMTAB = 6
_DT_SYMENT = 11
_DT_PLTREL = 20
_DT_JMPREL = 23
_DT_RELA = 7

_SYM_SZ = 24          # Elf64_Sym
_DYN_SZ = 16          # Elf64_Dyn


def _u(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _cstr(mem_read, addr: int, limit: int = 256) -> str:
    try:
        raw = mem_read(addr, limit)
    except Exception:  # noqa: BLE001
        return ""
    nul = raw.find(b"\x00")
    raw = raw if nul < 0 else raw[:nul]
    return raw.decode("ascii", "replace")


def parse_elf(mem_read, base: int):
    """Return ``(defined, imports)`` for the ELF image at *base*.

    ``defined`` is ``{addr: name}`` (this module's defined dynamic symbols);
    ``imports`` is ``{resolved_addr: name}`` (PLT/GOT-bound imports).
    """
    try:
        ident = mem_read(base, 16)
        if ident[:4] != b"\x7fELF" or ident[4] != 2:   # 64-bit only
            return {}, {}
        ehdr = mem_read(base, 64)
        e_phoff = _u(ehdr[32:40])
        e_phentsize = _u(ehdr[54:56])
        e_phnum = _u(ehdr[56:58])

        # Program headers: load bias (base - first PT_LOAD vaddr) + PT_DYNAMIC.
        first_load = None
        dyn_vaddr = None
        for i in range(min(e_phnum, 64)):
            ph = mem_read(base + e_phoff + i * e_phentsize, 56)
            p_type = _u(ph[0:4])
            p_vaddr = _u(ph[16:24])
            if p_type == 1 and first_load is None:   # PT_LOAD
                first_load = p_vaddr
            elif p_type == 2:                          # PT_DYNAMIC
                dyn_vaddr = p_vaddr
        if dyn_vaddr is None:
            return {}, {}
        bias = base - (first_load or 0)

        # Dynamic table.
        d = {}
        addr = bias + dyn_vaddr
        for _ in range(4096):
            ent = mem_read(addr, _DYN_SZ)
            tag, val = _u(ent[0:8]), _u(ent[8:16])
            if tag == _DT_NULL:
                break
            d[tag] = val
            addr += _DYN_SZ
        if _DT_SYMTAB not in d or _DT_STRTAB not in d:
            return {}, {}

        symtab = bias + d[_DT_SYMTAB]
        strtab = bias + d[_DT_STRTAB]
        syment = d.get(_DT_SYMENT, _SYM_SZ) or _SYM_SZ
        # Heuristic symbol count: .dynsym usually runs right up to .dynstr.
        nsyms = (d[_DT_STRTAB] - d[_DT_SYMTAB]) // syment
        nsyms = max(0, min(nsyms, 50000))

        def sym(i):
            s = mem_read(symtab + i * syment, _SYM_SZ)
            return (_u(s[0:4]), _u(s[6:8]), _u(s[8:16]))   # st_name, shndx, value

        defined = {}
        for i in range(nsyms):
            st_name, st_shndx, st_value = sym(i)
            if st_value and st_shndx != 0:                 # defined (not UNDEF)
                name = _cstr(mem_read, strtab + st_name)
                if name:
                    defined[bias + st_value] = name

        # PLT/GOT imports via .rela.plt, resolved through the bound GOT.
        imports = {}
        if _DT_JMPREL in d and _DT_PLTRELSZ in d:
            rel = bias + d[_DT_JMPREL]
            entsz = 24 if d.get(_DT_PLTREL) == _DT_RELA else 16
            count = d[_DT_PLTRELSZ] // entsz
            for i in range(min(count, 20000)):
                r = mem_read(rel + i * entsz, entsz)
                r_offset = _u(r[0:8])
                symidx = _u(r[8:16]) >> 32              # ELF64_R_SYM
                st_name, _shndx, _val = sym(symidx)
                name = _cstr(mem_read, strtab + st_name)
                if not name:
                    continue
                resolved = _u(mem_read(bias + r_offset, 8))  # bound GOT slot
                if resolved:
                    imports[resolved] = name
        return defined, imports
    except Exception:  # noqa: BLE001 - tolerate truncated / unmapped images
        return {}, {}
