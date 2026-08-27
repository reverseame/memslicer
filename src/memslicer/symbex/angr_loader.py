"""Load an MSL slice into an angr Project + SimState.

angr is imported lazily so importing :mod:`memslicer.symbex` does not hard
require the ``symbex`` extra.
"""
from __future__ import annotations

import io
import logging
from typing import TYPE_CHECKING

from memslicer.msl.constants import ArchType
from memslicer.emu.loader import SliceImage, load_slice

if TYPE_CHECKING:
    import angr

logger = logging.getLogger(__name__)

_ANGR_ARCH = {
    ArchType.x86: "X86",
    ArchType.x86_64: "AMD64",
    ArchType.ARM64: "AARCH64",
    ArchType.ARM32: "ARMEL",
}


class SymbexError(RuntimeError):
    """Raised when a slice cannot be loaded into angr."""


def _region_at(image: SliceImage, addr: int):
    for r in image.regions:
        if r.base <= addr < r.base + r.size:
            return r
    return None


def _contiguous(region) -> bytes:
    """Materialize a region as a contiguous image (failed pages -> zeros).
    Validates page boundaries to prevent buffer overflows and corrupt slices.
    """
    buf = bytearray(region.size)
    for paddr, data in region.pages.items():
        if not (region.base <= paddr < region.base + region.size):
            raise SymbexError(
                f"Page at 0x{paddr:x} is outside region bounds "
                f"(0x{region.base:x} - 0x{region.base + region.size:x})"
            )
        off = paddr - region.base
        if off + len(data) > region.size:
            raise SymbexError(
                f"Page at 0x{paddr:x} with length {len(data)} exceeds region size {region.size}"
            )
        buf[off:off + len(data)] = data
    return bytes(buf)


def load_angr(path: str, image: SliceImage | None = None, thread=None, symbol_map: dict | None = None):
    """Return ``(project, state)`` for the slice at *path*.

    The project is backed by the region holding the captured program counter;
    every captured page is mapped into the state's memory and a thread's
    registers are seeded, so the state sits exactly where the slice was taken —
    ready for ``project.factory.simgr(state)``. *thread* selects which captured
    thread to seed from (its tid or an :class:`EmuThread`); the default is the
    Current thread.
    """
    try:
        import angr
        import claripy
    except ImportError as exc:
        raise SymbexError(
            "symbolic execution requires the 'symbex' extra: "
            "pip install memslicer[symbex]"
        ) from exc

    try:
        image = image or load_slice(path)
    except Exception:
        try:
            project = angr.Project(path, main_opts={"backend": "blob", "arch": "AMD64"}, auto_load_libs=False)
            state = project.factory.entry_state()
            register_exported_symbols(project, symbol_map)
            return project, state
        except Exception as exc:
            raise SymbexError(f"Failed to load '{path}' as MSL slice or binary executable: {exc}") from exc

    if image.arch not in _ANGR_ARCH:
        arch_name = getattr(image.arch, "name", str(image.arch))
        raise SymbexError(f"unsupported architecture for angr: {arch_name}")

    if not image.regions:
        raise SymbexError("slice has no memory regions")

    try:
        sel = image.select_thread(thread)
    except KeyError as exc:
        raise SymbexError(f"Thread selection failed: {exc}") from exc
    except Exception as exc:
        raise SymbexError(f"Thread selection error: {exc}") from exc

    entry = sel.pc if sel is not None and sel.pc is not None else image.entry
    code = _region_at(image, entry) if entry is not None else None
    if code is None:
        code = image.regions[0]
    blob = _contiguous(code)

    angr_arch_name = _ANGR_ARCH.get(image.arch)
    if not angr_arch_name:
        raise SymbexError(f"unsupported architecture for angr: {image.arch}")

    try:
        project = angr.Project(
            io.BytesIO(blob),
            main_opts={"backend": "blob", "arch": angr_arch_name, "base_addr": code.base},
            auto_load_libs=False,
        )
        state = project.factory.blank_state(
            addr=entry if entry is not None else code.base
        )
    except KeyError as exc:
        raise SymbexError(f"angr architecture configuration error: {exc}") from exc
    except Exception as exc:
        raise SymbexError(f"Failed to initialize angr project: {exc}") from exc

    # Map every captured page into the symbolic state's memory.
    for r in image.regions:
        for paddr, data in r.pages.items():
            if not (0 <= paddr <= 0xFFFFFFFFFFFFFFFF):
                raise SymbexError(f"Out-of-bounds page address: 0x{paddr:x}")
            if len(data) != 4096:
                raise SymbexError(f"Invalid page size ({len(data)} bytes) at 0x{paddr:x}")
            try:
                state.memory.store(paddr, data, disable_actions=True, inspect=False)
            except Exception as exc:
                raise SymbexError(f"Failed to store page at 0x{paddr:x}: {exc}") from exc
            if hasattr(state.scratch, "dirty_addrs"):
                state.scratch.dirty_addrs.clear()

    # Seed the captured registers by name.
    if sel is not None:
        for reg in sel.registers:
            try:
                setattr(state.regs, reg.name, reg.value)
            except Exception as exc:
                # A captured register from the real dump silently not applied
                # means the state diverges from what was actually on the
                # machine — worth a warning, not just a swallowed exception.
                logger.warning("[angr_loader] Failed to seed captured register '%s'=0x%x: %s", reg.name, reg.value, exc)
            reg_lower = reg.name.lower()
            # angr exposes the full segment base as plain `gs`/`fs` on both
            # X86 and AMD64 — `gs_base`/`gs_const`/`gs_offset`/`fs_base`/... do
            # not exist as state.regs attributes on either arch, so a capture
            # using one of those names must be normalized onto `gs`/`fs`
            # itself instead of being silently dropped (previously this branch
            # zeroed gs/fs and then tried only the nonexistent names, which
            # discarded the real captured segment base).
            if reg_lower in ("gs_base", "gs", "gs_const", "gs_offset") and hasattr(state.regs, "gs"):
                try:
                    state.regs.gs = claripy.BVV(reg.value, state.regs.gs.length)
                except Exception as exc:
                    logger.warning("[angr_loader] Failed to seed gs=0x%x from captured '%s': %s", reg.value, reg.name, exc)
            elif reg_lower in ("fs_base", "fs", "fs_const", "fs_offset") and hasattr(state.regs, "fs"):
                try:
                    state.regs.fs = claripy.BVV(reg.value, state.regs.fs.length)
                except Exception as exc:
                    logger.warning("[angr_loader] Failed to seed fs=0x%x from captured '%s': %s", reg.value, reg.name, exc)

    register_exported_symbols(project, symbol_map)

    # Stash the captured module list (base/size/path per loaded DLL) so callers
    # that need to resolve a real API address (e.g. anti_analysis's hooking)
    # can walk each module's PE export table directly from captured memory —
    # CLE only ever loads the single region containing the entry point as a
    # real object, so find_symbol()/hook_symbol() cannot see any other DLL's
    # exports on a real multi-module dump.
    state.globals["msl_modules"] = list(getattr(image, "modules", []) or [])

    return project, state


def _read_cstr(state: angr.SimState, addr: int, max_len: int = 256) -> bytes | None:
    """Reads a NUL-terminated ASCII string from concrete memory. Returns None on
    any failure (unmapped page, symbolic content, etc.) instead of raising.
    """
    try:
        raw = state.solver.eval(state.memory.load(addr, max_len), cast_to=bytes)
    except Exception:
        return None
    end = raw.find(b"\x00")
    return raw[:end] if end != -1 else raw


def resolve_pe_export(
    state: angr.SimState,
    modules: list,
    dll_candidates: list[str],
    export_name: str,
) -> int | None:
    """Resolves *export_name* to its real virtual address by walking the PE
    export directory of each module in *modules* whose basename matches one
    of *dll_candidates* (case-insensitive), reading the PE headers and export
    tables directly out of captured memory (``state.memory``). Every matching
    module is tried in turn — a name matching multiple candidates (e.g. both
    "kernel32.dll" and "ntdll.dll" are valid candidates for an API, but only
    one of them actually exports it) must not stop at the first match if that
    module simply doesn't have the requested export.

    Because each module was captured already loaded/rebased, RVAs in its PE
    headers map directly onto ``module.base + rva`` — no raw-file-offset
    translation is needed, unlike parsing a PE straight off disk.

    Returns the resolved address, or None if no candidate module exports it
    or the headers aren't fully present in the captured pages.
    """
    candidates_lower = {c.lower() for c in dll_candidates}
    endness = state.arch.memory_endness

    def read_uint(addr: int, size: int) -> int:
        # state.memory.load() defaults to big-endian interpretation regardless
        # of target arch — MUST pass the arch's real endness (little-endian on
        # x86/AMD64) or every multi-byte integer comes out byte-reversed.
        return state.solver.eval(state.memory.load(addr, size, endness=endness))

    def search_module(base: int, mod_name: str) -> int | None:
        try:
            dos_magic = state.solver.eval(state.memory.load(base, 2), cast_to=bytes)
            if dos_magic != b"MZ":
                return None
            e_lfanew = read_uint(base + 0x3C, 4)
            pe_off = base + e_lfanew

            pe_magic = state.solver.eval(state.memory.load(pe_off, 4), cast_to=bytes)
            if pe_magic != b"PE\x00\x00":
                return None

            # IMAGE_FILE_HEADER starts right after the PE signature (20 bytes);
            # SizeOfOptionalHeader is the last field, offset +16 within it).
            file_hdr = pe_off + 4
            opt_hdr = file_hdr + 20
            opt_magic = read_uint(opt_hdr, 2)
            if opt_magic == 0x20B:      # PE32+ (x64)
                data_dir_off = opt_hdr + 112
            elif opt_magic == 0x10B:    # PE32 (x86)
                data_dir_off = opt_hdr + 96
            else:
                return None

            export_rva = read_uint(data_dir_off, 4)
            export_size = read_uint(data_dir_off + 4, 4)
            if not export_rva or not export_size:
                return None  # no export table (common for .exe modules)

            export_dir = base + export_rva
            num_names = read_uint(export_dir + 24, 4)
            addr_functions = base + read_uint(export_dir + 28, 4)
            addr_names = base + read_uint(export_dir + 32, 4)
            addr_ordinals = base + read_uint(export_dir + 36, 4)

            target_bytes = export_name.encode("ascii")
            for i in range(num_names):
                name_rva = read_uint(addr_names + i * 4, 4)
                name_bytes = _read_cstr(state, base + name_rva, max_len=len(target_bytes) + 1)
                if name_bytes == target_bytes:
                    ordinal = read_uint(addr_ordinals + i * 2, 2)
                    func_rva = read_uint(addr_functions + ordinal * 4, 4)
                    # A func_rva landing inside the export directory itself isn't
                    # code — it's a forwarder string (e.g. "KERNELBASE.NtQueryInformationProcess")
                    # telling the loader to resolve this import elsewhere. Hooking
                    # it would install a SimProcedure somewhere real callers never
                    # actually reach (their IAT is resolved straight through to the
                    # forward target at load time), so treat it as not-found here
                    # and let the caller fall back to the next DLL candidate.
                    if export_rva <= func_rva < export_rva + export_size:
                        logger.debug(
                            "[angr_loader] '%s' in '%s' is a forwarder (rva=0x%x); skipping",
                            export_name, mod_name, func_rva,
                        )
                        return None
                    return base + func_rva
            return None
        except Exception as exc:
            logger.debug("[angr_loader] PE export resolution for '%s' in '%s' failed: %s", export_name, mod_name, exc)
            return None

    for mod in modules:
        name = getattr(mod, "name", "") or ""
        if name.lower() in candidates_lower:
            addr = search_module(mod.base, name)
            if addr is not None:
                return addr
    return None


def extract_exported_symbols(project: angr.Project) -> dict[str, tuple[int, int]]:
    """Extract exported symbols from every object loaded by CLE.

    Returned addresses are rebased virtual addresses so they can be passed
    directly to :func:`register_exported_symbols`.
    """
    if project is None or not hasattr(project, "loader") or project.loader is None:
        return {}

    exported: dict[str, tuple[int, int]] = {}
    for obj in getattr(project.loader, "all_objects", ()):  # main object plus libraries
        for symbol in getattr(obj, "symbols", ()):
            if not getattr(symbol, "is_export", False):
                continue
            name = getattr(symbol, "name", None)
            address = getattr(symbol, "rebased_addr", None)
            if not name or not isinstance(address, int) or address < 0:
                continue
            size = getattr(symbol, "size", 0) or 0
            exported.setdefault(name, (address, int(size)))
    return exported


def register_exported_symbols(
    project: angr.Project,
    symbols: dict[str, int] | dict[str, tuple[int, int]] | None = None,
) -> int:
    """Register exported symbols into the owning CLE object symbol tables.
    Allows project.hook_symbol("SymbolName", sim_procedure) and
    project.hook_symbol("module.dll!SymbolName", sim_procedure) to resolve addresses correctly.

    When *symbols* is ``None``, exports are extracted from all loaded CLE
    objects. Explicit maps remain supported for MSL slices and tests.

    Returns the number of symbols registered.
    """
    import cle

    if project is None or not hasattr(project, "loader") or project.loader is None:
        return 0

    objects = tuple(getattr(project.loader, "all_objects", ()))
    main_obj = getattr(project.loader, "main_object", None)
    if main_obj is None and not objects:
        return 0

    if symbols is None:
        symbols = extract_exported_symbols(project)

    symbols_count = 0
    if symbols:
        for sym_name, sym_info in symbols.items():
            if isinstance(sym_info, tuple):
                sym_addr, sym_size = sym_info
            else:
                sym_addr = sym_info
                sym_size = 32

            if not isinstance(sym_addr, int) or sym_addr < 0:
                continue

            owner = next(
                (
                    obj for obj in objects
                    if (getattr(obj, "min_addr", 0) or 0)
                    <= sym_addr
                    <= (getattr(obj, "max_addr", -1) or -1)
                ),
                main_obj,
            )
            if owner is None:
                continue

            sym_obj = None
            min_a = getattr(owner, "min_addr", 0) or 0
            rel_a = sym_addr - min_a

            try:
                sym_obj = cle.Symbol(
                    owner=owner,
                    name=sym_name,
                    relative_addr=rel_a,
                    size=sym_size,
                    sym_type=cle.SymbolType.TYPE_FUNCTION,
                )
            except Exception:
                try:
                    sym_obj = cle.Symbol(
                        owner,
                        sym_name,
                        rel_a,
                        sym_size,
                        cle.SymbolType.TYPE_FUNCTION,
                    )
                except Exception:
                    pass

            if sym_obj is not None:
                sym_obj.is_export = True

                if hasattr(owner, "symbols"):
                    try:
                        owner.symbols.add(sym_obj)
                    except Exception:
                        try:
                            owner.symbols.append(sym_obj)
                        except Exception:
                            pass

                if hasattr(owner, "_symbol_cache"):
                    try:
                        owner._symbol_cache[sym_name] = sym_obj
                    except Exception:
                        pass

                symbols_count += 1

    return symbols_count


def handoff_to_angr(emu):
    """Hand a *live* emulator off to angr: concrete -> symbolic.

    Builds ``(project, state)`` from the emulator's **current** registers and
    memory (after however many concrete steps it has run), positioned at the
    current PC.
    """
    try:
        import angr
        import claripy
    except ImportError as exc:
        raise SymbexError(
            "symbolic execution requires the 'symbex' extra: "
            "pip install memslicer[symbex]"
        ) from exc

    image = emu.image
    if image.arch not in _ANGR_ARCH:
        arch_name = getattr(image.arch, "name", str(image.arch))
        raise SymbexError(f"unsupported architecture for angr: {arch_name}")
    if not image.regions:
        raise SymbexError("slice has no memory regions")

    pc = emu.pc
    code = _region_at(image, pc) or image.regions[0]
    blob = _contiguous(code)

    angr_arch_name = _ANGR_ARCH.get(image.arch)
    if not angr_arch_name:
        raise SymbexError(f"unsupported architecture for angr: {image.arch}")

    try:
        project = angr.Project(
            io.BytesIO(blob),
            main_opts={"backend": "blob", "arch": angr_arch_name, "base_addr": code.base},
            auto_load_libs=False,
        )
        state = project.factory.blank_state(addr=pc)
    except KeyError as exc:
        raise SymbexError(f"angr architecture configuration error: {exc}") from exc
    except Exception as exc:
        raise SymbexError(f"Failed to initialize angr project in handoff: {exc}") from exc

    # Copy the *live* memory (captured pages, with any emulated writes applied).
    for r in image.regions:
        for paddr, data in r.pages.items():
            try:
                live = emu.read_mem(paddr, len(data))
                state.memory.store(paddr, live, disable_actions=True, inspect=False)
            except Exception as exc:
                logger.warning("[angr_loader] Failed to copy live memory at 0x%x in handoff: %s", paddr, exc)

    # Seed the *live* register file from the emulator. Most emulator register
    # names are expected to miss angr's regs (aliases, sub-registers, arch
    # variants) so failures here are routine — logged at debug, not warning.
    for name, value in emu.registers().items():
        try:
            setattr(state.regs, name, value)
        except Exception as exc:  # noqa: BLE001 - unknown/aliased register name
            logger.debug("[angr_loader] Live register '%s'=0x%x not applicable to angr regs: %s", name, value, exc)
        reg_lower = name.lower()
        # angr exposes the full segment base as plain `gs`/`fs`, not
        # `gs_base`/`fs_base` (that attribute doesn't exist on X86 or AMD64),
        # so normalize onto the real attribute instead of a no-op guarded by
        # a hasattr() that was always False.
        if reg_lower in ("gs_base", "gs") and hasattr(state.regs, "gs"):
            try:
                state.regs.gs = claripy.BVV(value, state.regs.gs.length)
            except Exception as exc:
                logger.warning("[angr_loader] Failed to set gs=0x%x in handoff: %s", value, exc)
        elif reg_lower in ("fs_base", "fs") and hasattr(state.regs, "fs"):
            try:
                state.regs.fs = claripy.BVV(value, state.regs.fs.length)
            except Exception as exc:
                logger.warning("[angr_loader] Failed to set fs=0x%x in handoff: %s", value, exc)

    return project, state
