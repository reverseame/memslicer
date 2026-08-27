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
            except Exception:
                pass
            reg_lower = reg.name.lower()
            if reg_lower in ("gs_base", "gs", "gs_const"):
                try:
                    state.regs.gs = 0
                except Exception:
                    pass
                for rname in ("gs_base", "gs_const", "gs_offset"):
                    if hasattr(state.regs, rname):
                        try:
                            setattr(state.regs, rname, claripy.BVV(reg.value, 64))
                        except Exception:
                            pass
            elif reg_lower in ("fs_base", "fs", "fs_const"):
                try:
                    state.regs.fs = 0
                except Exception:
                    pass
                for rname in ("fs_base", "fs_const", "fs_offset"):
                    if hasattr(state.regs, rname):
                        try:
                            setattr(state.regs, rname, claripy.BVV(reg.value, 32))
                        except Exception:
                            pass

    register_exported_symbols(project, symbol_map)

    return project, state


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

    # Seed the *live* register file from the emulator.
    for name, value in emu.registers().items():
        try:
            setattr(state.regs, name, value)
        except Exception:  # noqa: BLE001 - unknown/aliased register name
            pass
        reg_lower = name.lower()
        if reg_lower in ("gs_base", "gs") and hasattr(state.regs, "gs_base"):
            try:
                state.regs.gs_base = value
            except Exception:
                pass
        elif reg_lower in ("fs_base", "fs") and hasattr(state.regs, "fs_base"):
            try:
                state.regs.fs_base = value
            except Exception:
                pass

    return project, state
