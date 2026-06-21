"""Load an MSL slice into an angr Project + SimState.

angr is imported lazily so importing :mod:`memslicer.symbex` does not hard
require the ``symbex`` extra.
"""
from __future__ import annotations

import io

from memslicer.msl.constants import ArchType
from memslicer.emu.loader import SliceImage, load_slice

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
    """Materialize a region as a contiguous image (failed pages -> zeros)."""
    buf = bytearray(region.size)
    for paddr, data in region.pages.items():
        off = paddr - region.base
        buf[off:off + len(data)] = data
    return bytes(buf)


def load_angr(path: str, image: SliceImage | None = None):
    """Return ``(project, state)`` for the slice at *path*.

    The project is backed by the region holding the captured program counter;
    every captured page is mapped into the state's memory and the Current
    thread's registers are seeded, so the state sits exactly where the slice
    was taken — ready for ``project.factory.simgr(state)``.
    """
    try:
        import angr
    except ImportError as exc:
        raise SymbexError(
            "symbolic execution requires the 'symbex' extra: "
            "pip install memslicer[symbex]"
        ) from exc

    image = image or load_slice(path)
    if image.arch not in _ANGR_ARCH:
        raise SymbexError(f"unsupported architecture for angr: {image.arch.name}")
    if not image.regions:
        raise SymbexError("slice has no memory regions")

    entry = image.entry
    code = _region_at(image, entry) if entry is not None else None
    if code is None:
        code = image.regions[0]
    blob = _contiguous(code)

    project = angr.Project(
        io.BytesIO(blob),
        main_opts={"backend": "blob", "arch": _ANGR_ARCH[image.arch],
                   "base_addr": code.base},
        auto_load_libs=False,
    )
    state = project.factory.blank_state(
        addr=entry if entry is not None else code.base
    )

    # Map every captured page into the symbolic state's memory.
    for r in image.regions:
        for paddr, data in r.pages.items():
            state.memory.store(paddr, data, disable_actions=True, inspect=False)

    # Seed the captured registers by name (skip names angr doesn't know).
    thread = image.current_thread
    if thread is not None:
        for reg in thread.registers:
            try:
                setattr(state.regs, reg.name, reg.value)
            except Exception:  # noqa: BLE001 - unknown/aliased register name
                pass

    return project, state
