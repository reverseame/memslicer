"""Resolve an absolute address back to ``module+offset``.

Built from the slice's module list (parsed by the loader). When an address
falls inside a known module image it is labelled ``basename+0xoffset``; this
turns raw call targets into human-readable nodes and is the hook point for the
Windows-export resolution planned as a second iteration (mapping a call target
to ``kernel32!CreateFileW`` instead of ``kernel32.dll+0x1a2b0``).
"""
from __future__ import annotations

from memslicer.emu.loader import EmuModule, SliceImage


class AddressResolver:
    def __init__(self, modules: list[EmuModule] | None = None) -> None:
        # sorted by base for a simple range scan
        self._modules = sorted(modules or [], key=lambda m: m.base)

    @classmethod
    def from_image(cls, image: SliceImage) -> "AddressResolver":
        return cls(image.modules)

    def module_at(self, addr: int) -> EmuModule | None:
        for mod in self._modules:
            if mod.base <= addr < mod.base + mod.size:
                return mod
        return None

    def resolve(self, addr: int) -> str | None:
        """Return ``module+0xoffset`` for *addr*, or ``None`` if unknown."""
        mod = self.module_at(addr)
        if mod is None:
            return None
        off = addr - mod.base
        return f"{mod.name}+{off:#x}" if off else mod.name

    def label(self, addr: int) -> str:
        """Like :meth:`resolve` but always returns something (falls back to hex)."""
        return self.resolve(addr) or f"0x{addr:x}"
