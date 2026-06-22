"""Resolve an absolute address back to ``module+offset`` or ``module!Export``.

Built from the slice's module list (parsed by the loader). When an address is
the entry of a PE export it is labelled ``module!Export`` (Windows-style API
resolution); otherwise, if it falls inside a known module image it is labelled
``basename+0xoffset``. Export resolution needs a memory reader (the emulator),
so use :meth:`from_emulator`; :meth:`from_image` gives module+offset only.
"""
from __future__ import annotations

from memslicer.behavior.pe import parse_pe_exports
from memslicer.emu.loader import EmuModule, SliceImage


class AddressResolver:
    def __init__(self, modules: list[EmuModule] | None = None,
                 mem_read=None) -> None:
        # sorted by base for a simple range scan
        self._modules = sorted(modules or [], key=lambda m: m.base)
        self._mem_read = mem_read
        self._exports: dict[int, str] | None = None   # addr -> "mod!Name"

    @classmethod
    def from_image(cls, image: SliceImage) -> "AddressResolver":
        return cls(image.modules)

    @classmethod
    def from_emulator(cls, emu) -> "AddressResolver":
        """Resolver with PE export resolution enabled (reads image memory)."""
        return cls(emu.image.modules, mem_read=emu.read_mem)

    # -- exports -------------------------------------------------------------

    def _ensure_exports(self) -> dict[int, str]:
        if self._exports is None:
            self._exports = {}
            if self._mem_read is not None:
                for mod in self._modules:
                    for addr, name in parse_pe_exports(self._mem_read,
                                                       mod.base).items():
                        self._exports[addr] = f"{mod.name}!{name}"
        return self._exports

    def export_at(self, addr: int) -> str | None:
        """Return ``module!Export`` if *addr* is an export entry, else None."""
        return self._ensure_exports().get(addr)

    # -- module ranges -------------------------------------------------------

    def module_at(self, addr: int) -> EmuModule | None:
        for mod in self._modules:
            if mod.base <= addr < mod.base + mod.size:
                return mod
        return None

    def resolve(self, addr: int) -> str | None:
        """``module!Export`` for an export entry, else ``module+0xoffset``,
        else ``None``."""
        exp = self.export_at(addr)
        if exp is not None:
            return exp
        mod = self.module_at(addr)
        if mod is None:
            return None
        off = addr - mod.base
        return f"{mod.name}+{off:#x}" if off else mod.name

    def label(self, addr: int) -> str:
        """Like :meth:`resolve` but always returns something (falls back to hex)."""
        return self.resolve(addr) or f"0x{addr:x}"
