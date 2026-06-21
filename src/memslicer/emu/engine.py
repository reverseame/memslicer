"""Unicorn-backed emulator for MSL slices, with Capstone disassembly.

Unicorn and Capstone are imported lazily so that importing
:mod:`memslicer.emu` does not hard-require the ``emu`` extra.
"""
from __future__ import annotations

from dataclasses import dataclass

from memslicer.msl.constants import ArchType
from memslicer.emu.loader import SliceImage, load_slice

_UC_PAGE = 0x1000


class EmuError(RuntimeError):
    """Raised when emulation cannot be set up or a step faults fatally."""


@dataclass
class StepResult:
    """Outcome of a single emulated instruction."""
    addr: int
    size: int
    mnemonic: str
    op_str: str
    ok: bool
    error: str | None = None

    def __str__(self) -> str:
        text = f"{self.addr:#012x}  {self.mnemonic} {self.op_str}".rstrip()
        return text if self.ok else f"{text}    ! {self.error}"


# arch -> (uc_arch, uc_mode, cs_arch, cs_mode, bits, const_module, reg_prefix,
#          pc_name, sp_name, gpr_names)
def _arch_table():
    import unicorn as U
    from capstone import (
        CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64,
        CS_MODE_32, CS_MODE_64, CS_MODE_ARM,
    )
    x86_gpr = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
               "rip", "rflags"]
    x86_gpr32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                 "eip", "eflags"]
    arm64_gpr = [f"x{i}" for i in range(31)] + ["sp", "pc", "pstate"]
    arm_gpr = [f"r{i}" for i in range(13)] + ["sp", "lr", "pc", "cpsr"]
    return {
        ArchType.x86_64: (U.UC_ARCH_X86, U.UC_MODE_64, CS_ARCH_X86, CS_MODE_64,
                          64, "x86_const", "UC_X86_REG_", "rip", "rsp", x86_gpr),
        ArchType.x86: (U.UC_ARCH_X86, U.UC_MODE_32, CS_ARCH_X86, CS_MODE_32,
                       32, "x86_const", "UC_X86_REG_", "eip", "esp", x86_gpr32),
        ArchType.ARM64: (U.UC_ARCH_ARM64, U.UC_MODE_ARM, CS_ARCH_ARM64, CS_MODE_ARM,
                         64, "arm64_const", "UC_ARM64_REG_", "pc", "sp", arm64_gpr),
        ArchType.ARM32: (U.UC_ARCH_ARM, U.UC_MODE_ARM, CS_ARCH_ARM, CS_MODE_ARM,
                         32, "arm_const", "UC_ARM_REG_", "pc", "sp", arm_gpr),
    }


def _coalesce(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge [start, end) spans (already page-aligned) that touch or overlap."""
    out: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


class MSLEmulator:
    """Emulate an :class:`SliceImage` with Unicorn."""

    def __init__(self, image: SliceImage):
        try:
            import unicorn  # noqa: F401
            import capstone  # noqa: F401
        except ImportError as exc:
            raise EmuError(
                "emulation requires the 'emu' extra: pip install memslicer[emu]"
            ) from exc

        self.image = image
        table = _arch_table()
        if image.arch not in table:
            raise EmuError(f"unsupported architecture for emulation: {image.arch.name}")
        (uc_arch, uc_mode, cs_arch, cs_mode, self.bits,
         self._const_mod, self._reg_prefix, self._pc_name,
         self._sp_name, self._gpr_names) = table[image.arch]

        import unicorn
        import capstone
        self._U = unicorn
        self.uc = unicorn.Uc(uc_arch, uc_mode)
        self.cs = capstone.Cs(cs_arch, cs_mode)
        self._until = (1 << self.bits) - 1

        self._map_memory()
        self._seed_registers()

    # -- setup ---------------------------------------------------------------

    def _map_memory(self) -> None:
        spans = []
        for r in self.image.regions:
            lo = r.base & ~(_UC_PAGE - 1)
            hi = (r.base + r.size + _UC_PAGE - 1) & ~(_UC_PAGE - 1)
            spans.append((lo, hi))
        for lo, hi in _coalesce(spans):
            self.uc.mem_map(lo, hi - lo)
        for r in self.image.regions:
            for paddr, data in r.pages.items():
                self.uc.mem_write(paddr, data)

    def _reg_const(self, name: str):
        mod = getattr(self._U, self._const_mod)
        return getattr(mod, self._reg_prefix + name.upper(), None)

    def _seed_registers(self) -> None:
        thread = self.image.current_thread
        if thread is None:
            return
        for reg in thread.registers:
            if reg.width > 8:
                continue  # vector/extended registers not seeded in MVP
            const = self._reg_const(reg.name)
            if const is not None:
                self.uc.reg_write(const, reg.value)

    # -- registers / memory --------------------------------------------------

    @property
    def pc(self) -> int:
        return self.uc.reg_read(self._reg_const(self._pc_name))

    @pc.setter
    def pc(self, value: int) -> None:
        self.uc.reg_write(self._reg_const(self._pc_name), value)

    def read_reg(self, name: str) -> int:
        const = self._reg_const(name)
        if const is None:
            raise EmuError(f"unknown register: {name}")
        return self.uc.reg_read(const)

    def write_reg(self, name: str, value: int) -> None:
        const = self._reg_const(name)
        if const is None:
            raise EmuError(f"unknown register: {name}")
        self.uc.reg_write(const, value)

    def registers(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for name in self._gpr_names:
            const = self._reg_const(name)
            if const is not None:
                out[name] = self.uc.reg_read(const)
        return out

    def read_mem(self, addr: int, size: int) -> bytes:
        return bytes(self.uc.mem_read(addr, size))

    # -- execution -----------------------------------------------------------

    def _disasm_at(self, pc: int) -> tuple[int, str, str]:
        try:
            code = bytes(self.uc.mem_read(pc, 16))
        except self._U.UcError:
            return 0, "(unreadable)", ""
        insn = next(self.cs.disasm(code, pc), None)
        if insn is None:
            return 0, "(bad)", ""
        return insn.size, insn.mnemonic, insn.op_str

    def step(self) -> StepResult:
        """Emulate a single instruction at the current PC."""
        pc = self.pc
        size, mnemonic, op_str = self._disasm_at(pc)
        try:
            self.uc.emu_start(pc, self._until, count=1)
            return StepResult(pc, size, mnemonic, op_str, True)
        except self._U.UcError as exc:
            return StepResult(pc, size, mnemonic, op_str, False, str(exc))

    def step_until(self, addr: int, max_steps: int = 100000):
        """Step until PC == *addr* or a fault, yielding each StepResult."""
        for _ in range(max_steps):
            res = self.step()
            yield res
            if not res.ok or self.pc == addr:
                return


def open_slice(path: str) -> MSLEmulator:
    """Convenience: load *path* and build a ready-to-step emulator."""
    return MSLEmulator(load_slice(path))
