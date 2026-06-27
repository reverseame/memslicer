"""Unicorn-backed emulator for MSL slices, with Capstone disassembly.

Unicorn and Capstone are imported lazily so that importing
:mod:`memslicer.emu` does not hard-require the ``emu`` extra.
"""
from __future__ import annotations

from dataclasses import dataclass

from memslicer.msl.constants import ArchType, OSType
from memslicer.emu.loader import EmuThread, SliceImage, load_slice

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


def _gdt_descriptor(base: int, limit: int, access: int, gran: int) -> bytes:
    """Pack an 8-byte legacy GDT segment descriptor.

    *access* is the access byte (e.g. ``0xf2`` = present, ring-3, data RW) and
    *gran* the 4-bit granularity/flags nibble (e.g. ``0xc`` = page-granular,
    32-bit). Used to give 32-bit ``fs``/``gs`` a base Unicorn won't accept via
    ``UC_X86_REG_*_BASE``.
    """
    desc = limit & 0xffff
    desc |= (base & 0xffffff) << 16
    desc |= (access & 0xff) << 40
    desc |= ((limit >> 16) & 0xf) << 48
    desc |= (gran & 0xf) << 52
    desc |= ((base >> 24) & 0xff) << 56
    return desc.to_bytes(8, "little")


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

    def __init__(self, image: SliceImage, thread: "int | EmuThread | None" = None):
        """Build an emulator for *image*.

        *thread* selects which captured thread to seed the CPU from: ``None``
        uses the Current thread (the default), otherwise pass a captured thread
        id or an :class:`EmuThread`. Use :meth:`switch_thread` to re-seed from
        another thread later.
        """
        try:
            import unicorn  # noqa: F401
            import capstone  # noqa: F401
        except ImportError as exc:
            raise EmuError(
                "emulation requires the 'emu' extra: pip install memslicer[emu]"
            ) from exc

        self.image = image
        self.thread = self._resolve_thread(thread)
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

        self._mapped: list[tuple[int, int]] = []  # coalesced mapped spans
        self._seg_bases: dict[str, int] = {}       # x86 fs/gs base (GDT-seeded)
        self._map_memory()
        self._seed_registers()

        # Reverse-execution journal: Unicorn has no native undo, so before each
        # step we snapshot the CPU context and record every memory write (with
        # its pre-write bytes) via a hook. step_back() restores the context and
        # reverts the writes.
        self._history = []        # list of (UcContext, [(addr, old_bytes), ...])
        self._max_back = 4096
        self._pending = None      # write log of the in-progress step
        # Self-modifying-code tracking: every [addr, addr+size) the emulated code
        # writes is recorded, and executing an address that was previously written
        # is flagged as a write-then-execute (W->X) event -- the moment a packer
        # jumps into its freshly decoded payload.
        self._written = []        # list of [start, end) byte ranges written
        self._wx_events = []      # PCs where execution entered written memory
        self._wx_seen = set()
        self.uc.hook_add (self._U.UC_HOOK_MEM_WRITE, self._on_mem_write)

    def _on_mem_write(self, uc, access, address, size, value, user):
        # Called before the write is applied, so mem_read returns the old bytes.
        self._written.append ((address, address + size))
        if self._pending is None:
            return
        try:
            old = bytes (uc.mem_read (address, size))
        except self._U.UcError:
            return
        self._pending.append ((address, old))

    # -- setup ---------------------------------------------------------------

    def _map_memory(self) -> None:
        spans = []
        for r in self.image.regions:
            lo = r.base & ~(_UC_PAGE - 1)
            hi = (r.base + r.size + _UC_PAGE - 1) & ~(_UC_PAGE - 1)
            spans.append((lo, hi))
        self._mapped = _coalesce(spans)
        for lo, hi in self._mapped:
            self.uc.mem_map(lo, hi - lo)
        for r in self.image.regions:
            for paddr, data in r.pages.items():
                self.uc.mem_write(paddr, data)

    def _find_free_page(self, size: int) -> int:
        """Return a page-aligned address with *size* bytes free of mapped spans."""
        size = (size + _UC_PAGE - 1) & ~(_UC_PAGE - 1)
        limit = 1 << self.bits
        candidates = [(hi + _UC_PAGE - 1) & ~(_UC_PAGE - 1) for _, hi in self._mapped]
        candidates.append(_UC_PAGE)
        for c in sorted(candidates):
            if c + size > limit:
                continue
            if not any(c < hi and c + size > lo for lo, hi in self._mapped):
                return c
        raise EmuError("no free address space for synthetic GDT")

    def _reg_const(self, name: str):
        mod = getattr(self._U, self._const_mod)
        return getattr(mod, self._reg_prefix + name.upper(), None)

    def _resolve_thread(self, spec) -> "EmuThread | None":
        try:
            return self.image.select_thread(spec)
        except KeyError as exc:
            raise EmuError(str(exc)) from exc

    def _seed_registers(self) -> None:
        thread = self.thread
        if thread is None:
            self._seg_bases = {}
            return
        is_x86 = self.image.arch == ArchType.x86
        for reg in thread.registers:
            # In 32-bit mode Unicorn ignores UC_X86_REG_FS_BASE/GS_BASE (no-op);
            # those bases are installed via a synthetic GDT in _seed_x86_segments.
            if is_x86 and reg.name.lower().endswith("_base"):
                continue
            const = self._reg_const(reg.name)
            if const is None:
                continue
            try:
                # Unicorn accepts a Python int for GPRs and for vector/FP
                # registers alike (XMM=128-bit, YMM=256-bit, ...).
                self.uc.reg_write(const, reg.value)
            except (self._U.UcError, OverflowError, TypeError):
                continue  # a register width this engine build can't accept
        if is_x86:
            self._seed_x86_segments()

    def _seed_x86_segments(self) -> None:
        """Install a synthetic GDT so 32-bit ``fs:``/``gs:`` accesses resolve.

        In 32-bit mode the segment base lives in a descriptor, not a register
        Unicorn will honor. For each captured ``fs_base``/``gs_base`` we add a
        flat ring-3 data descriptor and load the matching selector, so TEB/PEB-
        and TLS-relative reads (e.g. the CRT SEH prologue's ``mov eax, fs:[0]``)
        work during emulation. No-op when the slice carried no segment base.
        """
        bases: dict[str, int] = {}
        for reg in (self.thread.registers if self.thread else []):
            n = reg.name.lower()
            if n in ("fs_base", "gs_base") and reg.value:
                bases[n[:2]] = reg.value
        self._seg_bases = bases
        if not bases:
            return
        order = [s for s in ("fs", "gs") if s in bases]
        descriptors = [b"\x00" * 8]                     # mandatory null descriptor
        selectors: dict[str, int] = {}
        for idx, seg in enumerate(order, start=1):
            descriptors.append(
                _gdt_descriptor(bases[seg], 0xfffff, access=0xf2, gran=0xc)
            )
            selectors[seg] = (idx << 3) | 3             # GDT index, TI=0, RPL=3
        gdt = b"".join(descriptors)
        gdt_base = self._find_free_page(len(gdt))
        self.uc.mem_map(gdt_base, _UC_PAGE)
        self.uc.mem_write(gdt_base, gdt)
        self._mapped = _coalesce(self._mapped + [(gdt_base, gdt_base + _UC_PAGE)])
        xc = getattr(self._U, self._const_mod)
        self.uc.reg_write(xc.UC_X86_REG_GDTR, (0, gdt_base, len(gdt) - 1, 0))
        for seg, sel in selectors.items():
            self.uc.reg_write(self._reg_const(seg), sel)

    def switch_thread(self, thread: "int | EmuThread | None") -> "EmuThread | None":
        """Re-seed the CPU from another captured thread (by tid or EmuThread).

        Registers are reset to that thread's captured Thread Context and the PC
        to its captured PC; residual register state from the previous thread is
        cleared first. Mapped memory is shared, so any writes made so far
        persist. The reverse-execution history is dropped (it belonged to the
        previous thread). Returns the newly selected thread.
        """
        self.thread = self._resolve_thread(thread)
        for name in self._gpr_names:        # clear residual state from prior thread
            const = self._reg_const(name)
            if const is not None:
                self.uc.reg_write(const, 0)
        self._seed_registers()
        self._history = []
        return self.thread

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

    def segment_base(self, seg: str) -> int | None:
        """Return the captured ``fs_base`` / ``gs_base``, or None if the slice
        didn't capture it. These anchor TEB/PEB and TLS access."""
        seg = seg.lower()
        if self.image.arch == ArchType.x86:
            # 32-bit base lives in the synthetic GDT, not a readable MSR.
            return self._seg_bases.get(seg)
        const = self._reg_const(f"{seg}_base")
        if const is None:
            return None
        return self.uc.reg_read(const)

    def peb_address(self) -> int | None:
        """Resolve the Windows PEB pointer from the captured segment base:
        ``gs:[0x60]`` on x64, ``fs:[0x30]`` on x86. Requires that the slice
        captured fs/gs base and the TEB page. Returns None otherwise."""
        if self.image.os != OSType.Windows:
            return None
        if self.image.arch == ArchType.x86_64:
            base, off, psize = self.segment_base("gs"), 0x60, 8
        elif self.image.arch == ArchType.x86:
            base, off, psize = self.segment_base("fs"), 0x30, 4
        else:
            return None
        if not base:
            return None
        try:
            return int.from_bytes(self.read_mem(base + off, psize), "little")
        except self._U.UcError:
            return None

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
        # Write-then-execute detection: if the instruction about to run lives in
        # memory that earlier instructions wrote, record it once (self-modifying
        # / unpacked code).
        if pc not in self._wx_seen and self._is_written(pc):
            self._wx_seen.add(pc)
            self._wx_events.append(pc)
        size, mnemonic, op_str = self._disasm_at(pc)
        ctx = self.uc.context_save()       # CPU state before the step
        self._pending = []                 # collect this step's memory writes
        try:
            self.uc.emu_start(pc, self._until, count=1)
            res = StepResult(pc, size, mnemonic, op_str, True)
        except self._U.UcError as exc:
            res = StepResult(pc, size, mnemonic, op_str, False, str(exc))
        writes = self._pending
        self._pending = None
        self._history.append((ctx, writes))
        if len(self._history) > self._max_back:
            self._history.pop(0)
        return res

    def can_step_back(self) -> bool:
        return bool(self._history)

    def step_back(self) -> bool:
        """Undo the last step: restore the CPU context and revert the memory
        writes recorded for that step. Returns False if there is no history."""
        if not self._history:
            return False
        ctx, writes = self._history.pop()
        self.uc.context_restore(ctx)
        for addr, old in reversed(writes):   # reverse order for overlaps
            self.uc.mem_write(addr, old)
        return True

    def step_until(self, addr: int, max_steps: int = 100000):
        """Step until PC == *addr* or a fault, yielding each StepResult."""
        for _ in range(max_steps):
            res = self.step()
            yield res
            if not res.ok or self.pc == addr:
                return

    # -- self-modifying code / unpacking ------------------------------------

    def written_ranges(self) -> list[tuple[int, int]]:
        """Coalesced ``[start, end)`` byte ranges the emulated code has written
        so far (its dirtied memory)."""
        return _coalesce(self._written)

    def _is_written(self, addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in self._written)

    def self_modified_exec(self) -> list[int]:
        """Addresses where execution entered memory that was written during
        emulation (write-then-execute). A non-empty list is a strong unpacking /
        self-modifying-code signal; the first entry is the unpack tail-jump."""
        return list(self._wx_events)

    def dump_written(self, outdir: str) -> list[tuple[str, int, int, bool]]:
        """Write each coalesced dirtied range to ``outdir`` as a ``.bin`` file
        (current, post-execution bytes). Returns ``(path, start, end, executed)``
        per range, where *executed* marks ranges that were also run (the unpacked
        payload). Useful for recovering decoded/unpacked code from a slice."""
        import os
        os.makedirs(outdir, exist_ok=True)
        out: list[tuple[str, int, int, bool]] = []
        for lo, hi in self.written_ranges():
            try:
                data = bytes(self.uc.mem_read(lo, hi - lo))
            except self._U.UcError:
                continue
            executed = any(lo <= pc < hi for pc in self._wx_events)
            path = os.path.join(outdir, f"written_{lo:#x}_{hi:#x}.bin")
            with open(path, "wb") as f:
                f.write(data)
            out.append((path, lo, hi, executed))
        return out


def open_slice(path: str, thread: "int | EmuThread | None" = None) -> MSLEmulator:
    """Convenience: load *path* and build a ready-to-step emulator.

    *thread* selects the captured thread to seed from (default: the Current
    thread); see :class:`MSLEmulator`.
    """
    return MSLEmulator(load_slice(path), thread=thread)
