"""Probes: the only layer that talks to Unicorn hooks.

Each probe installs hook(s) and emits :class:`~memslicer.behavior.events.BehaviorEvent`
records through the tracer. Granularity lives entirely in
:class:`ControlFlowProbe`: it installs ``UC_HOOK_BLOCK`` or ``UC_HOOK_CODE``
depending on ``granularity`` and emits the *same* event shape either way, so
switching block <-> instruction is a one-line change and nothing downstream
moves. Adding a new granularity is a new probe, nothing else.
"""
from __future__ import annotations

from memslicer.behavior.events import BehaviorEvent, EventKind, EdgeType
from memslicer.behavior.stubs import make_context, syscall_name
from memslicer.msl.constants import ArchType


class Probe:
    """A probe installs Unicorn hooks against ``tracer.emu.uc``."""
    def attach(self, tracer) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class ControlFlowProbe(Probe):
    """Emits a code NODE per executed unit and a classified control-flow EDGE
    from the previous unit. ``granularity`` is ``"block"`` (UC_HOOK_BLOCK) or
    ``"instruction"`` (UC_HOOK_CODE)."""

    def __init__(self, granularity: str = "block") -> None:
        if granularity not in ("block", "instruction"):
            raise ValueError(f"unknown granularity: {granularity!r}")
        self.granularity = granularity
        self._prev: tuple[int, int] | None = None   # (addr, size) of last unit

    def attach(self, tracer) -> None:
        self._tracer = tracer
        from capstone import CS_GRP_CALL, CS_GRP_RET, CS_GRP_JUMP
        self._g = {CS_GRP_CALL: EdgeType.CALL, CS_GRP_RET: EdgeType.RET,
                   CS_GRP_JUMP: EdgeType.JUMP}
        tracer.emu.cs.detail = True
        U = tracer.emu._U
        htype = (U.UC_HOOK_BLOCK if self.granularity == "block"
                 else U.UC_HOOK_CODE)
        tracer.emu.uc.hook_add(htype, self._on_node)

    def _classify(self, addr: int, size: int) -> str:
        emu = self._tracer.emu
        try:
            code = bytes(emu.uc.mem_read(addr, size))
        except emu._U.UcError:
            return EdgeType.FALLTHROUGH
        last = None
        for insn in emu.cs.disasm(code, addr):
            last = insn
        if last is None:
            return EdgeType.FALLTHROUGH
        for grp, etype in self._g.items():
            if grp in last.groups:
                return etype
        return EdgeType.FALLTHROUGH

    def _on_node(self, uc, address, size, user):
        tracer = self._tracer
        # The tracer creates the node (and may intercept the address as an API
        # call, in which case no plain code node/edge is emitted and the caller
        # stays the current node).
        if tracer.on_code_node(address, size, self.granularity):
            return
        if self._prev is not None:
            paddr, psize = self._prev
            etype = self._classify(paddr, psize)
            tracer.emit(BehaviorEvent(
                kind=EventKind.EDGE, seq=tracer.seq,
                src=f"0x{paddr:x}", dst=f"0x{address:x}", edge_type=etype,
            ))
        self._prev = (address, size)


class SyscallProbe(Probe):
    """Observes syscalls and routes them to the stub registry.

    x86/x86-64 ``syscall`` is caught with ``UC_HOOK_INSN``; software interrupts
    (``int 0x80`` on x86, ``svc`` on ARM) with ``UC_HOOK_INTR``. The stub
    decides the return value and whether to stop; the call becomes a SYSCALL
    event (and node) wired by the tracer to its call site and the previous
    system event.
    """

    def attach(self, tracer) -> None:
        self._tracer = tracer
        U = tracer.emu._U
        uc = tracer.emu.uc
        arch = tracer.emu.image.arch
        if arch in (ArchType.x86_64, ArchType.x86):
            from unicorn.x86_const import UC_X86_INS_SYSCALL
            uc.hook_add(U.UC_HOOK_INSN, self._on_syscall, None, 1, 0,
                        UC_X86_INS_SYSCALL)
        # int 0x80 / svc and the like
        uc.hook_add(U.UC_HOOK_INTR, self._on_intr)

    def _on_syscall(self, uc, user):
        self._handle(nr=None)

    def _on_intr(self, uc, intno, user):
        # x86 int 0x80 uses eax for the number; ARM svc routes here too.
        self._handle(nr=None)

    def _handle(self, nr):
        tracer = self._tracer
        emu = tracer.emu
        arch = emu.image.arch
        from memslicer.behavior.stubs import _SYS_ABI
        nrreg = _SYS_ABI.get(arch, ("rax",))[0]
        number = emu.read_reg(nrreg) if nr is None else nr
        name = syscall_name(arch, number)
        site = emu.pc
        ctx = make_context(emu, arch, name, number, site, kind="syscall")
        result = tracer.registry.dispatch(ctx)
        tracer.emit(BehaviorEvent(
            kind=EventKind.SYSCALL, seq=tracer.next_seq(), addr=site,
            label=name, attrs={
                "number": number,
                "category": ctx.category,
                "args": ctx.args(4),
                "ret": ctx.get_reg(ctx._retreg),
                "log": ctx.logs[-1] if ctx.logs else "",
            },
        ))
        if result == ctx.STOP:
            tracer.stop("syscall stub requested stop")
