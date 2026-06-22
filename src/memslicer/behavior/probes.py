"""Probes: the only layer that talks to Unicorn hooks.

Each probe installs hook(s) and emits :class:`~memslicer.behavior.events.BehaviorEvent`
records through the tracer. Granularity lives entirely in
:class:`ControlFlowProbe`: it installs ``UC_HOOK_BLOCK`` or ``UC_HOOK_CODE``
depending on ``granularity`` and emits the *same* event shape either way, so
switching block <-> instruction is a one-line change and nothing downstream
moves. Adding a new granularity is a new probe, nothing else.
"""
from __future__ import annotations

import bisect

from memslicer.behavior.events import BehaviorEvent, EventKind, EdgeType
from memslicer.behavior.stubs import make_context, syscall_name
from memslicer.msl.constants import ArchType, RegionType
from memslicer.utils.protection import PROT_X, is_rwx

_RT_CATEGORY = {
    RegionType.Heap: "heap", RegionType.Stack: "stack",
    RegionType.Image: "image", RegionType.MappedFile: "mapped",
    RegionType.Anon: "anon", RegionType.SharedMem: "shared",
    RegionType.Other: "other", RegionType.Unknown: "unknown",
}


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


class MemProbe(Probe):
    """Annotates memory writes (A3): writes to *executable* memory (unpacking,
    self-modifying code, code injection), the write-target's region type
    (heap/stack/image/...), and any statically-RWX regions.

    Aggregates land in ``graph.meta['memory']``; a code node that writes to
    executable memory is tagged with ``attrs['writes_exec']`` so the suspicious
    block stands out in the graph.
    """

    def attach(self, tracer) -> None:
        self._tracer = tracer
        regions = sorted(tracer.emu.image.regions, key=lambda r: r.base)
        self._bases = [r.base for r in regions]
        self._regions = regions
        U = tracer.emu._U
        tracer.emu.uc.hook_add(U.UC_HOOK_MEM_WRITE, self._on_write)
        mem = tracer.graph.meta.setdefault("memory", {
            "writes": 0, "exec_writes": 0, "by_region": {},
            "exec_write_targets": [], "rwx_regions": [],
        })
        for r in regions:
            if is_rwx(r.protection):
                mem["rwx_regions"].append(f"0x{r.base:x}")

    def _region_at(self, addr: int):
        i = bisect.bisect_right(self._bases, addr) - 1
        if i < 0:
            return None
        r = self._regions[i]
        return r if r.base <= addr < r.base + r.size else None

    def _on_write(self, uc, access, address, size, value, user):
        tracer = self._tracer
        mem = tracer.graph.meta["memory"]
        mem["writes"] += 1
        r = self._region_at(address)
        # RegionType is an IntEnum, so the raw int key matches directly.
        cat = ("unmapped" if r is None
               else _RT_CATEGORY.get(r.region_type, "other"))
        mem["by_region"][cat] = mem["by_region"].get(cat, 0) + 1
        if r is not None and (r.protection & PROT_X):
            mem["exec_writes"] += 1
            tgt = f"0x{address:x}"
            tgts = mem["exec_write_targets"]
            if len(tgts) < 64 and tgt not in tgts:
                tgts.append(tgt)
            src = tracer._cur_code
            node = tracer.graph.nodes.get(src) if src else None
            if node is not None:
                node["attrs"]["writes_exec"] = \
                    node["attrs"].get("writes_exec", 0) + 1


class FunctionProbe(Probe):
    """Builds a dynamic call graph (A2): function nodes keyed by entry address,
    ``call`` edges caller->callee, and ``ret`` edges back.

    An overlay -- it runs alongside the block/instruction CFG without disturbing
    it. Call/return are detected from each block's terminator (Capstone groups),
    and a shadow call stack tracks the current function so returns rejoin the
    caller. API thunk addresses (resolved exports) are skipped: those are
    intercepted as API nodes by the tracer.
    """

    def attach(self, tracer) -> None:
        self._tracer = tracer
        from capstone import CS_GRP_CALL, CS_GRP_RET
        self._CALL, self._RET = CS_GRP_CALL, CS_GRP_RET
        tracer.emu.cs.detail = True
        U = tracer.emu._U
        tracer.emu.uc.hook_add(U.UC_HOOK_BLOCK, self._on_block)
        self._stack: list[str] = []
        self._cur: str | None = None
        self._prev_term: str | None = None

    def _terminator(self, addr: int, size: int) -> str | None:
        emu = self._tracer.emu
        try:
            code = bytes(emu.uc.mem_read(addr, size))
        except emu._U.UcError:
            return None
        last = None
        for insn in emu.cs.disasm(code, addr):
            last = insn
        if last is None:
            return None
        if self._CALL in last.groups:
            return "call"
        if self._RET in last.groups:
            return "ret"
        return None

    def _on_block(self, uc, address, size, user):
        tracer = self._tracer
        if tracer.resolver.export_at(address) is not None:
            return  # an API thunk: handled as an API node, not a function
        fid = f"func:0x{address:x}"
        graph = tracer.graph
        prev = self._prev_term
        if self._cur is None:
            self._cur = fid
            graph.touch_node_id(fid, "func", label=tracer.resolver.label(address),
                                addr=address)
        elif prev == "call":
            graph.touch_node_id(fid, "func",
                                label=tracer.resolver.label(address), addr=address)
            graph.add_edge(self._cur, fid, EdgeType.CALL)
            self._stack.append(self._cur)
            self._cur = fid
        elif prev == "ret":
            if self._stack:
                caller = self._stack.pop()
                graph.add_edge(self._cur, caller, EdgeType.RET)
                self._cur = caller
        self._prev_term = self._terminator(address, size)
