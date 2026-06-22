"""Orchestrates emulation + probes into a :class:`BehaviorGraph`.

Wires the layers together and owns the small bit of shared state probes need
(the current code node, the previous system event) plus API interception.

When execution reaches a resolved PE export entry the tracer intercepts it:
the call is dispatched to the stub registry (so the analyst controls the
return), recorded as an API behavior node, and execution is redirected back to
the caller -- so the API body is never emulated (the Speakeasy approach). That
redirect is done by stopping Unicorn and restarting ``emu_start`` at the return
address in an outer loop; the same loop is the natural seam for a future angr
SimOS hand-off.
"""
from __future__ import annotations

from memslicer.behavior.dataflow import link_dataflow
from memslicer.behavior.events import BehaviorEvent, EventKind, EdgeType
from memslicer.behavior.graph import BehaviorGraph
from memslicer.behavior.probes import (
    ControlFlowProbe, FunctionProbe, MemProbe, SyscallProbe,
)
from memslicer.behavior.resolver import AddressResolver
from memslicer.behavior.stubs import StubRegistry, make_api_context
from memslicer.emu.engine import MSLEmulator, open_slice
from memslicer.msl.constants import ArchType


class BehaviorTracer:
    def __init__(self, emu: MSLEmulator, *, granularity: str = "block",
                 registry: StubRegistry | None = None,
                 resolver: AddressResolver | None = None,
                 intercept_apis: bool = True, memory: bool = True,
                 call_graph: bool = False, probes=None) -> None:
        self.emu = emu
        self.graph = BehaviorGraph()
        self.resolver = resolver or AddressResolver.from_emulator(emu)
        self.registry = registry or StubRegistry()
        self.granularity = granularity
        self.intercept_apis = intercept_apis
        if probes is None:
            probes = [ControlFlowProbe(granularity), SyscallProbe()]
            if memory:
                probes.append(MemProbe())
            if call_graph:
                probes.append(FunctionProbe())
        self.probes = probes
        self.seq = 0
        self._steps = 0
        self._cur_code: str | None = None
        self._last_event: str | None = None
        self._stopped = False
        self._redirect: int | None = None

    # -- state shared with probes -------------------------------------------

    def tick(self) -> None:
        self.seq += 1
        self._steps += 1

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def on_code_node(self, addr: int, size: int, granularity: str) -> bool:
        """Handle an executed code unit. Returns True if it was intercepted as
        an API call (caller stays current, no plain code node is emitted)."""
        if self._maybe_intercept_api(addr):
            return True
        self.tick()
        self.emit(BehaviorEvent(
            kind=EventKind.NODE, seq=self.seq, addr=addr, size=size,
            node_kind="block" if granularity == "block" else "insn",
            label=self.resolver.label(addr),
        ))
        return False

    def emit(self, ev: BehaviorEvent) -> None:
        self.graph.consume(ev)
        if ev.kind == EventKind.NODE:
            self._cur_code = f"0x{ev.addr:x}"
        elif ev.kind in (EventKind.SYSCALL, EventKind.API):
            nid = f"{ev.kind}:{ev.label}"
            if self._cur_code:
                self.graph.add_edge(self._cur_code, nid, EdgeType.INVOKE)
            if self._last_event:
                self.graph.add_edge(self._last_event, nid, EdgeType.SEQ)
            self._last_event = nid

    def stop(self, reason: str) -> None:
        self._stopped = True
        self.graph.meta["stop_reason"] = reason
        self.emu.uc.emu_stop()

    def redirect(self, pc: int) -> None:
        """Soft-stop emulation; the run loop resumes ``emu_start`` at *pc*."""
        self._redirect = pc
        self.emu.uc.emu_stop()

    # -- API interception ----------------------------------------------------

    def _maybe_intercept_api(self, addr: int) -> bool:
        if not self.intercept_apis:
            return False
        name = self.resolver.export_at(addr)
        if name is None:
            return False
        self._dispatch_api(addr, name)
        return True

    def _dispatch_api(self, site: int, name: str) -> None:
        emu = self.emu
        # Stubs are keyed by the bare export name (the analyst writes
        # `def CreateFileW`), while the graph keeps the full `module!Export`.
        bare = name.rsplit("!", 1)[-1]
        ctx = make_api_context(emu, emu.image.arch, emu.image.os, bare, site)
        result = self.registry.dispatch(ctx)
        self.emit(BehaviorEvent(
            kind=EventKind.API, seq=self.next_seq(), addr=site, label=name,
            attrs={"category": ctx.category, "args": ctx.args(4),
                   "ret": ctx.get_reg(ctx._retreg),
                   "log": ctx.logs[-1] if ctx.logs else ""},
        ))
        if result == ctx.STOP:
            self.stop("api stub requested stop")
            return
        self._return_from_api()

    def _return_from_api(self) -> None:
        """Pop the return address (or read the link register) and redirect."""
        emu = self.emu
        arch = emu.image.arch
        if arch in (ArchType.x86_64, ArchType.x86):
            ptr = emu.bits // 8
            sp = emu.read_reg(emu._sp_name)
            ret = int.from_bytes(emu.read_mem(sp, ptr), "little")
            emu.write_reg(emu._sp_name, sp + ptr)
            self.redirect(ret)
        elif arch == ArchType.ARM64:
            self.redirect(emu.read_reg("x30"))
        elif arch == ArchType.ARM32:
            self.redirect(emu.read_reg("lr"))

    # -- run -----------------------------------------------------------------

    def run(self, start: int | None = None, max_steps: int = 100000) -> BehaviorGraph:
        pc = self.emu.pc if start is None else start
        for probe in self.probes:
            probe.attach(self)
        self.graph.meta.update({
            "arch": self.emu.image.arch.name,
            "entry": f"0x{pc:x}",
            "granularity": self.granularity,
        })
        remaining = max_steps
        while True:
            self._redirect = None
            try:
                self.emu.uc.emu_start(pc, self.emu._until, count=remaining)
            except self.emu._U.UcError as exc:
                self.graph.meta.setdefault("stop_reason", f"fault: {exc}")
                break
            if self._redirect is not None and not self._stopped:
                pc = self._redirect
                remaining = max_steps - self._steps
                if remaining <= 0:
                    self.graph.meta.setdefault("stop_reason", "max_steps reached")
                    break
                continue
            if not self._stopped:
                self.graph.meta.setdefault("stop_reason", "max_steps reached")
            break
        self.graph.meta["steps"] = self._steps
        self.graph.meta["last_pc"] = f"0x{self.emu.pc:x}"
        self.graph.meta["dataflow_edges"] = link_dataflow(self.graph)
        return self.graph


def trace_slice(path: str, *, granularity: str = "block",
                registry: StubRegistry | None = None,
                max_steps: int = 100000) -> BehaviorGraph:
    """Convenience: load *path*, emulate it, and return its behavior graph."""
    emu = open_slice(path)
    tracer = BehaviorTracer(emu, granularity=granularity, registry=registry)
    return tracer.run(max_steps=max_steps)
