"""Orchestrates emulation + probes into a :class:`BehaviorGraph`.

Wires the layers together and owns the small bit of shared state probes need
(the current code node and the previous system event, used to attach syscall
nodes). Drives Unicorn with a single bounded ``emu_start``; faults at the edge
of captured memory (running off the snapshot) are an expected stop, not an error.
"""
from __future__ import annotations

from memslicer.behavior.events import BehaviorEvent, EventKind, EdgeType
from memslicer.behavior.graph import BehaviorGraph
from memslicer.behavior.probes import ControlFlowProbe, SyscallProbe
from memslicer.behavior.resolver import AddressResolver
from memslicer.behavior.stubs import StubRegistry
from memslicer.emu.engine import MSLEmulator, open_slice


class BehaviorTracer:
    def __init__(self, emu: MSLEmulator, *, granularity: str = "block",
                 registry: StubRegistry | None = None,
                 resolver: AddressResolver | None = None,
                 probes=None) -> None:
        self.emu = emu
        self.graph = BehaviorGraph()
        self.resolver = resolver or AddressResolver.from_image(emu.image)
        self.registry = registry or StubRegistry()
        self.granularity = granularity
        self.probes = probes or [ControlFlowProbe(granularity), SyscallProbe()]
        self.seq = 0
        self._steps = 0
        self._cur_code: str | None = None
        self._last_event: str | None = None
        self._stopped = False

    # -- state shared with probes -------------------------------------------

    def tick(self) -> None:
        self.seq += 1
        self._steps += 1

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

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
        try:
            self.emu.uc.emu_start(pc, self.emu._until, count=max_steps)
            if not self._stopped:
                self.graph.meta.setdefault("stop_reason", "max_steps reached")
        except self.emu._U.UcError as exc:
            self.graph.meta.setdefault("stop_reason", f"fault: {exc}")
        self.graph.meta["steps"] = self._steps
        self.graph.meta["last_pc"] = f"0x{self.emu.pc:x}"
        return self.graph


def trace_slice(path: str, *, granularity: str = "block",
                registry: StubRegistry | None = None,
                max_steps: int = 100000) -> BehaviorGraph:
    """Convenience: load *path*, emulate it, and return its behavior graph."""
    emu = open_slice(path)
    tracer = BehaviorTracer(emu, granularity=granularity, registry=registry)
    return tracer.run(max_steps=max_steps)
