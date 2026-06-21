"""Behavior-graph extraction from emulated MSL slices.

Emulating a slice with Unicorn and instrumenting it with hooks yields a
*behavior graph*: nodes are executed code (basic blocks or instructions) and
"system" events (syscalls / API calls), edges are control flow and the temporal
order of system interactions. The graph is meant to feed graph-based dynamic
analysis pipelines.

The pipeline is layered and each layer is decoupled by :class:`BehaviorEvent`::

    MSLEmulator (Unicorn)
        | hooks
    [ Probes ] --emit--> BehaviorEvent --> GraphBuilder --> BehaviorGraph --> JSON/DOT
        |                                       ^
    SyscallHandler (strategy)                   AddressResolver (addr -> module+off)

Changing granularity (basic block <-> instruction) swaps a single probe; the
rest of the pipeline is untouched.

System calls / APIs cannot be truly executed from a static snapshot (there is
no OS). Three interchangeable *handler strategies* model them:

* **observe** (default): log the call, fake a return, continue.
* **model by hand**: an analyst-editable *stub skeleton* (this module's
  :class:`~memslicer.behavior.stubs.StubRegistry`) decides the return value /
  side effects -- the Speakeasy/Qiling approach.
* **angr SimOS** (future): hand the state to angr, whose SimOS/SimProcedures
  model real OS/libc semantics.
"""
from memslicer.behavior.events import BehaviorEvent, EventKind, EdgeType
from memslicer.behavior.graph import BehaviorGraph
from memslicer.behavior.resolver import AddressResolver
from memslicer.behavior.stubs import StubRegistry, StubContext, emit_skeleton, load_stubs
from memslicer.behavior.tracer import BehaviorTracer, trace_slice

__all__ = [
    "BehaviorEvent", "EventKind", "EdgeType",
    "BehaviorGraph", "AddressResolver",
    "StubRegistry", "StubContext", "emit_skeleton", "load_stubs",
    "BehaviorTracer", "trace_slice",
]
