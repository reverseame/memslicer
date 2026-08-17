"""The normalized event contract that decouples probes from the graph builder.

Probes emit :class:`BehaviorEvent` records; the :class:`~memslicer.behavior.graph.BehaviorGraph`
consumes them. Neither side knows how the other works, so a new probe (e.g. a
different granularity) or a new serializer can be added without touching the
rest of the pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class EventKind:
    """Kinds of behavior event (the ``kind`` field of :class:`BehaviorEvent`)."""
    NODE = "node"        # a piece of executed code (basic block or instruction)
    EDGE = "edge"        # a control-flow transition between two code nodes
    SYSCALL = "syscall"  # a system call observed at a ``syscall``/``svc``/``int`` site
    API = "api"          # a call into a resolved module export (Windows-style API)
    MEM = "mem"          # a memory access (optional data-flow annotation)


class EdgeType:
    """Control-flow edge classifications (from the source block's terminator)."""
    FALLTHROUGH = "fallthrough"
    JUMP = "jump"
    CALL = "call"
    RET = "ret"
    SEQ = "seq"          # temporal ordering between consecutive system events
    INVOKE = "invoke"    # from a code node to the syscall/api node it triggered
    DATAFLOW = "dataflow"  # a value produced by one call is consumed by another
    BUFFER = "buffer"    # two calls share the same pointer/handle (co-use)


@dataclass
class BehaviorEvent:
    """A single normalized observation produced by a probe.

    For a NODE: ``addr``/``size``/``node_kind``/``label`` are set.
    For an EDGE: ``src``/``dst``/``edge_type`` are set.
    For SYSCALL/API: ``addr`` (call site), ``label`` (name), ``attrs`` (number,
    args, return value, ...).
    """
    kind: str
    seq: int = 0
    addr: int = 0
    size: int = 0
    node_kind: str = ""          # "block" | "insn" for NODE events
    label: str = ""
    src: int = 0
    dst: int = 0
    edge_type: str = ""
    attrs: dict = field(default_factory=dict)
