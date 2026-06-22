"""Lightweight inter-call data-flow (A1): value-equality taint.

A full taint engine tracks every byte through registers and memory. That is
expensive and, for a *behavior* graph, more than we need: what matters is the
causal chain between system interactions -- the handle ``CreateFile`` returns
and ``WriteFile`` later consumes, the address ``VirtualAlloc`` returns and
``WriteProcessMemory`` writes to, the socket ``socket`` returns and ``connect``
uses.

So we approximate taint by *value equality*: a call "produces" its return value
and "consumes" its integer arguments. When a later call consumes a value an
earlier call produced, we add a ``dataflow`` edge from producer to consumer.
This is cheap (one linear pass over the ordered event trace), backend-agnostic
(it reads only ``graph.events``, which both the Unicorn and Speakeasy backends
fill the same way), and surprisingly informative for malware triage.

Trivial values (0, 1, -1, small integers) are ignored: they collide constantly
(every other argument is 0) and carry no provenance. Handles, file descriptors,
pointers and allocation bases -- the things worth linking -- are distinctive and
large, so a single threshold filters the noise well. Our stub library hands out
handles from 0x100 up and allocations far higher, and real Windows handles are
similarly distinctive, so the default threshold catches them while dropping
booleans and counts.
"""
from __future__ import annotations

from memslicer.behavior.events import EdgeType
from memslicer.behavior.graph import BehaviorGraph

__all__ = ["link_dataflow", "MIN_TAINT_VALUE", "SENTINELS"]

# Smallest produced value considered a real datum (handle/fd/pointer). Below
# this, integers are almost always flags/counts/indices and collide constantly.
MIN_TAINT_VALUE = 0x100

# Common "no value" / error returns that must never seed a dataflow edge.
SENTINELS = frozenset({
    0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFF,
})


def _is_taintable(value) -> bool:
    return (isinstance(value, int) and value not in SENTINELS
            and value >= MIN_TAINT_VALUE)


def link_dataflow(graph: BehaviorGraph, *,
                  min_value: int = MIN_TAINT_VALUE) -> int:
    """Add ``dataflow`` edges to *graph* by value-equality taint.

    Walks ``graph.events`` in order. Each event's return value (if distinctive)
    is registered as produced by that call's node; each event's integer
    arguments are matched against everything produced so far, and a match adds a
    ``producer -> consumer`` dataflow edge annotated with the value and argument
    index. Returns the number of distinct edges created.
    """
    produced: dict[int, str] = {}   # value -> producer node id
    before = len(graph.edges)

    for ev in graph.events:
        nid = f"{ev['kind']}:{ev['name']}"
        # consume: any argument equal to a previously produced value
        for idx, arg in enumerate(ev.get("args", []) or []):
            if not isinstance(arg, int) or arg < min_value or arg in SENTINELS:
                continue
            src = produced.get(arg)
            if src is not None and src != nid:
                _add_dataflow(graph, src, nid, arg, idx)
        # produce: register this call's return value
        ret = ev.get("ret")
        if isinstance(ret, int) and ret not in SENTINELS and ret >= min_value:
            produced[ret] = nid

    return len(graph.edges) - before


def _add_dataflow(graph: BehaviorGraph, src: str, dst: str, value: int,
                  arg_index: int) -> None:
    key = (src, dst, EdgeType.DATAFLOW)
    edge = graph.edges.get(key)
    if edge is None:
        graph.edges[key] = {
            "source": src, "target": dst, "type": EdgeType.DATAFLOW,
            "count": 1, "value": hex(value), "arg": arg_index,
        }
    else:
        edge["count"] += 1
