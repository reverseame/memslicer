"""Lightweight inter-call data-flow (A1): value-equality taint.

A full taint engine tracks every byte through registers and memory. That is
expensive and, for a *behavior* graph, more than we need: what matters is the
causal chain between system interactions -- the handle ``CreateFile`` returns
and ``WriteFile`` later consumes, the address ``VirtualAlloc`` returns and
``WriteProcessMemory`` writes to, the socket ``socket`` returns and ``connect``
uses.

So we approximate taint by *value equality*: a call "produces" its return value
and "consumes" its integer arguments. Two relationships fall out of one linear
pass over the ordered event trace:

* ``dataflow`` -- a later call consumes a value an earlier call *returned*
  (provenance: the handle ``CreateFile`` returns, used by ``WriteFile``).
* ``buffer`` -- two calls pass the *same pointer/handle as an argument*, neither
  having produced it (co-use: ``ReadFile`` fills ``buf``, ``send`` ships it;
  ``sprintf`` formats ``buf``, ``CreateProcess`` runs it). Consecutive users of
  the same value are chained, so the buffer's life shows as a path.

This is cheap, backend-agnostic (it reads only ``graph.events``, which both the
Unicorn and Speakeasy backends fill the same way), and surprisingly informative
for malware triage.

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


def link_dataflow(graph: BehaviorGraph, *, min_value: int = MIN_TAINT_VALUE,
                  buffers: bool = True) -> int:
    """Add ``dataflow`` (and, when *buffers*, ``buffer``) edges to *graph*.

    Walks ``graph.events`` in order. A distinctive return value is registered as
    produced by that call's node; a matching argument in a later call adds a
    ``dataflow`` edge (producer -> consumer). When *buffers* is set, a pointer or
    handle passed as an argument by two different calls links the earlier user to
    the later one with a ``buffer`` edge, chaining consecutive users. Edges carry
    the shared value and the consuming argument index. Returns the number of
    edges created.
    """
    produced: dict[int, str] = {}     # value -> producer node id (returned it)
    arg_users: dict[int, str] = {}    # value -> last node that used it as an arg
    before = len(graph.edges)

    for ev in graph.events:
        nid = f"{ev['kind']}:{ev['name']}"
        for idx, arg in enumerate(ev.get("args", []) or []):
            if not isinstance(arg, int) or arg < min_value or arg in SENTINELS:
                continue
            src = produced.get(arg)
            if src is not None and src != nid:
                _add_edge(graph, src, nid, EdgeType.DATAFLOW, arg, idx)
            if buffers:
                prev = arg_users.get(arg)
                if prev is not None and prev != nid:
                    _add_edge(graph, prev, nid, EdgeType.BUFFER, arg, idx)
                arg_users[arg] = nid
        ret = ev.get("ret")
        if isinstance(ret, int) and ret not in SENTINELS and ret >= min_value:
            produced[ret] = nid

    return len(graph.edges) - before


def _add_edge(graph: BehaviorGraph, src: str, dst: str, etype: str, value: int,
              arg_index: int) -> None:
    key = (src, dst, etype)
    edge = graph.edges.get(key)
    if edge is None:
        graph.edges[key] = {
            "source": src, "target": dst, "type": etype,
            "count": 1, "value": hex(value), "arg": arg_index,
        }
    else:
        edge["count"] += 1
