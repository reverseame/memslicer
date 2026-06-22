"""The behavior graph and its serializers (JSON node-link, Graphviz DOT).

Granularity-agnostic: it consumes :class:`~memslicer.behavior.events.BehaviorEvent`
records and never inspects how they were produced. Code nodes are aggregated by
address (so a CFG/call-graph emerges and revisits bump a hit counter); syscall /
API nodes are aggregated by name. An ordered ``events`` trace is kept alongside
so the temporal sequence of system interactions is preserved.
"""
from __future__ import annotations

import json

from memslicer.behavior.events import BehaviorEvent, EventKind


class BehaviorGraph:
    def __init__(self) -> None:
        # node id -> {id, kind, label, addr, hits, attrs}
        self.nodes: dict[str, dict] = {}
        # (src, dst, type) -> {source, target, type, count}
        self.edges: dict[tuple[str, str, str], dict] = {}
        # ordered raw trace of system interactions (syscall/api)
        self.events: list[dict] = []
        self.meta: dict = {}

    # -- builder (consumes events) ------------------------------------------

    def consume(self, ev: BehaviorEvent) -> None:
        if ev.kind == EventKind.NODE:
            self._touch_node(self._code_id(ev.addr), ev.node_kind or "block",
                             label=ev.label, addr=ev.addr)
        elif ev.kind == EventKind.EDGE:
            self._touch_edge(ev.src, ev.dst, ev.edge_type)
        elif ev.kind in (EventKind.SYSCALL, EventKind.API):
            nid = f"{ev.kind}:{ev.label}"
            node = self._touch_node(nid, ev.kind, label=ev.label)
            node["attrs"].setdefault("calls", 0)
            node["attrs"]["calls"] += 1
            if ev.attrs.get("category"):
                node["attrs"]["category"] = ev.attrs["category"]
            self.events.append({
                "seq": ev.seq, "kind": ev.kind, "name": ev.label,
                "site": self._code_id(ev.addr), **ev.attrs,
            })

    def _code_id(self, addr: int) -> str:
        return f"0x{addr:x}"

    def _touch_node(self, nid: str, kind: str, *, label: str = "",
                    addr: int = 0) -> dict:
        node = self.nodes.get(nid)
        if node is None:
            node = {"id": nid, "kind": kind, "label": label or nid,
                    "addr": addr, "hits": 0, "attrs": {}}
            self.nodes[nid] = node
        if label:
            node["label"] = label
        node["hits"] += 1
        return node

    def touch_node_id(self, nid: str, kind: str, *, label: str = "",
                      addr: int = 0) -> dict:
        """Public helper for probes that need a node id back (e.g. the call
        site of a syscall) without going through an event."""
        return self._touch_node(nid, kind, label=label, addr=addr)

    def _touch_edge(self, src: str, dst: str, etype: str) -> None:
        if not src or not dst:
            return
        key = (src, dst, etype)
        edge = self.edges.get(key)
        if edge is None:
            self.edges[key] = {"source": src, "target": dst, "type": etype,
                               "count": 1}
        else:
            edge["count"] += 1

    def add_edge(self, src: str, dst: str, etype: str) -> None:
        """Public edge helper for probes operating on node ids directly."""
        self._touch_edge(src, dst, etype)

    # -- serialization -------------------------------------------------------

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps({
            "meta": self.meta,
            "nodes": list(self.nodes.values()),
            "links": list(self.edges.values()),
            "events": self.events,
        }, indent=indent)

    def to_dot(self) -> str:
        styles = {
            "block": ("box", "lightgray"),
            "insn": ("box", "white"),
            "syscall": ("ellipse", "khaki"),
            "api": ("ellipse", "lightblue"),
        }
        lines = ["digraph behavior {", "  rankdir=LR;",
                 '  node [fontname="monospace"];']
        for node in self.nodes.values():
            shape, color = styles.get(node["kind"], ("box", "white"))
            label = _dot_escape(node["label"])
            if node["hits"] > 1:
                label += f"\\n(x{node['hits']})"
            lines.append(
                f'  "{node["id"]}" [label="{label}", shape={shape}, '
                f'style=filled, fillcolor={color}];'
            )
        for edge in self.edges.values():
            attrs = f'label="{edge["type"]}"'
            if edge["type"] == EventKind.SYSCALL or edge["type"] == "invoke":
                attrs += ", style=dashed"
            lines.append(
                f'  "{edge["source"]}" -> "{edge["target"]}" [{attrs}];'
            )
        lines.append("}")
        return "\n".join(lines)


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')
