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
            "func": ("component", "lightyellow"),
        }
        lines = ["digraph behavior {", "  rankdir=LR;",
                 '  node [fontname="monospace"];']
        for node in self.nodes.values():
            shape, color = styles.get(node["kind"], ("box", "white"))
            # a block that wrote to executable memory (self-modifying) stands out
            if node["attrs"].get("writes_exec"):
                color = "tomato"
            label = _dot_escape(node["label"])
            if node["hits"] > 1:
                label += f"\\n(x{node['hits']})"
            if node["attrs"].get("writes_exec"):
                label += f"\\n[writes exec x{node['attrs']['writes_exec']}]"
            lines.append(
                f'  "{node["id"]}" [label="{label}", shape={shape}, '
                f'style=filled, fillcolor={color}];'
            )
        for edge in self.edges.values():
            etype = edge["type"]
            if etype == "dataflow":
                lbl = f'{etype} {edge["value"]}' if edge.get("value") else etype
                attrs = f'label="{lbl}", color=red, style=bold, constraint=false'
            elif etype == "buffer":
                lbl = f'{etype} {edge["value"]}' if edge.get("value") else etype
                attrs = (f'label="{lbl}", color=orange, style=dashed, '
                         'constraint=false')
            elif etype == EventKind.SYSCALL or etype == "invoke":
                attrs = f'label="{etype}", style=dashed'
            else:
                attrs = f'label="{etype}"'
            lines.append(
                f'  "{edge["source"]}" -> "{edge["target"]}" [{attrs}];'
            )
        lines.append("}")
        return "\n".join(lines)

    # -- GraphML / GEXF (dependency-free XML) --------------------------------

    # node/edge attributes promoted to typed graph attributes on export
    _NODE_KEYS = [("kind", "string"), ("label", "string"), ("addr", "long"),
                  ("hits", "int"), ("category", "string"),
                  ("calls", "int"), ("writes_exec", "int")]
    _EDGE_KEYS = [("type", "string"), ("count", "int"), ("value", "string"),
                  ("arg", "int")]

    def _node_attr(self, node: dict, key: str):
        if key in node:
            return node[key]
        return node.get("attrs", {}).get(key)

    def to_graphml(self) -> str:
        """Serialize to GraphML (consumed by Gephi, yEd, networkx, igraph)."""
        out = ['<?xml version="1.0" encoding="UTF-8"?>',
               '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">']
        for name, typ in self._NODE_KEYS:
            out.append(f'  <key id="n_{name}" for="node" attr.name="{name}" '
                       f'attr.type="{typ}"/>')
        for name, typ in self._EDGE_KEYS:
            out.append(f'  <key id="e_{name}" for="edge" attr.name="{name}" '
                       f'attr.type="{typ}"/>')
        out.append('  <graph edgedefault="directed">')
        for node in self.nodes.values():
            out.append(f'    <node id="{_xml(node["id"])}">')
            for name, _typ in self._NODE_KEYS:
                val = self._node_attr(node, name)
                if val is not None:
                    out.append(f'      <data key="n_{name}">{_xml(val)}</data>')
            out.append('    </node>')
        for edge in self.edges.values():
            out.append(f'    <edge source="{_xml(edge["source"])}" '
                       f'target="{_xml(edge["target"])}">')
            for name, _typ in self._EDGE_KEYS:
                if name in edge and edge[name] is not None:
                    out.append(f'      <data key="e_{name}">'
                               f'{_xml(edge[name])}</data>')
            out.append('    </edge>')
        out += ['  </graph>', '</graphml>']
        return "\n".join(out)

    def to_gexf(self) -> str:
        """Serialize to GEXF 1.3 (Gephi's native format)."""
        node_attr = [(i, n, t) for i, (n, t) in enumerate(self._NODE_KEYS)
                     if n != "label"]
        edge_attr = [(i, n, t) for i, (n, t) in enumerate(self._EDGE_KEYS)]
        gtypes = {"string": "string", "int": "integer", "long": "long"}
        out = ['<?xml version="1.0" encoding="UTF-8"?>',
               '<gexf xmlns="http://gexf.net/1.3" version="1.3">',
               '  <graph defaultedgetype="directed">',
               '    <attributes class="node">']
        for i, name, typ in node_attr:
            out.append(f'      <attribute id="{i}" title="{name}" '
                       f'type="{gtypes.get(typ, "string")}"/>')
        out += ['    </attributes>', '    <attributes class="edge">']
        for i, name, typ in edge_attr:
            out.append(f'      <attribute id="{i}" title="{name}" '
                       f'type="{gtypes.get(typ, "string")}"/>')
        out += ['    </attributes>', '    <nodes>']
        for node in self.nodes.values():
            out.append(f'      <node id="{_xml(node["id"])}" '
                       f'label="{_xml(node.get("label", node["id"]))}">')
            vals = [(i, self._node_attr(node, name)) for i, name, _t in node_attr]
            vals = [(i, v) for i, v in vals if v is not None]
            if vals:
                out.append('        <attvalues>')
                for i, v in vals:
                    out.append(f'          <attvalue for="{i}" '
                               f'value="{_xml(v)}"/>')
                out.append('        </attvalues>')
            out.append('      </node>')
        out += ['    </nodes>', '    <edges>']
        for eid, edge in enumerate(self.edges.values()):
            out.append(f'      <edge id="{eid}" source="{_xml(edge["source"])}" '
                       f'target="{_xml(edge["target"])}" '
                       f'weight="{edge.get("count", 1)}" '
                       f'label="{_xml(edge["type"])}">')
            vals = [(i, edge.get(name)) for i, name, _t in edge_attr
                    if edge.get(name) is not None]
            if vals:
                out.append('        <attvalues>')
                for i, v in vals:
                    out.append(f'          <attvalue for="{i}" '
                               f'value="{_xml(v)}"/>')
                out.append('        </attvalues>')
            out.append('      </edge>')
        out += ['    </edges>', '  </graph>', '</gexf>']
        return "\n".join(out)

    def to_networkx(self):
        """Build a :class:`networkx.MultiDiGraph` (needs the optional networkx).

        A multigraph because two nodes can be joined by several edge *types*
        (e.g. a ``call`` and a ``dataflow`` edge)."""
        try:
            import networkx as nx
        except ImportError as exc:  # pragma: no cover - optional dep
            raise ImportError(
                "to_networkx() requires networkx: pip install networkx"
            ) from exc
        g = nx.MultiDiGraph(**{k: v for k, v in self.meta.items()
                               if isinstance(v, (str, int, float))})
        for node in self.nodes.values():
            attrs = {k: v for k, v in node.items() if k != "attrs"}
            attrs.update(node.get("attrs", {}))
            g.add_node(node["id"], **attrs)
        for edge in self.edges.values():
            attrs = {k: v for k, v in edge.items()
                     if k not in ("source", "target")}
            g.add_edge(edge["source"], edge["target"],
                       key=edge["type"], **attrs)
        return g

    # -- feature vector ------------------------------------------------------

    #: stable behavior categories (matches stubs.categorize) -> vector slots
    FEATURE_CATEGORIES = ("file", "network", "registry", "process", "memory",
                          "library", "crypto", "system", "other")
    FEATURE_NODE_KINDS = ("block", "insn", "syscall", "api", "func")
    FEATURE_EDGE_TYPES = ("fallthrough", "jump", "call", "ret", "seq",
                          "invoke", "dataflow", "buffer")

    def feature_vector(self) -> dict:
        """A flat, fixed-key numeric summary for graph-based ML / triage.

        Keys are stable across graphs (zero-filled when absent), so the values
        can be stacked straight into a feature matrix.
        """
        feats: dict[str, int] = {}
        feats["nodes"] = len(self.nodes)
        feats["edges"] = len(self.edges)
        for kind in self.FEATURE_NODE_KINDS:
            feats[f"n_{kind}"] = 0
        for node in self.nodes.values():
            key = f"n_{node['kind']}"
            if key in feats:
                feats[key] += 1
        for etype in self.FEATURE_EDGE_TYPES:
            feats[f"e_{etype}"] = 0
        for edge in self.edges.values():
            key = f"e_{edge['type']}"
            if key in feats:
                feats[key] += 1
        # behavior categories: count distinct calls per category from the trace
        for cat in self.FEATURE_CATEGORIES:
            feats[f"cat_{cat}"] = 0
        for ev in self.events:
            cat = ev.get("category")
            if cat in self.FEATURE_CATEGORIES:
                feats[f"cat_{cat}"] += 1
        feats["unique_apis"] = sum(1 for n in self.nodes.values()
                                   if n["kind"] == "api")
        feats["unique_syscalls"] = sum(1 for n in self.nodes.values()
                                       if n["kind"] == "syscall")
        feats["total_calls"] = len(self.events)
        mem = self.meta.get("memory", {})
        feats["mem_writes"] = mem.get("writes", 0)
        feats["mem_exec_writes"] = mem.get("exec_writes", 0)
        feats["rwx_regions"] = len(mem.get("rwx_regions", []))
        feats["dataflow_edges"] = self.meta.get("dataflow_edges", 0)
        return feats


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _xml(value) -> str:
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;"))
