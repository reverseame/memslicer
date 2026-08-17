# tools

Companion utilities for MemSlicer output.

## `graph_viewer.html` — Behavior Graph Viewer

A self-contained, single-file web viewer for the node-link JSON produced by
`memslicer-behavior … -o graph.json`. Open it in a browser and drag the JSON
onto the page — no server needed (`file://` works).

```bash
memslicer-behavior dump.msl --stublib -o graph.json
open tools/graph_viewer.html        # then drop graph.json (or tools/example_graph.json)
```

It mirrors the styling of `BehaviorGraph.to_dot()`:

- **Node shape/colour by kind** — block (lightgray), insn (white), syscall
  (khaki), api (lightblue), func (lightyellow).
- **Tomato fill + red border** for blocks that wrote to executable memory
  (`attrs.writes_exec` — unpacking / self-modifying code / injection).
- **Edge colours** — `dataflow` red (a return value later passed as an
  argument), `buffer` orange dashed (two calls sharing a pointer/handle),
  `invoke`/`syscall` grey dashed, `call` blue, `ret` grey, and the CFG edges.

Sidebar: summary + `meta`, search, per-kind / per-edge-type filters with counts,
label toggles, an "only writes-exec paths" filter, and Fit / Freeze buttons.
Interaction: wheel to zoom, drag the background to pan, drag a node to pin it,
double-click a node to release it.

`example_graph.json` is a small sample (an ALINA-style behaviour chain:
unpack → enumerate processes → scrape → exfiltrate) exercising every node kind
and edge type.

> Loads D3 v7 from a CDN, so it needs internet on first use (the browser caches
> it afterwards). To run fully offline, drop a `d3.min.js` next to this file and
> change the `<script src>` to point at the local copy.
