"""``memslicer-behavior`` -- extract a behavior graph from an MSL slice.

Emulates the slice with Unicorn, instruments it with hooks, and writes a
behavior graph (control flow + syscalls/APIs) as JSON or Graphviz DOT.

System calls are modelled by an analyst-editable *stub skeleton*:

    memslicer-behavior dump.msl --emit-stubs stubs.py    # 1. discover calls
    # edit stubs.py to return what you need
    memslicer-behavior dump.msl --stubs stubs.py -o g.dot # 2. re-run with stubs

Requires the ``emu`` extra::  pip install memslicer[emu]
"""
from __future__ import annotations

import click

from memslicer.behavior.stublib import build_default_registry
from memslicer.behavior.stubs import emit_skeleton, load_stubs
from memslicer.behavior.tracer import BehaviorTracer
from memslicer.emu.engine import EmuError, open_slice


@click.command()
@click.argument("dump", type=click.Path(exists=True, dir_okay=False))
@click.option("-g", "--granularity", type=click.Choice(["block", "instruction"]),
              default="block", help="Graph node granularity. [default: block]")
@click.option("-n", "--max-steps", type=int, default=100000,
              help="Maximum instructions to emulate. [default: 100000]")
@click.option("--start", default=None, help="Override start address (hex/dec).")
@click.option("--backend", type=click.Choice(["unicorn", "speakeasy"]),
              default="unicorn",
              help="Emulation backend. 'speakeasy' gives high-fidelity Windows "
              "API emulation (needs the speakeasy extra). [default: unicorn]")
@click.option("--stublib", is_flag=True, default=False,
              help="Start from the bundled, categorized stub library.")
@click.option("--stubs", type=click.Path(exists=True, dir_okay=False),
              default=None, help="Load analyst-edited syscall/API stubs "
              "(merged on top of --stublib if both are given).")
@click.option("--memory/--no-memory", "memory", default=True,
              help="Annotate memory writes (RWX, self-modifying code, region "
              "type). [default: on]")
@click.option("--call-graph", is_flag=True, default=False,
              help="Overlay a dynamic call graph (function nodes + call/ret).")
@click.option("--emit-stubs", type=click.Path(dir_okay=False), default=None,
              help="After the run, write an editable stub skeleton here.")
@click.option("-o", "--output", type=click.Path(dir_okay=False), default=None,
              help="Write the graph to FILE (.json or .dot by extension).")
@click.option("-f", "--format", "fmt",
              type=click.Choice(["json", "dot", "graphml", "gexf"]),
              default=None, help="Output format (else inferred from -o).")
@click.option("--features", type=click.Path(dir_okay=False), default=None,
              help="Write a per-graph feature vector (JSON) to FILE.")
def main(dump, granularity, max_steps, start, backend, memory, call_graph,
         stublib, stubs, emit_stubs, output, fmt, features):
    """Extract the behavior graph of the MSL slice DUMP."""
    registry = build_default_registry() if stublib else None
    if stubs:
        edited = load_stubs(stubs)
        registry = registry.merge(edited) if registry else edited

    if backend == "speakeasy":
        graph = _run_speakeasy(dump, granularity, registry)
        _write_graph(graph, output, fmt)
        _write_features(graph, features)
        return

    try:
        emu = open_slice(dump)
    except EmuError as exc:
        raise click.ClickException(str(exc))

    tracer = BehaviorTracer(emu, granularity=granularity, registry=registry,
                            memory=memory, call_graph=call_graph)
    start_addr = int(start, 0) if start is not None else None
    graph = tracer.run(start=start_addr, max_steps=max_steps)

    if emit_stubs:
        emit_skeleton(tracer.registry, emit_stubs)
        click.echo(f"wrote stub skeleton: {emit_stubs}")

    _write_graph(graph, output, fmt)
    _write_features(graph, features)


def _run_speakeasy(dump, granularity, registry):
    """Drive the Speakeasy backend over the slice's main PE image."""
    from memslicer.behavior.speakeasy_backend import (
        SpeakeasyUnavailable, trace_slice_speakeasy,
    )
    gran = granularity if granularity == "instruction" else None
    try:
        return trace_slice_speakeasy(dump, granularity=gran, registry=registry)
    except SpeakeasyUnavailable as exc:
        raise click.ClickException(str(exc))


_EXT_FMT = {".dot": "dot", ".graphml": "graphml", ".gexf": "gexf",
            ".json": "json"}
_SERIALIZERS = {
    "dot": lambda g: g.to_dot(),
    "graphml": lambda g: g.to_graphml(),
    "gexf": lambda g: g.to_gexf(),
    "json": lambda g: g.to_json(),
}


def _write_features(graph, features):
    if not features:
        return
    import json
    with open(features, "w") as f:
        json.dump(graph.feature_vector(), f, indent=2)
    click.echo(f"wrote feature vector: {features}")


def _write_graph(graph, output, fmt):
    if fmt is None and output:
        ext = output[output.rfind("."):].lower() if "." in output else ""
        fmt = _EXT_FMT.get(ext, "json")
    text = _SERIALIZERS.get(fmt, _SERIALIZERS["json"])(graph)

    if output:
        with open(output, "w") as f:
            f.write(text)
        click.echo(f"wrote {fmt or 'json'} graph: {output}")
    elif fmt:
        click.echo(text)

    m = graph.meta
    click.echo(
        f"arch={m.get('arch')} entry={m.get('entry')} "
        f"steps={m.get('steps', m.get('api_calls'))} nodes={len(graph.nodes)} "
        f"edges={len(graph.edges)} syscalls={len(graph.events)} "
        f"stop={m.get('stop_reason')!r}"
    )


if __name__ == "__main__":
    main()
