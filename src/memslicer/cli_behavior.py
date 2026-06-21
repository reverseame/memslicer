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
@click.option("--stubs", type=click.Path(exists=True, dir_okay=False),
              default=None, help="Load analyst-edited syscall/API stubs.")
@click.option("--emit-stubs", type=click.Path(dir_okay=False), default=None,
              help="After the run, write an editable stub skeleton here.")
@click.option("-o", "--output", type=click.Path(dir_okay=False), default=None,
              help="Write the graph to FILE (.json or .dot by extension).")
@click.option("-f", "--format", "fmt", type=click.Choice(["json", "dot"]),
              default=None, help="Output format (else inferred from -o).")
def main(dump, granularity, max_steps, start, stubs, emit_stubs, output, fmt):
    """Extract the behavior graph of the MSL slice DUMP."""
    registry = load_stubs(stubs) if stubs else None
    try:
        emu = open_slice(dump)
    except EmuError as exc:
        raise click.ClickException(str(exc))

    tracer = BehaviorTracer(emu, granularity=granularity, registry=registry)
    start_addr = int(start, 0) if start is not None else None
    graph = tracer.run(start=start_addr, max_steps=max_steps)

    if emit_stubs:
        emit_skeleton(tracer.registry, emit_stubs)
        click.echo(f"wrote stub skeleton: {emit_stubs}")

    if fmt is None and output:
        fmt = "dot" if output.lower().endswith(".dot") else "json"
    text = graph.to_dot() if fmt == "dot" else graph.to_json()

    if output:
        with open(output, "w") as f:
            f.write(text)
        click.echo(f"wrote {fmt or 'json'} graph: {output}")
    elif fmt:
        click.echo(text)

    m = graph.meta
    click.echo(
        f"arch={m.get('arch')} entry={m.get('entry')} "
        f"steps={m.get('steps')} nodes={len(graph.nodes)} "
        f"edges={len(graph.edges)} syscalls={len(graph.events)} "
        f"stop={m.get('stop_reason')!r}"
    )


if __name__ == "__main__":
    main()
