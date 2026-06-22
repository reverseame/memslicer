"""``memslicer-symbex`` — load an MSL slice into angr for symbolic execution.

Loads the captured memory + registers into an angr state positioned at the
captured PC, then optionally explores to / away from addresses.

Requires the ``symbex`` extra::  pip install memslicer[symbex]
"""
from __future__ import annotations

import click

from memslicer.symbex.angr_loader import load_angr, SymbexError


def _addrs(values):
    return [int(v, 0) for v in values]


@click.command()
@click.argument("dump", type=click.Path(exists=True, dir_okay=False))
@click.option("-f", "--find", multiple=True,
              help="Address(es) to reach (repeatable)")
@click.option("-a", "--avoid", multiple=True,
              help="Address(es) to avoid (repeatable)")
@click.option("-s", "--steps", type=int, default=0,
              help="Symbolic steps to run when no --find is given")
def main(dump, find, avoid, steps):
    """Load the MSL slice DUMP into angr."""
    try:
        project, state = load_angr(dump)
    except SymbexError as exc:
        raise click.ClickException(str(exc))

    click.echo(f"arch    : {project.arch.name}")
    click.echo(f"entry   : {state.addr:#x}")
    click.echo(f"loaded  : {project.loader.min_addr:#x}-{project.loader.max_addr:#x}")

    simgr = project.factory.simgr(state)

    if find:
        simgr.explore(find=_addrs(find), avoid=_addrs(avoid) or None)
        if simgr.found:
            s = simgr.found[0]
            click.echo(f"\nreached {s.addr:#x} in {len(s.history.bbl_addrs)} blocks")
            try:
                stdin = s.posix.dumps(0)
                if stdin:
                    click.echo(f"stdin   : {stdin!r}")
            except Exception:  # noqa: BLE001
                pass
        else:
            click.echo("\ntarget not reachable")
    elif steps > 0:
        for _ in range(steps):
            if not simgr.active:
                break
            simgr.step()
        click.echo(f"\nactive states: {len(simgr.active)}")
        for s in simgr.active[:8]:
            click.echo(f"  pc = {s.addr:#x}")
    else:
        click.echo("\nloaded into angr; use --find ADDR (and --avoid) or --steps N")


if __name__ == "__main__":
    main()
