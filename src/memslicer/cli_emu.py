"""``memslicer-emu`` — emulate / single-step an MSL slice (Unicorn + Capstone).

A slice is a static snapshot, so this advances execution by *emulation*: the
captured memory is mapped into a Unicorn CPU and registers are seeded from the
Current thread's Thread Context, then execution is stepped forward.

Requires the ``emu`` extra::  pip install memslicer[emu]
"""
from __future__ import annotations

import click

from memslicer.emu.loader import load_slice
from memslicer.emu.engine import MSLEmulator, EmuError


def _parse_addr(value: str | None) -> int | None:
    if value is None:
        return None
    return int(value, 0)


def _print_summary(image) -> None:
    click.echo(f"arch    : {image.arch.name}")
    click.echo(f"os      : {image.os.name}")
    click.echo(f"regions : {len(image.regions)}")
    click.echo(f"threads : {len(image.threads)}")
    entry = image.entry
    click.echo(f"entry   : {entry:#x}" if entry is not None else "entry   : (none)")


def _dump_registers(emu: MSLEmulator) -> None:
    for name, val in emu.registers().items():
        click.echo(f"  {name:<7}= {val:#018x}")


def _trace(emu: MSLEmulator, results) -> None:
    prev = emu.registers()
    for res in results:
        now = emu.registers()
        changed = " ".join(
            f"{k}={now[k]:#x}" for k in now if now.get(k) != prev.get(k)
        )
        click.echo(f"  {res}" + (f"    [{changed}]" if changed else ""))
        prev = now
        if not res.ok:
            break


@click.command()
@click.argument("dump", type=click.Path(exists=True, dir_okay=False))
@click.option("-s", "--steps", type=int, default=0,
              help="Single-step this many instructions")
@click.option("-u", "--until", "until_addr", default=None,
              help="Step until this address (hex or decimal)")
@click.option("--pc", "pc_override", default=None,
              help="Override the start program counter")
@click.option("--max-steps", type=int, default=100000,
              help="Safety cap when using --until")
@click.option("-r", "--registers", "show_regs", is_flag=True,
              help="Dump registers after stepping")
def main(dump, steps, until_addr, pc_override, show_regs, max_steps):
    """Emulate the MSL slice DUMP."""
    image = load_slice(dump)
    _print_summary(image)
    try:
        emu = MSLEmulator(image)
    except EmuError as exc:
        raise click.ClickException(str(exc))

    pc = _parse_addr(pc_override)
    if pc is not None:
        emu.pc = pc

    if steps > 0 or until_addr is not None:
        click.echo("")
        click.echo(f"[start pc = {emu.pc:#x}]")
        if until_addr is not None:
            target = _parse_addr(until_addr)
            _trace(emu, emu.step_until(target, max_steps=max_steps))
        else:
            def _stepper():
                for _ in range(steps):
                    res = emu.step()
                    yield res
                    if not res.ok:
                        return
            _trace(emu, _stepper())

    if show_regs:
        click.echo("")
        click.echo("registers:")
        _dump_registers(emu)


if __name__ == "__main__":
    main()
