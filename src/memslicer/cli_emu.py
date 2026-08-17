"""``memslicer-emu`` — emulate / single-step an MSL slice (Unicorn + Capstone).

A slice is a static snapshot, so this advances execution by *emulation*: the
captured memory is mapped into a Unicorn CPU and registers are seeded from a
thread's Thread Context (the Current thread by default, or ``--thread TID``),
then execution is stepped forward. Use ``--list-threads`` to see what was
captured.

A slice is often captured parked in a blocking library/syscall (e.g. a Sleep),
so its PC sits in ntdll/kernel and stepping forward would hit a syscall the
emulator can't service. ``--resume-from-syscall`` unwinds that: it finds the
caller's return address on the stack and continues in the program image as if
the call had returned.

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


def _parse_range(value: str | None) -> "tuple[int, int] | None":
    if not value:
        return None
    lo, sep, hi = value.partition(":")
    if not sep or not hi:
        raise click.ClickException(
            "--image-range expects LO:HI (e.g. 0xb0000:0xd5000)")
    return int(lo, 0), int(hi, 0)


def _module_loc(image, addr: int) -> str | None:
    """Format ``addr`` as ``module+offset`` if it falls inside a captured
    module, else None."""
    for m in image.modules:
        if m.base <= addr < m.base + m.size:
            return f"{m.name}+{addr - m.base:#x}"
    return None


def _print_summary(image) -> None:
    click.echo(f"arch    : {image.arch.name}")
    click.echo(f"os      : {image.os.name}")
    click.echo(f"regions : {len(image.regions)}")
    click.echo(f"threads : {len(image.threads)}")
    entry = image.entry
    click.echo(f"entry   : {entry:#x}" if entry is not None else "entry   : (none)")


def _print_threads(image) -> None:
    """List captured threads; the Current thread (default seed) is marked '*'."""
    if not image.threads:
        click.echo("threads : (none captured)")
        return
    click.echo("threads :")
    for t in image.threads:
        mark = "*" if t.is_current else " "
        pc = t.pc
        pcs = f"{pc:#x}" if pc is not None else "?"
        click.echo(f"  {mark} tid={t.tid:<8} pc={pcs:<18} regs={len(t.registers)}")


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
@click.option("-R", "--resume-from-syscall", "resume_syscall", is_flag=True,
              help="Unwind out of the library/syscall the slice is parked in: "
                   "find the caller's return address on the stack and continue "
                   "in the program image as if the call had returned")
@click.option("--pop-bytes", type=int, default=0,
              help="With -R, also discard this many stdcall argument bytes "
                   "(the callee's 'ret N' cleanup, e.g. 4 for Sleep)")
@click.option("--image-range", default=None,
              help="With -R, target return addresses in LO:HI instead of the "
                   "auto-detected program image (e.g. 0xb0000:0xd5000)")
@click.option("--unwind-depth", type=int, default=256,
              help="With -R, max stack slots to scan for the return address")
@click.option("--max-steps", type=int, default=100000,
              help="Safety cap when using --until")
@click.option("-b", "--back", type=int, default=0,
              help="After stepping, step back this many instructions (reverse)")
@click.option("-t", "--thread", "thread_id", type=int, default=None,
              help="Seed registers from this captured thread id (default: Current thread)")
@click.option("-T", "--list-threads", "list_threads", is_flag=True,
              help="List captured threads and exit")
@click.option("-r", "--registers", "show_regs", is_flag=True,
              help="Dump registers after stepping")
@click.option("--dump-written", "dump_written_dir", default=None,
              type=click.Path(file_okay=False),
              help="After stepping, write dirtied memory ranges to this dir "
                   "(recovers unpacked/decoded payloads)")
def main(dump, steps, until_addr, pc_override, resume_syscall, pop_bytes,
         image_range, unwind_depth, show_regs, max_steps, back,
         thread_id, list_threads, dump_written_dir):
    """Emulate the MSL slice DUMP."""
    image = load_slice(dump)
    _print_summary(image)
    if list_threads:
        click.echo("")
        _print_threads(image)
        return
    try:
        emu = MSLEmulator(image, thread=thread_id)
    except EmuError as exc:
        raise click.ClickException(str(exc))
    if emu.thread is not None:
        cur = " (current)" if emu.thread.is_current else ""
        click.echo(f"thread  : tid={emu.thread.tid}{cur}")

    pc = _parse_addr(pc_override)
    if pc is not None:
        emu.pc = pc

    if resume_syscall:
        click.echo("")
        here = _module_loc(image, emu.pc)
        click.echo(f"[resume-from-syscall] pc = {emu.pc:#x}"
                   + (f"  ({here})" if here else ""))
        frame = emu.resume_from_syscall(
            image_range=_parse_range(image_range),
            max_depth=unwind_depth, pop_bytes=pop_bytes)
        if frame is None:
            raise click.ClickException(
                "no return address into the program image found on the stack "
                "(try --image-range LO:HI or a larger --unwind-depth)")
        where = f"  ({frame.module})" if frame.module else ""
        click.echo(f"  caller return @ {frame.return_addr:#x}{where}"
                   f"  [stack {frame.sp_slot:#x}, depth {frame.depth}]")
        click.echo(f"  resumed: pc -> {emu.pc:#x}, "
                   f"{emu.sp_name} -> {emu.read_reg(emu.sp_name):#x}")

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

    if back > 0:
        click.echo("")
        click.echo(f"[rewind {back}]")
        prev = emu.registers()
        for _ in range(back):
            if not emu.step_back():
                click.echo("  (no more history)")
                break
            now = emu.registers()
            changed = " ".join(
                f"{k}={now[k]:#x}" for k in now if now.get(k) != prev.get(k)
            )
            click.echo(f"  <- {emu.pc:#012x}" + (f"    [{changed}]" if changed else ""))
            prev = now

    wx = emu.self_modified_exec()
    if wx:
        click.echo("")
        click.echo(f"[self-modifying code: {len(wx)} write-then-execute site(s)]")
        for addr in wx[:8]:
            click.echo(f"  W->X @ {addr:#012x}")
        if len(wx) > 8:
            click.echo(f"  ... and {len(wx) - 8} more")

    if dump_written_dir is not None:
        dumped = emu.dump_written(dump_written_dir)
        click.echo("")
        if not dumped:
            click.echo("[no memory was written during emulation]")
        else:
            click.echo(f"[wrote {len(dumped)} dirtied range(s) to {dump_written_dir}]")
            for path, lo, hi, executed in dumped:
                tag = " (executed)" if executed else ""
                click.echo(f"  {lo:#012x}-{hi:#012x}  {hi - lo:#x} bytes{tag}  -> {path}")

    if show_regs:
        click.echo("")
        click.echo("registers:")
        _dump_registers(emu)


if __name__ == "__main__":
    main()
