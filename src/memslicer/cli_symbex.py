"""``memslicer-symbex`` — load an MSL slice into angr for symbolic execution.

Loads the captured memory + registers into an angr state positioned at the
captured PC, then optionally explores to / away from addresses.

Requires the ``symbex`` extra::  pip install memslicer[symbex]
"""
from __future__ import annotations

from typing import Any
import click

from memslicer.symbex.angr_loader import load_angr, SymbexError
from memslicer.symbex.anti_analysis import apply_anti_analysis_bypass


def format_address(val: int | None) -> str:
    """Format register/address integer as canonical hex string."""
    if val is None:
        return "N/A"
    if isinstance(val, int):
        if val > 0xFFFFFFFF:
            return f"0x{val & 0xFFFFFFFFFFFFFFFF:016x}"
        return f"0x{val & 0xFFFFFFFF:08x}"
    return str(val)


def classify_memory_region(addr: int) -> str:
    """Classify virtual memory region."""
    if addr >= 0x7FF000000000 or addr >= 0x7FFF0000:
        return "Stack"
    elif addr >= 0xFF00000000000000 or addr >= 0x8000000000000000:
        return "Symbolic Virtual Memory"
    elif addr >= 0x140000000 or addr >= 0x400000:
        return "Executable Image"
    return "Heap"


def inspect_and_print_provenance(state: Any) -> None:
    """Inspect state constraints and print classified sources, pointers, and values."""
    click.echo("\n=================================================================")
    click.echo(" [CONSTRAINTS & SOURCE PROVENANCE INSPECTOR]")
    click.echo("=================================================================")

    findings: dict[str, Any] = {
        "STDIN": [],
        "Files": {},
        "Network Sockets": {},
        "CPU Registers": {},
        "RAM Memory": {},
        "CLI Arguments": [],
        "Environment Variables": [],
        "Pointer Mapping": {},
    }

    if not hasattr(state, "solver") or not hasattr(state.solver, "constraints"):
        click.echo(" [-] No active symbolic constraints found.")
        click.echo("=================================================================\n")
        return

    mem_bytes: dict[int, int] = {}

    for constraint in state.solver.constraints:
        variables = getattr(constraint, "variables", set())
        for var in variables:
            # CPU Registers
            if var.startswith("reg_"):
                parts = var.split("_")
                if len(parts) >= 2:
                    reg_name = parts[1]
                    try:
                        reg_val = state.solver.eval(getattr(state.regs, reg_name, None))
                        findings["CPU Registers"][reg_name] = reg_val
                    except Exception:
                        findings["CPU Registers"][reg_name] = "Symbolic"

            # RAM Memory
            elif var.startswith("mem_"):
                parts = var.split("_")
                if len(parts) >= 2:
                    try:
                        addr = int(parts[1], 16)
                        byte_val = state.solver.eval(state.memory.load(addr, 1))
                        if isinstance(byte_val, int):
                            mem_bytes[addr] = byte_val
                    except Exception:
                        pass

            # STDIN Channel
            elif "stdin" in var or var.startswith("file_0_"):
                try:
                    if hasattr(state, "posix") and hasattr(state.posix, "dumps"):
                        val = state.posix.dumps(0)
                        if val and val not in findings["STDIN"]:
                            findings["STDIN"].append(val)
                except Exception:
                    pass

            # Network Sockets
            elif "socket" in var or "net" in var:
                parts = var.split("_")
                fd_name = parts[1] if len(parts) > 1 else var
                try:
                    val = state.solver.eval(constraint, cast_to=bytes)
                    findings["Network Sockets"][fd_name] = val
                except Exception:
                    findings["Network Sockets"][fd_name] = "Symbolic Data"

            # Disk Files
            elif var.startswith("file_"):
                parts = var.split("_")
                file_name = parts[1] if len(parts) > 1 else var
                try:
                    val = state.solver.eval(constraint, cast_to=bytes)
                    findings["Files"][file_name] = val
                except Exception:
                    findings["Files"][file_name] = "Symbolic Content"

            # CLI Arguments
            elif var.startswith("arg_") or "argv" in var:
                try:
                    val = state.solver.eval(constraint, cast_to=bytes)
                    if val not in findings["CLI Arguments"]:
                        findings["CLI Arguments"].append(val)
                except Exception:
                    pass

    # Reconstruct memory string and map register pointers
    if mem_bytes:
        sorted_addrs = sorted(mem_bytes.keys())
        start_addr = sorted_addrs[0]
        end_addr = sorted_addrs[-1]
        raw_bytes = bytes([mem_bytes[a] for a in sorted_addrs])
        decoded_text = raw_bytes.decode("latin-1", errors="ignore")

        findings["RAM Memory"] = {
            "start_address": format_address(start_addr),
            "end_address": format_address(end_addr),
            "region": classify_memory_region(start_addr),
            "raw_hex": raw_bytes.hex(),
            "decoded_text": decoded_text,
            "bytes_count": len(raw_bytes),
        }

        for reg_name, reg_val in findings["CPU Registers"].items():
            if isinstance(reg_val, int) and reg_val == start_addr:
                findings["Pointer Mapping"][reg_name] = (
                    f"{reg_name.upper()} ({format_address(reg_val)}) ---> Points to text: '{decoded_text}'"
                )

    has_data = False

    # Print Pointer Mapping
    if findings["Pointer Mapping"]:
        has_data = True
        click.echo("\n [+] POINTER & CONTENT MAPPING:")
        for reg_name, link_msg in findings["Pointer Mapping"].items():
            click.echo(f"     - {link_msg}")

    # Print RAM Memory
    if findings["RAM Memory"]:
        has_data = True
        ram = findings["RAM Memory"]
        click.echo("\n [+] DETECTED SOURCE: RAM Memory")
        click.echo(f"     - Memory Range     : {ram['start_address']} - {ram['end_address']}")
        click.echo(f"     - Memory Region    : {ram['region']}")
        click.echo(f"     - Resolved Text    : '{ram['decoded_text']}'")
        click.echo(f"     - Bytes (Hex)      : {ram['raw_hex']}")

    # Print CPU Registers
    if findings["CPU Registers"]:
        has_data = True
        click.echo("\n [+] DETECTED SOURCE: CPU Registers")
        for k, v in findings["CPU Registers"].items():
            formatted_val = format_address(v) if isinstance(v, int) else v
            click.echo(f"     - Register {k:<5} = {formatted_val}")

    # Print other channels
    for category in ["STDIN", "Files", "Network Sockets", "CLI Arguments"]:
        data = findings[category]
        if data:
            has_data = True
            click.echo(f"\n [+] DETECTED SOURCE: {category}")
            if isinstance(data, dict):
                for k, v in data.items():
                    click.echo(f"     - {k} = {v}")
            elif isinstance(data, list):
                for item in data:
                    click.echo(f"     - Value: {item!r}")

    if not has_data:
        click.echo(" [-] No active symbolic sources or constraints detected.")

    click.echo("=================================================================\n")


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
@click.option("-v", "--veritesting", "veritesting", is_flag=True, help="Enables veritesting, mitigating state explosion")
@click.option("-b", "--bypass-anti-analysis", "bypass_anti_analysis", is_flag=True, 
              help="Bypasses anti-debugging APIs (IsDebuggerPresent) and PEB flags")
def main(dump, find, avoid, steps, veritesting, bypass_anti_analysis):
    """Load the MSL slice DUMP into angr."""
    try:
        project, state = load_angr(dump)
    except SymbexError as exc:
        raise click.ClickException(str(exc))

    click.echo(f"arch    : {project.arch.name}")
    click.echo(f"entry   : {state.addr:#x}")
    click.echo(f"loaded  : {project.loader.min_addr:#x}-{project.loader.max_addr:#x}")

    # In case anti_analysis is enabled we hook the functions
    if bypass_anti_analysis:
        apply_anti_analysis_bypass(project=project, state=state)

    simgr = project.factory.simgr(state, veritesting=veritesting)

    if find:
        simgr.explore(find=_addrs(find), avoid=_addrs(avoid) or None)
        if simgr.found:
            s = simgr.found[0]
            click.echo(f"\nreached {s.addr:#x} in {len(s.history.bbl_addrs)} blocks")
            inspect_and_print_provenance(s)
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
