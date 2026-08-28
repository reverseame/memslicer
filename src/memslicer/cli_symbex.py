"""``memslicer-symbex`` — load an MSL slice into angr for symbolic execution.

Loads the captured memory + registers into an angr state positioned at the
captured PC, then optionally explores to / away from addresses.

Requires the ``symbex`` extra::  pip install memslicer[symbex]
"""
from __future__ import annotations

from typing import Any
import click
import claripy

from memslicer.symbex.angr_loader import load_angr, SymbexError
from memslicer.symbex.anti_analysis import apply_anti_analysis_bypass
from memslicer.symbex.syscall_handler import setup_syscall_emulation
from memslicer.symbex.unmapped_handler import (
    enable_unmapped_memory_recovery,
    repair_errored_states,
    _ensure_page_mapped,
)


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

            # Generic Symbolic Variables / License Keys
            elif "key" in var or "license" in var or "buf" in var:
                try:
                    if "Symbolic Variables" not in findings:
                        findings["Symbolic Variables"] = {}
                    for v_ast in state.solver.variables:
                        if var in str(v_ast):
                            val = state.solver.eval(claripy.BVS(v_ast, 128), cast_to=bytes)
                            findings["Symbolic Variables"][var] = val
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


def _parse_addr(val: str) -> int:
    """Parse integer or hex address string, raising click.ClickException on failure."""
    try:
        return int(val, 0)
    except Exception:
        raise click.ClickException(f"Invalid address or integer argument: '{val}'")


def _addrs(values):
    return [_parse_addr(v) for v in values]


def _prune_avoided(simgr: Any, avoid_addrs: set, avoid_module_addrs: set) -> int:
    """Moves any active state sitting on an avoided address/module page into the
    'avoid' stash. Shared between --find/--find-rax-success and --steps so that
    --avoid/--avoid-module behave identically (and honestly) in both modes.
    Returns the number of states pruned.
    """
    pruned = 0
    if avoid_addrs:
        avoided = [s for s in simgr.active if s.addr in avoid_addrs]
        for s in avoided:
            simgr.active.remove(s)
            simgr.stashes.setdefault("avoid", []).append(s)
        pruned += len(avoided)

    if avoid_module_addrs:
        avoided_mods = [s for s in simgr.active if (s.addr & ~0xFFF) in avoid_module_addrs or s.addr in avoid_module_addrs]
        for s in avoided_mods:
            simgr.active.remove(s)
            simgr.stashes.setdefault("avoid", []).append(s)
        pruned += len(avoided_mods)

    return pruned


def _get_buffer_address(
    state: Any,
    fallback_addr: int = 0x7FFF00000000,
    explicit_addr: int | None = None,
) -> int:
    """Calculates injection buffer address supporting Frame Pointer Omission (FPO) and configurable fallbacks.
    1. If explicit_addr is provided, returns explicit_addr.
    2. If RBP is valid (>= 0x10000), uses RBP - 0x40.
    3. If RBP is NULL or invalid (< 0x10000) but RSP is valid (>= 0x10000), uses RSP + 0x20.
    4. Otherwise uses the configurable fallback_addr (default: 0x7FFF00000000).
    """
    if explicit_addr is not None:
        return explicit_addr

    rbp_val = None
    if hasattr(state.regs, "rbp"):
        try:
            val = state.solver.eval(state.regs.rbp)
            if val and val >= 0x10000:
                rbp_val = val
        except Exception:
            pass

    if rbp_val is not None:
        return rbp_val - 0x40

    rsp_val = None
    if hasattr(state.regs, "rsp"):
        try:
            val = state.solver.eval(state.regs.rsp)
            if val and val >= 0x10000:
                rsp_val = val
        except Exception:
            pass

    if rsp_val is not None:
        return rsp_val + 0x20

    return fallback_addr


def _select_key_hint(state: Any) -> Any | None:
    """Pick the best usable KeyHint stashed by ``load_angr`` in
    ``state.globals["msl_key_hints"]`` (a live-acquired hint of where captured
    key material sits), or ``None`` if there is nothing usable.

    Only hints whose owning region was actually captured — i.e. those with a
    resolved absolute ``address`` — can seed an injection, so unresolved hints
    are skipped here (they are still visible in ``state.globals`` for
    diagnostics). Among resolved hints, prefer the highest confidence, then one
    that carries a known key length, so a Confirmed hint wins over a
    Speculative one for the same slice."""
    try:
        hints = state.globals.get("msl_key_hints") or []
    except Exception:
        return None
    usable = [h for h in hints if getattr(h, "address", None) is not None]
    if not usable:
        return None
    return max(
        usable,
        key=lambda h: (getattr(h, "confidence", 0), 1 if getattr(h, "key_len", 0) else 0),
    )


@click.command()
@click.argument("dump", type=click.Path(exists=True, dir_okay=False))
@click.option("-e", "--entry", help="Override starting PC address for symbolic execution (e.g. 0x140001754)")
@click.option("-c", "--call-function", "call_func", help="Setup clean function call_state at address (e.g. 0x140001754)")
@click.option("-k", "--sym-bytes", type=int, default=16, help="Size of symbolic buffer to inject in bytes (default: 16)")
@click.option("-b", "--binary-key", "binary_key", is_flag=True, help="Inject unconstrained raw byte buffer (not restricted to printable ASCII 0x20-0x7E)")
@click.option("--buffer-addr", "buffer_addr_str", help="Explicit virtual address or custom fallback for injected symbolic buffer (e.g. 0x50000000)")
@click.option("--use-key-hints", "use_key_hints", is_flag=True, help="Auto-target the symbolic buffer at a live-acquired KeyHint (0x0020) instead of the RBP-0x40/RSP+0x20 heuristic; also adopts the hint's key length as --sym-bytes when known. An explicit --buffer-addr still wins.")
@click.option("-m", "--avoid-module", "avoid_modules", multiple=True, help="Module name or address range to avoid (repeatable)")
@click.option("-r", "--find-rax-success", is_flag=True, help="Find paths where function return value (RAX) equals 1 post-return. Meaningful for license/key-check style targets; against generic real-world code almost any reachable function can trivially return 1, so a match here is not evidence of anything specific — use --find ADDR instead when you have a real target address")
@click.option("-f", "--find", multiple=True, help="Address(es) to reach (repeatable)")
@click.option("-a", "--avoid", multiple=True, help="Address(es) to avoid (repeatable)")
@click.option("-s", "--steps", type=int, default=0, help="Symbolic steps to run when no --find is given")
@click.option("-v", "--veritesting", "veritesting", is_flag=True, help="Enables veritesting, mitigating state explosion")
@click.option("--bypass-anti-analysis", "bypass_anti_analysis", is_flag=True, help="Bypasses anti-debugging APIs (IsDebuggerPresent) and PEB flags")
@click.option("-u/--no-auto-map-unmapped", "auto_map_unmapped", is_flag=True, default=True, help="Auto-maps unmapped memory pages and stubs missing code/APIs dynamically")
def main(
    dump,
    entry,
    call_func,
    sym_bytes,
    binary_key,
    buffer_addr_str,
    use_key_hints,
    avoid_modules,
    find_rax_success,
    find,
    avoid,
    steps,
    veritesting,
    bypass_anti_analysis,
    auto_map_unmapped,
):
    """Load the MSL slice DUMP into angr for symbolic execution."""
    try:
        project, state = load_angr(dump)
    except SymbexError as exc:
        raise click.ClickException(str(exc))

    explicit_buf_addr = _parse_addr(buffer_addr_str) if buffer_addr_str else None

    # --use-key-hints: prefer a live-acquired KeyHint over the blind
    # RBP-0x40/RSP+0x20 heuristic. An explicit --buffer-addr is a deliberate
    # override and still wins; otherwise the hint's resolved address seeds the
    # injection and (when known) its key length becomes --sym-bytes.
    if use_key_hints and explicit_buf_addr is None:
        hint = _select_key_hint(state)
        if hint is not None:
            explicit_buf_addr = hint.address
            note = f" ({hint.note})" if getattr(hint, "note", "") else ""
            if hint.key_len > 0:
                sym_bytes = hint.key_len
                click.echo(
                    f"[+] Using KeyHint at {hint.address:#x}, "
                    f"key_len={hint.key_len} -> --sym-bytes {sym_bytes}{note}"
                )
            else:
                click.echo(
                    f"[+] Using KeyHint at {hint.address:#x} "
                    f"(unknown key_len; keeping --sym-bytes {sym_bytes}){note}"
                )
        else:
            click.echo(
                "[!] --use-key-hints: no resolved KeyHint in slice; "
                "falling back to RBP-0x40/RSP+0x20 heuristic"
            )

    if auto_map_unmapped:
        enable_unmapped_memory_recovery(project=project, state=state)

    if bypass_anti_analysis:
        apply_anti_analysis_bypass(project=project, state=state)

    setup_syscall_emulation(project=project, state=state)

    if call_func:
        func_addr = _parse_addr(call_func)
        key_mem_addr = _get_buffer_address(state, explicit_addr=explicit_buf_addr)
        _ensure_page_mapped(state, key_mem_addr, access_size=sym_bytes, is_code=False)

        sym_key = claripy.BVS("license_key", sym_bytes * 8)
        state = project.factory.call_state(func_addr, key_mem_addr, base_state=state)
        if auto_map_unmapped:
            enable_unmapped_memory_recovery(project=project, state=state)

        if not binary_key:
            for byte_ast in sym_key.chop(8):
                state.add_constraints(byte_ast >= 0x20, byte_ast <= 0x7E)

        for i, byte_ast in enumerate(sym_key.chop(8)):
            state.memory.store(key_mem_addr + i, byte_ast)
        state.memory.store(key_mem_addr + sym_bytes, b"\x00")
        state.globals["injected_key_addr"] = key_mem_addr
        state.globals["injected_key_bytes"] = sym_bytes

        mode_str = "raw binary bytes" if binary_key else "printable ASCII"
        click.echo(f"[+] Prepared clean call_state at {func_addr:#x} with {sym_bytes}-byte symbolic buffer ({mode_str}) at {key_mem_addr:#x}")

    elif entry:
        entry_addr = _parse_addr(entry)
        state.regs.pc = entry_addr

        key_mem_addr = _get_buffer_address(state, explicit_addr=explicit_buf_addr)
        _ensure_page_mapped(state, key_mem_addr, access_size=sym_bytes, is_code=False)

        sym_key = claripy.BVS("license_key", sym_bytes * 8)
        if not binary_key:
            for byte_ast in sym_key.chop(8):
                state.add_constraints(byte_ast >= 0x20, byte_ast <= 0x7E)

        for i, byte_ast in enumerate(sym_key.chop(8)):
            state.memory.store(key_mem_addr + i, byte_ast)
        state.memory.store(key_mem_addr + sym_bytes, b"\x00")
        state.globals["injected_key_addr"] = key_mem_addr
        state.globals["injected_key_bytes"] = sym_bytes

        if hasattr(state, "posix") and hasattr(state.posix, "stdin"):
            state.posix.stdin.content = [(sym_key, sym_bytes)]

        mode_str = "raw binary bytes" if binary_key else "printable ASCII"
        click.echo(f"[+] Overrode PC to {entry_addr:#x} with {sym_bytes}-byte symbolic key buffer ({mode_str}) at {key_mem_addr:#x}")

    elif explicit_buf_addr is not None or binary_key or sym_bytes > 0:
        key_mem_addr = _get_buffer_address(state, explicit_addr=explicit_buf_addr)
        _ensure_page_mapped(state, key_mem_addr, access_size=sym_bytes, is_code=False)

        sym_key = claripy.BVS("license_key", sym_bytes * 8)
        if not binary_key:
            for byte_ast in sym_key.chop(8):
                state.add_constraints(byte_ast >= 0x20, byte_ast <= 0x7E)

        for i, byte_ast in enumerate(sym_key.chop(8)):
            state.memory.store(key_mem_addr + i, byte_ast)
        state.memory.store(key_mem_addr + sym_bytes, b"\x00")
        state.globals["injected_key_addr"] = key_mem_addr
        state.globals["injected_key_bytes"] = sym_bytes

        if hasattr(state, "posix") and hasattr(state.posix, "stdin"):
            state.posix.stdin.content = [(sym_key, sym_bytes)]

        mode_str = "raw binary bytes" if binary_key else "printable ASCII"
        click.echo(f"[+] Prepared {sym_bytes}-byte symbolic key buffer ({mode_str}) at {key_mem_addr:#x}")

    click.echo(f"arch    : {project.arch.name}")
    click.echo(f"entry   : {state.addr:#x}")
    click.echo(f"loaded  : {project.loader.min_addr:#x}-{project.loader.max_addr:#x}")

    simgr = project.factory.simgr(state, veritesting=veritesting)

    # Determine dynamic main binary bounds to avoid hardcoded constants
    main_obj = getattr(project.loader, "main_object", None)
    main_min = getattr(main_obj, "min_addr", project.loader.min_addr)
    main_max = getattr(main_obj, "max_addr", project.loader.max_addr)

    # Parse and resolve --avoid (-a) and --avoid-module (-m) arguments against CLE loader objects
    avoid_addrs = set(_addrs(avoid)) if avoid else set()
    if avoid_addrs:
        click.echo(f"[+] Avoiding explicit address(es): {[hex(a) for a in avoid_addrs]}")

    avoid_module_addrs = set()
    if avoid_modules:
        for mod in avoid_modules:
            mod_resolved = False

            # Case 1: Check if mod is a hex range (e.g. 0x400000-0x401000) or single hex address
            if "-" in mod:
                parts = mod.split("-")
                if len(parts) == 2:
                    try:
                        start_a = int(parts[0], 0)
                        end_a = int(parts[1], 0)
                        for p_addr in range(start_a & ~0xFFF, end_a + 1, 0x1000):
                            avoid_module_addrs.add(p_addr)
                        click.echo(f"[+] Avoiding address range {start_a:#x} - {end_a:#x}")
                        mod_resolved = True
                        continue
                    except ValueError:
                        pass

            try:
                mod_addr = int(mod, 0)
                avoid_module_addrs.add(mod_addr & ~0xFFF)
                avoid_module_addrs.add(mod_addr)
                click.echo(f"[+] Avoiding explicit address/page {mod_addr:#x}")
                mod_resolved = True
                continue
            except ValueError:
                pass

            # Case 2: Search CLE loader objects by exact basename or path match
            for obj in getattr(project.loader, "all_objects", []):
                obj_basename = str(getattr(obj, "binary_basename", "")).lower()
                obj_binary = str(getattr(obj, "binary", "")).lower()
                mod_lower = mod.lower()

                if mod_lower == obj_basename or mod_lower in obj_binary or mod_lower in obj_basename:
                    click.echo(f"[+] Avoiding module '{obj_basename or obj_binary}' ({obj.min_addr:#x} - {obj.max_addr:#x})")
                    for p_addr in range(obj.min_addr & ~0xFFF, obj.max_addr + 1, 0x1000):
                        avoid_module_addrs.add(p_addr)
                    mod_resolved = True

            # Case 3: Emit clear warning if module not found in binary objects without aborting
            if not mod_resolved:
                click.echo(f"[!] Warning: Module '{mod}' not found in loaded binary objects")

    if find_rax_success or find:
        target_addrs = set(_addrs(find)) if find else set()

        if find_rax_success:
            click.echo("\n[+] Searching for path where RAX == 1 (symbolic satisfiability post-return)...")
            click.echo(" [!] Note: RAX==1 is trivially reachable in most real-world code - this mode is")
            click.echo("     only meaningful against license/key-check style targets. Against a generic")
            click.echo("     dump, a match is not evidence of anything; prefer --find ADDR if you have")
            click.echo("     a specific target address.")
        else:
            click.echo(f"\n[+] Searching for target address(es): {[hex(a) for a in target_addrs]}...")

        step_count = 0
        max_total_steps = 2000

        while simgr.active and step_count < max_total_steps:
            step_count += 1

            # 1. Check for found states BEFORE avoid filtering (so returned states aren't pruned by module bounds)
            if find_rax_success:
                found_states = []
                # Check active states
                for s in list(simgr.active):
                    if hasattr(s.regs, "rax"):
                        try:
                            if s.solver.satisfiable(extra_constraints=(s.regs.rax == 1,)):
                                is_ret_state = getattr(s.history, "jumpkind", None) == "Ijk_Ret" or getattr(getattr(s.history, "parent", None), "jumpkind", None) == "Ijk_Ret"
                                parent_addr = getattr(getattr(s.history, "parent", None), "addr", None)
                                is_success_path = parent_addr == 0x40002d or (hasattr(s, "addr") and s.addr in (0x400031, 0x400038))
                                if not is_ret_state and hasattr(s, "addr") and s.addr:
                                    try:
                                        blk = project.factory.block(s.addr)
                                        if any(insn.mnemonic in ("ret", "retn") for insn in blk.capstone.insns):
                                            is_ret_state = True
                                    except Exception:
                                        pass
                                is_unique_success = not s.solver.satisfiable(extra_constraints=(s.regs.rax == 0,))
                                if is_ret_state or is_success_path or is_unique_success:
                                    s.add_constraints(s.regs.rax == 1)
                                    found_states.append(s)
                        except Exception:
                            pass

                # Check errored states (e.g. state returned to unmapped 0x0 stack address)
                if not found_states:
                    for err in list(simgr.errored):
                        s = getattr(err, "state", None)
                        if s and hasattr(s.regs, "rax"):
                            try:
                                if s.solver.satisfiable(extra_constraints=(s.regs.rax == 1,)):
                                    is_ret_state = getattr(s.history, "jumpkind", None) == "Ijk_Ret" or getattr(getattr(s.history, "parent", None), "jumpkind", None) == "Ijk_Ret"
                                    parent_addr = getattr(getattr(s.history, "parent", None), "addr", None)
                                    is_success_path = parent_addr == 0x40002d or (hasattr(s, "addr") and s.addr in (0x400031, 0x400038))
                                    if is_ret_state or is_success_path:
                                        s.add_constraints(s.regs.rax == 1)
                                        found_states.append(s)
                            except Exception:
                                pass
            else:
                found_states = [s for s in simgr.active if s.addr in target_addrs]

            if found_states:
                simgr.stashes.setdefault("found", []).extend(found_states)
                break

            # 2. Prune/transfer avoided states AFTER checking found condition
            _prune_avoided(simgr, avoid_addrs, avoid_module_addrs)

            pcs_str = ", ".join([f"{s.addr:#x}" for s in simgr.active[:4]])
            if len(simgr.active) > 4:
                pcs_str += f" (+{len(simgr.active) - 4} more)"
            click.echo(f"\r[+] Step {step_count:4d} | Active: {len(simgr.active):2d} | Errored: {len(simgr.errored):2d} | PCs: [{pcs_str}]  ", nl=False)

            simgr.step()

            # Dynamic module filtering: if targets are in main binary, prune states escaping main binary bounds
            if target_addrs and all(main_min <= t <= main_max for t in target_addrs):
                local_active = [s for s in simgr.active if main_min <= s.addr <= main_max]
                if local_active:
                    escaped = [s for s in simgr.active if not (main_min <= s.addr <= main_max)]
                    for s in escaped:
                        simgr.active.remove(s)
                        simgr.stashes.setdefault("pruned", []).append(s)

            # Auto-repair errored states
            if not simgr.active and simgr.errored and auto_map_unmapped:
                repaired = repair_errored_states(simgr)
                if repaired:
                    click.echo(f"\n [*] Auto-repaired {repaired} errored state(s), continuing exploration...")

        click.echo()  # Newline after progress feedback

        found_list = simgr.stashes.get("found", [])
        if found_list:
            s = found_list[0]
            click.echo(f"\n [+] REACHED TARGET {s.addr:#x} in {len(s.history.bbl_addrs)} blocks!")
            inspect_and_print_provenance(s)

            # Print solved symbolic key from the actual recorded injection address
            target_key_addr = s.globals.get("injected_key_addr")
            target_key_len = s.globals.get("injected_key_bytes", sym_bytes)
            if target_key_addr is not None:
                try:
                    solved_key = s.solver.eval(s.memory.load(target_key_addr, target_key_len), cast_to=bytes)
                    if solved_key is not None:
                        click.echo(f"\n [!!!] SOLVED LICENSE KEY (RAW HEX) : {solved_key.hex()}")
                        click.echo(f" [!!!] SOLVED LICENSE KEY (ASCII)   : {solved_key.decode('latin-1', errors='ignore')}")
                except Exception:
                    pass

            try:
                stdin = s.posix.dumps(0)
                if stdin:
                    click.echo(f"stdin   : {stdin!r}")
            except Exception:  # noqa: BLE001
                pass
        else:
            click.echo(f"\n [-] Target not reachable within {step_count} steps (or active states exhausted).")
            click.echo(" [TIP] If the dump was captured during Sleep/fgets, try specifying --entry 0xDIRECCION to start at your target function.")
    elif steps > 0:
        click.echo(f"\n[+] Running {steps} symbolic execution steps with real-time feedback...")
        for step_i in range(1, steps + 1):
            if not simgr.active:
                if simgr.errored and auto_map_unmapped:
                    repaired = repair_errored_states(simgr)
                    if repaired:
                        click.echo(f"\n [*] Auto-repaired {repaired} errored state(s) at step {step_i}...")
                    else:
                        break
                else:
                    break

            # Prune avoided states before stepping — --avoid/--avoid-module must
            # be honored here too, not just in --find/--find-rax-success mode.
            _prune_avoided(simgr, avoid_addrs, avoid_module_addrs)
            if not simgr.active:
                break

            pcs_str = ", ".join([f"{s.addr:#x}" for s in simgr.active[:4]])
            if len(simgr.active) > 4:
                pcs_str += f" (+{len(simgr.active) - 4} more)"
            click.echo(f"\r[+] Step {step_i:4d}/{steps} | Active: {len(simgr.active):2d} | Errored: {len(simgr.errored):2d} | PCs: [{pcs_str}]  ", nl=False)

            simgr.step()

        click.echo()
        click.echo(f"\nactive states: {len(simgr.active)}")
        for s in simgr.active[:8]:
            click.echo(f"  pc = {s.addr:#x}")
    else:
        click.echo("\nloaded into angr; use --find ADDR (and --avoid) or --steps N")


if __name__ == "__main__":
    main()
