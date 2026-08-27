"""Automatic recovery module for unmapped memory accesses and missing API stubs in angr."""

from __future__ import annotations

import logging
import angr
import claripy

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# 1. HELPER FUNCTIONS & GENERIC STUBS
# ----------------------------------------------------------------------

def _get_ret_bytes(arch_name: str) -> bytes:
    """Returns architecture-specific RET instruction bytes."""
    arch_lower = arch_name.lower()
    if "amd64" in arch_lower or "x86" in arch_lower or "i386" in arch_lower:
        return b"\xc3"
    elif "arm64" in arch_lower or "aarch64" in arch_lower:
        return b"\xc0\x03\x5f\xd6"  # ret
    elif "arm" in arch_lower:
        return b"\x1e\xff\x2f\xe1"  # bx lr
    elif "mips" in arch_lower:
        return b"\x08\x00\xe0\x03\x00\x00\x00\x00"  # jr ra; nop
    return b"\xc3"


class SimGenericAPIStub(angr.SimProcedure):
    """Calling convention-aware SimProcedure stub for code execution in unmapped memory.
    Supports explicit calling conventions (cdecl, stdcall, fastcall).
    - cdecl: caller cleans stack -> do NOT adjust ESP.
    - stdcall: callee cleans stack -> adjust ESP += num_args * 4 (x86 32-bit).
    - fastcall: callee cleans stack args -> adjust ESP += max(0, num_args - 2) * 4 (x86 32-bit).
    - auto / conservative default: do NOT clean stack if no convention metadata exists.
    - AMD64: RSP is always preserved.
    """
    def __init__(self, cc_name: str = "auto", num_args: int = 4, **kwargs):
        super().__init__(**kwargs)
        self.cc_name = (cc_name or "auto").lower()
        self.num_args = num_args

    def run(self, *args, **kwargs):
        arch_bits = self.state.arch.bits
        arch_name = self.state.arch.name.lower()
        logger.info("[unmapped_handler] Executing SimGenericAPIStub (cc=%s, num_args=%d) at %s", self.cc_name, self.num_args, hex(self.state.addr))

        # Perform 32-bit x86 stack cleanup ONLY when calling convention explicitly requires it
        if ("x86" in arch_name or "i386" in arch_name) and arch_bits == 32:
            try:
                cleanup_bytes = 0
                if self.cc_name == "stdcall":
                    cleanup_bytes = self.num_args * 4
                elif self.cc_name == "fastcall":
                    cleanup_bytes = max(0, self.num_args - 2) * 4
                elif self.cc_name in ("cdecl", "auto"):
                    cleanup_bytes = 0  # Conservative policy: no stack adjustment

                if cleanup_bytes > 0:
                    self.state.regs.esp += cleanup_bytes
            except Exception as exc:
                logger.debug("[unmapped_handler] Stack cleanup note for x86 stub: %s", exc)

        return claripy.BVV(0, arch_bits)


def classify_state_error(error_record: angr.sim_manager.ErrorRecord) -> tuple[str, int | claripy.ast.BV | None, int]:
    """Classifies an ErrorRecord into a structured fault category.
    Returns tuple of (fault_category, fault_addr, access_size).
    Categories:
      - 'read': Data memory read fault
      - 'write': Data memory write fault
      - 'exec': Code execution fault
      - 'permission_fault': Memory permission violation
      - 'unsupported_syscall': Unsupported syscall (unrepairable by memory mapping)
      - 'engine_error': Generic engine error (unrepairable by memory mapping)
      - 'unknown': Unrecognized error
    """
    if error_record is None or error_record.state is None or error_record.error is None:
        return ("unknown", None, 0)

    state = error_record.state
    error = error_record.error
    err_class = error.__class__.__name__.lower()
    err_str = str(error).lower()

    # 1. Check for unrepairable errors (syscalls, engine errors)
    try:
        pc_val = state.addr & ~1
        ins = state.solver.eval(state.memory.load(pc_val, 4), cast_to=bytes)
        if ins.startswith((b"\x0f\x05", b"\x0f\x34", b"\xcd\x2e", b"\x01\x00\x00\xd4")) or ins[:4] == b"\x00\x00\x00\xef":
            return ("unsupported_syscall", state.addr, 0)
    except Exception:
        pass

    if isinstance(error, angr.errors.AngrUnsupportedSyscallError) or "syscall" in err_class or "syscall" in err_str:
        return ("unsupported_syscall", state.addr, 0)

    is_segfault = isinstance(error, (angr.errors.SimSegfaultException, angr.errors.SimMemoryError)) or "segfault" in err_class or "unmapped" in err_str
    if not is_segfault and isinstance(error, angr.errors.SimEngineError):
        return ("engine_error", state.addr, 0)

    if not is_segfault:
        return ("unknown", getattr(error, "addr", state.addr), 0)

    fault_addr = getattr(error, "addr", None)
    if fault_addr is None:
        fault_addr = state.addr

    access_size = getattr(error, "size", 1) or getattr(error, "length", 1) or 1
    if state.solver.symbolic(access_size):
        try:
            access_size = state.solver.eval(access_size)
        except Exception:
            access_size = 1

    # 2. Structured metadata inspection (highest priority)
    action_attr = str(
        getattr(error, "action", "")
        or getattr(error, "access_type", "")
        or getattr(error, "permission", "")
    ).lower()

    if "permission" in action_attr or "prot" in action_attr or "permission" in err_str or "prot" in err_str:
        return ("permission_fault", fault_addr, int(access_size))

    if action_attr:
        if any(k in action_attr for k in ("exec", "code", "fetch", "instruction")):
            return ("exec", fault_addr, int(access_size))
        elif "write" in action_attr:
            return ("write", fault_addr, int(access_size))
        elif "read" in action_attr:
            return ("read", fault_addr, int(access_size))

    # 3. Fallback to normalized error string matching with execution priority
    if any(k in err_str for k in ("exec", "instruction", "fetch", "execute", "code")):
        return ("exec", fault_addr, int(access_size))

    if any(k in err_str for k in ("write", "mem_write")):
        return ("write", fault_addr, int(access_size))

    if any(k in err_str for k in ("read", "mem_read", "data")):
        return ("read", fault_addr, int(access_size))

    return ("read", fault_addr, int(access_size))


# ----------------------------------------------------------------------
# 2. BREAKPOINT ACTIONS & PRE-MAPPING FOR UNMAPPED MEMORY ACCESSES
# ----------------------------------------------------------------------

def _is_page_mapped(memory, addr: int) -> bool:
    """Checks if a virtual memory address is mapped in angr's SimMemory."""
    try:
        fn = getattr(memory, "is_mapped", None)
        if callable(fn):
            return fn(addr)
        if hasattr(memory, "permissions"):
            perm = memory.permissions(addr)
            return perm is not None
    except Exception:
        pass
    return False


def premap_stack_region(state: angr.SimState, region_size_mb: int = 64) -> None:
    """Pre-maps a contiguous virtual memory region (default 64MB) around the stack pointer (RSP/ESP)
    to prevent Unicorn / Veritesting from throwing UC_ERR_WRITE_UNMAPPED errors.
    """
    try:
        sp_val = None
        for sp_name in ("sp", "rsp", "esp", "r13", "r29", "r1"):
            if hasattr(state.regs, sp_name):
                reg = getattr(state.regs, sp_name)
                if reg is not None:
                    try:
                        if not state.solver.symbolic(reg):
                            val = state.solver.eval(reg)
                            if val and val >= 0x10000:
                                sp_val = val
                                break
                    except Exception:
                        pass

        if sp_val is None or sp_val < 0x10000:
            return

        page_size = 4096
        half_size = (region_size_mb * 1024 * 1024) // 2

        max_user_addr = (1 << state.arch.bits) - 1
        if state.arch.bits == 64:
            max_user_addr = 0x7FFFFFFFFFFF

        start_addr = max(0x10000, (sp_val - half_size) & ~(page_size - 1))
        end_addr = min(max_user_addr, (sp_val + half_size) & ~(page_size - 1))

        curr_unmapped_start = None
        for page_addr in range(start_addr, end_addr, page_size):
            already_mapped = _is_page_mapped(state.memory, page_addr)
            if not already_mapped:
                if curr_unmapped_start is None:
                    curr_unmapped_start = page_addr
            else:
                if curr_unmapped_start is not None:
                    chunk_len = page_addr - curr_unmapped_start
                    try:
                        state.memory.map_region(curr_unmapped_start, chunk_len, permissions=6)
                        state.memory.store(curr_unmapped_start, b"\x00" * chunk_len, disable_actions=True, inspect=False)
                    except Exception:
                        pass
                    curr_unmapped_start = None

        if curr_unmapped_start is not None:
            chunk_len = end_addr - curr_unmapped_start
            try:
                state.memory.map_region(curr_unmapped_start, chunk_len, permissions=6)
                state.memory.store(curr_unmapped_start, b"\x00" * chunk_len, disable_actions=True, inspect=False)
            except Exception:
                pass

        logger.info(
            "[unmapped_handler] Pre-mapped %d MB stack region around SP=0x%x (0x%x - 0x%x)",
            region_size_mb, sp_val, start_addr, end_addr,
        )
    except Exception as exc:
        logger.debug("[unmapped_handler] Stack pre-mapping note: %s", exc)


def _map_single_page(
    state: angr.SimState,
    page_base: int,
    fault_addr: int | None = None,
    cc_name: str = "auto",
    num_args: int = 4,
    is_code: bool = False,
) -> bool:
    """Helper to map a single 4KB page at page_base in state.memory.
    Fills pages with neutral zero bytes (b"\\x00") without repetitive RET bytes.
    Hooks SimGenericAPIStub at fault_addr if is_code is True.
    Returns True ONLY if map_region, store, and hook all succeed.
    Executes explicit rollback (unmap_region) if store or hook fails post-map_region.
    """
    if "auto_mapped_pages" not in state.globals:
        state.globals["auto_mapped_pages"] = set()
    else:
        state.globals["auto_mapped_pages"] = set(state.globals["auto_mapped_pages"])

    auto_mapped: set[int] = state.globals["auto_mapped_pages"]
    if page_base in auto_mapped and not is_code:
        return True

    if "synthetic_code_pages" not in state.globals:
        state.globals["synthetic_code_pages"] = set()
    else:
        state.globals["synthetic_code_pages"] = set(state.globals["synthetic_code_pages"])
    synthetic_code_pages: set[int] = state.globals["synthetic_code_pages"]

    newly_mapped = False
    page_size = 4096
    try:
        already_mapped = _is_page_mapped(state.memory, page_base)
        if not already_mapped:
            perm = 7 if is_code else 6  # RWX for code, RW for data
            state.memory.map_region(page_base, page_size, permissions=perm)
            newly_mapped = True
            # Store neutral bytes: \xf4 (hlt) for code, \x00 for data
            fill_bytes = (b"\xf4" * page_size) if is_code else (b"\x00" * page_size)
            state.memory.store(page_base, fill_bytes, disable_actions=True, inspect=False)
            if is_code:
                synthetic_code_pages.add(page_base)

        # Only stub-hook addresses inside pages WE synthesized because they were
        # genuinely unmapped (e.g. a missing DLL/API target). A page that already
        # held real, loaded code must never be hooked just because execution
        # revisits it (loops, backward jumps) — doing so silently replaces valid
        # instructions with a no-op stub and corrupts control flow.
        if is_code and page_base in synthetic_code_pages:
            hook_addr = fault_addr if fault_addr is not None else page_base
            is_ret = (
                getattr(state.history, "jumpkind", None) == "Ijk_Ret"
                or getattr(getattr(state.history, "parent", None), "jumpkind", None) == "Ijk_Ret"
                or hook_addr == 0
                or (hasattr(state, "addr") and state.addr == 0)
            )
            proj = getattr(state, "project", None)
            if not is_ret and proj is not None and hasattr(proj, "hook") and hasattr(proj, "is_hooked"):
                if not proj.is_hooked(hook_addr):
                    proj.hook(hook_addr, SimGenericAPIStub(cc_name=cc_name, num_args=num_args))
                    logger.info("[unmapped_handler] Hooked SimGenericAPIStub at 0x%x (cc=%s, num_args=%d)", hook_addr, cc_name, num_args)

        auto_mapped.add(page_base)
        logger.info("[unmapped_handler] Auto-mapped page at 0x%x (is_code=%s)", page_base, is_code)
        return True
    except Exception as exc:
        if newly_mapped:
            try:
                unmap_fn = getattr(state.memory, "unmap_region", getattr(state.memory, "unmap", None))
                if callable(unmap_fn):
                    unmap_fn(page_base, page_size)
            except Exception:
                pass
        logger.debug("[unmapped_handler] map_region note for 0x%x: %s", page_base, exc)
        return False


def _ensure_page_mapped(
    state: angr.SimState,
    addr_val: int | claripy.ast.BV,
    access_size: int = 1,
    is_code: bool = False,
    fault_addr: int | None = None,
    cc_name: str = "auto",
    num_args: int = 4,
) -> bool:
    """Auto-maps virtual memory pages (4KB) covering the full access range [addr_val, addr_val + access_size - 1].
    Preserves symbolic variables without imposing add_constraints on solver.
    Returns True only if all required pages in the range are successfully mapped.
    """
    max_user_addr = (1 << state.arch.bits) - 1
    if state.arch.bits == 64:
        max_user_addr = 0x7FFFFFFFFFFF

    if not isinstance(access_size, int) or not (1 <= access_size <= 0x1000000):
        access_size = 1

    page_size = 4096
    addrs_to_map: list[int] = []
    max_solutions = 32

    if state.solver.symbolic(addr_val):
        try:
            # Evaluate possible concrete targets (up to max_solutions + 1) without constraining state
            solutions = state.solver.eval_upto(addr_val, max_solutions + 1)
            if len(solutions) > max_solutions:
                logger.warning("[unmapped_handler] Symbolic address range exceeded max_solutions limit (%d)", max_solutions)
                solutions = solutions[:max_solutions]
            for sol in solutions:
                if 0x10000 <= sol < max_user_addr:
                    addrs_to_map.append(sol)
        except Exception:
            return False
    else:
        if isinstance(addr_val, int) and 0x10000 <= addr_val < max_user_addr:
            addrs_to_map.append(addr_val)

    if not addrs_to_map:
        return False

    all_success = True
    access_len = max(1, access_size)

    for target_addr in addrs_to_map:
        start_page = target_addr & ~(page_size - 1)
        end_page = min(max_user_addr, (target_addr + access_len - 1)) & ~(page_size - 1)
        if start_page > end_page:
            end_page = start_page
        for page_base in range(start_page, end_page + page_size, page_size):
            hook_at = fault_addr if (fault_addr is not None and (target_addr & ~(page_size - 1)) == (fault_addr & ~(page_size - 1))) else target_addr
            success = _map_single_page(
                state, page_base, fault_addr=hook_at, cc_name=cc_name, num_args=num_args, is_code=is_code
            )
            if not success:
                all_success = False

    return all_success


def _on_mem_read(state: angr.SimState) -> None:
    """Callback triggered before mem_read."""
    try:
        attrs = getattr(state.inspect, "attrs", state.inspect)
        read_addr = getattr(attrs, "mem_read_address", None)
        read_len = getattr(attrs, "mem_read_length", 1)
        if read_addr is None:
            return
        if isinstance(read_len, claripy.ast.Base):
            read_len = state.solver.eval(read_len)
        _ensure_page_mapped(state, read_addr, access_size=int(read_len or 1), is_code=False)
    except Exception:
        pass


def _on_mem_write(state: angr.SimState) -> None:
    """Callback triggered before mem_write."""
    try:
        attrs = getattr(state.inspect, "attrs", state.inspect)
        write_addr = getattr(attrs, "mem_write_address", None)
        write_len = getattr(attrs, "mem_write_length", 1)
        if write_addr is None:
            return
        if isinstance(write_len, claripy.ast.Base):
            write_len = state.solver.eval(write_len)
        _ensure_page_mapped(state, write_addr, access_size=int(write_len or 1), is_code=False)
    except Exception:
        pass


def _on_instruction(state: angr.SimState) -> None:
    """Callback triggered before instruction execution."""
    try:
        pc = state.addr
        _ensure_page_mapped(state, pc, access_size=1, is_code=True, fault_addr=pc)
    except Exception:
        pass


# ----------------------------------------------------------------------
# 3. PUBLIC INITIALIZATION & RECOVERY FUNCTIONS
# ----------------------------------------------------------------------

def enable_unmapped_memory_recovery(project: angr.Project, state: angr.SimState, premap_stack_mb: int = 64) -> None:
    """Hooks mem_read, mem_write, and instruction breakpoints on state to auto-map pages,
    configures direct kernel syscall emulation, and pre-maps a stack region (default 64MB).
    """
    from memslicer.symbex.syscall_handler import setup_syscall_emulation

    state.project = project
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.BYPASS_UNSUPPORTED_SYSCALL)

    # Configure direct kernel syscall handling & stubs
    setup_syscall_emulation(project, state)

    if premap_stack_mb > 0:
        premap_stack_region(state, region_size_mb=premap_stack_mb)

    state.inspect.b("mem_read", action=_on_mem_read)
    state.inspect.b("mem_write", action=_on_mem_write)
    state.inspect.b("instruction", action=_on_instruction)
    logger.info("[unmapped_handler] Unmapped memory recovery enabled on state at 0x%x", state.addr)


def repair_errored_states(simgr: angr.SimulationManager, max_repairs_per_state: int = 3) -> int:
    """Inspects simgr.errored for segfaults/memory errors or unsupported syscalls,
    maps missing pages across full access range or repairs syscall states,
    and moves repaired states back to simgr.active ONLY if all required repairs succeed.
    Returns the number of repaired states.
    """
    from memslicer.symbex.syscall_handler import repair_syscall_errored_state

    if not simgr.errored:
        return 0

    repaired_count = 0
    remaining_errored = []

    for error_record in list(simgr.errored):
        state = error_record.state
        category, fault_addr, access_size = classify_state_error(error_record)

        # Handle unsupported syscall repair
        if category == "unsupported_syscall" and state is not None:
            if repair_syscall_errored_state(state, error_record.error):
                simgr.errored.remove(error_record)
                simgr.active.append(state)
                repaired_count += 1
                continue

        # Unrepairable errors remain in simgr.errored
        if category in ("unsupported_syscall", "engine_error", "unknown", "permission_fault") or state is None:
            remaining_errored.append(error_record)
            continue

        repair_attempts = state.globals.get("repair_attempts", 0)
        if repair_attempts >= max_repairs_per_state:
            logger.warning("[unmapped_handler] State at 0x%x reached max repair attempts (%d)", state.addr, max_repairs_per_state)
            remaining_errored.append(error_record)
            continue

        is_code = (category == "exec")
        concrete_fault = None
        if not state.solver.symbolic(fault_addr) and isinstance(fault_addr, int):
            concrete_fault = fault_addr

        success = _ensure_page_mapped(
            state,
            fault_addr,
            access_size=access_size,
            is_code=is_code,
            fault_addr=concrete_fault,
        )

        if not success:
            logger.warning("[unmapped_handler] Failed to map all required pages for errored state at 0x%x; keeping in errored", state.addr)
            remaining_errored.append(error_record)
            continue

        state.globals["repair_attempts"] = repair_attempts + 1
        simgr.active.append(state)
        repaired_count += 1
        logger.info("[unmapped_handler] Repaired errored state at 0x%x (category=%s)", state.addr, category)

    simgr.errored[:] = remaining_errored
    return repaired_count
