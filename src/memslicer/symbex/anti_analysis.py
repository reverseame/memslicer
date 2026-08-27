"""Module for bypassing Windows Anti-Debugging and Anti-Analysis checks in angr."""

from __future__ import annotations

import angr
import claripy


# ----------------------------------------------------------------------
# 1. SIMPROCEDURES FOR WINDOWS ANTI-DEBUGGING APIS
# ----------------------------------------------------------------------

class SimIsDebuggerPresent(angr.SimProcedure):
    """SimProcedure stub for kernel32!IsDebuggerPresent.
    Always returns FALSE (0) indicating no debugger is attached.
    """
    def run(self):
        return claripy.BVV(0, 32)


class SimCheckRemoteDebuggerPresent(angr.SimProcedure):
    """SimProcedure stub for kernel32!CheckRemoteDebuggerPresent.
    Writes FALSE (0) to the output BOOL pointer and returns SUCCESS (1).
    """
    def run(self, hProcess, pbDebuggerPresent):
        if not self.state.solver.symbolic(pbDebuggerPresent):
            self.state.memory.store(
                pbDebuggerPresent,
                claripy.BVV(0, 32),
                endness=self.state.arch.memory_endness
            )
        return claripy.BVV(1, 32)


class SimNtQueryInformationProcess(angr.SimProcedure):
    """SimProcedure stub for ntdll!NtQueryInformationProcess.
    Handles ProcessDebugPort (7) and ProcessDebugFlags (31) checks.
    """
    def run(self, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength):
        cls_val = None
        if not self.state.solver.symbolic(ProcessInformationClass):
            cls_val = self.state.solver.eval(ProcessInformationClass)

        arch_bits = self.state.arch.bits

        # ProcessDebugPort (0x07): Return 0 (No debugger port)
        if cls_val == 7:
            self.state.memory.store(
                ProcessInformation,
                claripy.BVV(0, arch_bits),
                endness=self.state.arch.memory_endness
            )
        # ProcessDebugFlags (0x1F / 31): Return 1 (No debug flags set)
        elif cls_val == 31:
            self.state.memory.store(
                ProcessInformation,
                claripy.BVV(1, 32),
                endness=self.state.arch.memory_endness
            )

        # Return STATUS_SUCCESS (0x00000000)
        return claripy.BVV(0, 32)


# ----------------------------------------------------------------------
# 2. PEB ENVIRONMENT MASKING
# ----------------------------------------------------------------------

def mask_peb_anti_debug(state: angr.SimState, peb_base: int | None = None) -> None:
    """Masks PEB BeingDebugged, NtGlobalFlag, and ProcessHeap flags dynamically in x86/x64 states."""
    try:
        is_64bit = state.arch.bits == 64
        teb_base = None

        # 1. Dynamic PEB resolution if peb_base is not explicitly provided
        if peb_base is None:
            reg_names = ("gs", "gs_base") if is_64bit else ("fs", "fs_base")
            for reg_name in reg_names:
                if hasattr(state.regs, reg_name):
                    try:
                        reg_val = getattr(state.regs, reg_name)
                        if state.solver.symbolic(reg_val):
                            continue  # never seeded — not a real TEB pointer, skip to fallback
                        teb_val = state.solver.eval(reg_val)
                        if teb_val and teb_val >= 0x10000:
                            teb_base = teb_val
                            break
                    except Exception:
                        pass

            if teb_base is not None:
                peb_ptr_offset = 0x60 if is_64bit else 0x30
                try:
                    peb_ptr = state.solver.eval(
                        state.memory.load(teb_base + peb_ptr_offset, 8 if is_64bit else 4, endness=state.arch.memory_endness)
                    )
                    if peb_ptr and peb_ptr >= 0x10000:
                        peb_base = peb_ptr
                except Exception:
                    pass

        # Default Fallback TEB / PEB base if unassigned (0x7FFFFEF0000 matches
        # angr's conventional default TEB region on x64)
        if teb_base is None:
            teb_base = 0x7FFFFEF0000 if is_64bit else 0x7FFDF000
        if peb_base is None:
            peb_base = 0x7FFFFEF0000 if is_64bit else 0x7FFD0000

        # Ensure TEB points to PEB at offset 0x60 (x64) or 0x30 (x86)
        peb_ptr_offset = 0x60 if is_64bit else 0x30
        try:
            state.memory.store(
                teb_base + peb_ptr_offset,
                claripy.BVV(peb_base, 64 if is_64bit else 32),
                endness=state.arch.memory_endness
            )
        except Exception:
            pass

        if is_64bit:
            try:
                state.regs.gs = 0
            except Exception:
                pass
            for reg_name in ("gs_const", "gs_base", "gs_offset"):
                if hasattr(state.regs, reg_name):
                    try:
                        setattr(state.regs, reg_name, claripy.BVV(teb_base, 64))
                    except Exception:
                        pass
        else:
            try:
                state.regs.fs = 0
            except Exception:
                pass
            for reg_name in ("fs_const", "fs_base", "fs_offset"):
                if hasattr(state.regs, reg_name):
                    try:
                        setattr(state.regs, reg_name, claripy.BVV(teb_base, 32))
                    except Exception:
                        pass

        # Overwrite BeingDebugged = 0 (Byte at offset 0x02)
        state.memory.store(peb_base + 0x02, claripy.BVV(0, 8))

        # Architecture-aware NtGlobalFlag offset
        # x64: 0x68 | x86: 0xBC
        nt_global_flag_offset = 0x68 if is_64bit else 0xBC
        state.memory.store(peb_base + nt_global_flag_offset, claripy.BVV(0, 32))

        # Mask ProcessHeap flags if ProcessHeap pointer is populated
        # x64 PEB -> ProcessHeap pointer at offset 0x30
        # x86 PEB -> ProcessHeap pointer at offset 0x18
        proc_heap_ptr_offset = 0x30 if is_64bit else 0x18
        try:
            proc_heap_addr = state.solver.eval(
                state.memory.load(peb_base + proc_heap_ptr_offset, 8 if is_64bit else 4, endness=state.arch.memory_endness)
            )
            if proc_heap_addr and proc_heap_addr >= 0x10000:
                # Heap.Flags: x64 +0x70 | x86 +0x40 -> 0x2 (HEAP_GROWABLE)
                # Heap.ForceFlags: x64 +0x74 | x86 +0x44 -> 0x0
                heap_flags_offset = 0x70 if is_64bit else 0x40
                state.memory.store(proc_heap_addr + heap_flags_offset, claripy.BVV(2, 32), endness=state.arch.memory_endness)
                state.memory.store(proc_heap_addr + heap_flags_offset + 4, claripy.BVV(0, 32), endness=state.arch.memory_endness)
        except Exception:
            pass

    except Exception:
        pass


# ----------------------------------------------------------------------
# 3. HOOK REGISTRATION FUNCTION
# ----------------------------------------------------------------------

def apply_anti_analysis_bypass(project: angr.Project, state: angr.SimState, peb_base: int | None = None) -> None:
    """Registers SimProcedures for evasive Windows APIs and masks PEB flags."""

    # Mask PEB structure in the initial state
    mask_peb_anti_debug(state, peb_base=peb_base)

    # Hook symbol names safely if present in binary loader
    api_hooks = {
        "IsDebuggerPresent": SimIsDebuggerPresent(),
        "CheckRemoteDebuggerPresent": SimCheckRemoteDebuggerPresent(),
        "NtQueryInformationProcess": SimNtQueryInformationProcess(),
    }

    loader = getattr(project, "loader", None)
    find_sym = getattr(loader, "find_symbol", None) if loader is not None else None

    for api_name, procedure in api_hooks.items():
        if find_sym is not None and find_sym(api_name) is not None:
            try:
                project.hook_symbol(api_name, procedure)
            except Exception:
                pass

        for dll in ["kernel32.dll", "ntdll.dll", "KERNEL32.DLL", "NTDLL.DLL"]:
            sym_name = f"{dll}!{api_name}"
            if find_sym is not None and find_sym(sym_name) is not None:
                try:
                    project.hook_symbol(sym_name, procedure)
                except Exception:
                    pass

