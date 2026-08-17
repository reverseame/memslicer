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

def mask_peb_anti_debug(state: angr.SimState) -> None:
    """Masks PEB BeingDebugged and NtGlobalFlag in x86/x64 states."""
    try:
        peb_base = 0x7FFFFEF0000  # Default fallback PEB base in angr

        # Overwrite BeingDebugged = 0 (Byte at offset 0x02)
        state.memory.store(peb_base + 0x02, claripy.BVV(0, 8))

        # Overwrite NtGlobalFlag = 0 (4 bytes at offset 0x68)
        state.memory.store(peb_base + 0x68, claripy.BVV(0, 32))
    except Exception:
        pass


# ----------------------------------------------------------------------
# 3. HOOK REGISTRATION FUNCTION
# ----------------------------------------------------------------------

def apply_anti_analysis_bypass(project: angr.Project, state: angr.SimState) -> None:
    """Registers SimProcedures for evasive Windows APIs and masks PEB flags."""

    # Mask PEB structure in the initial state
    mask_peb_anti_debug(state)

    # Hook symbol names safely if present
    api_hooks = {
        "IsDebuggerPresent": SimIsDebuggerPresent(),
        "CheckRemoteDebuggerPresent": SimCheckRemoteDebuggerPresent(),
        "NtQueryInformationProcess": SimNtQueryInformationProcess(),
    }

    for api_name, procedure in api_hooks.items():
        try:
            project.hook_symbol(api_name, procedure)
        except Exception:
            pass

        for dll in ["kernel32.dll", "ntdll.dll", "KERNEL32.DLL", "NTDLL.DLL"]:
            try:
                project.hook_symbol(f"{dll}!{api_name}", procedure)
            except Exception:
                pass
