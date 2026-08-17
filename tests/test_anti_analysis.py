"""Unit and benchmark test suite for anti-analysis and anti-debugging bypass module."""
import os
import sys
import pytest

angr = pytest.importorskip("angr")
claripy = pytest.importorskip("claripy")

from memslicer.symbex.anti_analysis import (
    SimIsDebuggerPresent,
    SimCheckRemoteDebuggerPresent,
    SimNtQueryInformationProcess,
    mask_peb_anti_debug,
    apply_anti_analysis_bypass,
)


def create_anti_debug_test_binary():
    """Creates a synthetic x86_64 binary blob that evaluates IsDebuggerPresent."""
    code = (
        b"\x85\xc0"                      # test eax, eax
        b"\x75\x11"                      # jnz 0x401015
        b"\x48\xc7\xc0\x37\x13\x00\x00"  # mov rax, 0x1337 (SUCCESS)
        b"\xc3"                          # ret
        b"\x48\xc7\xc0\xad\xde\x00\x00"  # mov rax, 0xdead (FAIL)
        b"\xc3"                          # ret
    )
    return code


def test_is_debugger_present_bypass():
    """Test kernel32!IsDebuggerPresent SimProcedure return value."""
    print("\n------------------------------------------------------------")
    print(" [TEST 1] Testing IsDebuggerPresent SimProcedure Bypass")
    print("------------------------------------------------------------")
    
    project = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64"})
    state = project.factory.blank_state()
    
    proc = SimIsDebuggerPresent()
    proc.state = state
    ret_val = proc.run()
    
    sol_val = state.solver.eval(ret_val)
    assert sol_val == 0, f"Expected 0 (FALSE), got {sol_val}"
    print(f"  [PASS] IsDebuggerPresent returned {sol_val} (FALSE - No Debugger).")


def test_check_remote_debugger_present_bypass():
    """Test kernel32!CheckRemoteDebuggerPresent SimProcedure behavior."""
    print("\n------------------------------------------------------------")
    print(" [TEST 2] Testing CheckRemoteDebuggerPresent SimProcedure Bypass")
    print("------------------------------------------------------------")

    project = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64"})
    state = project.factory.blank_state()

    out_ptr = 0x7FFFF000
    proc = SimCheckRemoteDebuggerPresent()
    proc.state = state
    ret_code = proc.run(claripy.BVV(0xFFFF, 64), claripy.BVV(out_ptr, 64))

    out_bool = state.solver.eval(state.memory.load(out_ptr, 4, endness=state.arch.memory_endness))
    ret_val = state.solver.eval(ret_code)

    assert out_bool == 0, f"Expected out_bool 0 (FALSE), got {out_bool}"
    assert ret_val == 1, f"Expected return code 1 (SUCCESS), got {ret_val}"
    print(f"  [PASS] CheckRemoteDebuggerPresent wrote out_bool={out_bool} (FALSE) and returned {ret_val} (SUCCESS).")


def test_nt_query_information_process_bypass():
    """Test ntdll!NtQueryInformationProcess SimProcedure for ProcessDebugPort (7) and ProcessDebugFlags (31)."""
    print("\n------------------------------------------------------------")
    print(" [TEST 3] Testing NtQueryInformationProcess SimProcedure Bypass")
    print("------------------------------------------------------------")

    project = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64"})
    state = project.factory.blank_state()
    proc = SimNtQueryInformationProcess()
    proc.state = state

    out_ptr = 0x7FFFF000

    # Test ProcessDebugPort (0x07)
    proc.run(claripy.BVV(0xFFFF, 64), claripy.BVV(7, 32), claripy.BVV(out_ptr, 64), claripy.BVV(8, 32), claripy.BVV(0, 64))
    debug_port = state.solver.eval(state.memory.load(out_ptr, 8, endness=state.arch.memory_endness))
    assert debug_port == 0, f"Expected DebugPort 0, got {debug_port}"
    print(f"  [PASS] NtQueryInformationProcess (ProcessDebugPort) wrote {debug_port} (No Debugger Port).")

    # Test ProcessDebugFlags (0x1F / 31)
    proc.run(claripy.BVV(0xFFFF, 64), claripy.BVV(31, 32), claripy.BVV(out_ptr, 64), claripy.BVV(4, 32), claripy.BVV(0, 64))
    debug_flags = state.solver.eval(state.memory.load(out_ptr, 4, endness=state.arch.memory_endness))
    assert debug_flags == 1, f"Expected DebugFlags 1 (No debug), got {debug_flags}"
    print(f"  [PASS] NtQueryInformationProcess (ProcessDebugFlags) wrote {debug_flags} (No Debug Flags Set).")


def test_peb_masking():
    """Test PEB BeingDebugged and NtGlobalFlag memory masking."""
    print("\n------------------------------------------------------------")
    print(" [TEST 4] Testing PEB Environment Masking")
    print("------------------------------------------------------------")

    project = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64"})
    state = project.factory.blank_state()

    peb_base = 0x7FFFFEF0000
    # Simulate infected/debugged PEB flags
    state.memory.store(peb_base + 0x02, claripy.BVV(1, 8))       # BeingDebugged = 1
    state.memory.store(peb_base + 0x68, claripy.BVV(0x70, 32))   # NtGlobalFlag = 0x70

    # Apply masking
    mask_peb_anti_debug(state)

    being_debugged = state.solver.eval(state.memory.load(peb_base + 0x02, 1))
    nt_global_flag = state.solver.eval(state.memory.load(peb_base + 0x68, 4))

    assert being_debugged == 0, f"Expected BeingDebugged 0, got {being_debugged}"
    assert nt_global_flag == 0, f"Expected NtGlobalFlag 0, got {nt_global_flag}"
    print(f"  [PASS] PEB BeingDebugged={being_debugged} and NtGlobalFlag={nt_global_flag} masked to 0.")


def test_end_to_end_anti_analysis_bypass():
    """End-to-end simulation of anti-debugging bypass on synthetic binary code."""
    print("\n------------------------------------------------------------")
    print(" [TEST 5] Running End-to-End Anti-Analysis Bypass Simulation")
    print("------------------------------------------------------------")

    code_bytes = create_anti_debug_test_binary()
    base_addr = 0x401000

    project = angr.Project(
        __import__("io").BytesIO(code_bytes),
        main_opts={"backend": "blob", "arch": "amd64", "base_addr": base_addr},
        auto_load_libs=False,
    )
    
    stack_addr = 0x7FFFF000
    state = project.factory.blank_state(addr=base_addr)
    state.regs.rsp = stack_addr

    # 1. Apply anti-analysis bypass (hooks & PEB masking)
    apply_anti_analysis_bypass(project, state)

    # 2. Simulate SimIsDebuggerPresent procedure returning 0 into EAX
    proc = SimIsDebuggerPresent()
    proc.state = state
    state.regs.rax = proc.run()

    # 3. Explore to return instruction 0x40100b
    simgr = project.factory.simgr(state)
    simgr.explore(find=0x40100b, avoid=0x401015)

    assert len(simgr.found) > 0, "Failed to bypass anti-debugging path"
    found_state = simgr.found[0]
    final_rax = found_state.solver.eval(found_state.regs.rax)

    assert final_rax == 0x1337, f"Expected RAX=0x1337 (SUCCESS), got {final_rax:#x}"
    print(f"  [PASS] Anti-debugging bypass successful! Reached target 0x40100b with RAX={final_rax:#x}.")


def run_all_tests():
    print("==================================================================")
    print(" [TEST SUITE] ANTI-ANALYSIS & ANTI-DEBUGGING BYPASS MODULE")
    print("==================================================================")
    test_is_debugger_present_bypass()
    test_check_remote_debugger_present_bypass()
    test_nt_query_information_process_bypass()
    test_peb_masking()
    test_end_to_end_anti_analysis_bypass()
    print("\n==================================================================")
    print(" [!] [SUCCESS] ALL ANTI-ANALYSIS BYPASS TESTS PASSED SUCCESSFULLY")
    print("==================================================================\n")


if __name__ == "__main__":
    run_all_tests()