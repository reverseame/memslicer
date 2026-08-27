"""Unit tests for automatic unmapped memory recovery and generic API stubs in memslicer.symbex."""

import io
import pytest

angr = pytest.importorskip("angr")
claripy = pytest.importorskip("claripy")

from memslicer.symbex.unmapped_handler import (
    SimGenericAPIStub,
    _get_ret_bytes,
    enable_unmapped_memory_recovery,
    repair_errored_states,
)


def test_unmapped_read_recovery():
    """Test that reading an unmapped virtual address automatically maps the 4KB page."""
    project = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = project.factory.blank_state(addr=0x401000)

    enable_unmapped_memory_recovery(project, state)

    unmapped_addr = 0x90000500  # Address in unmapped 0x90000000 page
    page_base = 0x90000000

    # Read unmapped memory address
    val = state.memory.load(unmapped_addr, 4)

    # Verify that the 4KB page was automatically mapped
    assert "auto_mapped_pages" in state.globals
    assert page_base in state.globals["auto_mapped_pages"]
    assert val is not None


def test_unmapped_write_recovery():
    """Test that writing to an unmapped virtual address automatically maps the 4KB page."""
    project = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = project.factory.blank_state(addr=0x401000)

    enable_unmapped_memory_recovery(project, state)

    unmapped_addr = 0xA0001080
    page_base = 0xA0001000

    # Store bytes into unmapped address with explicit endness
    state.memory.store(unmapped_addr, claripy.BVV(0x1337, 32), endness=state.arch.memory_endness)

    assert page_base in state.globals["auto_mapped_pages"]
    loaded = state.solver.eval(state.memory.load(unmapped_addr, 4, endness=state.arch.memory_endness))
    assert loaded == 0x1337


def test_unmapped_code_execution_stub():
    """Test executing generic API stub in unmapped code."""
    project = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = project.factory.blank_state(addr=0x401000)

    proc = SimGenericAPIStub()
    proc.state = state
    ret_val = proc.run()

    sol_val = state.solver.eval(ret_val)
    assert sol_val == 0
    assert ret_val.length == 64  # Arch bits in amd64 is 64


def test_repair_errored_states():
    """Test repairing errored states containing SimSegfaultException."""
    project = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = project.factory.blank_state(addr=0x401000)

    simgr = project.factory.simgr(state)

    # Create ErrorRecord manually
    segfault_ex = angr.errors.SimSegfaultException(0xB0000500, "Unmapped execution read")
    errored_record = angr.sim_manager.ErrorRecord(state, segfault_ex, None)
    simgr.errored.append(errored_record)

    assert len(simgr.errored) == 1
    repaired_count = repair_errored_states(simgr)

    assert repaired_count == 1
    assert len(simgr.errored) == 0
    assert len(simgr.active) == 2  # Original initial state + repaired state


def test_state_copy_set_isolation():
    """Test that state.copy() does not mutate auto_mapped_pages across branched states (H-01 fix)."""
    project = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state1 = project.factory.blank_state(addr=0x401000)
    enable_unmapped_memory_recovery(project, state1)

    # Access page in state1
    _ = state1.memory.load(0x90000500, 4)

    # Copy state1 to state2
    state2 = state1.copy()

    # Access new page in state2
    _ = state2.memory.load(0x90001500, 4)

    # Ensure state1 auto_mapped_pages did NOT receive state2's new page
    assert 0x90001000 in state2.globals["auto_mapped_pages"]
    assert 0x90001000 not in state1.globals["auto_mapped_pages"]


def test_non_memory_error_skipped():
    """Test that non-memory errors (e.g., division by zero) are not repaired (H-02 fix)."""
    project = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = project.factory.blank_state(addr=0x401000)
    simgr = project.factory.simgr(state)

    zero_div_ex = angr.errors.SimZeroDivisionException("Division by zero")
    errored_record = angr.sim_manager.ErrorRecord(state, zero_div_ex, None)
    simgr.errored.append(errored_record)

    repaired = repair_errored_states(simgr)
    assert repaired == 0
    assert len(simgr.errored) == 1


def test_multi_arch_ret_bytes():
    """Test architecture-specific RET instruction opcodes (H-04 fix)."""
    assert _get_ret_bytes("AMD64") == b"\xc3"
    assert _get_ret_bytes("X86") == b"\xc3"
    assert _get_ret_bytes("ARM64") == b"\xc0\x03\x5f\xd6"
    assert _get_ret_bytes("ARM") == b"\x1e\xff\x2f\xe1"
    assert _get_ret_bytes("MIPS32") == b"\x08\x00\xe0\x03\x00\x00\x00\x00"


def test_null_page_guard_range():
    """Test that null pointer guard range (< 0x10000) ignores dereferences (H-05 fix)."""
    project = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = project.factory.blank_state(addr=0x401000)
    enable_unmapped_memory_recovery(project, state, premap_stack_mb=0)

    # Read from low address in null guard page (e.g. 0x2000)
    _ = state.memory.load(0x2000, 4)

    assert "auto_mapped_pages" not in state.globals or 0x2000 not in state.globals["auto_mapped_pages"]


def test_premap_stack_region():
    """Test pre-mapping 64MB stack region around RSP."""
    from memslicer.symbex.unmapped_handler import premap_stack_region, _is_page_mapped

    project = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = project.factory.blank_state(addr=0x401000)

    # Set RSP register to high stack address
    state.regs.rsp = 0x7FFBE668D624

    premap_stack_region(state, region_size_mb=64)

    # Verify that address around RSP is now mapped
    assert _is_page_mapped(state.memory, 0x7FFBE668D624) is True


