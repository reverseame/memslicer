"""Unit tests for Phase 3: Calling convention stubs (cdecl, stdcall, fastcall, auto)."""

import io
import pytest

angr = pytest.importorskip("angr")
claripy = pytest.importorskip("claripy")

from memslicer.symbex.unmapped_handler import SimGenericAPIStub, _ensure_page_mapped, enable_unmapped_memory_recovery


def test_stdcall_stack_cleanup_x86():
    """Verify that SimGenericAPIStub(cc_name='stdcall', num_args=4) cleans up stack arguments (16 bytes)
    on 32-bit x86 stdcall architectures.
    """
    proj = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "x86", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    initial_esp = 0x7FFFF000
    state.regs.esp = initial_esp

    stub = SimGenericAPIStub(cc_name="stdcall", num_args=4)
    stub.state = state
    ret_val = stub.run()

    assert state.solver.eval(ret_val) == 0
    assert ret_val.length == 32
    final_esp = state.solver.eval(state.regs.esp)
    assert final_esp == initial_esp + 16


def test_cdecl_stack_preservation_x86():
    """Verify that SimGenericAPIStub(cc_name='cdecl', num_args=4) DOES NOT adjust ESP on x86,
    since caller is responsible for stack cleanup in cdecl.
    """
    proj = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "x86", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    initial_esp = 0x7FFFF000
    state.regs.esp = initial_esp

    stub = SimGenericAPIStub(cc_name="cdecl", num_args=4)
    stub.state = state
    ret_val = stub.run()

    assert state.solver.eval(ret_val) == 0
    final_esp = state.solver.eval(state.regs.esp)
    assert final_esp == initial_esp


def test_fastcall_stack_cleanup_x86():
    """Verify that SimGenericAPIStub(cc_name='fastcall', num_args=4) adjusts ESP by max(0, num_args - 2) * 4 (8 bytes)
    on 32-bit x86 fastcall (where ECX and EDX pass first 2 args).
    """
    proj = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "x86", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    initial_esp = 0x7FFFF000
    state.regs.esp = initial_esp

    stub = SimGenericAPIStub(cc_name="fastcall", num_args=4)
    stub.state = state
    ret_val = stub.run()

    assert state.solver.eval(ret_val) == 0
    final_esp = state.solver.eval(state.regs.esp)
    assert final_esp == initial_esp + 8


def test_auto_conservative_policy_x86():
    """Verify that when no calling convention metadata is available (cc_name='auto'),
    SimGenericAPIStub applies a conservative policy and DOES NOT adjust ESP.
    """
    proj = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "x86", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    initial_esp = 0x7FFFF000
    state.regs.esp = initial_esp

    stub = SimGenericAPIStub(cc_name="auto", num_args=4)
    stub.state = state
    ret_val = stub.run()

    assert state.solver.eval(ret_val) == 0
    final_esp = state.solver.eval(state.regs.esp)
    assert final_esp == initial_esp


def test_amd64_stub_execution_no_stack_corruption():
    """Verify that SimGenericAPIStub on 64-bit AMD64 architecture preserves RSP intact."""
    proj = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    initial_rsp = 0x7FFFF000
    state.regs.rsp = initial_rsp

    stub = SimGenericAPIStub(cc_name="stdcall", num_args=4)
    stub.state = state
    ret_val = stub.run()

    assert state.solver.eval(ret_val) == 0
    assert ret_val.length == 64
    final_rsp = state.solver.eval(state.regs.rsp)
    assert final_rsp == initial_rsp


def test_real_call_ret_execution_with_stub():
    """Verify execution of a real call instruction to an unmapped API stub, followed by ret."""
    # Assembly (x64): mov rax, 0x88880000; call rax; ret
    # Bytes: 48 b8 00 00 88 88 00 00 00 00  ffd0  c3
    code = b"\x48\xb8\x00\x00\x88\x88\x00\x00\x00\x00\xff\xd0\xc3"
    base_addr = 0x401000
    proj = angr.Project(io.BytesIO(code), main_opts={"backend": "blob", "arch": "amd64", "base_addr": base_addr})
    state = proj.factory.blank_state(addr=base_addr)
    state.regs.rsp = 0x7FFFF000

    enable_unmapped_memory_recovery(proj, state)

    # Pre-map target code page at 0x88880000 and hook stub
    _ensure_page_mapped(state, 0x88880000, access_size=1, is_code=True, fault_addr=0x88880000)

    simgr = proj.factory.simgr(state)
    simgr.step()  # mov rax, 0x88880000
    simgr.step()  # call rax -> jumps into SimGenericAPIStub at 0x88880000
    simgr.step()  # returns back from stub to 0x40100c

    assert len(simgr.active) > 0
    active_state = simgr.active[0]
    # RAX must be 0 (returned by stub)
    assert active_state.solver.eval(active_state.regs.rax) == 0
