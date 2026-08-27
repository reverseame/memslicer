"""Unit tests for Phase 2 & P0 remediations: Preservación de Simbolismo, Mapeo Neutral, Rollback y Clasificación Estructurada."""

import logging
import pytest

angr = pytest.importorskip("angr")
claripy = pytest.importorskip("claripy")

import memslicer.symbex.unmapped_handler as unmapped_module
from memslicer.symbex.unmapped_handler import (
    enable_unmapped_memory_recovery,
    repair_errored_states,
    _ensure_page_mapped,
    _is_page_mapped,
    classify_state_error,
)
from angr.sim_manager import ErrorRecord


def test_auto_mapped_code_page_has_no_repetitive_ret_bytes():
    """Verify that auto-mapped code pages are filled with a neutral HLT trap (b"\\xf4")
    and DO NOT contain repetitive RET (\\xc3) bytes.

    HLT (not \\x00) is the deliberate choice: \\x00\\x00 decodes as `add [rax], al`,
    which would silently touch memory through whatever garbage RAX holds. HLT
    traps immediately instead, so a state landing on synthetic filler surfaces
    as an explicit fault rather than executing unintended semantics.
    """
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    code_addr = 0x88880000
    success = _ensure_page_mapped(state, code_addr, access_size=1, is_code=True, fault_addr=code_addr)
    assert success is True

    # Read 16 bytes from mapped code page; MUST be HLT (b"\xf4"), NOT RET (b"\xc3")
    page_bytes = state.solver.eval(state.memory.load(code_addr, 16), cast_to=bytes)
    assert page_bytes == b"\xf4" * 16
    assert b"\xc3" not in page_bytes


def test_rollback_on_store_failure_post_map_region(monkeypatch):
    """Verify that if memory.store fails after map_region, _map_single_page executes rollback (unmap)
    and returns False without adding page_base to auto_mapped_pages.
    """
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    page_base = 0x88880000
    unmap_called = []

    def failing_store(*args, **kwargs):
        raise RuntimeError("Store exception after map_region")

    def mock_unmap_region(addr, size):
        unmap_called.append((addr, size))

    monkeypatch.setattr(state.memory, "store", failing_store)
    monkeypatch.setattr(state.memory, "unmap_region", mock_unmap_region, raising=False)

    success = unmapped_module._map_single_page(state, page_base, is_code=False)

    assert success is False
    assert len(unmap_called) == 1
    assert unmap_called[0] == (page_base, 4096)
    auto_mapped = state.globals.get("auto_mapped_pages", set())
    assert page_base not in auto_mapped


def test_permission_fault_explicit_classification_and_unrepairable():
    """Verify that memory permission faults are explicitly classified as 'permission_fault'
    and are NOT repaired by repair_errored_states (remain in simgr.errored).
    """
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    # Permission fault exception
    err_perm = ErrorRecord(state, angr.errors.SimSegfaultException(0x88880000, "page permission protection violation"), None)
    cat, addr, _ = classify_state_error(err_perm)

    assert cat == "permission_fault"
    assert addr == 0x88880000

    simgr = proj.factory.simgr(state)
    simgr.active.clear()
    simgr.errored.append(err_perm)

    repaired = repair_errored_states(simgr)
    assert repaired == 0
    assert len(simgr.active) == 0
    assert len(simgr.errored) == 1


def test_classify_state_error_categories():
    """Verify structured classification for read, write, exec, permission_fault, unsupported_syscall, and engine_error."""
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    # 1. Unsupported Syscall Error
    err1 = ErrorRecord(state, angr.errors.AngrUnsupportedSyscallError("sys_42 not supported"), None)
    cat1, _, _ = classify_state_error(err1)
    assert cat1 == "unsupported_syscall"

    # 2. Generic Engine Error
    err2 = ErrorRecord(state, angr.errors.SimEngineError("generic engine failure"), None)
    cat2, _, _ = classify_state_error(err2)
    assert cat2 == "engine_error"

    # 3. Segfault Read Fault
    err3 = ErrorRecord(state, angr.errors.SimSegfaultException(0x88880000, "unmapped memory read"), None)
    cat3, addr3, _ = classify_state_error(err3)
    assert cat3 == "read"
    assert addr3 == 0x88880000

    # 4. Segfault Write Fault
    err4 = ErrorRecord(state, angr.errors.SimSegfaultException(0x88890000, "unmapped memory write"), None)
    cat4, addr4, _ = classify_state_error(err4)
    assert cat4 == "write"
    assert addr4 == 0x88890000

    # 5. Segfault Exec Fault
    err5 = ErrorRecord(state, angr.errors.SimSegfaultException(0x888a0000, "unmapped execution fetch"), None)
    cat5, addr5, _ = classify_state_error(err5)
    assert cat5 == "exec"
    assert addr5 == 0x888a0000


def test_unrepairable_errors_remain_in_errored():
    """Verify that unsupported syscalls and generic engine errors are NOT repaired
    and remain in simgr.errored.
    """
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    simgr = proj.factory.simgr(state)
    simgr.active.clear()

    # Add unrepairable engine error and permission fault error
    simgr.errored.append(ErrorRecord(state, angr.errors.SimEngineError("unsupported VEX op"), None))
    simgr.errored.append(ErrorRecord(state, angr.errors.SimMemoryError("permission fault violation"), None))

    repaired = repair_errored_states(simgr)
    assert repaired == 0
    assert len(simgr.active) == 0
    assert len(simgr.errored) == 2


def test_symbolic_address_preservation_multi_page_span():
    """Verify that auto-mapping unmapped memory across MULTIPLE distinct 4KB pages
    preserves symbolic variables without forcing add_constraints, and that ALL pages
    are actually mapped and physically readable.
    """
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    mult_sym = claripy.BVS("page_idx", 64)
    state.add_constraints(mult_sym >= 0, mult_sym <= 2)
    rdx_sym = mult_sym * 0x1000

    rsi_base = 0x88880000
    sym_addr = rsi_base + rdx_sym

    _ensure_page_mapped(state, sym_addr, access_size=4, is_code=False)

    assert state.solver.symbolic(rdx_sym)
    solutions = state.solver.eval_upto(rdx_sym, 10)
    assert len(solutions) == 3
    assert set(solutions) == {0x0, 0x1000, 0x2000}

    mapped_pages = state.globals.get("auto_mapped_pages", set())
    assert 0x88880000 in mapped_pages
    assert 0x88881000 in mapped_pages
    assert 0x88882000 in mapped_pages

    for page_addr in (0x88880000, 0x88881000, 0x88882000):
        assert _is_page_mapped(state.memory, page_addr)
        page_content = state.solver.eval(state.memory.load(page_addr, 4), cast_to=bytes)
        assert page_content == b"\x00\x00\x00\x00"


def test_cross_page_boundary_access():
    """Verify that an access of 8 bytes starting at 0x88880FFD spans across
    the boundary of page 0x88880000 and page 0x88881000, mapping BOTH pages.
    """
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    boundary_addr = 0x88880FFD
    success = _ensure_page_mapped(state, boundary_addr, access_size=8, is_code=False)
    assert success is True

    assert _is_page_mapped(state.memory, 0x88880000)
    assert _is_page_mapped(state.memory, 0x88881000)


class DummySymbolicMemoryError(angr.errors.SimMemoryError):
    def __init__(self, addr_ast):
        self.addr = addr_ast


def test_errored_state_repair_with_symbolic_fault_addr_all_candidates_mapped():
    """Verify that repairing an errored state with a SYMBOLIC fault_addr AST
    executes the symbolic branch of repair_errored_states, preserves symbolism,
    AND physically maps ALL candidate target pages.
    """
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    idx_sym = claripy.BVS("sym_page_idx", 64)
    state.add_constraints(idx_sym >= 0, idx_sym <= 2)
    rsi_sym = 0x88880000 + idx_sym * 0x1000
    state.regs.rsi = rsi_sym

    simgr = proj.factory.simgr(state)
    error_obj = DummySymbolicMemoryError(rsi_sym)
    error_rec = ErrorRecord(state, error_obj, None)
    simgr.errored.append(error_rec)

    repaired = repair_errored_states(simgr)
    assert repaired > 0
    assert len(simgr.active) > 0

    repaired_state = simgr.active[0]
    assert repaired_state.solver.symbolic(repaired_state.regs.rsi)

    for page_addr in (0x88880000, 0x88881000, 0x88882000):
        assert _is_page_mapped(repaired_state.memory, page_addr)
        content = repaired_state.solver.eval(repaired_state.memory.load(page_addr, 4), cast_to=bytes)
        assert content == b"\x00\x00\x00\x00"


def test_repair_failure_keeps_state_in_errored(monkeypatch):
    """Verify that if mapping any required page fails (_map_single_page returns False),
    repair_errored_states DOES NOT move state to simgr.active and keeps it in simgr.errored.
    """
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    simgr = proj.factory.simgr(state)
    simgr.active.clear()
    error_obj = angr.errors.SimSegfaultException(0x88880000, "read unmapped memory")
    simgr.errored.append(ErrorRecord(state, error_obj, None))

    monkeypatch.setattr(unmapped_module, "_map_single_page", lambda state, page_base, fault_addr=None, cc_name="auto", num_args=4, is_code=False: False)

    repaired = repair_errored_states(simgr)
    assert repaired == 0
    assert len(simgr.active) == 0
    assert len(simgr.errored) == 1


def test_retry_failed_page_mapping_can_succeed_on_subsequent_attempt():
    """Verify that if _map_single_page fails on the first attempt (e.g. exception),
    the page_base is NOT added to auto_mapped_pages, allowing a subsequent retry to succeed.
    """
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    page_base = 0x88880000

    real_map_region = state.memory.map_region
    def failing_map_region(*args, **kwargs):
        raise RuntimeError("Transient mapping error")

    state.memory.map_region = failing_map_region
    success_attempt1 = unmapped_module._map_single_page(state, page_base, is_code=False)
    assert success_attempt1 is False

    auto_mapped = state.globals.get("auto_mapped_pages", set())
    assert page_base not in auto_mapped

    state.memory.map_region = real_map_region
    success_attempt2 = unmapped_module._map_single_page(state, page_base, is_code=False)
    assert success_attempt2 is True
    assert page_base in state.globals["auto_mapped_pages"]
    assert unmapped_module._is_page_mapped(state.memory, page_base)
