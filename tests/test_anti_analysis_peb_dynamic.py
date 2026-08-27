"""Unit tests for Phase 1: Dynamic PEB/TEB Resolution & Architecture-Specific Offsets."""

import pytest

angr = pytest.importorskip("angr")
claripy = pytest.importorskip("claripy")

from memslicer.symbex.anti_analysis import mask_peb_anti_debug, apply_anti_analysis_bypass


def test_peb_masking_x64_explicit_and_dynamic():
    """Test x64 PEB masking with explicit PEB base and dynamic TEB resolution."""
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64"})
    state = proj.factory.blank_state()

    peb_x64 = 0x7FFD0000
    state.memory.store(peb_x64 + 0x02, claripy.BVV(1, 8))        # BeingDebugged = 1
    state.memory.store(peb_x64 + 0x68, claripy.BVV(0x70, 32))    # NtGlobalFlag = 0x70

    heap_ptr = 0x90000000
    state.memory.store(peb_x64 + 0x30, claripy.BVV(heap_ptr, 64), endness=state.arch.memory_endness)
    state.memory.store(heap_ptr + 0x70, claripy.BVV(0x4000, 32), endness=state.arch.memory_endness) # Heap.Flags
    state.memory.store(heap_ptr + 0x74, claripy.BVV(0x4000, 32), endness=state.arch.memory_endness) # Heap.ForceFlags

    mask_peb_anti_debug(state, peb_base=peb_x64)

    assert state.solver.eval(state.memory.load(peb_x64 + 0x02, 1)) == 0
    assert state.solver.eval(state.memory.load(peb_x64 + 0x68, 4)) == 0
    assert state.solver.eval(state.memory.load(heap_ptr + 0x70, 4, endness=state.arch.memory_endness)) == 2
    assert state.solver.eval(state.memory.load(heap_ptr + 0x74, 4, endness=state.arch.memory_endness)) == 0


def test_peb_masking_x86_architecture_offsets():
    """Test x86 PEB masking using 32-bit architecture offsets (NtGlobalFlag at +0xBC)."""
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "x86"})
    state = proj.factory.blank_state()

    peb_x86 = 0x7FFDF000
    state.memory.store(peb_x86 + 0x02, claripy.BVV(1, 8))        # BeingDebugged = 1
    state.memory.store(peb_x86 + 0xBC, claripy.BVV(0x70, 32))    # NtGlobalFlag = 0x70 (x86 offset)

    heap_ptr = 0x20000000
    state.memory.store(peb_x86 + 0x18, claripy.BVV(heap_ptr, 32), endness=state.arch.memory_endness)
    state.memory.store(heap_ptr + 0x40, claripy.BVV(0x4000, 32), endness=state.arch.memory_endness) # Heap.Flags x86

    mask_peb_anti_debug(state, peb_base=peb_x86)

    assert state.solver.eval(state.memory.load(peb_x86 + 0x02, 1)) == 0
    assert state.solver.eval(state.memory.load(peb_x86 + 0xBC, 4)) == 0
    assert state.solver.eval(state.memory.load(heap_ptr + 0x40, 4, endness=state.arch.memory_endness)) == 2


def test_teb_dynamic_peb_resolution():
    """Test dynamic PEB resolution via GS_BASE (TEB + 0x60 -> PEB)."""
    proj = angr.Project(__import__("io").BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64"})
    state = proj.factory.blank_state()

    teb_base = 0x7FFF0000
    peb_base = 0x7FFE0000
    state.regs.gs = teb_base
    state.memory.store(teb_base + 0x60, claripy.BVV(peb_base, 64), endness=state.arch.memory_endness)

    # Set debugged flags on peb_base
    state.memory.store(peb_base + 0x02, claripy.BVV(1, 8))
    state.memory.store(peb_base + 0x68, claripy.BVV(0x70, 32))

    apply_anti_analysis_bypass(proj, state)

    assert state.solver.eval(state.memory.load(peb_base + 0x02, 1)) == 0
    assert state.solver.eval(state.memory.load(peb_base + 0x68, 4)) == 0
