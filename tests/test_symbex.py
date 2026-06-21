"""Tests for the angr bridge (memslicer.symbex). Requires the symbex extra."""
import pytest

from memslicer.msl.writer import MSLWriter
from memslicer.msl.types import (
    FileHeader, ProcessIdentity, MemoryRegion, ThreadContext, ThreadRegister,
)
from memslicer.msl.constants import (
    ArchType, CapBit, CompAlgo, OSType, PageState, RegionType,
    REG_FLAG_PC, REG_FLAG_SP, THREAD_FLAG_CURRENT, ThreadState,
)

PS = 4096
CODE_VA = 0x401000
STACK_VA = 0x7ffff000
CODE = bytes.fromhex("48c7c001000000" "48c7c302000000" "4801d8" "48ffc0" "4889c1")


def _write_slice(path):
    page = CODE + b"\x90" * (PS - len(CODE))
    cap = ((1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity)
           | (1 << CapBit.ThreadContexts))
    hdr = FileHeader(os_type=OSType.Linux, arch_type=ArchType.x86_64, pid=7, cap_bitmap=cap)
    with open(path, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="/bin/demo"))
        w.write_memory_region(MemoryRegion(
            base_addr=CODE_VA, region_size=PS, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[page]))
        w.write_memory_region(MemoryRegion(
            base_addr=STACK_VA, region_size=PS, protection=0b011,
            region_type=RegionType.Stack, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[b"\x00" * PS]))
        w.write_thread_context(ThreadContext(
            thread_id=7, flags=THREAD_FLAG_CURRENT, state=ThreadState.Stopped,
            name="main", registers=[
                ThreadRegister("rip", CODE_VA.to_bytes(8, "little"), REG_FLAG_PC),
                ThreadRegister("rsp", (STACK_VA + 0xf00).to_bytes(8, "little"), REG_FLAG_SP),
                ThreadRegister("rax", (0xcafe).to_bytes(8, "little"), 0),
            ]))
        w.finalize()


def test_load_angr_seeds_state(tmp_path):
    pytest.importorskip("angr")
    from memslicer.symbex import load_angr

    p = tmp_path / "code.msl"
    _write_slice(p)
    project, state = load_angr(str(p))

    assert project.arch.name == "AMD64"
    assert state.addr == CODE_VA                              # entry = captured PC
    assert state.solver.eval(state.regs.rax) == 0xcafe        # seeded register
    code = state.solver.eval(state.memory.load(CODE_VA, 7), cast_to=bytes)
    assert code == CODE[:7]                                   # captured memory
    rsp = state.solver.eval(state.regs.rsp)
    assert rsp == STACK_VA + 0xf00


def test_load_angr_can_execute(tmp_path):
    pytest.importorskip("angr")
    from memslicer.symbex import load_angr

    p = tmp_path / "code.msl"
    _write_slice(p)
    project, state = load_angr(str(p))
    simgr = project.factory.simgr(state)
    simgr.step()
    assert simgr.active                                       # has a successor
    # the basic block executed mov rax,1; mov rbx,2; add; inc; mov rcx,rax
    succ = simgr.active[0]
    assert succ.solver.eval(succ.regs.rcx) == 4
