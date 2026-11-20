"""Regression tests for the symbex fixes of PR #18.

Covers: importing ``memslicer.symbex`` without angr, slices whose page size is
not 4 KiB, a plain ``memslicer-symbex`` run leaving captured memory untouched,
and the syscall hook keeping the instructions before the syscall.
"""
import importlib
import io
import sys

import pytest

from memslicer.msl.writer import MSLWriter
from memslicer.msl.types import (
    FileHeader, ProcessIdentity, MemoryRegion, ThreadContext, ThreadRegister,
)
from memslicer.msl.constants import (
    ArchType, CapBit, CompAlgo, OSType, PageState, RegionType,
    REG_ROLE_PC, REG_ROLE_SP, TC_FLAG_CURRENT, ThreadState,
)

CAP = ((1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity)
       | (1 << CapBit.ThreadContexts))


def _write_slice(path, *, arch, regions, registers):
    """*regions*: (base, page_size, data); *registers*: (name, width, role, value)."""
    hdr = FileHeader(os_type=OSType.Linux, arch_type=arch, pid=7, cap_bitmap=CAP)
    with open(path, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="/bin/demo"))
        for base, page_size, data in regions:
            npages = len(data) // page_size
            w.write_memory_region(MemoryRegion(
                base_addr=base, region_size=len(data), protection=0b111,
                region_type=RegionType.Image, page_size=page_size,
                page_states=[PageState.CAPTURED] * npages,
                page_data_chunks=[data[i * page_size:(i + 1) * page_size]
                                  for i in range(npages)]))
        w.write_thread_context(ThreadContext(
            thread_id=7, flags=TC_FLAG_CURRENT, state=ThreadState.STOPPED,
            name="main", registers=[
                ThreadRegister(name, width, role, value.to_bytes(width, "little"))
                for name, width, role, value in registers
            ]))
        w.finalize()


# ---- import without angr -------------------------------------------------

def test_symbex_import_without_angr_raises_symbex_error(monkeypatch):
    """``memslicer.symbex`` imports without angr and ``load_angr`` raises the
    friendly SymbexError naming the extra (not ModuleNotFoundError)."""
    import memslicer
    import memslicer.symbex

    # The fresh import below rebinds ``memslicer.symbex``; restore it after.
    monkeypatch.setattr(memslicer, "symbex", memslicer.symbex)
    monkeypatch.setitem(sys.modules, "angr", None)
    monkeypatch.setitem(sys.modules, "claripy", None)
    for name in [m for m in sys.modules if m.startswith("memslicer.symbex")]:
        monkeypatch.delitem(sys.modules, name)

    symbex = importlib.import_module("memslicer.symbex")

    with pytest.raises(symbex.SymbexError, match=r"pip install memslicer\[symbex\]"):
        symbex.load_angr("whatever.msl")


# ---- non-4K pages ----------------------------------------------------------

def test_load_angr_accepts_16k_pages(tmp_path):
    """A slice with 16 KiB pages (macOS/iOS arm64) loads; every page is mapped."""
    pytest.importorskip("angr")
    from memslicer.symbex import load_angr

    ps = 16384
    base = 0x100000000
    nop = bytes.fromhex("1f2003d5")
    data = bytearray(nop * (2 * ps // 4))
    data[ps + 0x40:ps + 0x44] = b"\xde\xad\xbe\xef"
    p = tmp_path / "arm64_16k.msl"
    _write_slice(p, arch=ArchType.ARM64, regions=[(base, ps, bytes(data))],
                 registers=[("pc", 8, REG_ROLE_PC, base),
                            ("sp", 8, REG_ROLE_SP, base + ps)])

    project, state = load_angr(str(p))

    assert state.addr == base
    got = state.solver.eval(state.memory.load(base + ps + 0x40, 4), cast_to=bytes)
    assert got == b"\xde\xad\xbe\xef"


# ---- default CLI run leaves captured memory untouched ---------------------

CODE_VA = 0x401000
STACK_VA = 0x7ffff000
RBP = STACK_VA + 0x800
STACK = bytes(range(256)) * 16


def _x64_slice(path):
    code = b"\x90" * 4096
    _write_slice(path, arch=ArchType.x86_64,
                 regions=[(CODE_VA, 4096, code), (STACK_VA, 4096, STACK)],
                 registers=[("rip", 8, REG_ROLE_PC, CODE_VA),
                            ("rsp", 8, REG_ROLE_SP, STACK_VA + 0x700),
                            ("rbp", 8, 0, RBP)])


def _run_cli(monkeypatch, args):
    """Run ``memslicer-symbex`` and return (result, initial state)."""
    pytest.importorskip("angr")
    from click.testing import CliRunner
    import memslicer.cli_symbex as cli

    seen = {}
    real = cli.load_angr

    def spy(path):
        project, state = real(path)
        seen["state"] = state
        return project, state

    monkeypatch.setattr(cli, "load_angr", spy)
    result = CliRunner().invoke(cli.main, args)
    return result, seen["state"]


def _stack_bytes(state, addr, n):
    data = state.memory.load(addr, n)
    assert not state.solver.symbolic(data)
    return state.solver.eval(data, cast_to=bytes)


def test_default_symbex_run_keeps_captured_memory(tmp_path, monkeypatch):
    """No injection option: the state starts exactly as captured."""
    p = tmp_path / "x64.msl"
    _x64_slice(p)
    result, state = _run_cli(monkeypatch, [str(p), "-s", "1"])

    assert result.exit_code == 0, result.output
    assert "symbolic key buffer" not in result.output
    assert "injected_key_addr" not in state.globals
    off = RBP - 0x40 - STACK_VA
    assert _stack_bytes(state, RBP - 0x40, 17) == STACK[off:off + 17]


def test_explicit_sym_bytes_injects_buffer_with_nul(tmp_path, monkeypatch):
    """-k N asks for a printable C-string key: N symbolic bytes plus a NUL."""
    p = tmp_path / "x64.msl"
    _x64_slice(p)
    result, state = _run_cli(monkeypatch, [str(p), "-k", "8"])

    assert result.exit_code == 0, result.output
    assert state.globals["injected_key_addr"] == RBP - 0x40
    assert state.solver.symbolic(state.memory.load(RBP - 0x40, 8))
    assert _stack_bytes(state, RBP - 0x40 + 8, 1) == b"\x00"


def test_binary_key_keeps_byte_after_key(tmp_path, monkeypatch):
    """--binary-key writes no trailing NUL over the captured byte after the key."""
    p = tmp_path / "x64.msl"
    _x64_slice(p)
    result, state = _run_cli(monkeypatch, [str(p), "--binary-key", "-k", "8"])

    assert result.exit_code == 0, result.output
    after = RBP - 0x40 + 8
    assert _stack_bytes(state, after, 1) == STACK[after - STACK_VA:after - STACK_VA + 1]


# ---- syscall hook ----------------------------------------------------------

def test_syscall_hook_keeps_instructions_before_syscall():
    """``mov rbx, 0x1234; syscall``: the mov still runs, and execution resumes
    right after the 2-byte syscall."""
    angr = pytest.importorskip("angr")
    from memslicer.symbex.syscall_handler import setup_syscall_emulation

    code = bytes.fromhex("48c7c334120000" "0f05" "90" "c3")
    base = 0x401000
    project = angr.Project(io.BytesIO(code), auto_load_libs=False,
                           main_opts={"backend": "blob", "arch": "amd64",
                                      "base_addr": base})
    state = project.factory.blank_state(addr=base)
    state.regs.rbx = 0x1111
    setup_syscall_emulation(project, state)

    assert project.is_hooked(base + 7)
    assert not project.is_hooked(base)

    simgr = project.factory.simgr(state)
    while simgr.active and simgr.active[0].addr != base + 9:
        simgr.step()
    assert simgr.active
    s = simgr.active[0]
    assert s.solver.eval(s.regs.rbx) == 0x1234
    assert s.solver.eval(s.regs.rax) == 0      # stub's return value


def test_no_syscall_handler_leaves_syscalls_unhooked():
    """enable_unmapped_memory_recovery(syscall_emulation=False) installs no
    syscall hooks, so angr's own syscall models stay in charge."""
    angr = pytest.importorskip("angr")
    from memslicer.symbex.unmapped_handler import enable_unmapped_memory_recovery

    code = bytes.fromhex("48c7c334120000" "0f05" "c3")
    project = angr.Project(io.BytesIO(code), auto_load_libs=False,
                           main_opts={"backend": "blob", "arch": "amd64",
                                      "base_addr": 0x401000})
    state = project.factory.blank_state(addr=0x401000)
    enable_unmapped_memory_recovery(project, state, premap_stack_mb=0,
                                    syscall_emulation=False)
    assert not project.is_hooked(0x401007)
