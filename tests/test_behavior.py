"""Tests for behavior-graph extraction (memslicer.behavior). Needs the emu extra."""
import json

import pytest

from memslicer.msl.writer import MSLWriter
from memslicer.msl.types import (
    FileHeader, ProcessIdentity, MemoryRegion, ModuleEntry,
    ThreadContext, ThreadRegister,
)
from memslicer.msl.constants import (
    ArchType, CapBit, CompAlgo, OSType, PageState, RegionType,
    REG_FLAG_PC, REG_FLAG_SP, THREAD_FLAG_CURRENT, ThreadState,
)

PS = 4096
CODE_VA = 0x401000
STACK_VA = 0x7ffff000
# mov rax,1; mov rbx,2; add rax,rbx (rax=3); syscall; mov rcx,rax
CODE = bytes.fromhex(
    "48c7c001000000" "48c7c302000000" "4801d8" "0f05" "4889c1"
)


def _write_slice(path, with_module=False):
    page = CODE + b"\x90" * (PS - len(CODE))   # nop-fill the rest
    cap = ((1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity)
           | (1 << CapBit.ThreadContexts) | (1 << CapBit.ModuleList))
    hdr = FileHeader(os_type=OSType.Linux, arch_type=ArchType.x86_64, pid=7,
                     cap_bitmap=cap)
    with open(path, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="/bin/demo"))
        if with_module:
            w.write_module_list([ModuleEntry(
                base_addr=CODE_VA, module_size=PS, path="/bin/demo")])
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
            ]))
        w.finalize()


# -- loader: module parsing (dependency-free) -------------------------------

def test_loader_parses_modules(tmp_path):
    from memslicer.emu.loader import load_slice
    p = tmp_path / "m.msl"
    _write_slice(p, with_module=True)
    img = load_slice(str(p))
    assert len(img.modules) == 1
    assert img.modules[0].base == CODE_VA
    assert img.modules[0].name == "demo"


def test_resolver_maps_address(tmp_path):
    from memslicer.emu.loader import load_slice
    from memslicer.behavior.resolver import AddressResolver
    p = tmp_path / "m.msl"
    _write_slice(p, with_module=True)
    res = AddressResolver.from_image(load_slice(str(p)))
    assert res.resolve(CODE_VA) == "demo"
    assert res.resolve(CODE_VA + 0x10) == "demo+0x10"
    assert res.resolve(0xdead0000) is None
    assert res.label(0xdead0000) == "0xdead0000"


# -- tracer: behavior graph -------------------------------------------------

def test_trace_builds_graph_with_syscall(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.behavior import trace_slice

    p = tmp_path / "code.msl"
    _write_slice(p)
    graph = trace_slice(str(p), max_steps=12)

    # the syscall (rax=3 -> "close") became a behavior node + event
    assert "syscall:close" in graph.nodes
    assert any(e["name"] == "close" and e["number"] == 3 for e in graph.events)
    # at least one code node and one control-flow edge
    assert any(n["kind"] == "block" for n in graph.nodes.values())
    assert graph.edges


def test_default_stub_observes_and_continues(tmp_path):
    pytest.importorskip("unicorn")
    from memslicer.behavior.tracer import BehaviorTracer
    from memslicer.emu.engine import open_slice

    p = tmp_path / "code.msl"
    _write_slice(p)
    emu = open_slice(str(p))
    tracer = BehaviorTracer(emu)
    tracer.run(max_steps=12)
    # default stub set the syscall return (rax) to 0, so mov rcx,rax -> rcx=0
    assert emu.read_reg("rcx") == 0


def test_analyst_stub_overrides_return(tmp_path):
    pytest.importorskip("unicorn")
    from memslicer.behavior.stubs import load_stubs
    from memslicer.behavior.tracer import BehaviorTracer
    from memslicer.emu.engine import open_slice

    stub_file = tmp_path / "stubs.py"
    stub_file.write_text(
        "def close(ctx):\n"
        "    ctx.set_ret(0x1234)\n"
        "    return ctx.CONTINUE\n"
    )
    p = tmp_path / "code.msl"
    _write_slice(p)
    emu = open_slice(str(p))
    tracer = BehaviorTracer(emu, registry=load_stubs(str(stub_file)))
    tracer.run(max_steps=12)
    # analyst stub forced rax=0x1234, so mov rcx,rax -> rcx=0x1234
    assert emu.read_reg("rcx") == 0x1234


def test_granularity_instruction_makes_insn_nodes(tmp_path):
    pytest.importorskip("unicorn")
    from memslicer.behavior import trace_slice

    p = tmp_path / "code.msl"
    _write_slice(p)
    graph = trace_slice(str(p), granularity="instruction", max_steps=12)
    assert any(n["kind"] == "insn" for n in graph.nodes.values())


def test_emit_skeleton_lists_observed_calls(tmp_path):
    pytest.importorskip("unicorn")
    from memslicer.behavior.stubs import emit_skeleton
    from memslicer.behavior.tracer import BehaviorTracer
    from memslicer.emu.engine import open_slice

    p = tmp_path / "code.msl"
    _write_slice(p)
    emu = open_slice(str(p))
    tracer = BehaviorTracer(emu)
    tracer.run(max_steps=12)

    out = tmp_path / "stubs.py"
    emit_skeleton(tracer.registry, str(out))
    text = out.read_text()
    assert "def close(ctx):" in text
    assert "return ctx.CONTINUE" in text


# -- Windows PE export resolution + API interception ------------------------

def _build_pe_page(func_rva=0x400, name=b"CreateFileW"):
    """A minimal 4 KiB PE64 image page exporting one function by name."""
    page = bytearray(b"\xc3" * PS)            # 'ret' fill
    def put(off, data):
        page[off:off + len(data)] = data
    import struct as _s
    put(0, b"MZ")
    put(0x3C, _s.pack("<I", 0x80))            # e_lfanew
    put(0x80, b"PE\x00\x00")
    put(0x94, _s.pack("<H", 0xF0))            # SizeOfOptionalHeader
    put(0x98, _s.pack("<H", 0x20B))           # Optional magic = PE32+
    exp_rva = 0x200
    put(0x108, _s.pack("<II", exp_rva, 0x80))  # DataDirectory[0] = export
    # export directory @ exp_rva
    put(exp_rva + 0x14, _s.pack("<I", 1))      # NumberOfFunctions
    put(exp_rva + 0x18, _s.pack("<I", 1))      # NumberOfNames
    put(exp_rva + 0x1C, _s.pack("<I", 0x240))  # AddressOfFunctions
    put(exp_rva + 0x20, _s.pack("<I", 0x250))  # AddressOfNames
    put(exp_rva + 0x24, _s.pack("<I", 0x260))  # AddressOfNameOrdinals
    put(0x240, _s.pack("<I", func_rva))        # function RVA
    put(0x250, _s.pack("<I", 0x270))           # name RVA
    put(0x260, _s.pack("<H", 0))               # ordinal
    put(0x270, name + b"\x00")
    return bytes(page)


def test_pe_export_parser():
    from memslicer.behavior.pe import parse_pe_exports
    page = _build_pe_page()
    base = 0x70000000
    mem = lambda a, n: page[a - base:a - base + n]   # noqa: E731
    exports = parse_pe_exports(mem, base)
    assert exports == {base + 0x400: "CreateFileW"}


MOD_VA = 0x70000000
# mov rcx,0x1234 ; movabs rax,0x70000400 ; call rax ; mov rbx,rax
CODE_API = bytes.fromhex(
    "48c7c134120000" "48b80004007000000000" "ffd0" "4889c3"
)


def _write_api_slice(path):
    cap = ((1 << CapBit.MemoryRegions) | (1 << CapBit.ThreadContexts)
           | (1 << CapBit.ModuleList))
    hdr = FileHeader(os_type=OSType.Windows, arch_type=ArchType.x86_64, pid=7,
                     cap_bitmap=cap)
    code_page = CODE_API + b"\x90" * (PS - len(CODE_API))
    with open(path, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="C:/demo.exe"))
        w.write_module_list([ModuleEntry(
            base_addr=MOD_VA, module_size=PS,
            path="C:/Windows/System32/kernel32.dll")])
        w.write_memory_region(MemoryRegion(
            base_addr=CODE_VA, region_size=PS, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[code_page]))
        w.write_memory_region(MemoryRegion(
            base_addr=MOD_VA, region_size=PS, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[_build_pe_page()]))
        w.write_memory_region(MemoryRegion(
            base_addr=STACK_VA, region_size=PS, protection=0b011,
            region_type=RegionType.Stack, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[b"\x00" * PS]))
        w.write_thread_context(ThreadContext(
            thread_id=7, flags=THREAD_FLAG_CURRENT, state=ThreadState.Stopped,
            name="main", registers=[
                ThreadRegister("rip", CODE_VA.to_bytes(8, "little"), REG_FLAG_PC),
                ThreadRegister("rsp", (STACK_VA + 0x800).to_bytes(8, "little"), REG_FLAG_SP),
            ]))
        w.finalize()


def test_api_call_intercepted_and_stubbed(tmp_path):
    pytest.importorskip("unicorn")
    from memslicer.behavior.stubs import load_stubs
    from memslicer.behavior.tracer import BehaviorTracer
    from memslicer.emu.engine import open_slice

    stub_file = tmp_path / "stubs.py"
    stub_file.write_text(
        "def CreateFileW(ctx):\n"
        "    ctx.log(f'CreateFileW arg0={ctx.arg(0):#x}')\n"
        "    ctx.set_ret(0x99)\n"
        "    return ctx.CONTINUE\n"
    )
    p = tmp_path / "api.msl"
    _write_api_slice(p)
    emu = open_slice(str(p))
    tracer = BehaviorTracer(emu, registry=load_stubs(str(stub_file)))
    graph = tracer.run(max_steps=20)

    # the export was resolved, intercepted, stubbed (rax=0x99) and returned to
    # the caller, so `mov rbx, rax` set rbx to the stubbed return value.
    assert emu.read_reg("rbx") == 0x99
    assert "api:kernel32.dll!CreateFileW" in graph.nodes
    ev = [e for e in graph.events if e["kind"] == "api"]
    assert ev and ev[0]["name"] == "kernel32.dll!CreateFileW"
    assert ev[0]["args"][0] == 0x1234            # rcx (Win64 arg0)


def test_graph_serializers(tmp_path):
    pytest.importorskip("unicorn")
    from memslicer.behavior import trace_slice

    p = tmp_path / "code.msl"
    _write_slice(p)
    graph = trace_slice(str(p), max_steps=12)

    data = json.loads(graph.to_json())
    assert "nodes" in data and "links" in data and "events" in data
    dot = graph.to_dot()
    assert dot.startswith("digraph behavior {")
    assert "syscall:close" in dot
