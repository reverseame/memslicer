"""Tests for inter-call data-flow linking (A1: value-equality taint)."""
from memslicer.behavior.dataflow import MIN_TAINT_VALUE, link_dataflow
from memslicer.behavior.graph import BehaviorGraph


def _graph(events):
    g = BehaviorGraph()
    g.events = events
    return g


def _ev(name, args, ret, kind="api"):
    return {"kind": kind, "name": name, "args": args, "ret": ret}


def _df(graph):
    return {k: v for k, v in graph.edges.items() if v["type"] == "dataflow"}


def test_handle_flows_from_producer_to_consumer():
    g = _graph([
        _ev("CreateFileW", [0x1, 0x2], 0x140),     # produces handle 0x140
        _ev("ReadFile", [0x140, 0x9000, 0x10], 0),  # consumes it as arg0
    ])
    n = link_dataflow(g)
    assert n == 1
    edge = _df(g)[("api:CreateFileW", "api:ReadFile", "dataflow")]
    assert edge["value"] == "0x140" and edge["arg"] == 0


def test_no_edge_when_value_only_appears_as_arg():
    g = _graph([
        _ev("ReadFile", [0x140], 0),               # consumes before any producer
        _ev("CreateFileW", [], 0x140),
    ])
    assert link_dataflow(g) == 0


def test_self_consumption_is_not_linked():
    # a call whose own return matches one of its args must not self-loop
    g = _graph([_ev("GetThing", [0x500], 0x500)])
    assert link_dataflow(g) == 0


def test_sentinels_and_small_values_ignored():
    g = _graph([
        _ev("A", [], 0),                # 0 sentinel -> not produced
        _ev("B", [], 1),                # 1 sentinel
        _ev("C", [], 0xFFFFFFFFFFFFFFFF),
        _ev("D", [], 0x10),             # below threshold
        _ev("E", [0, 1, 0xFFFFFFFFFFFFFFFF, 0x10], 0),
    ])
    assert link_dataflow(g) == 0


def test_threshold_is_configurable():
    g = _graph([_ev("P", [], 0x10), _ev("Q", [0x10], 0)])
    assert link_dataflow(g, min_value=0x10) == 1


def test_repeated_flow_increments_count():
    g = _graph([
        _ev("Alloc", [], 0x7F0000000000),
        _ev("Write", [0x7F0000000000], 0),
        _ev("Write", [0x7F0000000000], 0),
    ])
    link_dataflow(g)
    edge = _df(g)[("api:Alloc", "api:Write", "dataflow")]
    assert edge["count"] == 2


def test_string_args_do_not_break_matching():
    # Speakeasy decodes some args to str; they must be skipped, not crash
    g = _graph([
        _ev("LoadLibraryW", ["C:/evil.dll"], 0x10000000),
        _ev("GetProcAddress", [0x10000000, "Foo"], 0x20000000),
    ])
    assert link_dataflow(g) == 1
    assert ("api:LoadLibraryW", "api:GetProcAddress", "dataflow") in g.edges


def test_min_taint_value_default():
    assert MIN_TAINT_VALUE == 0x100


def _write_linux_code_slice(path, code):
    """A minimal Linux x86-64 slice running *code* from 0x401000."""
    from memslicer.msl.writer import MSLWriter
    from memslicer.msl.types import (
        FileHeader, ProcessIdentity, MemoryRegion, ThreadContext,
        ThreadRegister,
    )
    from memslicer.msl.constants import (
        ArchType, CapBit, CompAlgo, OSType, PageState, RegionType,
        REG_FLAG_PC, REG_FLAG_SP, THREAD_FLAG_CURRENT, ThreadState,
    )
    PS, CODE_VA, STACK_VA = 4096, 0x401000, 0x7ffff000
    page = code + b"\x90" * (PS - len(code))
    cap = ((1 << CapBit.MemoryRegions) | (1 << CapBit.ThreadContexts))
    hdr = FileHeader(os_type=OSType.Linux, arch_type=ArchType.x86_64, pid=7,
                     cap_bitmap=cap)
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
                ThreadRegister("rsp", (STACK_VA + 0xf00).to_bytes(8, "little"),
                               REG_FLAG_SP),
            ]))
        w.finalize()


def test_dataflow_end_to_end_through_tracer(tmp_path):
    import pytest
    pytest.importorskip("unicorn")
    from memslicer.behavior.stublib import build_default_registry
    from memslicer.behavior.tracer import BehaviorTracer
    from memslicer.emu.engine import open_slice

    # mov rax,9 (mmap); syscall; mov rdi,rax; mov rax,11 (munmap); syscall
    code = bytes.fromhex(
        "48c7c009000000" "0f05" "4889c7" "48c7c00b000000" "0f05" "4889c1"
    )
    p = tmp_path / "df.msl"
    _write_linux_code_slice(p, code)
    emu = open_slice(str(p))
    graph = BehaviorTracer(emu, registry=build_default_registry()).run(
        max_steps=20)

    # the address mmap returned is consumed by munmap -> a dataflow edge
    assert graph.meta.get("dataflow_edges", 0) >= 1
    key = ("syscall:mmap", "syscall:munmap", "dataflow")
    assert key in graph.edges


def test_dataflow_in_dot_export():
    g = _graph([
        _ev("CreateFileW", [], 0x140),
        _ev("WriteFile", [0x140], 0),
    ])
    link_dataflow(g)
    # nodes referenced by the edge must exist for a meaningful DOT; create them
    g.touch_node_id("api:CreateFileW", "api", label="CreateFileW")
    g.touch_node_id("api:WriteFile", "api", label="WriteFile")
    dot = g.to_dot()
    assert "dataflow 0x140" in dot
    assert "color=red" in dot
