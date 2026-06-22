"""Tests for the memory-annotation probe (A3) and function call-graph probe
(A2). Both need the emu extra (Unicorn)."""
import pytest

CODE_VA = 0x401000
STACK_VA = 0x7ffff000
PS = 4096


def _write_slice(path, code, *, code_prot=0b101):
    """A Linux x86-64 slice running *code* from 0x401000 with a stack."""
    from memslicer.msl.writer import MSLWriter
    from memslicer.msl.types import (
        FileHeader, ProcessIdentity, MemoryRegion, ThreadContext,
        ThreadRegister,
    )
    from memslicer.msl.constants import (
        ArchType, CapBit, CompAlgo, OSType, PageState, RegionType,
        REG_FLAG_PC, REG_FLAG_SP, THREAD_FLAG_CURRENT, ThreadState,
    )
    page = code + b"\x90" * (PS - len(code))
    cap = ((1 << CapBit.MemoryRegions) | (1 << CapBit.ThreadContexts))
    hdr = FileHeader(os_type=OSType.Linux, arch_type=ArchType.x86_64, pid=7,
                     cap_bitmap=cap)
    with open(path, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="/bin/demo"))
        w.write_memory_region(MemoryRegion(
            base_addr=CODE_VA, region_size=PS, protection=code_prot,
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


def _trace(path, **kw):
    from memslicer.behavior.tracer import BehaviorTracer
    from memslicer.emu.engine import open_slice
    return BehaviorTracer(open_slice(path), **kw).run(max_steps=40)


# -- A3: memory annotations ---------------------------------------------------

def test_region_type_preserved_by_loader(tmp_path):
    from memslicer.emu.loader import load_slice
    from memslicer.msl.constants import RegionType
    p = tmp_path / "s.msl"
    _write_slice(p, b"\x90")
    img = load_slice(str(p))
    rts = {r.base: r.region_type for r in img.regions}
    assert rts[CODE_VA] == RegionType.Image
    assert rts[STACK_VA] == RegionType.Stack


def test_self_modifying_write_detected(tmp_path):
    pytest.importorskip("unicorn")
    # movabs rax,0x401050 ; mov byte [rax],0x90 ; mov [rsp],rax
    code = bytes.fromhex("48b85010400000000000" "c60090" "48890424")
    p = tmp_path / "smc.msl"
    _write_slice(p, code, code_prot=0b111)        # RWX code region
    graph = _trace(p)

    mem = graph.meta["memory"]
    assert mem["exec_writes"] >= 1                 # wrote into executable memory
    assert "0x401050" in mem["exec_write_targets"]
    assert mem["by_region"].get("stack", 0) >= 1   # the [rsp] write
    assert mem["by_region"].get("image", 0) >= 1   # the code write
    assert "0x401000" in mem["rwx_regions"]        # static RWX region flagged
    # the executing block is tagged so it stands out
    assert graph.nodes["0x401000"]["attrs"].get("writes_exec", 0) >= 1


def test_non_executable_writes_not_flagged(tmp_path):
    pytest.importorskip("unicorn")
    # only a stack write: mov [rsp], rax
    code = bytes.fromhex("48890424")
    p = tmp_path / "nx.msl"
    _write_slice(p, code)                          # default r-x code, rw- stack
    graph = _trace(p)
    mem = graph.meta["memory"]
    assert mem["exec_writes"] == 0
    assert mem["by_region"].get("stack", 0) >= 1
    assert mem["rwx_regions"] == []


def test_memory_probe_can_be_disabled(tmp_path):
    pytest.importorskip("unicorn")
    p = tmp_path / "s.msl"
    _write_slice(p, b"\x48\x89\x04\x24")
    graph = _trace(p, memory=False)
    assert "memory" not in graph.meta


# -- A2: dynamic call graph ---------------------------------------------------

def test_call_graph_records_call_and_return(tmp_path):
    pytest.importorskip("unicorn")
    # 0x401000 call 0x401010 ; 0x401005 xor rax,rax ; 0x401008 jmp $ ;
    # 0x401010 ret
    code = bytearray(b"\x90" * 0x11)
    code[0x00:0x05] = bytes.fromhex("e80b000000")  # call 0x401010
    code[0x05:0x08] = bytes.fromhex("4831c0")      # xor rax,rax
    code[0x08:0x0a] = bytes.fromhex("ebfe")        # jmp $ (self loop)
    code[0x10:0x11] = bytes.fromhex("c3")          # ret (callee)
    p = tmp_path / "cg.msl"
    _write_slice(p, bytes(code))
    graph = _trace(p, call_graph=True)

    assert "func:0x401000" in graph.nodes
    assert "func:0x401010" in graph.nodes
    assert ("func:0x401000", "func:0x401010", "call") in graph.edges
    assert ("func:0x401010", "func:0x401000", "ret") in graph.edges


def test_call_graph_off_by_default(tmp_path):
    pytest.importorskip("unicorn")
    code = bytes.fromhex("e80b000000" "4831c0" "ebfe")
    p = tmp_path / "cg2.msl"
    _write_slice(p, code)
    graph = _trace(p)
    assert not any(n.startswith("func:") for n in graph.nodes)
