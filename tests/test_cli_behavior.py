"""Tests for the memslicer-behavior CLI (cli_behavior). Needs the emu extra
for the runs themselves; argument wiring is exercised via Click's CliRunner."""
import json
import xml.etree.ElementTree as ET

import pytest
from click.testing import CliRunner

from memslicer.cli_behavior import main

CODE_VA = 0x401000
STACK_VA = 0x7ffff000
PS = 4096
# mov rax,9 (mmap) ; syscall ; mov rdi,rax ; mov rax,11 (munmap) ; syscall
CODE = bytes.fromhex("48c7c009000000" "0f05" "4889c7" "48c7c00b000000" "0f05")


def _slice(path):
    from memslicer.msl.writer import MSLWriter
    from memslicer.msl.types import (
        FileHeader, ProcessIdentity, MemoryRegion, ThreadContext, ThreadRegister,
    )
    from memslicer.msl.constants import (
        ArchType, CapBit, CompAlgo, OSType, PageState, RegionType,
        REG_FLAG_PC, REG_FLAG_SP, THREAD_FLAG_CURRENT, ThreadState,
    )
    page = CODE + b"\x90" * (PS - len(CODE))
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


@pytest.fixture
def slc(tmp_path):
    p = tmp_path / "s.msl"
    _slice(p)
    return str(p)


def _run(args):
    return CliRunner().invoke(main, args)


def test_help_lists_new_flags():
    r = _run(["--help"])
    assert r.exit_code == 0
    for flag in ("--backend", "--memory", "--call-graph", "--features",
                 "--stublib", "graphml", "gexf"):
        assert flag in r.output


def test_json_output_to_file(tmp_path, slc):
    pytest.importorskip("unicorn")
    out = tmp_path / "g.json"
    r = _run([slc, "-o", str(out)])
    assert r.exit_code == 0, r.output
    data = json.loads(out.read_text())
    assert {"meta", "nodes", "links", "events"} <= data.keys()


@pytest.mark.parametrize("ext,check", [
    ("dot", lambda t: t.startswith("digraph behavior {")),
    ("graphml", lambda t: (ET.fromstring(t) is not None)),
    ("gexf", lambda t: (ET.fromstring(t) is not None)),
])
def test_format_inferred_from_extension(tmp_path, slc, ext, check):
    pytest.importorskip("unicorn")
    out = tmp_path / f"g.{ext}"
    r = _run([slc, "-o", str(out)])
    assert r.exit_code == 0, r.output
    assert check(out.read_text())


def test_explicit_format_to_stdout(slc):
    pytest.importorskip("unicorn")
    r = _run([slc, "-f", "graphml"])
    assert r.exit_code == 0
    assert "<graphml" in r.output


def test_features_file(tmp_path, slc):
    pytest.importorskip("unicorn")
    feat = tmp_path / "f.json"
    r = _run([slc, "--features", str(feat)])
    assert r.exit_code == 0, r.output
    feats = json.loads(feat.read_text())
    assert "nodes" in feats and "cat_file" in feats


def test_call_graph_flag_adds_func_nodes(tmp_path, slc):
    pytest.importorskip("unicorn")
    out = tmp_path / "g.json"
    _run([slc, "--call-graph", "-o", str(out)])
    nodes = json.loads(out.read_text())["nodes"]
    assert any(n["id"].startswith("func:") for n in nodes)


def test_no_memory_flag(tmp_path, slc):
    pytest.importorskip("unicorn")
    out = tmp_path / "g.json"
    _run([slc, "--no-memory", "-o", str(out)])
    assert "memory" not in json.loads(out.read_text())["meta"]
    out2 = tmp_path / "g2.json"
    _run([slc, "-o", str(out2)])                 # default: memory present
    assert "memory" in json.loads(out2.read_text())["meta"]


def test_stublib_returns_handles(tmp_path, slc):
    pytest.importorskip("unicorn")
    out = tmp_path / "g.json"
    _run([slc, "--stublib", "-o", str(out)])
    events = json.loads(out.read_text())["events"]
    mmap_ev = [e for e in events if e["name"] == "mmap"]
    assert mmap_ev and mmap_ev[0]["ret"] >= 0x100   # stublib handed out an addr


def test_emit_stubs(tmp_path, slc):
    pytest.importorskip("unicorn")
    skel = tmp_path / "stubs.py"
    r = _run([slc, "--emit-stubs", str(skel)])
    assert r.exit_code == 0
    assert "def " in skel.read_text()


def test_speakeasy_backend_without_pe_errors_cleanly(slc):
    # a Linux slice has no PE image; the speakeasy path should fail clearly
    # (this runs before any speakeasy import, so it needs no optional dep)
    r = _run([slc, "--backend", "speakeasy"])
    assert r.exit_code != 0
    assert "no PE image" in r.output
