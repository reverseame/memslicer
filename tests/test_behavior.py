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


# -- syscall tables ---------------------------------------------------------

def test_syscall_tables_per_arch():
    from memslicer.behavior.syscalls import syscall_name
    assert syscall_name(ArchType.x86_64, 257) == "openat"
    assert syscall_name(ArchType.x86_64, 9) == "mmap"
    assert syscall_name(ArchType.x86_64, 435) == "clone3"
    assert syscall_name(ArchType.x86, 11) == "execve"        # i386 numbering
    assert syscall_name(ArchType.ARM64, 221) == "execve"     # generic numbering
    assert syscall_name(ArchType.ARM32, 322) == "openat"
    assert syscall_name(ArchType.x86_64, 99999) == "sys_99999"


# -- ELF dynsym + PLT/GOT resolution ----------------------------------------

ELF_BASE = 0x555555554000
LIBC_BASE = 0x7FFFF7A00000
MALLOC_ADDR = 0x7FFFF7A12345


def _build_elf_image():
    import struct as _s
    img = bytearray(0x600)

    def put(off, data):
        img[off:off + len(data)] = data

    # ELF header (ET_DYN, x86-64)
    put(0, b"\x7fELF\x02\x01\x01")
    put(16, _s.pack("<H", 3))          # e_type = ET_DYN
    put(18, _s.pack("<H", 0x3E))       # e_machine = x86-64
    put(32, _s.pack("<Q", 64))         # e_phoff
    put(52, _s.pack("<H", 64))         # e_ehsize
    put(54, _s.pack("<H", 56))         # e_phentsize
    put(56, _s.pack("<H", 2))          # e_phnum
    # PT_LOAD
    put(64, _s.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 0x600, 0x600, 0x1000))
    # PT_DYNAMIC @ vaddr 0x200
    put(120, _s.pack("<IIQQQQQQ", 2, 6, 0x200, 0x200, 0, 0xA0, 0xA0, 8))
    # dynamic table @ 0x200
    dyn = [(6, 0x300), (5, 0x348), (11, 24), (23, 0x360), (2, 24),
           (20, 7), (0, 0)]
    off = 0x200
    for tag, val in dyn:
        put(off, _s.pack("<QQ", tag, val))
        off += 16
    # .dynsym @ 0x300: [null, foo(defined), malloc(undef)]
    put(0x318, _s.pack("<IBBHQQ", 1, 0x12, 0, 1, 0x500, 0))   # foo @ 0x500
    put(0x330, _s.pack("<IBBHQQ", 5, 0x12, 0, 0, 0, 0))       # malloc (UNDEF)
    # .dynstr @ 0x348
    put(0x348, b"\x00foo\x00malloc\x00")
    # .rela.plt @ 0x360: one JUMP_SLOT for malloc (symidx 2), GOT slot @ 0x4F0
    put(0x360, _s.pack("<QQQ", 0x4F0, (2 << 32) | 7, 0))
    # bound GOT slot -> resolved malloc address
    put(0x4F0, _s.pack("<Q", MALLOC_ADDR))
    return bytes(img)


def _elf_mem(base):
    img = _build_elf_image()
    def mem(a, n):                                            # noqa: ANN001
        off = a - base
        if 0 <= off < len(img):
            return img[off:off + n]
        return b"\x00" * n
    return mem


def test_elf_parser_defined_and_imports():
    from memslicer.behavior.elf import parse_elf
    defined, imports = parse_elf(_elf_mem(ELF_BASE), ELF_BASE)
    assert defined == {ELF_BASE + 0x500: "foo"}
    assert imports == {MALLOC_ADDR: "malloc"}


def test_resolver_elf_dynsym_and_plt():
    from memslicer.behavior.resolver import AddressResolver
    from memslicer.emu.loader import EmuModule
    mods = [EmuModule(ELF_BASE, 0x600, "/lib/libfoo.so"),
            EmuModule(LIBC_BASE, 0x100000, "/lib/x86_64-linux-gnu/libc.so.6")]
    res = AddressResolver(mods, mem_read=_elf_mem(ELF_BASE))
    assert res.export_at(ELF_BASE + 0x500) == "libfoo.so!foo"
    # PLT/GOT import attributed to the module owning the bound address (libc)
    assert res.export_at(MALLOC_ADDR) == "libc.so.6!malloc"


# -- end-to-end ELF PLT/GOT interception (emulate through a real PLT stub) ---

MAIN_BASE = 0x400000
MALLOC_RESOLVED = LIBC_BASE + 0x1234


def _build_elf_plt_image():
    """A 4 KiB ET_DYN image: user code does `call malloc@plt`; the PLT stub
    jumps through a GOT slot bound to a libc address."""
    import struct as _s
    img = bytearray(PS)

    def put(off, data):
        img[off:off + len(data)] = data

    put(0, b"\x7fELF\x02\x01\x01")
    put(16, _s.pack("<H", 3))            # ET_DYN -> load bias = base
    put(18, _s.pack("<H", 0x3E))         # x86-64
    put(32, _s.pack("<Q", 0x40))         # e_phoff
    put(52, _s.pack("<H", 64))
    put(54, _s.pack("<H", 56))
    put(56, _s.pack("<H", 2))            # 2 program headers
    put(0x40, _s.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, PS, PS, 0x1000))    # PT_LOAD
    put(0x78, _s.pack("<IIQQQQQQ", 2, 6, 0x200, 0x200, 0, 0xA0, 0xA0, 8))  # DYNAMIC
    # user code @0x100: mov rdi,0x20 ; call <plt@0x140> ; mov rbx,rax
    put(0x100, bytes.fromhex("48c7c720000000" "e834000000" "4889c3"))
    # PLT stub @0x140: jmp qword [rip+0x2aa]  (-> GOT slot @0x3F0)
    put(0x140, bytes.fromhex("ff25aa020000"))
    # dynamic table @0x200
    for i, (t, v) in enumerate([(6, 0x300), (5, 0x330), (11, 24), (23, 0x360),
                                (2, 24), (20, 7), (0, 0)]):
        put(0x200 + i * 16, _s.pack("<QQ", t, v))
    # .dynsym @0x300: sym0 null, sym1 malloc (UNDEF) @0x318
    put(0x318, _s.pack("<IBBHQQ", 1, 0x12, 0, 0, 0, 0))
    put(0x330, b"\x00malloc\x00")        # .dynstr
    # .rela.plt @0x360: JUMP_SLOT for malloc (symidx 1), GOT slot @0x3F0
    put(0x360, _s.pack("<QQQ", 0x3F0, (1 << 32) | 7, 0))
    put(0x3F0, _s.pack("<Q", MALLOC_RESOLVED))   # bound GOT slot
    return bytes(img)


def _write_elf_plt_slice(path):
    cap = ((1 << CapBit.MemoryRegions) | (1 << CapBit.ThreadContexts)
           | (1 << CapBit.ModuleList))
    hdr = FileHeader(os_type=OSType.Linux, arch_type=ArchType.x86_64, pid=7,
                     cap_bitmap=cap)
    with open(path, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="/bin/app"))
        w.write_module_list([
            ModuleEntry(base_addr=MAIN_BASE, module_size=PS, path="/bin/app"),
            ModuleEntry(base_addr=LIBC_BASE, module_size=0x2000,
                        path="/lib/x86_64-linux-gnu/libc.so.6")])
        w.write_memory_region(MemoryRegion(
            base_addr=MAIN_BASE, region_size=PS, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED],
            page_data_chunks=[_build_elf_plt_image()]))
        # libc region: the resolved malloc address must be mapped so the block
        # hook (and thus interception) fires there.
        w.write_memory_region(MemoryRegion(
            base_addr=LIBC_BASE, region_size=0x2000, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED, PageState.CAPTURED],
            page_data_chunks=[b"\xc3" * PS, b"\xc3" * PS]))
        w.write_memory_region(MemoryRegion(
            base_addr=STACK_VA, region_size=PS, protection=0b011,
            region_type=RegionType.Stack, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[b"\x00" * PS]))
        w.write_thread_context(ThreadContext(
            thread_id=7, flags=THREAD_FLAG_CURRENT, state=ThreadState.Stopped,
            name="main", registers=[
                ThreadRegister("rip", (MAIN_BASE + 0x100).to_bytes(8, "little"), REG_FLAG_PC),
                ThreadRegister("rsp", (STACK_VA + 0x800).to_bytes(8, "little"), REG_FLAG_SP),
            ]))
        w.finalize()


def test_elf_plt_call_intercepted_and_stubbed(tmp_path):
    pytest.importorskip("unicorn")
    from memslicer.behavior.stubs import load_stubs
    from memslicer.behavior.tracer import BehaviorTracer
    from memslicer.emu.engine import open_slice

    stub_file = tmp_path / "stubs.py"
    stub_file.write_text(
        "def malloc(ctx):\n"
        "    ctx.log(f'malloc(size={ctx.arg(0)})')\n"
        "    ctx.set_ret(0xdead000)\n"
        "    return ctx.CONTINUE\n"
    )
    p = tmp_path / "plt.msl"
    _write_elf_plt_slice(p)
    emu = open_slice(str(p))
    tracer = BehaviorTracer(emu, registry=load_stubs(str(stub_file)))
    graph = tracer.run(max_steps=20)

    # call malloc@plt -> PLT stub jmp [GOT] -> libc entry (intercepted) ->
    # stub returned 0xdead000 -> back to caller -> mov rbx, rax.
    assert emu.read_reg("rbx") == 0xDEAD000
    assert "api:libc.so.6!malloc" in graph.nodes
    ev = [e for e in graph.events if e["kind"] == "api"]
    assert ev and ev[0]["name"] == "libc.so.6!malloc"
    assert ev[0]["args"][0] == 0x20            # rdi (SysV arg0 = size)


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
