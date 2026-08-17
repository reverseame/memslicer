"""Tests for the curated stub library + categorization + decode helpers
(Block 1: C7 + C8). These exercise StubContext/StubRegistry/stublib without
needing Unicorn -- a tiny fake emulator backs the memory/register ABI.
"""
import pytest

from memslicer.behavior.stubs import (
    StubRegistry, categorize, make_api_context,
)
from memslicer.behavior.stublib import build_default_registry, STUBS
from memslicer.msl.constants import ArchType, OSType


class FakeEmu:
    """Minimal MSLEmulator stand-in: sparse byte memory + a register file."""
    def __init__(self) -> None:
        self.bits = 64
        self.regs: dict[str, int] = {}
        self._sp_name = "rsp"
        self._mem: dict[int, int] = {}
        emu = self

        class _UC:
            def mem_write(self, addr, data):
                for i, b in enumerate(bytes(data)):
                    emu._mem[addr + i] = b

        self.uc = _UC()

    def read_reg(self, name):
        return self.regs.get(name, 0)

    def write_reg(self, name, value):
        self.regs[name] = value

    def read_mem(self, addr, size):
        return bytes(self._mem.get(addr + i, 0) for i in range(size))

    def put(self, addr, data):
        self.uc.mem_write(addr, data)


def _api_ctx(emu, name, os=OSType.Windows):
    return make_api_context(emu, ArchType.x86_64, os, name, site=0x401000)


# -- C8: categorization -------------------------------------------------------

@pytest.mark.parametrize("name,cat", [
    ("CreateFileW", "file"),
    ("openat", "file"),
    ("socket", "network"),
    ("WSASocketA", "network"),
    ("RegOpenKeyExW", "registry"),
    ("CreateProcessA", "process"),
    ("VirtualAlloc", "memory"),
    ("mmap", "memory"),
    ("LoadLibraryW", "library"),
    ("GetProcAddress", "library"),
    ("IsDebuggerPresent", "system"),
    ("SomethingUnknown", "other"),
])
def test_categorize(name, cat):
    assert categorize(name) == cat


# -- C8: decode helpers -------------------------------------------------------

def test_read_str_and_arg_str():
    emu = FakeEmu()
    emu.put(0x5000, b"/etc/passwd\x00garbage")
    ctx = _api_ctx(emu, "open", os=OSType.Linux)
    assert ctx.read_str(0x5000) == "/etc/passwd"
    emu.write_reg("rdi", 0x5000)            # SysV arg0
    assert ctx.arg_str(0) == "/etc/passwd"


def test_read_wstr_and_arg_wstr():
    emu = FakeEmu()
    emu.put(0x6000, "C:\\evil.exe".encode("utf-16-le") + b"\x00\x00")
    ctx = _api_ctx(emu, "CreateFileW")
    assert ctx.read_wstr(0x6000) == "C:\\evil.exe"
    emu.write_reg("rcx", 0x6000)            # Win64 arg0
    assert ctx.arg_wstr(0) == "C:\\evil.exe"


def test_read_ptr():
    emu = FakeEmu()
    emu.put(0x7000, (0xCAFEBABE).to_bytes(8, "little"))
    ctx = _api_ctx(emu, "x")
    assert ctx.read_ptr(0x7000) == 0xCAFEBABE
    assert ctx.read_ptr(0) == 0


def test_set_category_on_context():
    ctx = _api_ctx(FakeEmu(), "x")
    ctx.set_category("network")
    assert ctx.category == "network"


# -- C7: stub library ---------------------------------------------------------

def test_create_file_returns_handle_and_category():
    emu = FakeEmu()
    emu.put(0x8000, "C:/Windows/sys.dll".encode("utf-16-le") + b"\x00\x00")
    emu.write_reg("rcx", 0x8000)
    reg = build_default_registry()
    ctx = _api_ctx(emu, "CreateFileW")
    reg.dispatch(ctx)
    assert ctx.category == "file"
    assert emu.read_reg("rax") >= 0x100          # a plausible handle, not 0/-1
    assert "C:/Windows/sys.dll" in ctx.logs[-1]


def test_handles_are_unique_via_shared_state():
    emu = FakeEmu()
    reg = build_default_registry()
    h1 = (reg.dispatch(_api_ctx(emu, "CreateFileW")), emu.read_reg("rax"))[1]
    h2 = (reg.dispatch(_api_ctx(emu, "CreateFileW")), emu.read_reg("rax"))[1]
    assert h1 != h2                              # counter persisted across calls


def test_virtualalloc_returns_mapped_address():
    emu = FakeEmu()
    emu.write_reg("rdx", 0x2000)                 # Win64 arg1 = size
    reg = build_default_registry()
    ctx = _api_ctx(emu, "VirtualAlloc")
    reg.dispatch(ctx)
    assert ctx.category == "memory"
    assert emu.read_reg("rax") != 0


def test_regopenkey_writes_out_handle():
    emu = FakeEmu()
    emu.put(0x9000, "Software\\Run".encode("utf-16-le") + b"\x00\x00")
    emu.write_reg("rdx", 0x9000)                 # subkey (arg1)
    emu.write_reg("r8", 0)                        # arg2
    emu.write_reg("r9", 0)                        # arg3
    # arg4 (out hkey) is the first stacked arg on Win64: [rsp + 0x28].
    out = 0xA000
    emu.write_reg("rsp", 0x1000)
    emu.put(0x1000 + 0x28, out.to_bytes(8, "little"))
    reg = build_default_registry()
    ctx = _api_ctx(emu, "RegOpenKeyExW")
    reg.dispatch(ctx)
    assert ctx.category == "registry"
    assert emu.read_reg("rax") == 0              # ERROR_SUCCESS
    assert int.from_bytes(emu.read_mem(out, 8), "little") >= 0x100


def test_unknown_call_falls_back_to_default_stub():
    emu = FakeEmu()
    reg = build_default_registry()
    ctx = _api_ctx(emu, "TotallyUnknownApi")
    result = reg.dispatch(ctx)
    assert result == ctx.CONTINUE
    assert emu.read_reg("rax") == 0
    assert ctx.category == "other"


# -- C7: merge with analyst stubs --------------------------------------------

def test_merge_lets_analyst_override_library():
    reg = build_default_registry()
    edited = StubRegistry()

    def CreateFileW(ctx):
        ctx.set_ret(0xABCD)
        return ctx.CONTINUE

    edited.register("CreateFileW", CreateFileW)
    reg.merge(edited)

    emu = FakeEmu()
    ctx = _api_ctx(emu, "CreateFileW")
    reg.dispatch(ctx)
    assert emu.read_reg("rax") == 0xABCD         # analyst stub won


def test_registry_has_detects_explicit_stubs():
    reg = build_default_registry()
    assert reg.has("CreateFileW")      # via A/W twin -> bare CreateFile
    assert reg.has("mmap")             # exact
    assert reg.has("VIRTUALALLOC")     # case-insensitive
    assert not reg.has("TotallyUnknownApi")
    assert not StubRegistry().has("CreateFileW")


def test_read_cstr_handles_unmapped_tail():
    # a string just before an unmapped boundary must not over-read to b""
    class BoundedEmu(FakeEmu):
        BOUNDARY = 0x5010

        def read_mem(self, addr, size):
            if addr + size > self.BOUNDARY:
                raise ValueError("unmapped tail")
            return super().read_mem(addr, size)

    emu = BoundedEmu()
    emu.put(0x5000, b"hi\x00")
    ctx = _api_ctx(emu, "x")
    assert ctx.read_str(0x5000) == "hi"


def test_stub_library_covers_each_category():
    cats = {categorize(name) for name in STUBS}
    for expected in ("file", "network", "registry", "process", "memory",
                     "library", "system"):
        assert expected in cats


# -- end-to-end: category lands on the graph node ----------------------------

def test_category_propagates_to_graph_node(tmp_path):
    pytest.importorskip("unicorn")
    from memslicer.behavior.tracer import BehaviorTracer
    from memslicer.emu.engine import open_slice
    import test_behavior as tb

    p = tmp_path / "api.msl"
    tb._write_api_slice(p)
    emu = open_slice(str(p))
    tracer = BehaviorTracer(emu, registry=build_default_registry())
    graph = tracer.run(max_steps=20)

    node = graph.nodes["api:kernel32.dll!CreateFileW"]
    assert node["attrs"]["category"] == "file"
    ev = [e for e in graph.events if e["kind"] == "api"][0]
    assert ev["category"] == "file"
    # the bundled stub returned a real handle, not the default 0
    assert emu.read_reg("rbx") >= 0x100
