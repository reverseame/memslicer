"""KeyHint (0x0020) read path: acquisition-side write -> symbex-side read.

The write side normally comes from a live Frida hook on a key-derivation API,
but the on-disk block is the same one ``MSLWriter.write_key_hint`` produces, so
these tests build the ``.msl`` by hand (no Frida) and verify the full
write -> read journey: ``load_slice`` resolves the hint to an absolute address,
``load_angr`` stashes it in ``state.globals``, and the CLI selector picks it.
"""
import io

from memslicer.msl.writer import MSLWriter
from memslicer.msl.types import (
    FileHeader, ProcessIdentity, MemoryRegion, ThreadContext, ThreadRegister,
    KeyHint,
)
from memslicer.msl.constants import (
    ArchType, CapBit, CompAlgo, OSType, PageState, RegionType,
    REG_FLAG_PC, REG_FLAG_SP, THREAD_FLAG_CURRENT, ThreadState,
)
from memslicer.emu.loader import load_slice, KeyHintInfo

PS = 4096
CODE_VA = 0x401000
HEAP_VA = 0x00A00000          # where the "derived key" buffer lives
KEY_OFFSET = 0x140            # offset of the key within the heap region
KEY_LEN = 32                  # AES-256


def _write_slice_with_key_hint(path, *, region_offset=KEY_OFFSET,
                               key_len=KEY_LEN, dangling=False):
    """Build a slice with a heap region and a KeyHint pointing into it.

    Returns the heap region's expected absolute key address. When *dangling*
    is set the hint references a random UUID (no captured region owns it), so
    it must stay unresolved on read.
    """
    page = b"\x90" * PS
    keybytes = bytes(range(key_len))
    keypage = bytearray(page)
    keypage[region_offset:region_offset + key_len] = keybytes
    cap = ((1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity)
           | (1 << CapBit.ThreadContexts))
    hdr = FileHeader(os_type=OSType.Windows, arch_type=ArchType.x86_64,
                     pid=7, cap_bitmap=cap)
    with open(path, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="C:/demo.exe"))
        w.write_memory_region(MemoryRegion(
            base_addr=CODE_VA, region_size=PS, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[page]))
        heap_uuid = w.write_memory_region(MemoryRegion(
            base_addr=HEAP_VA, region_size=PS, protection=0b011,
            region_type=RegionType.Heap, page_size=PS,
            page_states=[PageState.CAPTURED],
            page_data_chunks=[bytes(keypage)]))
        w.write_thread_context(ThreadContext(
            thread_id=7, flags=THREAD_FLAG_CURRENT, state=ThreadState.Stopped,
            name="main", registers=[
                ThreadRegister("rip", CODE_VA.to_bytes(8, "little"), REG_FLAG_PC),
                ThreadRegister("rsp", (0x7ffff000).to_bytes(8, "little"), REG_FLAG_SP),
            ]))
        ref_uuid = b"\xAB" * 16 if dangling else heap_uuid
        w.write_key_hint(KeyHint(
            region_uuid=ref_uuid,
            region_offset=region_offset,
            key_len=key_len,
            key_type=0x01,
            protocol=0x01,
            confidence=0x02,      # Confirmed
            key_state=0x01,       # Active
            note="BCryptGenerateSymmetricKey AES-256",
        ))
        w.finalize()
    return HEAP_VA + region_offset


def test_load_slice_resolves_key_hint(tmp_path):
    """A KeyHint referencing a captured region resolves to base+offset."""
    p = tmp_path / "keyed.msl"
    expected_addr = _write_slice_with_key_hint(p)

    image = load_slice(str(p))

    assert len(image.key_hints) == 1
    hint = image.key_hints[0]
    assert isinstance(hint, KeyHintInfo)
    assert hint.address == expected_addr           # base + offset, not guessed
    assert hint.region_offset == KEY_OFFSET
    assert hint.key_len == KEY_LEN
    assert hint.key_type == 0x01
    assert hint.protocol == 0x01
    assert hint.confidence == 0x02
    assert hint.key_state == 0x01
    assert hint.note == "BCryptGenerateSymmetricKey AES-256"


def test_key_hint_note_optional(tmp_path):
    """A KeyHint with an empty note round-trips with note == ''."""
    p = tmp_path / "nonote.msl"
    page = b"\x90" * PS
    cap = (1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity)
    hdr = FileHeader(os_type=OSType.Windows, arch_type=ArchType.x86_64,
                     pid=7, cap_bitmap=cap)
    with open(p, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        u = w.write_memory_region(MemoryRegion(
            base_addr=HEAP_VA, region_size=PS, protection=0b011,
            region_type=RegionType.Heap, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[page]))
        w.write_key_hint(KeyHint(region_uuid=u, region_offset=0x10, key_len=0,
                                 note=""))
        w.finalize()

    image = load_slice(str(p))
    assert len(image.key_hints) == 1
    assert image.key_hints[0].note == ""
    assert image.key_hints[0].key_len == 0
    assert image.key_hints[0].address == HEAP_VA + 0x10


def test_dangling_key_hint_stays_unresolved(tmp_path):
    """A KeyHint whose region was not captured has address == None (a false
    hint must not be invented at some bogus address)."""
    p = tmp_path / "dangling.msl"
    _write_slice_with_key_hint(p, dangling=True)

    image = load_slice(str(p))
    assert len(image.key_hints) == 1
    assert image.key_hints[0].address is None


def test_no_key_hint_yields_empty_list(tmp_path):
    """A slice with no KeyHint block has an empty key_hints list (no crash)."""
    p = tmp_path / "plain.msl"
    page = b"\x90" * PS
    cap = 1 << CapBit.MemoryRegions
    hdr = FileHeader(os_type=OSType.Windows, arch_type=ArchType.x86_64,
                     pid=7, cap_bitmap=cap)
    with open(p, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_memory_region(MemoryRegion(
            base_addr=HEAP_VA, region_size=PS, protection=0b011,
            region_type=RegionType.Heap, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[page]))
        w.finalize()

    image = load_slice(str(p))
    assert image.key_hints == []


def test_load_angr_stashes_key_hints(tmp_path):
    """load_angr surfaces resolved hints in state.globals["msl_key_hints"]."""
    import pytest
    pytest.importorskip("angr")
    from memslicer.symbex.angr_loader import load_angr

    p = tmp_path / "keyed.msl"
    expected_addr = _write_slice_with_key_hint(p)

    _project, state = load_angr(str(p))
    hints = state.globals["msl_key_hints"]
    assert len(hints) == 1
    assert hints[0].address == expected_addr


def test_engine_writes_key_hint_from_bridge_event(tmp_path):
    """End-to-end write path (no Frida): a bridge that reports a KeyHintEvent
    inside a captured region makes the engine emit a KeyHint block that the
    reader resolves back to the exact event address."""
    from memslicer.acquirer.engine import AcquisitionEngine
    from memslicer.acquirer.bridge import (
        PlatformInfo, MemoryRange, KeyHintEvent,
    )
    from memslicer.acquirer.region_filter import RegionFilter

    key_addr = HEAP_VA + KEY_OFFSET

    class FakeBridge:
        is_remote = False

        def connect(self):
            pass

        def get_platform_info(self):
            return PlatformInfo(arch=ArchType.x86_64, os=OSType.Windows,
                                pid=1234, page_size=PS)

        def enumerate_modules(self):
            return []

        def enumerate_threads(self):
            return []

        def enumerate_ranges(self):
            return [MemoryRange(base=HEAP_VA, size=PS, protection="rw-",
                                file_path="")]

        def read_memory(self, address, size):
            # A page of zeros with the key bytes planted at KEY_OFFSET.
            buf = bytearray(size)
            if address == HEAP_VA and size >= KEY_OFFSET + KEY_LEN:
                buf[KEY_OFFSET:KEY_OFFSET + KEY_LEN] = bytes(range(KEY_LEN))
            return bytes(buf)

        def collect_key_hints(self):
            return [KeyHintEvent(address=key_addr, length=KEY_LEN,
                                 api="BCryptGenerateSymmetricKey")]

        def disconnect(self):
            pass

    out = tmp_path / "captured.msl"
    engine = AcquisitionEngine(
        bridge=FakeBridge(),
        region_filter=RegionFilter(skip_no_read=False),
        capture_threads=False,
    )
    engine.acquire(str(out))

    image = load_slice(str(out))
    assert len(image.key_hints) == 1
    hint = image.key_hints[0]
    assert hint.address == key_addr           # resolved to the real address
    assert hint.key_len == KEY_LEN
    assert hint.confidence == 0x02            # Confirmed (live API call)
    assert "BCryptGenerateSymmetricKey" in hint.note


def test_engine_skips_key_hint_outside_captured_regions(tmp_path):
    """A key event whose address is not inside any captured region produces
    no KeyHint block (no false hint at a bogus location)."""
    from memslicer.acquirer.engine import AcquisitionEngine
    from memslicer.acquirer.bridge import (
        PlatformInfo, MemoryRange, KeyHintEvent,
    )
    from memslicer.acquirer.region_filter import RegionFilter

    class FakeBridge:
        is_remote = False

        def connect(self):
            pass

        def get_platform_info(self):
            return PlatformInfo(arch=ArchType.x86_64, os=OSType.Windows,
                                pid=1234, page_size=PS)

        def enumerate_modules(self):
            return []

        def enumerate_threads(self):
            return []

        def enumerate_ranges(self):
            return [MemoryRange(base=HEAP_VA, size=PS, protection="rw-",
                                file_path="")]

        def read_memory(self, address, size):
            return bytes(size)

        def collect_key_hints(self):
            # Address far outside the single captured region.
            return [KeyHintEvent(address=0xDEAD0000, length=16,
                                 api="NCryptDeriveKey")]

        def disconnect(self):
            pass

    out = tmp_path / "captured.msl"
    engine = AcquisitionEngine(
        bridge=FakeBridge(),
        region_filter=RegionFilter(skip_no_read=False),
        capture_threads=False,
    )
    engine.acquire(str(out))

    image = load_slice(str(out))
    assert image.key_hints == []


def test_cli_select_key_hint_prefers_confirmed(tmp_path):
    """_select_key_hint picks the resolved, highest-confidence hint."""
    from memslicer.cli_symbex import _select_key_hint

    class G(dict):
        pass

    speculative = KeyHintInfo(region_uuid=b"\x00" * 16, region_offset=0,
                              key_len=16, confidence=0x00, address=0x1000)
    confirmed = KeyHintInfo(region_uuid=b"\x00" * 16, region_offset=0,
                            key_len=32, confidence=0x02, address=0x2000)
    unresolved = KeyHintInfo(region_uuid=b"\x00" * 16, region_offset=0,
                             key_len=32, confidence=0x02, address=None)

    class FakeState:
        def __init__(self, hints):
            self.globals = {"msl_key_hints": hints}

    assert _select_key_hint(FakeState([speculative, confirmed, unresolved])) is confirmed
    assert _select_key_hint(FakeState([unresolved])) is None
    assert _select_key_hint(FakeState([])) is None
