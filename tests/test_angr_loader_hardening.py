"""Unit tests for P1 hardening in angr_loader.py: architecture validation, SymbexError conversion, and page boundary checks."""

import pytest

angr = pytest.importorskip("angr")

from memslicer.symbex.angr_loader import SymbexError, _contiguous, load_angr
from memslicer.msl.constants import ArchType


class MockRegion:
    def __init__(self, base, size, pages=None):
        self.base = base
        self.size = size
        self.pages = pages or {}


class MockImage:
    def __init__(self, arch, regions=None):
        self.arch = arch
        self.regions = regions or []
        self.entry = 0x401000

    def select_thread(self, thread):
        return None


def test_unsupported_arch_raises_symbex_error():
    """Verify that passing an unsupported architecture raises SymbexError without crashing with KeyError."""
    class UnsupportedArch:
        name = "RISCV64"

    fake_image = MockImage(arch=UnsupportedArch(), regions=[MockRegion(0x401000, 0x1000)])

    with pytest.raises(SymbexError) as exc_info:
        load_angr("dummy_path.msl", image=fake_image)

    assert "unsupported architecture for angr" in str(exc_info.value)


def test_out_of_bounds_page_address_raises_symbex_error():
    """Verify that a page address outside region bounds raises SymbexError in _contiguous."""
    # Region at 0x401000 of size 0x1000, but page is at 0x500000 (out of bounds)
    region = MockRegion(base=0x401000, size=0x1000, pages={0x500000: b"\x90" * 0x100})

    with pytest.raises(SymbexError) as exc_info:
        _contiguous(region)

    assert "outside region bounds" in str(exc_info.value)


def test_page_length_overflow_raises_symbex_error():
    """Verify that a page length overflowing the region size raises SymbexError in _contiguous."""
    # Region at 0x401000 of size 0x1000, page at 0x401000 with size 0x2000 (overflows region)
    region = MockRegion(base=0x401000, size=0x1000, pages={0x401000: b"\x90" * 0x2000})

    with pytest.raises(SymbexError) as exc_info:
        _contiguous(region)

    assert "exceeds region size" in str(exc_info.value)
