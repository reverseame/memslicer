"""Unit tests for Phase 6: Multi-CLE Symbol Registration and Exported Symbol Hooking in angr.Project."""

import io
from types import SimpleNamespace
import pytest

angr = pytest.importorskip("angr")

from memslicer.symbex.angr_loader import (
    extract_exported_symbols,
    register_exported_symbols,
    load_angr,
)


class CustomHookProcedure(angr.SimProcedure):
    """Custom SimProcedure for testing symbol hooks."""
    def run(self):
        self.state.globals["custom_hook_executed"] = True
        return 0


def test_manual_symbol_registration_and_hooking():
    """Verify manual registration of exported symbols in angr project and successful hook_symbol execution."""
    code = b"\xe8\xfb\xff\xff\xff\xc3"  # call 0x401000; ret
    proj = angr.Project(io.BytesIO(code), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})

    # Register exported symbol TargetAPI at 0x401000
    count = register_exported_symbols(proj, {"TargetAPI": 0x401000})
    assert count == 1
    assert proj.loader.find_symbol("TargetAPI") is not None

    # Hook symbol by name
    proj.hook_symbol("TargetAPI", CustomHookProcedure())

    state = proj.factory.blank_state(addr=0x401000)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    simgr = proj.factory.simgr(state)
    simgr.step()

    succ = (simgr.active or simgr.deadended)[0]
    assert succ.globals.get("custom_hook_executed") is True


def test_module_prefixed_symbol_hooking():
    """Verify registration and hooking of module-prefixed symbols (e.g. kernel32.dll!IsDebuggerPresent)."""
    code = b"\xc3"
    proj = angr.Project(io.BytesIO(code), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})

    count = register_exported_symbols(proj, {
        "IsDebuggerPresent": (0x402000, 32),
        "kernel32.dll!IsDebuggerPresent": (0x402000, 32),
    })
    assert count == 2
    assert proj.loader.find_symbol("IsDebuggerPresent") is not None
    assert proj.loader.find_symbol("kernel32.dll!IsDebuggerPresent") is not None

    proj.hook_symbol("kernel32.dll!IsDebuggerPresent", CustomHookProcedure())

    state = proj.factory.blank_state(addr=0x402000)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    simgr = proj.factory.simgr(state)
    simgr.step()

    succ = (simgr.active or simgr.deadended)[0]
    assert succ.globals.get("custom_hook_executed") is True


def test_symbol_map_loading_in_angr_loader(tmp_path):
    """Verify symbol_map argument passing in load_angr populates angr main_object symbols."""
    code = b"\x48\xc7\xc0\x00\x00\x00\x00\xc3"
    dump_file = tmp_path / "slice_with_symbols.bin"
    dump_file.write_bytes(code)

    symbol_map = {
        "ExitProcess": 0x401050,
        "NtAllocateVirtualMemory": 0x401100,
    }

    proj, state = load_angr(str(dump_file), symbol_map=symbol_map)

    assert proj.loader.find_symbol("ExitProcess") is not None
    assert proj.loader.find_symbol("NtAllocateVirtualMemory") is not None
    assert proj.loader.find_symbol("ExitProcess").rebased_addr == 0x401050


def test_symbol_registration_resilience():
    """Verify resilience when registering empty or invalid symbol maps."""
    proj = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})

    # Empty dictionary
    assert register_exported_symbols(proj, {}) == 0

    # None input
    assert register_exported_symbols(proj, None) == 0

    # Invalid address values
    invalid_map = {"BadSymbol": -100, "ValidSymbol": 0x401000}
    assert register_exported_symbols(proj, invalid_map) == 1
    assert proj.loader.find_symbol("ValidSymbol") is not None


def test_extract_exported_symbols_scans_all_cle_objects():
    """Exports are collected from the main object and loaded libraries."""
    main_symbol = SimpleNamespace(
        is_export=True, name="main_export", rebased_addr=0x401000, size=16,
    )
    library_symbol = SimpleNamespace(
        is_export=True, name="library_export", rebased_addr=0x701000, size=32,
    )
    hidden_symbol = SimpleNamespace(
        is_export=False, name="internal", rebased_addr=0x401100, size=8,
    )
    project = SimpleNamespace(
        loader=SimpleNamespace(
            all_objects=(
                SimpleNamespace(symbols=(main_symbol, hidden_symbol)),
                SimpleNamespace(symbols=(library_symbol,)),
            )
        )
    )

    assert extract_exported_symbols(project) == {
        "main_export": (0x401000, 16),
        "library_export": (0x701000, 32),
    }


def test_load_angr_auto_registers_extracted_symbols(monkeypatch, tmp_path):
    """load_angr requests automatic export registration without a symbol_map."""
    code_path = tmp_path / "auto_symbols.bin"
    code_path.write_bytes(b"\xc3")
    captured = {}

    def fake_register(project, symbols=None):
        captured["symbols"] = symbols
        return 0

    monkeypatch.setattr("memslicer.symbex.angr_loader.register_exported_symbols", fake_register)
    load_angr(str(code_path))

    assert captured["symbols"] is None
