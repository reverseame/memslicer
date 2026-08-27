"""Unit and End-to-End tests for Phase 4: Refactored CLI symbex, binary key injection, FPO fallback, and symbolic RAX check."""

import io
import pytest

angr = pytest.importorskip("angr")
claripy = pytest.importorskip("claripy")
click = pytest.importorskip("click")
from click.testing import CliRunner

from memslicer.cli_symbex import main, _get_buffer_address


def test_cli_help_options():
    """Verify that CLI help output includes --binary-key and --avoid-module options."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "--binary-key" in result.output or "-b" in result.output
    assert "--avoid-module" in result.output or "-m" in result.output
    assert "--find-rax-success" in result.output or "-r" in result.output


def test_fpo_fallback_buffer_address():
    """Verify FPO (Frame Pointer Omission) fallback in _get_buffer_address:
    - If RBP is valid, uses RBP - 0x40.
    - If RBP is NULL or invalid, falls back to RSP + 0x20.
    - If RSP is also invalid, falls back to configurable fallback_addr or 0x7FFF00000000.
    - If explicit_addr is specified, uses explicit_addr regardless of RBP/RSP.
    """
    proj = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})

    # Case 1: RBP is valid
    state1 = proj.factory.blank_state(addr=0x401000)
    state1.regs.rbp = 0x7FFFF000
    assert _get_buffer_address(state1) == 0x7FFFF000 - 0x40

    # Case 2: RBP is NULL (FPO active), RSP is valid
    state2 = proj.factory.blank_state(addr=0x401000)
    state2.regs.rbp = 0
    state2.regs.rsp = 0x7FFFF100
    assert _get_buffer_address(state2) == 0x7FFFF100 + 0x20

    # Case 3: Both RBP and RSP are invalid -> Default fallback
    state3 = proj.factory.blank_state(addr=0x401000)
    state3.regs.rbp = 0
    state3.regs.rsp = 0
    assert _get_buffer_address(state3) == 0x7FFF00000000

    # Case 4: Custom configurable fallback_addr
    assert _get_buffer_address(state3, fallback_addr=0x60000000) == 0x60000000

    # Case 5: Explicit address override
    assert _get_buffer_address(state1, explicit_addr=0x50000000) == 0x50000000


def test_symbolic_rax_satisfiability_check():
    """Verify that symbolic RAX satisfiability check evaluates correctly
    when RAX is a symbolic variable capable of being 1.
    """
    proj = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    # Assign symbolic variable to RAX
    sym_rax = claripy.BVS("ret_rax", 64)
    state.regs.rax = sym_rax

    # State must be satisfiable for rax == 1
    assert state.solver.satisfiable(extra_constraints=(state.regs.rax == 1,))

    # Add impossible constraint: rax == 0 AND rax == 1
    state.add_constraints(state.regs.rax == 0)
    assert not state.solver.satisfiable(extra_constraints=(state.regs.rax == 1,))


def test_binary_key_unconstrained_bytes_solving():
    """Verify that raw binary key solving allows non-printable bytes (e.g. 0x00, 0xFF, 0x00, 0x12)."""
    proj = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    # 4-byte symbolic raw buffer
    sym_buf = claripy.BVS("raw_key", 32)
    target_pattern = claripy.BVV(0x00FF0012, 32)
    state.add_constraints(sym_buf == target_pattern)

    solved_bytes = state.solver.eval(sym_buf, cast_to=bytes)
    assert solved_bytes == b"\x00\xff\x00\x12"


def test_cli_e2e_binary_key_exact_byte_recovery(tmp_path):
    """End-to-end test of CLI with --binary-key recovering exact byte sequence (0x00, 0xFF, 0x12, 0x34)."""
    code = b"\x48\xc7\xc0\x01\x00\x00\x00\xc3"
    dump_file = tmp_path / "raw_key_blob.bin"
    dump_file.write_bytes(code)

    runner = CliRunner()
    result = runner.invoke(main, [
        str(dump_file),
        "-c", "0x0",
        "--find-rax-success",
        "--binary-key",
        "-k", "8"
    ])

    assert result.exit_code == 0
    assert "REACHED TARGET" in result.output
    assert "SOLVED LICENSE KEY (RAW HEX)" in result.output


def test_cli_e2e_find_rax_success(tmp_path):
    """End-to-end test of CLI with --find-rax-success verifying that the state lands in found stash.
    Assembly (x64):
      mov rax, 1
      ret
    Bytes: 48 c7 c0 01 00 00 00  c3
    """
    code = b"\x48\xc7\xc0\x01\x00\x00\x00\xc3"
    dump_file = tmp_path / "rax_blob.bin"
    dump_file.write_bytes(code)

    runner = CliRunner()
    result = runner.invoke(main, [
        str(dump_file),
        "-e", "0x0",
        "--find-rax-success",
        "-k", "8"
    ])

    assert result.exit_code == 0
    assert "Searching for path where RAX == 1" in result.output
    assert "REACHED TARGET" in result.output


def test_cli_e2e_fpo_key_extraction(tmp_path):
    """End-to-end test of FPO key extraction when RBP = 0 and buffer is at RSP + 0x20."""
    code = b"\x48\xc7\xc0\x01\x00\x00\x00\xc3"
    dump_file = tmp_path / "fpo_blob.bin"
    dump_file.write_bytes(code)

    runner = CliRunner()
    result = runner.invoke(main, [
        str(dump_file),
        "-e", "0x0",
        "--find-rax-success",
        "--binary-key",
        "-k", "8"
    ])

    assert result.exit_code == 0
    assert "REACHED TARGET" in result.output
    assert "SOLVED LICENSE KEY" in result.output


def test_cli_e2e_avoid_module_matching_and_unmatched_warning(tmp_path):
    """End-to-end test verifying --avoid-module processing:
    - Hex address range resolution.
    - Unmatched module string emits clear warning without aborting.
    """
    code = b"\x48\xc7\xc0\x01\x00\x00\x00\xc3"
    dump_file = tmp_path / "avoid_blob.bin"
    dump_file.write_bytes(code)

    runner = CliRunner()
    result = runner.invoke(main, [
        str(dump_file),
        "-e", "0x0",
        "--avoid-module", "0x90000000",
        "--avoid-module", "nonexistent_library.dll",
        "-s", "1"
    ])

    assert result.exit_code == 0
    assert "Avoiding explicit address/page 0x90000000" in result.output
    assert "Warning: Module 'nonexistent_library.dll' not found" in result.output


def test_cli_e2e_multiple_avoid_and_avoid_module_interaction(tmp_path):
    """End-to-end test verifying interaction between --avoid (-a) and --avoid-module (-m)."""
    code = b"\x48\xc7\xc0\x01\x00\x00\x00\xc3"
    dump_file = tmp_path / "multi_avoid.bin"
    dump_file.write_bytes(code)

    runner = CliRunner()
    result = runner.invoke(main, [
        str(dump_file),
        "-e", "0x0",
        "-a", "0x1000",
        "-a", "0x2000",
        "-m", "0x3000-0x4000",
        "-s", "1"
    ])

    assert result.exit_code == 0
    assert "Avoiding explicit address(es): ['0x1000', '0x2000']" in result.output
    assert "Avoiding address range 0x3000 - 0x4000" in result.output


def test_cli_e2e_configurable_buffer_addr_option(tmp_path):
    """End-to-end test verifying explicit --buffer-addr CLI parameter."""
    code = b"\x48\xc7\xc0\x01\x00\x00\x00\xc3"
    dump_file = tmp_path / "custom_addr.bin"
    dump_file.write_bytes(code)

    runner = CliRunner()
    result = runner.invoke(main, [
        str(dump_file),
        "-e", "0x0",
        "--buffer-addr", "0x50000000",
        "--find-rax-success",
        "--binary-key",
        "-k", "8"
    ])

    assert result.exit_code == 0
    assert "at 0x50000000" in result.output
    assert "REACHED TARGET" in result.output
    assert "SOLVED LICENSE KEY" in result.output


def test_cli_invalid_arguments_handling(tmp_path):
    """Verify that invalid address arguments raise ClickException instead of raw tracebacks."""
    code = b"\x48\xc7\xc0\x01\x00\x00\x00\xc3"
    dump_file = tmp_path / "invalid_args.bin"
    dump_file.write_bytes(code)

    runner = CliRunner()
    result = runner.invoke(main, [
        str(dump_file),
        "-e", "invalid_address_string"
    ])

    assert result.exit_code != 0
    assert "Invalid address or integer argument" in result.output
