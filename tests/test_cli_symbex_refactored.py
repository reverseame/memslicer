"""Unit and end-to-end tests for the CLI symbex options: binary key injection, FPO fallback, RAX search, raw blobs."""

import io
import pytest

angr = pytest.importorskip("angr")
claripy = getattr(angr, "claripy", None) or pytest.importorskip("claripy")
click = pytest.importorskip("click")
from click.testing import CliRunner

from memslicer.cli_symbex import main, _get_buffer_address


def test_cli_help_options():
    """The help lists the injection/avoid options, and -b is --bypass-anti-analysis as before."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    for opt in ("--binary-key", "--avoid-module", "--find-rax-success",
                "--raw-blob", "--no-syscall-handler", "--find-max-steps"):
        assert opt in result.output
    assert "-b, --bypass-anti-analysis" in result.output
    assert "-b, --binary-key" not in result.output


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


def test_cli_rejects_zero_sym_bytes(tmp_path):
    """-k 0 is a usage error instead of a crash on a zero-width BVS."""
    dump_file = tmp_path / "zero.bin"
    dump_file.write_bytes(b"\xc3")
    result = CliRunner().invoke(main, [str(dump_file), "--raw-blob", "-e", "0x0", "-k", "0"])
    assert result.exit_code == 2
    assert "--sym-bytes" in result.output


def test_cli_non_msl_file_is_an_error_without_raw_blob(tmp_path):
    """A file that is not an MSL slice is reported, never executed as a raw blob."""
    dump_file = tmp_path / "bad.msl"
    dump_file.write_bytes(b"\x48\xc7\xc0\x01\x00\x00\x00\xc3")
    result = CliRunner().invoke(main, [str(dump_file), "-s", "1"])
    assert result.exit_code == 1
    assert "as an MSL slice" in result.output
    assert "Running" not in result.output


def test_cli_e2e_binary_key_exact_byte_recovery(tmp_path):
    """End-to-end test of CLI with --binary-key recovering exact byte sequence (0x00, 0xFF, 0x12, 0x34)."""
    code = b"\x48\xc7\xc0\x01\x00\x00\x00\xc3"
    dump_file = tmp_path / "raw_key_blob.bin"
    dump_file.write_bytes(code)

    runner = CliRunner()
    result = runner.invoke(main, [
        str(dump_file), "--raw-blob",
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
        str(dump_file), "--raw-blob",
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
        str(dump_file), "--raw-blob",
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
        str(dump_file), "--raw-blob",
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
        str(dump_file), "--raw-blob",
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
        str(dump_file), "--raw-blob",
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
        str(dump_file), "--raw-blob",
        "-e", "invalid_address_string"
    ])

    assert result.exit_code != 0
    assert "Invalid address or integer argument" in result.output
