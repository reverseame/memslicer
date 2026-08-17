"""Benchmark and unit test for Veritesting anti-state explosion in memslicer.symbex."""

import os
import sys
import time
import pytest

angr = pytest.importorskip("angr")
claripy = pytest.importorskip("claripy")

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def create_branching_test_binary():
    """Creates a synthetic x86_64 binary with multiple sequential branches.
    Simulates nested logic where input bytes 'ABC' lead to SUCCESS 0x401050.
    """
    # 0x401000: cmp byte ptr [rsi], 'A'
    # 0x401003: jne 0x401060 (FAIL)
    # 0x401009: cmp byte ptr [rsi+1], 'B'
    # 0x40100d: jne 0x401060 (FAIL)
    # 0x401013: cmp byte ptr [rsi+2], 'C'
    # 0x401017: jne 0x401060 (FAIL)
    # 0x40101d: mov rax, 0x1337 (SUCCESS)
    # 0x401024: ret
    # 0x401060: mov rax, 0xdead (FAIL)
    # 0x401067: ret
    code = (
        b"\x80\x3e\x41"                  # cmp byte ptr [rsi], 'A'
        b"\x0f\x85\x53\x00\x00\x00"      # jne 0x401060
        b"\x80\x7e\x01\x42"              # cmp byte ptr [rsi+1], 'B'
        b"\x0f\x85\x49\x00\x00\x00"      # jne 0x401060
        b"\x80\x7e\x02\x43"              # cmp byte ptr [rsi+2], 'C'
        b"\x0f\x85\x3f\x00\x00\x00"      # jne 0x401060
        b"\x48\xc7\xc0\x37\x13\x00\x00"  # mov rax, 0x1337 (SUCCESS)
        b"\xc3"                          # ret
    )
    # Add padding up to 0x60
    code += b"\x90" * (0x60 - len(code))
    code += (
        b"\x48\xc7\xc0\xad\xde\x00\x00"  # mov rax, 0xdead (FAIL)
        b"\xc3"                          # ret
    )
    return code


def test_veritesting_state_merging():
    """Verifies that Veritesting merges paths and reaches the target address."""
    code_bytes = create_branching_test_binary()
    base_addr = 0x401000
    target_addr = 0x40101d
    fail_addr = 0x401060

    project = angr.Project(
        __import__("io").BytesIO(code_bytes),
        main_opts={"backend": "blob", "arch": "amd64", "base_addr": base_addr},
        auto_load_libs=False,
    )

    buf_addr = 0x7FFFF000
    state = project.factory.blank_state(addr=base_addr)
    state.regs.rsi = buf_addr
    state.regs.rsp = 0x7FFFF800

    sym_buf = claripy.BVS("input_buf", 24)
    state.memory.store(buf_addr, sym_buf)

    # 1. Run symbolic execution WITH Veritesting enabled
    t0 = time.time()
    simgr_veritesting = project.factory.simgr(state, veritesting=True)
    simgr_veritesting.explore(find=target_addr, avoid=fail_addr)
    t_veritesting = time.time() - t0

    assert len(simgr_veritesting.found) > 0, "Veritesting failed to find target state"

    found_state = simgr_veritesting.found[0]
    solved_buf = found_state.solver.eval(sym_buf, cast_to=bytes)

    assert solved_buf == b"ABC", f"Expected b'ABC', got {solved_buf}"
    print(f"\n[PASS] Veritesting successfully resolved input: {solved_buf} in {t_veritesting:.4f}s")


if __name__ == "__main__":
    test_veritesting_state_merging()
