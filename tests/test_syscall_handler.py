"""Unit tests for Phase 5: Kernel Syscall Interception, OS/Arch Separation, Emulation, and Error Repair."""

import io
import pytest

angr = pytest.importorskip("angr")

from memslicer.symbex.syscall_handler import (
    resolve_syscall_name,
    setup_syscall_emulation,
    repair_syscall_errored_state,
    detect_os_and_arch,
    WINDOWS_NT_X64_TABLE,
    LINUX_X86_64,
    ANDROID_ARM64_TABLE,
)
from memslicer.symbex.unmapped_handler import enable_unmapped_memory_recovery, repair_errored_states


def test_windows_linux_android_syscall_table_separation():
    """Verify that Windows, Linux, and Android syscall tables do NOT share numbers incorrectly."""
    # Windows NT 0x0018 -> NtAllocateVirtualMemory
    win_name, win_status = resolve_syscall_name(0x0018, "windows", "amd64")
    assert win_name == "NtAllocateVirtualMemory"
    assert win_status == "MODELED"

    # Linux 0x0 -> sys_read
    linux_name, linux_status = resolve_syscall_name(0, "linux", "amd64")
    assert linux_name == "sys_read"
    assert linux_status == "MODELED"

    # Android ARM64 278 -> gettid
    android_name, android_status = resolve_syscall_name(278, "android", "arm64")
    assert android_name == "gettid"
    assert android_status == "MODELED"

    # Linux OS with Windows NT syscall number (0x18 = 24) -> sys_sched_yield (NO cross-table fallback to NtAllocateVirtualMemory!)
    cross_name, cross_status = resolve_syscall_name(0x0018, "linux", "amd64")
    assert cross_name != "NtAllocateVirtualMemory"
    assert cross_name == "sys_sched_yield"

    # Unknown Syscall
    unknown_name, unknown_status = resolve_syscall_name(0x9999, "windows", "amd64")
    assert unknown_name == "sys_0x9999"
    assert unknown_status == "APPROXIMATE_FALLBACK"


def test_windows_x86_syscall_resolution_returns_name_and_status():
    """Windows x86 must return the same (name, status) contract as x64."""
    name, status = resolve_syscall_name(0x11, "windows", "x86")

    assert name == "NtAllocateVirtualMemory"
    assert status == "MODELED"


def test_os_and_arch_detection_unidentified():
    """Verify explicit OS and architecture detection without assuming Windows for unidentified OS."""
    proj = angr.Project(io.BytesIO(b"\xc3"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    # State without os_name specified
    enable_unmapped_memory_recovery(proj, state)
    os_name, arch_name = detect_os_and_arch(state)
    assert os_name == "unidentified"
    assert arch_name == "amd64"

    state.os_name = "Windows"
    os_name, arch_name = detect_os_and_arch(state)
    assert os_name == "windows"

    state.os_name = "Linux"
    os_name, arch_name = detect_os_and_arch(state)
    assert os_name == "linux"


def test_arm32_little_endian_svc_emulation_and_repair():
    """Verify ARM32 little-endian 'svc 0xef000000' (b"\\x00\\x00\\x00\\xef") opcode advances PC 4 bytes and sets R0."""
    code = b"\x00\x00\x00\xef"  # ARM32 svc
    proj = angr.Project(io.BytesIO(code), main_opts={"backend": "blob", "arch": "arm", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)
    state.os_name = "Linux"

    success = repair_syscall_errored_state(state)
    assert success is True
    assert state.addr == 0x401004
    assert state.solver.eval(state.regs.r0) == 0


def test_arm32_non_svc_with_trailing_ef_is_rejected():
    """A random ARM32 word ending in EF is not the exact SVC encoding."""
    code = b"\x12\x34\x56\xef"
    proj = angr.Project(
        io.BytesIO(code),
        main_opts={"backend": "blob", "arch": "arm", "base_addr": 0x401000},
    )
    state = proj.factory.blank_state(addr=0x401000)
    state.os_name = "Linux"
    original_pc = state.addr

    assert repair_syscall_errored_state(state) is False
    assert state.addr == original_pc


def test_x64_syscall_emulation_and_execution():
    """Verify x64 direct 'syscall' instruction (0x0f 0x05) execution in angr.
    Assembly (x64):
      mov rax, 0x18
      syscall
      ret
    Bytes: 48 c7 c0 18 00 00 00  0f 05  c3
    """
    code = b"\x48\xc7\xc0\x18\x00\x00\x00\x0f\x05\xc3"
    proj = angr.Project(io.BytesIO(code), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)
    state.os_name = "Windows"

    enable_unmapped_memory_recovery(proj, state)
    simgr = proj.factory.simgr(state)

    simgr.step()
    if simgr.errored:
        repair_errored_states(simgr)

    simgr.step()
    if simgr.errored:
        repair_errored_states(simgr)

    assert len(simgr.errored) == 0
    assert len(simgr.active) > 0 or len(simgr.deadended) > 0


def test_x86_sysenter_emulation_and_execution():
    """Verify x86 direct 'sysenter' instruction (0x0f 0x34) execution in angr."""
    code = b"\xb8\x18\x00\x00\x00\x0f\x34\xc3"
    proj = angr.Project(io.BytesIO(code), main_opts={"backend": "blob", "arch": "i386", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)
    state.os_name = "Windows"

    enable_unmapped_memory_recovery(proj, state)
    simgr = proj.factory.simgr(state)

    simgr.step()
    if simgr.errored:
        repair_errored_states(simgr)

    simgr.step()
    if simgr.errored:
        repair_errored_states(simgr)

    assert len(simgr.errored) == 0


def test_int2e_emulation_and_execution():
    """Verify x86 'int 0x2e' instruction (0xcd 0x2e) execution in angr."""
    code = b"\xb8\x18\x00\x00\x00\xcd\x2e\xc3"
    proj = angr.Project(io.BytesIO(code), main_opts={"backend": "blob", "arch": "i386", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)
    state.os_name = "Windows"

    enable_unmapped_memory_recovery(proj, state)
    simgr = proj.factory.simgr(state)

    simgr.step()
    if simgr.errored:
        repair_errored_states(simgr)

    simgr.step()
    if simgr.errored:
        repair_errored_states(simgr)

    assert len(simgr.errored) == 0


def test_arm64_svc_emulation_and_execution():
    """Verify ARM64 'svc #0' instruction (0x01 0x00 0x00 0xd4) execution."""
    code = b"\x01\x00\x00\xd4\xc0\x03\x5f\xd6"
    proj = angr.Project(io.BytesIO(code), main_opts={"backend": "blob", "arch": "aarch64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)
    state.os_name = "Linux"

    enable_unmapped_memory_recovery(proj, state)
    simgr = proj.factory.simgr(state)

    simgr.step()
    if simgr.errored:
        repair_errored_states(simgr)

    assert len(simgr.errored) == 0


def test_non_syscall_opcode_repair_rejected():
    """Verify that repair_syscall_errored_state rejects non-syscall opcodes without modifying PC or registers."""
    proj = angr.Project(io.BytesIO(b"\x90\x90\x90\x90"), main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x401000})
    state = proj.factory.blank_state(addr=0x401000)

    # NOP opcode b"\x90\x90\x90\x90" is not a syscall instruction
    success = repair_syscall_errored_state(state)
    assert success is False
    assert state.addr == 0x401000  # PC remains unchanged
