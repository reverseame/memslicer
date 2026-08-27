"""Kernel syscall direct interception, OS/Arch-aware resolution, and state repair for angr symbolic execution."""

from __future__ import annotations

import logging
from typing import Any

import angr
import claripy

from memslicer.behavior.syscalls import LINUX_X86_64

logger = logging.getLogger(__name__)

# Windows NT Syscall Tables (SSDT IDs)
WINDOWS_NT_X64_TABLE: dict[int, str] = {
    0x0000: "NtAcceptConnectPort",
    0x0001: "NtAccessCheck",
    0x000F: "NtClose",
    0x0018: "NtAllocateVirtualMemory",
    0x001C: "NtFreeVirtualMemory",
    0x0025: "NtQueryInformationProcess",
    0x002A: "NtSetInformationProcess",
    0x0030: "NtCreateFile",
    0x0033: "NtOpenFile",
    0x0034: "NtDeviceIoControlFile",
    0x0035: "NtReadFile",
    0x003A: "NtWriteFile",
    0x0050: "NtProtectVirtualMemory",
    0x0052: "NtQueryVirtualMemory",
    0x0055: "NtOpenProcess",
    0x0056: "NtOpenThread",
    0x00B7: "NtQuerySystemInformation",
}

WINDOWS_NT_X86_TABLE: dict[int, str] = {
    0x0011: "NtAllocateVirtualMemory",
    0x0019: "NtClose",
    0x003A: "NtCreateFile",
    0x0042: "NtFreeVirtualMemory",
    0x0077: "NtOpenFile",
    0x0089: "NtProtectVirtualMemory",
    0x009A: "NtQueryInformationProcess",
    0x00B2: "NtReadFile",
    0x0115: "NtWriteFile",
}

# Linux Syscall Tables
LINUX_X86_TABLE: dict[int, str] = {
    1: "exit", 3: "read", 4: "write", 5: "open", 6: "close", 11: "execve",
    45: "brk", 90: "old_mmap", 122: "uname", 125: "mprotect", 192: "mmap2",
}

LINUX_ARM64_TABLE: dict[int, str] = {
    56: "openat", 57: "close", 63: "read", 64: "write", 93: "exit",
    160: "uname", 222: "mmap", 226: "mprotect", 227: "munmap",
}

LINUX_ARM32_TABLE: dict[int, str] = {
    1: "exit", 3: "read", 4: "write", 5: "open", 6: "close", 90: "mmap",
    91: "munmap", 122: "uname", 125: "mprotect", 192: "mmap2",
}

# Android Syscall Tables (Inherits Linux + Bionic specifics)
ANDROID_ARM64_TABLE: dict[int, str] = {
    **LINUX_ARM64_TABLE,
    220: "clone", 221: "execve", 260: "wait4", 278: "gettid",
}

ANDROID_ARM32_TABLE: dict[int, str] = {
    **LINUX_ARM32_TABLE,
    120: "clone", 190: "vfork", 224: "gettid", 238: "tkill",
}

NT_STATUS_SUCCESS = 0x00000000


def detect_os_and_arch(state: angr.SimState) -> tuple[str, str]:
    """Detect OS and Architecture explicitly without assuming Windows for unidentified OS."""
    arch_name = state.arch.name.lower()
    if "amd64" in arch_name or "x86_64" in arch_name:
        canonical_arch = "amd64"
    elif "x86" in arch_name or "i386" in arch_name:
        canonical_arch = "x86"
    elif "arm64" in arch_name or "aarch64" in arch_name:
        canonical_arch = "arm64"
    elif "arm" in arch_name:
        canonical_arch = "arm32"
    else:
        canonical_arch = arch_name

    raw_os = str(getattr(state, "os_name", "") or "").lower()
    if "win" in raw_os:
        canonical_os = "windows"
    elif "android" in raw_os:
        canonical_os = "android"
    elif "linux" in raw_os:
        canonical_os = "linux"
    else:
        project = getattr(state, "project", None)
        loader_os = ""
        if project and hasattr(project, "loader") and hasattr(project.loader, "main_object"):
            main_obj = project.loader.main_object
            loader_os = str(getattr(main_obj, "os", "")).lower()

        if "win" in loader_os:
            canonical_os = "windows"
        elif "android" in loader_os:
            canonical_os = "android"
        elif "linux" in loader_os:
            canonical_os = "linux"
        else:
            canonical_os = "unidentified"

    return canonical_os, canonical_arch


def resolve_syscall_name(sys_nr: int, os_name: str, arch_name: str) -> tuple[str, str]:
    """Resolve a syscall number to a canonical API name and classification status:
    Returns (name, status) where status is 'MODELED' or 'APPROXIMATE_FALLBACK'.
    Eliminates cross-table fallback between different operating systems.
    """
    if os_name == "windows":
        table = None
        if arch_name in ("amd64", "x86_64") and sys_nr in WINDOWS_NT_X64_TABLE:
            table = WINDOWS_NT_X64_TABLE
        if arch_name in ("x86", "i386") and sys_nr in WINDOWS_NT_X86_TABLE:
            table = WINDOWS_NT_X86_TABLE
        if table is not None and sys_nr in table:
            return table[sys_nr], "MODELED"
        

    elif os_name == "android":
        if arch_name == "arm64" and sys_nr in ANDROID_ARM64_TABLE:
            return ANDROID_ARM64_TABLE[sys_nr], "MODELED"
        if arch_name == "arm32" and sys_nr in ANDROID_ARM32_TABLE:
            return ANDROID_ARM32_TABLE[sys_nr], "MODELED"

    elif os_name == "linux":
        if arch_name in ("amd64", "x86_64") and sys_nr in LINUX_X86_64:
            return f"sys_{LINUX_X86_64[sys_nr]}", "MODELED"
        if arch_name in ("x86", "i386") and sys_nr in LINUX_X86_TABLE:
            return f"sys_{LINUX_X86_TABLE[sys_nr]}", "MODELED"
        if arch_name == "arm64" and sys_nr in LINUX_ARM64_TABLE:
            return f"sys_{LINUX_ARM64_TABLE[sys_nr]}", "MODELED"
        if arch_name == "arm32" and sys_nr in LINUX_ARM32_TABLE:
            return f"sys_{LINUX_ARM32_TABLE[sys_nr]}", "MODELED"

    return f"sys_0x{sys_nr:x}", "APPROXIMATE_FALLBACK"


class GenericSyscallStub(angr.SimProcedure):
    """Generic SimProcedure stub for direct kernel syscalls.
    Returns STATUS_SUCCESS (0x0) for Windows NT APIs or 0 for Linux/Android syscalls.
    Logs OS, Arch, Syscall NR, Syscall Name, and Result without mutating output buffers.
    Jumps directly to the next instruction after syscall without popping RSP.
    """

    IS_SYSCALL = True

    def __init__(self, target_next_addr: int | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.target_next_addr = target_next_addr

    def run(self, *args, **kwargs) -> Any:  # noqa: ARG002
        state = self.state
        os_name, arch_name = detect_os_and_arch(state)

        sys_nr = 0
        if arch_name == "amd64":
            if hasattr(state.regs, "rax"):
                try:
                    sys_nr = state.solver.eval(state.regs.rax)
                except Exception:
                    pass
        elif arch_name == "x86":
            if hasattr(state.regs, "eax"):
                try:
                    sys_nr = state.solver.eval(state.regs.eax)
                except Exception:
                    pass
        elif arch_name == "arm64":
            if hasattr(state.regs, "x8"):
                try:
                    sys_nr = state.solver.eval(state.regs.x8)
                except Exception:
                    pass
        elif arch_name == "arm32":
            if hasattr(state.regs, "r7"):
                try:
                    sys_nr = state.solver.eval(state.regs.r7)
                except Exception:
                    pass

        sys_name, mode_status = resolve_syscall_name(sys_nr, os_name, arch_name)
        ret_val = NT_STATUS_SUCCESS

        logger.info(
            "[SYSCALL] OS: %s | Arch: %s | NR: %#x | Name: %s | Classification: %s | Result: %#x",
            os_name, arch_name, sys_nr, sys_name, mode_status, ret_val,
        )

        bv_ret = claripy.BVV(ret_val, state.arch.bits)
        if arch_name == "amd64" and hasattr(state.regs, "rax"):
            state.regs.rax = bv_ret
        elif arch_name == "x86" and hasattr(state.regs, "eax"):
            state.regs.eax = bv_ret
        elif arch_name == "arm64" and hasattr(state.regs, "x0"):
            state.regs.x0 = bv_ret
        elif arch_name == "arm32" and hasattr(state.regs, "r0"):
            state.regs.r0 = bv_ret

        next_addr = self.target_next_addr

        if next_addr is None and hasattr(self.state, "scratch"):
            bbl_addr = getattr(self.state.scratch, "bbl_addr", None)
            bbl_size = getattr(self.state.scratch, "bbl_size", None)
            if bbl_addr is not None and bbl_size is not None and bbl_size > 0:
                next_addr = bbl_addr + bbl_size

        if next_addr is None and hasattr(self.state, "addr") and self.state.addr is not None:
            if arch_name in ("amd64", "x86_64", "x86", "i386"):
                next_addr = self.state.addr + 2
            elif arch_name in ("arm64", "aarch64"):
                next_addr = self.state.addr + 4
            else:
                next_addr = self.state.addr + 2

        if next_addr is not None:
            self.jump(next_addr)
        else:
            return bv_ret


def setup_syscall_emulation(project: angr.Project, state: angr.SimState | None = None) -> None:
    """Configure project and state for direct kernel syscall handling."""
    if project is None:
        return

    logging.getLogger("angr.engines.syscall").setLevel(logging.ERROR)
    logging.getLogger("angr.simos").setLevel(logging.ERROR)

    import types

    if hasattr(project, "simos") and project.simos is not None:
        try:
            def _get_syscall_stub(self_simos: Any, st: angr.SimState, **kwargs: Any) -> GenericSyscallStub:
                proc = GenericSyscallStub(project=project)
                proc.addr = st.addr
                return proc

            if hasattr(project.simos, "syscall_table") and project.simos.syscall_table is not None:
                project.simos.syscall_table.default = GenericSyscallStub
            else:
                project.simos.syscall = types.MethodType(_get_syscall_stub, project.simos)
        except Exception as exc:
            logger.debug("Syscall table default assignment note: %s", exc)

    # Disassemble binary memory objects dynamically to identify basic block boundaries containing syscalls
    if hasattr(project, "loader") and hasattr(project.loader, "all_objects") and hasattr(project.loader, "memory"):
        cs = getattr(project.arch, "capstone", None)
        for obj in project.loader.all_objects:
            try:
                min_a = getattr(obj, "min_addr", None)
                max_a = getattr(obj, "max_addr", None)
                if min_a is None or max_a is None or min_a >= max_a:
                    continue
                mem_bytes = bytes(project.loader.memory.load(min_a, max_a - min_a + 1))
                if not mem_bytes:
                    continue

                if cs is not None:
                    insns = list(cs.disasm(mem_bytes, min_a))
                    block_starts = {min_a}
                    for insn in insns:
                        if (
                            insn.group(1)
                            or insn.group(2)
                            or insn.mnemonic in ("jmp", "jne", "je", "jz", "jnz", "call", "ret", "syscall", "sysenter", "svc", "int")
                        ):
                            block_starts.add(insn.address + insn.size)
                            if insn.mnemonic.startswith(("j", "call")):
                                try:
                                    op_str = insn.op_str.strip()
                                    if op_str.startswith("0x"):
                                        block_starts.add(int(op_str, 16))
                                except Exception:
                                    pass

                    for insn in insns:
                        if insn.mnemonic in ("syscall", "sysenter", "svc", "int"):
                            b_start = max(a for a in block_starts if a <= insn.address)
                            b_end = insn.address + insn.size
                            hook_len = b_end - b_start
                            if not project.is_hooked(b_start):
                                project.hook(
                                    b_start,
                                    GenericSyscallStub(project=project, target_next_addr=b_end),
                                    length=hook_len,
                                )
                else:
                    # Fallback opcode search
                    sys_offset = 0
                    while True:
                        idx = mem_bytes.find(b"\x0f\x05", sys_offset)
                        if idx == -1:
                            break
                        target_addr = min_a + idx
                        if not project.is_hooked(target_addr):
                            project.hook(target_addr, GenericSyscallStub(project=project), length=2)
                        sys_offset = idx + 2
            except Exception as exc:
                logger.debug("Syscall scanning note for object: %s", exc)

    if hasattr(project, "factory") and hasattr(project.factory, "default_engine"):
        if hasattr(project.factory.default_engine, "clear_cache"):
            try:
                project.factory.default_engine.clear_cache()
            except Exception:
                pass

    if state is not None:
        state.globals["syscall_emulation_enabled"] = True


def repair_syscall_errored_state(state: angr.SimState, error: Exception | None = None) -> bool:
    """Attempt to repair an errored state resulting from an unsupported syscall instruction.

    Differentiates instruction opcodes:
    - x64 'syscall' (0x0f 0x05): 2 bytes, sets RAX = 0.
    - x86 'sysenter' (0x0f 0x34): 2 bytes, sets EAX = 0.
    - x86 'int 0x2e' (0xcd 0x2e): 2 bytes, sets EAX = 0.
    - ARM64 'svc #0' (0x01 0x00 0x00 0xd4): 4 bytes, sets X0 = 0.
    - ARM32 'svc #imm24' (0x.. 0x.. 0x.. 0xef): 4 bytes, sets R0 = 0.
    - ARM32 Thumb 'svc #imm8' (0x.. 0xdf): 2 bytes, sets R0 = 0.

    Does NOT repair generic engine errors, division by zero, permission faults, or non-syscall opcodes.
    Returns True if repair succeeded, False otherwise.
    """
    if state is None:
        return False

    # Check for unrepairable errors explicitly
    if error is not None:
        err_str = str(error).lower()
        err_class = error.__class__.__name__.lower()
        if "zerodivision" in err_class or "zerodivision" in err_str or "permission" in err_str or "permission" in err_class:
            return False
        if "simengineerror" in err_class or "vex" in err_str:
            return False

    os_name, arch_name = detect_os_and_arch(state)
    pc_val = state.addr

    # Normalizar dirección si el bit Thumb está activo en la dirección
    actual_pc = pc_val & ~1

    # Inspect 4 bytes at PC to validate instruction opcode
    ins_bytes = b""
    try:
        ins_bytes = state.solver.eval(state.memory.load(actual_pc, 4), cast_to=bytes)
    except Exception:
        return False

    # Detectar si el estado de ARM se encuentra en modo Thumb
    is_thumb = (
        getattr(state, "thumb", False)
        or (pc_val % 2 != 0)
        or ("thumb" in arch_name.lower())
    )

    skip_len = 0
    target_arch = arch_name

    if ins_bytes.startswith(b"\x0f\x05"):  # syscall (x64)
        skip_len = 2
        target_arch = "amd64"
    elif ins_bytes.startswith(b"\x0f\x34"):  # sysenter (x86)
        skip_len = 2
        target_arch = "x86"
    elif ins_bytes.startswith(b"\xcd\x2e"):  # int 0x2e (x86)
        skip_len = 2
        target_arch = "x86"
    elif ins_bytes.startswith(b"\x01\x00\x00\xd4"):  # ARM64 svc #0 (little-endian)
        skip_len = 4
        target_arch = "arm64"
    elif is_thumb and len(ins_bytes) >= 2 and ins_bytes[1] == 0xDF:  # ARM32 Thumb SVC #imm8
        skip_len = 2
        target_arch = "arm32"
    elif ins_bytes[:4] == b"\x00\x00\x00\xef":  # ARM32 ARM SVC #0 (little-endian)
        skip_len = 4
        target_arch = "arm32"
    else:
        # Not a recognized syscall opcode, return False without modifying PC or registers
        return False

    # Reparar estado: avanzar el PC y setear el registro de retorno a 0 (éxito)
    state.regs.pc = actual_pc + skip_len

    if target_arch == "amd64":
        state.regs.rax = 0
    elif target_arch == "x86":
        state.regs.eax = 0
    elif target_arch == "arm64":
        state.regs.x0 = 0
    elif target_arch == "arm32":
        state.regs.r0 = 0

    return True