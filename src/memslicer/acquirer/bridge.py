"""Backend-agnostic protocol and data types for debugger bridges."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from memslicer.msl.constants import ArchType, OSType


@dataclass
class PlatformInfo:
    """Platform information returned by a debugger bridge."""

    arch: ArchType
    os: OSType
    pid: int
    page_size: int


@dataclass
class MemoryRange:
    """A memory range as reported by the debugger."""

    base: int
    size: int
    protection: str  # "rwx" / "r--" / etc.
    file_path: str = ""


@dataclass
class ModuleInfo:
    """A loaded module/shared library."""

    name: str
    path: str
    base: int
    size: int


@dataclass
class RegisterValue:
    """A single CPU register reported by a debugger bridge.

    ``role`` marks special registers so the engine can flag them without
    architecture-specific knowledge: one of ``"pc"``, ``"sp"``, ``"fp"``,
    ``"flags"``, ``"tls"``, ``"lr"`` or ``""`` for a general register.
    """

    name: str             # lowercase canonical mnemonic (spec Table 19g), e.g. "rip"
    value: int            # register value as an unsigned integer
    size: int = 8         # value width in bytes
    role: str = ""        # "pc" | "sp" | "fp" | "flags" | "tls" | "lr" | ""


@dataclass
class ThreadInfo:
    """Execution state of a single thread reported by a debugger bridge."""

    tid: int
    registers: list[RegisterValue]
    name: str = ""
    is_current: bool = False
    state: int = 0        # ThreadState code (0=Unknown)
    suspended: bool = False  # registers read while the thread was stopped
    partial: bool = False    # some register the bridge normally reads was lost


# Debugger-native names that spec Table 19g forbids on disk, per architecture.
_CANONICAL_NAMES: dict[ArchType, dict[str, str]] = {
    ArchType.x86_64: {"eflags": "rflags"},
    ArchType.ARM64: {"fp": "x29", "lr": "x30", "cpsr": "pstate",
                     "tpidr": "tpidr_el0"},
    ArchType.ARM32: {"r13": "sp", "r14": "lr", "r15": "pc"},
}


def canonical_register_name(name: str, arch: ArchType) -> str:
    """Lowercase *name* and replace Table 19g-forbidden aliases for *arch*."""
    n = name.lower()
    return _CANONICAL_NAMES.get(arch, {}).get(n, n)


# Role sets for canonical names (spec Section 5.7, Table 19b/19g roles).
_PC_NAMES = frozenset({"rip", "eip", "pc"})
_SP_NAMES = frozenset({"rsp", "esp", "sp"})
_FP_NAMES = frozenset({"rbp", "ebp", "x29"})
_FLAGS_NAMES = frozenset({"rflags", "eflags", "cpsr", "pstate", "nzcv"})
_LR_NAMES = frozenset({"x30", "lr"})

# Thread-pointer register per (arch, os): the one the OS uses for TLS. Only
# that register carries the TLS role (Table 19g).
_TLS_UNIX_X86_64 = "fs_base"
_TLS_UNIX_ARM64 = "tpidr_el0"
_TLS_NAMES: dict[tuple[ArchType, OSType], str] = {
    (ArchType.x86_64, OSType.Windows): "gs_base",
    (ArchType.x86_64, OSType.macOS): "gs_base",
    (ArchType.x86_64, OSType.Linux): _TLS_UNIX_X86_64,
    (ArchType.x86_64, OSType.Android): _TLS_UNIX_X86_64,
    (ArchType.x86_64, OSType.FreeBSD): _TLS_UNIX_X86_64,
    (ArchType.x86, OSType.Windows): "fs_base",
    (ArchType.x86, OSType.Linux): "gs_base",
    (ArchType.x86, OSType.Android): "gs_base",
    (ArchType.ARM64, OSType.Windows): "x18",
    (ArchType.ARM64, OSType.macOS): "tpidrro_el0",
    (ArchType.ARM64, OSType.iOS): "tpidrro_el0",
    (ArchType.ARM64, OSType.Linux): _TLS_UNIX_ARM64,
    (ArchType.ARM64, OSType.Android): _TLS_UNIX_ARM64,
    (ArchType.ARM64, OSType.FreeBSD): _TLS_UNIX_ARM64,
    (ArchType.ARM32, OSType.Linux): "tpidruro",
    (ArchType.ARM32, OSType.Android): "tpidruro",
}


def register_role(name: str, arch: ArchType | None = None,
                  os: OSType | None = None) -> str:
    """Map a canonical register name to its role.

    Returns ``pc``/``sp``/``fp``/``flags``/``lr``/``tls`` or ``""``. The
    ``tls`` role needs *arch* and *os*: it is assigned only to the register
    the OS uses as thread pointer (e.g. ``fs_base`` on Linux x86_64,
    ``gs_base`` on Windows x86_64, ``tpidr_el0`` on Linux ARM64).
    """
    n = name.lower()
    if n in _PC_NAMES:
        return "pc"
    if n in _SP_NAMES:
        return "sp"
    if n in _FP_NAMES:
        return "fp"
    if n in _FLAGS_NAMES:
        return "flags"
    if n in _LR_NAMES:
        return "lr"
    if arch is not None and os is not None and n == _TLS_NAMES.get((arch, os)):
        return "tls"
    return ""


def make_register(name: str, value: int, size: int,
                  arch: ArchType, os: OSType) -> RegisterValue:
    """Build a :class:`RegisterValue` with the canonical name and role."""
    canon = canonical_register_name(name, arch)
    return RegisterValue(name=canon, value=value, size=size,
                         role=register_role(canon, arch, os))


# Register width in bytes per architecture (GPRs).
_REG_WIDTH = {
    ArchType.x86: 4, ArchType.ARM32: 4, ArchType.MIPS32: 4,
    ArchType.RISC_V_RV32: 4, ArchType.PPC32: 4,
}


def register_width_bytes(arch: ArchType) -> int:
    """Return the integer register width in bytes for *arch* (default 8)."""
    return _REG_WIDTH.get(arch, 8)


# Vector register byte widths, longest prefix first.
_VECTOR_WIDTHS = (("zmm", 64), ("ymm", 32), ("xmm", 16))


def vector_register_width(name: str) -> int:
    """Byte width of a vector register (``xmm``=16, ``ymm``=32, ``zmm``=64), or
    0 if *name* is not a recognized vector register. Lets a bridge capture wide
    registers at full width instead of truncating them to the GPR width."""
    n = name.lower()
    for prefix, width in _VECTOR_WIDTHS:
        if n.startswith(prefix):
            return width
    return 0


@runtime_checkable
class DebuggerBridge(Protocol):
    """Protocol for debugger backends.

    Each backend implements only these methods.
    Everything else (read strategy, MSL writing, progress,
    volatility sorting) lives in AcquisitionEngine.
    """

    @property
    def is_remote(self) -> bool:
        """Whether this bridge is connected to a remote target."""
        return False

    def connect(self) -> None:
        """Attach to the target process."""
        ...

    def get_platform_info(self) -> PlatformInfo:
        """Return arch, OS, PID, and page size."""
        ...

    def enumerate_ranges(self) -> list[MemoryRange]:
        """List all memory regions in the target process."""
        ...

    def enumerate_modules(self) -> list[ModuleInfo]:
        """List all loaded modules/libraries."""
        ...

    def enumerate_threads(self) -> list[ThreadInfo]:
        """List all threads with their register state.

        Optional capability. Backends that cannot read register state
        return an empty list; the engine then omits Thread Context blocks.
        """
        return []

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Read *size* bytes from *address*. Return ``None`` on failure."""
        ...

    def disconnect(self) -> None:
        """Detach from the target process and clean up."""
        ...
