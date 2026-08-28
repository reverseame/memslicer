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
    ``"flags"`` or ``""`` for a general register.
    """

    name: str             # lowercase canonical mnemonic, e.g. "rip"
    value: int            # register value as an unsigned integer
    size: int = 8         # value width in bytes
    role: str = ""        # "pc" | "sp" | "fp" | "flags" | ""


@dataclass
class ThreadInfo:
    """Execution state of a single thread reported by a debugger bridge."""

    tid: int
    registers: list[RegisterValue]
    name: str = ""
    is_current: bool = False
    state: int = 0        # ThreadState code (0=Unknown)


@dataclass
class KeyHintEvent:
    """A cryptographic-key event observed live by a bridge hook.

    Reported by an optional in-target interceptor on a key-derivation API
    (e.g. Windows CNG ``BCryptGenerateSymmetricKey``). ``address`` is the
    absolute virtual address of the key material at the moment of the call and
    ``length`` its byte length (0 if the hook could not determine it). The
    engine later maps ``address`` to the owning captured MemoryRegion and emits
    a ``KeyHint`` block (region UUID + offset). ``api`` and ``algorithm`` are
    human-readable provenance carried into the hint's Note."""

    address: int
    length: int = 0
    key_type: int = 0     # KeyHint key_type code (0 = unknown/unspecified)
    protocol: int = 0     # KeyHint protocol code (0 = unknown/unspecified)
    api: str = ""         # e.g. "BCryptGenerateSymmetricKey"
    algorithm: str = ""   # e.g. "AES" (best-effort; may be empty)


# Canonical register-name sets used to tag special registers regardless of
# the originating backend (spec Section 5.7, Table 19b roles).
_PC_NAMES = frozenset({"rip", "eip", "pc"})
_SP_NAMES = frozenset({"rsp", "esp", "sp"})
_FP_NAMES = frozenset({"rbp", "ebp", "fp", "x29"})
_FLAGS_NAMES = frozenset({"rflags", "eflags", "cpsr", "pstate", "flags", "cspr"})


def register_role(name: str) -> str:
    """Map a register mnemonic to its role: ``pc``/``sp``/``fp``/``flags``/``""``."""
    n = name.lower()
    if n in _PC_NAMES:
        return "pc"
    if n in _SP_NAMES:
        return "sp"
    if n in _FP_NAMES:
        return "fp"
    if n in _FLAGS_NAMES:
        return "flags"
    return ""


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

    def collect_key_hints(self) -> list[KeyHintEvent]:
        """Return key-derivation events observed since ``connect()``.

        Optional capability. Bridges that do not hook key-derivation APIs
        return an empty list (the default); the engine then emits no KeyHint
        blocks. A bridge that supports it must arm its hooks in ``connect()``
        so calls made during the whole capture window are caught.
        """
        return []

    def disconnect(self) -> None:
        """Detach from the target process and clean up."""
        ...
