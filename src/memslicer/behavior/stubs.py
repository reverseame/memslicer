"""Analyst-editable *stub skeleton* for system calls / APIs.

A static snapshot has no OS, so a ``syscall`` cannot be truly executed. Instead
each syscall/API is modelled by a *stub*: a small Python function the analyst
reviews and fills in to return whatever the investigation needs (a handle, a
buffer, an error) so emulation keeps advancing down the path of interest. This
is the Speakeasy/Qiling approach.

Workflow::

    1. run once -> unknown calls hit the default stub (observe + return 0)
    2. ``emit_skeleton(registry, "stubs.py")`` writes a template, one function
       per observed call, pre-filled with the observed arguments as comments
    3. edit ``stubs.py``; re-run with ``load_stubs("stubs.py")`` so the edited
       functions override the defaults

A stub receives a :class:`StubContext` and returns ``ctx.STOP`` to halt
emulation or ``ctx.CONTINUE`` (or ``None``) to resume after the call site.

This is the *model-by-hand* handler strategy. The other two strategies share
the same call site: *observe* (the built-in default below) and a future
*angr SimOS* hand-off (see :mod:`memslicer.behavior`).
"""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field

from memslicer.behavior.syscalls import syscall_name
from memslicer.msl.constants import ArchType, OSType

__all__ = [
    "StubContext", "StubRegistry", "default_stub", "make_context",
    "make_api_context", "emit_skeleton", "load_stubs", "syscall_name",
]

# arch -> (syscall-number register, [arg registers...], return register)
_SYS_ABI = {
    ArchType.x86_64: ("rax", ["rdi", "rsi", "rdx", "r10", "r8", "r9"], "rax"),
    ArchType.x86:    ("eax", ["ebx", "ecx", "edx", "esi", "edi", "ebp"], "eax"),
    ArchType.ARM64:  ("x8",  ["x0", "x1", "x2", "x3", "x4", "x5"], "x0"),
    ArchType.ARM32:  ("r7",  ["r0", "r1", "r2", "r3", "r4", "r5"], "r0"),
}

# Function-call ABIs for API stubs: argument registers spilled to the stack
# after they run out. ``stack0`` is the byte offset from the stack pointer to
# the first *stacked* argument (past the return address and any shadow space).
_ARM64_ARGS = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
_ARM32_ARGS = ["r0", "r1", "r2", "r3"]
_SYSV64_ARGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
_WIN64_ARGS = ["rcx", "rdx", "r8", "r9"]

# Syscalls that terminate the process -> default stub stops emulation.
_TERMINATORS = {"exit", "exit_group", "execve", "execveat"}


@dataclass
class StubContext:
    """Passed to every stub. Abstracts the ABI so a stub never touches Unicorn.

    Read arguments with :meth:`arg`, set the return value with :meth:`set_ret`,
    touch memory with :meth:`read_mem`/:meth:`write_mem`/:meth:`read_cstr`, and
    return :attr:`STOP` / :attr:`CONTINUE` to control emulation.
    """
    emu: object               # MSLEmulator
    arch: ArchType
    name: str
    number: int
    site: int                 # address of the call site
    kind: str = "syscall"     # "syscall" | "api"
    _argregs: list[str] = field(default_factory=list)
    _retreg: str = "rax"
    _spreg: str = "rsp"
    _ptr: int = 8
    _stack_arg0: int | None = None   # sp offset to first stacked arg, or None
    logs: list[str] = field(default_factory=list)

    CONTINUE = False
    STOP = True

    # -- arguments / registers ----------------------------------------------

    def arg(self, i: int) -> int:
        """Value of the *i*-th integer argument (ABI-ordered; reg then stack)."""
        if i < len(self._argregs):
            return self.emu.read_reg(self._argregs[i])
        if self._stack_arg0 is not None:
            idx = i - len(self._argregs)
            addr = self.emu.read_reg(self._spreg) + self._stack_arg0 + idx * self._ptr
            try:
                return int.from_bytes(self.emu.read_mem(addr, self._ptr), "little")
            except Exception:  # noqa: BLE001
                return 0
        return 0

    def args(self, n: int) -> list[int]:
        return [self.arg(i) for i in range(n)]

    def set_ret(self, value: int) -> None:
        self.emu.write_reg(self._retreg, value & ((1 << self.emu.bits) - 1))

    def get_reg(self, name: str) -> int:
        return self.emu.read_reg(name)

    def set_reg(self, name: str, value: int) -> None:
        self.emu.write_reg(name, value)

    # -- memory --------------------------------------------------------------

    def read_mem(self, addr: int, size: int) -> bytes:
        return self.emu.read_mem(addr, size)

    def write_mem(self, addr: int, data: bytes) -> None:
        self.emu.uc.mem_write(addr, bytes(data))

    def read_cstr(self, addr: int, limit: int = 4096) -> bytes:
        if not addr:
            return b""
        try:
            raw = self.emu.read_mem(addr, limit)
        except Exception:  # noqa: BLE001 - unmapped/short read
            return b""
        nul = raw.find(b"\x00")
        return raw if nul < 0 else raw[:nul]

    def log(self, message: str) -> None:
        self.logs.append(message)


def default_stub(ctx: StubContext):
    """Built-in *observe* behavior: record up to 4 args, return 0, continue
    (or stop on a process-terminating syscall)."""
    ctx.log(f"{ctx.name}({', '.join(hex(a) for a in ctx.args(4))})")
    if ctx.name in _TERMINATORS:
        return ctx.STOP
    ctx.set_ret(0)
    return ctx.CONTINUE


class StubRegistry:
    """Holds the per-name stub functions and records what was observed.

    Lookup is by name (``"openat"``, ``"write"``, ...). Anything without an
    explicit stub falls back to :func:`default_stub`. ``observed`` accumulates
    one sample per name so :func:`emit_skeleton` can pre-fill a template.
    """
    def __init__(self) -> None:
        self._byname: dict[str, callable] = {}
        self.observed: dict[str, dict] = {}

    def register(self, name: str, fn) -> None:
        self._byname[name] = fn

    def handler(self, name: str):
        return self._byname.get(name, default_stub)

    def note(self, name: str, args: list[int]) -> None:
        rec = self.observed.setdefault(name, {"count": 0, "sample_args": args})
        rec["count"] += 1

    def dispatch(self, ctx: StubContext):
        self.note(ctx.name, ctx.args(6))
        return self.handler(ctx.name)(ctx)


def make_context(emu, arch: ArchType, name: str, number: int, site: int,
                 kind: str = "syscall") -> StubContext:
    _nr, argregs, retreg = _SYS_ABI.get(arch, ("rax", [], "rax"))
    return StubContext(emu=emu, arch=arch, name=name, number=number, site=site,
                       kind=kind, _argregs=list(argregs), _retreg=retreg)


def make_api_context(emu, arch: ArchType, os: OSType, name: str,
                     site: int) -> StubContext:
    """Build a :class:`StubContext` for an API call using the function-call ABI
    of *arch*/*os* (Win64 vs SysV vs ARM AAPCS)."""
    ptr = emu.bits // 8
    spreg = emu._sp_name
    if arch == ArchType.x86_64:
        if os == OSType.Windows:
            argregs, retreg, stack0 = _WIN64_ARGS, "rax", ptr + 32  # +shadow
        else:
            argregs, retreg, stack0 = _SYSV64_ARGS, "rax", ptr
    elif arch == ArchType.x86:
        argregs, retreg, stack0 = [], "eax", ptr                    # cdecl/stdcall
    elif arch == ArchType.ARM64:
        argregs, retreg, stack0 = _ARM64_ARGS, "x0", 0
    elif arch == ArchType.ARM32:
        argregs, retreg, stack0 = _ARM32_ARGS, "r0", 0
    else:
        argregs, retreg, stack0 = [], "rax", None
    return StubContext(emu=emu, arch=arch, name=name, number=-1, site=site,
                       kind="api", _argregs=list(argregs), _retreg=retreg,
                       _spreg=spreg, _ptr=ptr, _stack_arg0=stack0)


def emit_skeleton(registry: StubRegistry, path: str) -> None:
    """Write an editable stub skeleton for everything observed in a run.

    One function per observed call, pre-filled with the sampled arguments as a
    comment. The analyst edits the bodies and reloads with :func:`load_stubs`.
    """
    lines = [
        '"""Auto-generated stub skeleton for MSL behavior emulation.',
        "",
        "Edit each function to return whatever the investigation needs, then",
        "re-run with --stubs <this file>. A stub receives a StubContext (ctx):",
        "  ctx.arg(i) / ctx.args(n) / ctx.read_cstr(addr) / ctx.read_mem(a, n)",
        "  ctx.set_ret(value) / ctx.write_mem(addr, data) / ctx.log(msg)",
        "  return ctx.STOP to halt emulation, else ctx.CONTINUE.",
        '"""',
        "",
        "",
    ]
    for name in sorted(registry.observed):
        rec = registry.observed[name]
        sample = ", ".join(hex(a) for a in rec["sample_args"])
        lines += [
            f"def {name}(ctx):",
            f"    # observed {rec['count']}x; sample args: {sample}",
            f'    ctx.log("{name}")',
            "    ctx.set_ret(0)",
            "    return ctx.CONTINUE",
            "",
            "",
        ]
    with open(path, "w") as f:
        f.write("\n".join(lines))


def load_stubs(path: str) -> StubRegistry:
    """Load an analyst-edited stub module: every top-level function becomes a
    stub keyed by its name."""
    spec = importlib.util.spec_from_file_location("_msl_stubs", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    registry = StubRegistry()
    for attr in dir(module):
        if attr.startswith("_"):
            continue
        fn = getattr(module, attr)
        if callable(fn) and getattr(fn, "__module__", None) == "_msl_stubs":
            registry.register(attr, fn)
    return registry
