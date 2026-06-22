"""Speakeasy backend: high-fidelity Windows API emulation.

Our default backend (:mod:`memslicer.behavior.tracer`) emulates the *snapshot*
with Unicorn and models APIs with the hand-written stub library. That is the
right tool for Linux/syscalls and for staying faithful to the captured address
space, but for Windows it reimplements -- slowly and partially -- what
Speakeasy already does completely.

Speakeasy (Mandiant) is a Windows user/kernel emulator built on the *same*
Unicorn engine, shipping hundreds of real API handlers plus PEB/TEB, the object
manager, a fake filesystem/registry/network, and dynamic import resolution.
This backend drives Speakeasy and projects its emulation onto the *same*
:class:`~memslicer.behavior.graph.BehaviorGraph` the Unicorn backend produces,
so everything downstream (categories, serializers, feature vectors) is shared.

Roles, after this module:

* **Windows, concrete**  -> Speakeasy (this backend)
* **Linux / syscalls**   -> Unicorn + :mod:`memslicer.behavior.stublib`
* **symbolic**           -> angr (:mod:`memslicer.symbex`)

Speakeasy is an optional dependency (it is not in the default install). Install
it with the ``speakeasy`` extra. Every public entry point raises a clear
:class:`SpeakeasyUnavailable` if it is missing.
"""
from __future__ import annotations

from memslicer.behavior.events import BehaviorEvent, EdgeType, EventKind
from memslicer.behavior.graph import BehaviorGraph
from memslicer.behavior.stubs import categorize

__all__ = [
    "SpeakeasyBackend", "SpeakeasyUnavailable",
    "trace_pe_speakeasy", "trace_slice_speakeasy", "speakeasy_available",
]


class SpeakeasyUnavailable(RuntimeError):
    """Raised when the optional ``speakeasy`` package is not importable."""


def speakeasy_available() -> bool:
    try:
        import speakeasy  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _import_speakeasy():
    try:
        import speakeasy
    except Exception as exc:  # noqa: BLE001
        raise SpeakeasyUnavailable(
            "the 'speakeasy' package is required for the Speakeasy backend; "
            "install it with: pip install memslicer[speakeasy]"
        ) from exc
    return speakeasy


class SpeakeasyBackend:
    """Emulates a Windows PE with Speakeasy into a :class:`BehaviorGraph`.

    Every emulated API call is captured (via a wildcard API hook) as an ``API``
    behavior event -- tagged with its behavior category, arguments and return
    value -- and wired to its call site and the previous system event exactly
    like the Unicorn tracer does. Set *granularity* to ``"instruction"`` to also
    record a code node per executed instruction (off by default: a full PE run
    is large, and control-flow is the Unicorn backend's job).
    """

    def __init__(self, *, granularity: str | None = None,
                 max_api_calls: int = 100000) -> None:
        self.granularity = granularity
        self.max_api_calls = max_api_calls
        self.graph = BehaviorGraph()
        self.seq = 0
        self._cur_code: str | None = None
        self._last_event: str | None = None
        self._prev_leader: int | None = None
        self._expected_next: int | None = None
        self._api_calls = 0

    # -- graph wiring (mirrors BehaviorTracer.emit) --------------------------

    def _next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def _emit(self, ev: BehaviorEvent) -> None:
        self.graph.consume(ev)
        if ev.kind == EventKind.NODE:
            self._cur_code = f"0x{ev.addr:x}"
        elif ev.kind in (EventKind.SYSCALL, EventKind.API):
            nid = f"{ev.kind}:{ev.label}"
            if self._cur_code:
                self.graph.add_edge(self._cur_code, nid, EdgeType.INVOKE)
            if self._last_event:
                self.graph.add_edge(self._last_event, nid, EdgeType.SEQ)
            self._last_event = nid

    # -- Speakeasy callbacks -------------------------------------------------

    @staticmethod
    def _norm_label(api_name: str) -> tuple[str, str]:
        """``"kernel32.CreateFileW"`` -> ("kernel32.dll!CreateFileW", bare)."""
        mod, _, bare = api_name.partition(".")
        if not bare:
            return api_name, api_name
        suffix = "" if mod.lower().endswith(".dll") else ".dll"
        return f"{mod}{suffix}!{bare}", bare

    def _on_api(self, emu, api_name, func, params):
        rv = func(params) if callable(func) else None
        self._api_calls += 1
        # The caller (its return address) is the code that invoked the API.
        try:
            site = emu.get_ret_address()
        except Exception:  # noqa: BLE001
            site = 0
        if site:
            self._cur_code = f"0x{site:x}"
            self.graph.touch_node_id(self._cur_code, "block", addr=site)
        label, bare = self._norm_label(api_name)
        # Speakeasy decodes some args to str/bytes; keep them but render safely.
        argv = list(params)[:4] if params else []
        shown = ", ".join(hex(a) if isinstance(a, int) else repr(a)
                          for a in argv)
        self._emit(BehaviorEvent(
            kind=EventKind.API, seq=self._next_seq(),
            addr=site, label=label,
            attrs={"category": categorize(bare),
                   "args": [a if isinstance(a, (int, str)) else repr(a)
                            for a in argv],
                   "ret": rv if isinstance(rv, int) else 0,
                   "log": f"{bare}({shown})"},
        ))
        if self._api_calls >= self.max_api_calls:
            self.graph.meta.setdefault("stop_reason", "max_api_calls reached")
            emu.stop()
        return rv

    def _on_code(self, emu, addr, size):
        if self.granularity == "instruction":
            self._emit(BehaviorEvent(kind=EventKind.NODE, seq=self._next_seq(),
                                     addr=addr, size=size, node_kind="insn",
                                     label=f"0x{addr:x}"))
            return True
        # block granularity: a leader is any address that is not the straight
        # fall-through of the previous instruction (i.e. a branch/call target).
        if self._expected_next is None or addr != self._expected_next:
            self._emit(BehaviorEvent(kind=EventKind.NODE, seq=self._next_seq(),
                                     addr=addr, size=size, node_kind="block",
                                     label=f"0x{addr:x}"))
            if self._prev_leader is not None:
                self.graph.add_edge(f"0x{self._prev_leader:x}",
                                    f"0x{addr:x}", EdgeType.JUMP)
            self._prev_leader = addr
        self._expected_next = addr + size
        return True

    # -- run -----------------------------------------------------------------

    def trace(self, *, path: str | None = None, data: bytes | None = None,
              arch: str | None = None) -> BehaviorGraph:
        """Emulate the PE at *path* (or in-memory *data*) and return its graph.

        Pass *arch* (``"x86"``/``"amd64"``) only for raw shellcode; for a PE
        Speakeasy infers it from the headers.
        """
        if path is None and data is None:
            raise ValueError("trace() needs either path= or data=")
        speakeasy = _import_speakeasy()
        se = speakeasy.Speakeasy()
        se.add_api_hook(self._on_api, "*", "*")
        if self.granularity in ("block", "instruction"):
            se.add_code_hook(self._on_code)

        is_pe = data is None or data[:2] == b"MZ"
        try:
            if is_pe:
                module = (se.load_module(path) if path is not None
                          else se.load_module(data=data))
                self.graph.meta["entry"] = f"0x{getattr(module, 'base', 0):x}"
                se.run_module(module)
            else:
                sc_addr = se.load_shellcode(path, arch, data=data)
                self.graph.meta["entry"] = f"0x{sc_addr:x}"
                se.run_shellcode(sc_addr)
        except Exception as exc:  # noqa: BLE001 - emulation faults are expected
            self.graph.meta.setdefault("stop_reason", f"speakeasy: {exc}")
        finally:
            try:
                arch_name = se.get_arch()
            except Exception:  # noqa: BLE001
                arch_name = arch or "?"
            self.graph.meta.update({
                "backend": "speakeasy", "arch": str(arch_name),
                "api_calls": self._api_calls,
            })
            self.graph.meta.setdefault("stop_reason", "run complete")
        return self.graph


def trace_pe_speakeasy(*, path: str | None = None, data: bytes | None = None,
                       granularity: str | None = None,
                       arch: str | None = None) -> BehaviorGraph:
    """Convenience: emulate a Windows PE (or shellcode) with Speakeasy."""
    return SpeakeasyBackend(granularity=granularity).trace(
        path=path, data=data, arch=arch)


def _main_image_bytes(slice_path: str) -> bytes:
    """Assemble the captured bytes of the slice's main PE image.

    Picks the lowest-based module whose region starts with ``MZ`` and returns
    that region's contiguous captured pages. This is a *memory* image; Speakeasy
    expects a file-layout PE, so this is best-effort -- see
    :func:`trace_slice_speakeasy`.
    """
    from memslicer.emu.loader import load_slice
    img = load_slice(slice_path)
    region_by_base = {r.base: r for r in img.regions}

    def region_bytes(region) -> bytes:
        out = bytearray()
        addr = region.base
        end = region.base + region.size
        while addr < end:
            page = region.pages.get(addr)
            if page is None:
                break
            out += page
            addr += region.page_size
        return bytes(out)

    candidates = []
    for mod in sorted(img.modules, key=lambda m: m.base):
        region = region_by_base.get(mod.base)
        if region is None:
            continue
        blob = region_bytes(region)
        if blob[:2] == b"MZ":
            candidates.append(blob)
    if not candidates:
        # fall back to any MZ-headed region
        for region in sorted(img.regions, key=lambda r: r.base):
            blob = region_bytes(region)
            if blob[:2] == b"MZ":
                candidates.append(blob)
                break
    if not candidates:
        raise SpeakeasyUnavailable(
            "no PE image (MZ header) found in slice; the Speakeasy backend "
            "needs a Windows PE")
    return candidates[0]


def trace_slice_speakeasy(slice_path: str, *,
                          granularity: str | None = None) -> BehaviorGraph:
    """Best-effort: extract the main PE image from an MSL slice and emulate it
    with Speakeasy.

    Note: an MSL slice holds a *memory* image, while Speakeasy's PE loader
    expects a file-layout PE. This works when the captured image is loadable as
    such; otherwise emulate the original on-disk PE via
    :func:`trace_pe_speakeasy`.
    """
    data = _main_image_bytes(slice_path)
    return trace_pe_speakeasy(data=data, granularity=granularity)
