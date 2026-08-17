"""A curated, categorized stub library for common OS APIs and libc calls.

Where :mod:`memslicer.behavior.stubs` provides the *mechanism* (the default
observe-and-continue stub and the skeleton/loader workflow), this module ships
*content*: hand-written stubs for the APIs malware most often touches, grouped
by behavior category (file/network/registry/process/memory/library/system).

Each stub does three things beyond the default:
  * decode its interesting arguments (paths, hostnames, key names) with the
    :class:`~memslicer.behavior.stubs.StubContext` decode helpers, and log them
    in a human-readable form so the behavior graph carries semantics, not just
    addresses;
  * return a *plausible* value (a fresh handle, an allocation address, success)
    so emulation keeps advancing down realistic paths instead of bailing on a
    zero return;
  * stay free of any Unicorn detail -- everything goes through ``ctx``.

Use :func:`build_default_registry` to get a ready registry, optionally merged
with an analyst-edited stub file::

    reg = build_default_registry().merge(load_stubs("stubs.py"))
"""
from __future__ import annotations

from memslicer.behavior.stubs import StubRegistry

__all__ = ["build_default_registry", "STUBS"]

# Per-call-name stubs, filled by the @stub decorator below. Names are matched
# case-insensitively and against the Windows A/W suffix variants, so a single
# ``CreateFile`` entry serves ``CreateFileA`` and ``CreateFileW``.
STUBS: dict[str, callable] = {}


def stub(*names: str):
    """Register *fn* under each given call name (case-insensitive)."""
    def deco(fn):
        for n in names:
            STUBS[n.lower()] = fn
        return fn
    return deco


# -- shared scratch allocators (state lives on the registry, via ctx.state) ----

def _counter(ctx, key: str, start: int, step: int) -> int:
    """Return the next value of a named monotonic counter in shared state."""
    cur = ctx.state.get(key, start)
    ctx.state[key] = cur + step
    return cur


def _handle(ctx) -> int:
    """Fresh, distinct, non-zero handle (avoids 0 / -1 which mean failure)."""
    return _counter(ctx, "_next_handle", 0x100, 4)


def _alloc(ctx, size: int) -> int:
    """Bump-allocate *size* bytes from a fake heap and return the base."""
    size = max(size or 0, 0x1000)
    base = _counter(ctx, "_heap_brk", 0x7F0000000000, (size + 0xFFF) & ~0xFFF)
    return base


def _ok(ctx, value: int = 1):
    """Log already done by caller; return *value* and continue."""
    ctx.set_ret(value)
    return ctx.CONTINUE


# -- file ----------------------------------------------------------------------

@stub("CreateFile", "_open", "fopen")
def _create_file(ctx):
    ctx.set_category("file")
    path = ctx.arg_wstr(0) if ctx.name.lower().endswith("w") else ctx.arg_str(0)
    ctx.log(f"{ctx.name}(path={path!r}) -> handle")
    return _ok(ctx, _handle(ctx))


@stub("openat", "open")
def _open(ctx):
    ctx.set_category("file")
    # openat(dirfd, path, ...) vs open(path, ...)
    pidx = 1 if ctx.name == "openat" else 0
    ctx.log(f"{ctx.name}(path={ctx.arg_str(pidx)!r}) -> fd")
    return _ok(ctx, _counter(ctx, "_next_fd", 3, 1))


@stub("ReadFile", "read", "fread")
def _read(ctx):
    ctx.set_category("file")
    ctx.log(f"{ctx.name}(fd={ctx.arg(0)}, len={ctx.arg(2)}) -> 0 bytes")
    return _ok(ctx, 0)


@stub("WriteFile", "write", "fwrite")
def _write(ctx):
    ctx.set_category("file")
    n = ctx.arg(2)
    ctx.log(f"{ctx.name}(fd={ctx.arg(0)}, len={n})")
    return _ok(ctx, n)


@stub("DeleteFile", "unlink", "remove", "unlinkat")
def _delete(ctx):
    ctx.set_category("file")
    pidx = 1 if ctx.name == "unlinkat" else 0
    path = ctx.arg_wstr(pidx) if ctx.name.lower().endswith("w") else ctx.arg_str(pidx)
    ctx.log(f"{ctx.name}(path={path!r})")
    return _ok(ctx, 0 if ctx.name in ("unlink", "remove", "unlinkat") else 1)


@stub("CloseHandle", "close", "fclose")
def _close(ctx):
    ctx.set_category("file")
    ctx.log(f"{ctx.name}(handle={ctx.arg(0)})")
    return _ok(ctx, 0 if ctx.name in ("close", "fclose") else 1)


# -- network -------------------------------------------------------------------

@stub("socket", "WSASocketA", "WSASocketW")
def _socket(ctx):
    ctx.set_category("network")
    ctx.log(f"{ctx.name}(af={ctx.arg(0)}, type={ctx.arg(1)}) -> sock")
    return _ok(ctx, _counter(ctx, "_next_sock", 0x200, 4))


@stub("connect")
def _connect(ctx):
    ctx.set_category("network")
    ctx.log(f"connect(sock={ctx.arg(0)})")
    return _ok(ctx, 0)


@stub("gethostbyname", "getaddrinfo")
def _resolve(ctx):
    ctx.set_category("network")
    ctx.log(f"{ctx.name}(host={ctx.arg_str(0)!r})")
    return _ok(ctx, 0)


@stub("InternetOpenA", "InternetOpenW", "WinHttpOpen")
def _inet_open(ctx):
    ctx.set_category("network")
    ctx.log(f"{ctx.name}() -> handle")
    return _ok(ctx, _handle(ctx))


@stub("InternetOpenUrlA", "InternetOpenUrlW", "URLDownloadToFileA",
      "URLDownloadToFileW")
def _inet_url(ctx):
    ctx.set_category("network")
    url = ctx.arg_wstr(1) if ctx.name.lower().endswith("w") else ctx.arg_str(1)
    ctx.log(f"{ctx.name}(url={url!r})")
    return _ok(ctx, _handle(ctx))


@stub("send", "recv", "WSASend", "WSARecv")
def _sendrecv(ctx):
    ctx.set_category("network")
    ctx.log(f"{ctx.name}(sock={ctx.arg(0)}, len={ctx.arg(2)})")
    return _ok(ctx, ctx.arg(2))


# -- registry ------------------------------------------------------------------

@stub("RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExA", "RegCreateKeyExW")
def _reg_open(ctx):
    ctx.set_category("registry")
    sub = ctx.arg_wstr(1) if ctx.name.lower().endswith("w") else ctx.arg_str(1)
    ctx.log(f"{ctx.name}(subkey={sub!r}) -> hkey")
    # The opened key handle is returned through the out-param (last arg).
    hkey = _handle(ctx)
    out = ctx.arg(4)
    if out:
        try:
            ctx.write_mem(out, hkey.to_bytes(ctx._ptr, "little"))
        except Exception:  # noqa: BLE001
            pass
    return _ok(ctx, 0)  # ERROR_SUCCESS


@stub("RegSetValueExA", "RegSetValueExW")
def _reg_set(ctx):
    ctx.set_category("registry")
    name = ctx.arg_wstr(1) if ctx.name.lower().endswith("w") else ctx.arg_str(1)
    ctx.log(f"{ctx.name}(value={name!r})")
    return _ok(ctx, 0)


@stub("RegQueryValueExA", "RegQueryValueExW", "RegGetValueA", "RegGetValueW")
def _reg_query(ctx):
    ctx.set_category("registry")
    name = ctx.arg_wstr(1) if ctx.name.lower().endswith("w") else ctx.arg_str(1)
    ctx.log(f"{ctx.name}(value={name!r})")
    return _ok(ctx, 0)


@stub("RegCloseKey")
def _reg_close(ctx):
    ctx.set_category("registry")
    ctx.log(f"RegCloseKey(hkey={ctx.arg(0)})")
    return _ok(ctx, 0)


# -- process -------------------------------------------------------------------

@stub("CreateProcessA", "CreateProcessW")
def _create_process(ctx):
    ctx.set_category("process")
    app = ctx.arg_wstr(0) if ctx.name.lower().endswith("w") else ctx.arg_str(0)
    cmd = ctx.arg_wstr(1) if ctx.name.lower().endswith("w") else ctx.arg_str(1)
    ctx.log(f"{ctx.name}(app={app!r}, cmdline={cmd!r})")
    return _ok(ctx, 1)


@stub("ShellExecuteA", "ShellExecuteW", "WinExec")
def _shell_execute(ctx):
    ctx.set_category("process")
    if ctx.name == "WinExec":
        target = ctx.arg_str(0)
    else:
        target = (ctx.arg_wstr(2) if ctx.name.lower().endswith("w")
                  else ctx.arg_str(2))
    ctx.log(f"{ctx.name}(cmd={target!r})")
    return _ok(ctx, 33)  # > 32 means success for ShellExecute


@stub("CreateRemoteThread", "CreateThread")
def _create_thread(ctx):
    ctx.set_category("process")
    ctx.log(f"{ctx.name}(start=0x{ctx.arg(3 if 'Remote' in ctx.name else 2):x})")
    return _ok(ctx, _handle(ctx))


@stub("OpenProcess")
def _open_process(ctx):
    ctx.set_category("process")
    ctx.log(f"OpenProcess(pid={ctx.arg(2)})")
    return _ok(ctx, _handle(ctx))


@stub("fork", "vfork")
def _fork(ctx):
    ctx.set_category("process")
    ctx.log(f"{ctx.name}() -> child")
    return _ok(ctx, _counter(ctx, "_next_pid", 0x4000, 1))


# -- memory --------------------------------------------------------------------

@stub("VirtualAlloc", "VirtualAllocEx")
def _virtual_alloc(ctx):
    ctx.set_category("memory")
    size_idx = 2 if ctx.name == "VirtualAllocEx" else 1
    prot_idx = 4 if ctx.name == "VirtualAllocEx" else 3
    size, prot = ctx.arg(size_idx), ctx.arg(prot_idx)
    addr = _alloc(ctx, size)
    ctx.log(f"{ctx.name}(size=0x{size:x}, prot=0x{prot:x}) -> 0x{addr:x}")
    return _ok(ctx, addr)


@stub("VirtualProtect", "VirtualProtectEx", "mprotect")
def _virtual_protect(ctx):
    ctx.set_category("memory")
    ctx.log(f"{ctx.name}(addr=0x{ctx.arg(0):x}, prot=0x{ctx.arg(2):x})")
    return _ok(ctx, 0 if ctx.name == "mprotect" else 1)


@stub("HeapAlloc", "LocalAlloc", "GlobalAlloc", "malloc", "calloc")
def _heap_alloc(ctx):
    ctx.set_category("memory")
    if ctx.name == "HeapAlloc":
        size = ctx.arg(2)
    elif ctx.name == "calloc":
        size = ctx.arg(0) * max(ctx.arg(1), 1)
    elif ctx.name in ("LocalAlloc", "GlobalAlloc"):
        size = ctx.arg(1)
    else:
        size = ctx.arg(0)
    addr = _alloc(ctx, size)
    ctx.log(f"{ctx.name}(size=0x{size:x}) -> 0x{addr:x}")
    return _ok(ctx, addr)


@stub("mmap")
def _mmap(ctx):
    ctx.set_category("memory")
    addr = _alloc(ctx, ctx.arg(1))
    ctx.log(f"mmap(len=0x{ctx.arg(1):x}, prot=0x{ctx.arg(2):x}) -> 0x{addr:x}")
    return _ok(ctx, addr)


@stub("WriteProcessMemory")
def _wpm(ctx):
    ctx.set_category("memory")
    ctx.log(f"WriteProcessMemory(dst=0x{ctx.arg(1):x}, len=0x{ctx.arg(3):x})")
    return _ok(ctx, 1)


@stub("free", "HeapFree", "VirtualFree", "munmap")
def _free(ctx):
    ctx.set_category("memory")
    ctx.log(f"{ctx.name}(addr=0x{ctx.arg(0):x})")
    return _ok(ctx, 0 if ctx.name == "munmap" else 1)


# -- library -------------------------------------------------------------------

@stub("LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
      "dlopen")
def _load_library(ctx):
    ctx.set_category("library")
    name = ctx.arg_wstr(0) if ctx.name.lower().endswith("w") else ctx.arg_str(0)
    ctx.log(f"{ctx.name}(lib={name!r}) -> hmodule")
    return _ok(ctx, _counter(ctx, "_next_module", 0x10000000, 0x10000))


@stub("GetProcAddress", "dlsym")
def _get_proc(ctx):
    ctx.set_category("library")
    proc = ctx.arg(1)
    # GetProcAddress's second arg may be an ordinal (low value) or a name ptr.
    name = ctx.read_str(proc) if proc > 0x10000 else f"#ordinal({proc})"
    ctx.log(f"{ctx.name}(proc={name!r}) -> addr")
    return _ok(ctx, _counter(ctx, "_next_proc", 0x20000000, 0x10))


@stub("GetModuleHandleA", "GetModuleHandleW")
def _get_module(ctx):
    ctx.set_category("library")
    name = ctx.arg_wstr(0) if ctx.name.lower().endswith("w") else ctx.arg_str(0)
    ctx.log(f"{ctx.name}(mod={name!r}) -> hmodule")
    return _ok(ctx, 0x10000000)


# -- system / anti-analysis ----------------------------------------------------

@stub("IsDebuggerPresent")
def _is_debugger(ctx):
    ctx.set_category("system")
    ctx.log("IsDebuggerPresent() -> 0")
    return _ok(ctx, 0)


@stub("GetTickCount", "GetTickCount64")
def _tick(ctx):
    ctx.set_category("system")
    t = _counter(ctx, "_tick", 0x1000, 0x10)
    ctx.log(f"{ctx.name}() -> {t}")
    return _ok(ctx, t)


@stub("GetCurrentProcessId", "getpid")
def _getpid(ctx):
    ctx.set_category("system")
    ctx.log(f"{ctx.name}() -> 0x1337")
    return _ok(ctx, 0x1337)


@stub("Sleep", "SleepEx", "nanosleep")
def _sleep(ctx):
    ctx.set_category("system")
    ctx.log(f"{ctx.name}(ms={ctx.arg(0)})")
    return _ok(ctx, 0)


# -- assembly ------------------------------------------------------------------

def build_default_registry() -> StubRegistry:
    """A :class:`StubRegistry` pre-loaded with the curated stub library.

    Names are registered for every spelling in :data:`STUBS` plus, for each
    entry, its bare form so analyst lookups by either the A/W-suffixed or the
    plain name succeed.
    """
    reg = StubRegistry()
    for name, fn in STUBS.items():
        reg.register(name, fn)
    return reg
