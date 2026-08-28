"""Frida-based DebuggerBridge implementation."""
from __future__ import annotations

import logging
from typing import Any

from memslicer.acquirer.bridge import (
    KeyHintEvent, MemoryRange, ModuleInfo, PlatformInfo,
    RegisterValue, ThreadInfo, register_role, register_width_bytes,
    vector_register_width,
)
from memslicer.acquirer.platform_detect import detect_platform


# Frida JS script for RPC exports
_FRIDA_SCRIPT = """\
// Resolve an export across Frida API generations (instance vs. legacy static).
function _resolveExport(mod, name) {
    try {
        var m = Process.findModuleByName(mod);
        if (m) {
            if (typeof m.findExportByName === 'function') {
                var p = m.findExportByName(name);
                if (p) return p;
            }
            if (typeof m.getExportByName === 'function') {
                try { return m.getExportByName(name); } catch (e) {}
            }
        }
    } catch (e) {}
    try {
        if (typeof Module.findExportByName === 'function') {
            var p2 = Module.findExportByName(mod, name);
            if (p2) return p2;
        }
    } catch (e) {}
    try {
        if (typeof Module.getExportByName === 'function') {
            return Module.getExportByName(mod, name);
        }
    } catch (e) {}
    return null;
}

// Build a per-thread TEB resolver on Windows. Frida's CpuContext carries no
// segment base, so the TEB/PEB and TLS anchor is otherwise lost; we recover it
// via NtQueryInformationThread(ThreadBasicInformation).TebBaseAddress. Returns
// null on non-Windows or when the needed exports are unavailable.
function _makeTebResolver() {
    if (Process.platform !== 'windows') return null;
    var pOpen = _resolveExport('kernel32.dll', 'OpenThread');
    var pQuery = _resolveExport('ntdll.dll', 'NtQueryInformationThread');
    var pClose = _resolveExport('kernel32.dll', 'CloseHandle');
    if (!pOpen || !pQuery || !pClose) return null;
    var OpenThread = new NativeFunction(pOpen, 'pointer', ['uint32', 'int', 'uint32']);
    var NtQueryInformationThread = new NativeFunction(
        pQuery, 'int', ['pointer', 'int', 'pointer', 'uint32', 'pointer']);
    var CloseHandle = new NativeFunction(pClose, 'int', ['pointer']);
    var THREAD_QUERY_INFORMATION = 0x0040;
    var ThreadBasicInformation = 0;
    var psize = Process.pointerSize;
    // THREAD_BASIC_INFORMATION: NTSTATUS ExitStatus; PVOID TebBaseAddress; ...
    // TebBaseAddress sits at offset == pointerSize (NTSTATUS padded to align).
    var bufLen = (psize === 8) ? 48 : 28;
    return function (tid) {
        var h = OpenThread(THREAD_QUERY_INFORMATION, 0, tid);
        if (h.isNull()) return null;
        try {
            var buf = Memory.alloc(bufLen);
            var status = NtQueryInformationThread(
                h, ThreadBasicInformation, buf, bufLen, NULL);
            if (status !== 0) return null;
            return buf.add(psize).readPointer();
        } finally {
            CloseHandle(h);
        }
    };
}

// Arm live hooks on Windows CNG key-derivation APIs. Each intercepted call
// records the ABSOLUTE address and byte length of the key material into an
// in-agent log; Python drains it synchronously via drainKeyHints() and maps
// each entry to a captured region + offset to record as a KeyHint block. A
// synchronous drain (rather than async send()) avoids any race between a
// derivation call and the moment the capture reads its collected hints. Hooks
// are installed on-demand (never by default) so the normal acquire path pays
// no interception cost.
var _keyHintLog = [];

function _installKeyHintHooks() {
    if (Process.platform !== 'windows') {
        return {armed: 0, errors: ['not-windows']};
    }
    var armed = 0;
    var errors = [];

    function emit(api, addrPtr, len) {
        try {
            if (!addrPtr || addrPtr.isNull()) return;
            _keyHintLog.push({api: api, addr: addrPtr.toString(), len: len >>> 0});
        } catch (e) {}
    }

    // BCryptGenerateSymmetricKey(hAlg, *phKey, pbKeyObject, cbKeyObject,
    //                            pbSecret, cbSecret, dwFlags)
    // pbSecret (arg 4) is the raw key material; cbSecret (arg 5) its length.
    // The secret is fully formed at call entry, so onEnter suffices.
    var pGen = _resolveExport('bcrypt.dll', 'BCryptGenerateSymmetricKey');
    if (pGen) {
        try {
            Interceptor.attach(pGen, {
                onEnter: function(args) {
                    emit('BCryptGenerateSymmetricKey', args[4], args[5].toInt32());
                }
            });
            armed++;
        } catch (e) { errors.push('BCryptGenerateSymmetricKey:' + e.message); }
    } else {
        errors.push('BCryptGenerateSymmetricKey:not-found');
    }

    // NCryptDeriveKey(hSharedSecret, pwszKDF, pParams, pbDerivedKey,
    //                 cbDerivedKey, *pcbResult, dwFlags)
    // The key is written to pbDerivedKey (arg 3) DURING the call, so read the
    // actual length from *pcbResult (arg 5) on a successful return.
    var pDerive = _resolveExport('ncrypt.dll', 'NCryptDeriveKey');
    if (pDerive) {
        try {
            Interceptor.attach(pDerive, {
                onEnter: function(args) {
                    this.pbDerivedKey = args[3];
                    this.cbDerivedKey = args[4].toInt32();
                    this.pcbResult = args[5];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) return;  // only successful calls
                    var len = this.cbDerivedKey;
                    try {
                        if (this.pcbResult && !this.pcbResult.isNull()) {
                            len = this.pcbResult.readU32();
                        }
                    } catch (e) {}
                    emit('NCryptDeriveKey', this.pbDerivedKey, len);
                }
            });
            armed++;
        } catch (e) { errors.push('NCryptDeriveKey:' + e.message); }
    } else {
        errors.push('NCryptDeriveKey:not-found');
    }

    return {armed: armed, errors: errors};
}

rpc.exports = {
    armKeyHintHooks: function() {
        return _installKeyHintHooks();
    },
    drainKeyHints: function() {
        var out = _keyHintLog;
        _keyHintLog = [];
        return out;
    },
    enumerateRanges: function(prot) {
        return Process.enumerateRanges(prot);
    },
    readMemory: function(addr, size) {
        try {
            return ptr(addr).readByteArray(size);
        } catch (e) {
            send({type: 'read-error', addr: addr, size: size, error: e.message, stack: e.stack || ''});
            return null;
        }
    },
    getPageSize: function() {
        return Process.pageSize;
    },
    enumerateModules: function() {
        return Process.enumerateModules();
    },
    enumerateThreads: function() {
        // Frida exposes CpuContext registers as NON-enumerable accessor
        // properties, so `for..in` / Object.keys yield nothing even though the
        // context is populated (read by name, e.g. raw.eip, works). Iterate an
        // explicit per-arch register-name list; keep a `for..in` pass as a
        // fallback for builds that DO expose them enumerably.
        var REG_NAMES = {
            ia32: ["pc","sp","eax","ecx","edx","ebx","esp","ebp","esi","edi","eip"],
            x64:  ["pc","sp","rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","rip",
                   "r8","r9","r10","r11","r12","r13","r14","r15"],
            arm:  ["pc","sp","lr","cpsr","r0","r1","r2","r3","r4","r5","r6","r7",
                   "r8","r9","r10","r11","r12"],
            arm64:["pc","sp","fp","lr","nzcv",
                   "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11",
                   "x12","x13","x14","x15","x16","x17","x18","x19","x20","x21",
                   "x22","x23","x24","x25","x26","x27","x28"]
        };
        var names = REG_NAMES[Process.arch] || [];
        // CpuContext exposes no segment base; recover the TEB on Windows and
        // surface it as gs_base (x64) / fs_base (ia32) so the emulator can seed
        // segment-relative (TEB/PEB, TLS) access.
        var tebResolver = _makeTebResolver();
        var segBaseReg = (Process.arch === 'x64') ? 'gs_base' : 'fs_base';
        return Process.enumerateThreads().map(function(t) {
            var ctx = {};
            var raw = t.context || {};
            // Primary: CpuContext serializes its registers via toJSON, which
            // for..in / Object.keys miss; JSON captures them all (any arch).
            try {
                var j = JSON.parse(JSON.stringify(raw));
                for (var jk in j) {
                    var jv = j[jk];
                    ctx[jk] = (jv && jv.toString) ? jv.toString() : String(jv);
                }
            } catch (e) {}
            // Fallback: explicit per-arch names by direct (by-name) access.
            for (var i = 0; i < names.length; i++) {
                var k = names[i];
                if (ctx[k] !== undefined) continue;
                var v = raw[k];
                if (v === undefined || v === null) continue;
                try { ctx[k] = v.toString(); } catch (e) { ctx[k] = String(v); }
            }
            if (tebResolver && ctx[segBaseReg] === undefined) {
                try {
                    var teb = tebResolver(t.id);
                    if (teb && !teb.isNull()) ctx[segBaseReg] = teb.toString();
                } catch (e) {}
            }
            return {id: t.id, state: t.state, context: ctx};
        });
    },
    getPlatform: function() {
        return Process.platform;
    },
    getArch: function() {
        return Process.arch;
    },
    getPid: function() {
        return Process.id;
    },
    validateApi: function() {
        var p = ptr(0);
        return {
            ptrType: typeof ptr,
            readByteArrayType: typeof p.readByteArray,
            pageSize: Process.pageSize
        };
    }
};
"""


def _parse_frida_addr(value: str | int) -> int:
    """Convert a Frida address (hex string or int) to int."""
    return int(value, 16) if isinstance(value, str) else value


def _ensure_bytes(data: Any) -> bytes:
    """Ensure data from Frida RPC is a bytes object."""
    return data if isinstance(data, bytes) else bytes(data)


class FridaBridge:
    """DebuggerBridge implementation using Frida."""

    def __init__(
        self,
        target: int | str,
        device: Any | None = None,
        read_timeout: float = 10.0,
        logger: logging.Logger | None = None,
        collect_key_hints: bool = False,
    ) -> None:
        self._target = target
        self._device = device
        self._read_timeout = read_timeout
        self._log = logger or logging.getLogger("memslicer")
        self._session: Any | None = None
        self._api: Any | None = None
        self._platform_info: PlatformInfo | None = None
        self._modules_cache: list[dict] | None = None
        self._collect_key_hints = collect_key_hints
        self._key_hint_events: list[KeyHintEvent] = []

    @property
    def is_remote(self) -> bool:
        """Whether this bridge is connected to a remote target."""
        if self._device is None:
            return False
        device_type = getattr(self._device, 'type', 'local')
        return device_type != 'local'

    def _on_message(self, message: dict, data: bytes | None) -> None:
        """Handle messages from the Frida JS agent."""
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict) and payload.get("type") == "read-error":
                self._log.warning(
                    "JS read-error at %s size=%s: %s",
                    payload.get("addr", "?"),
                    payload.get("size", "?"),
                    payload.get("error", "unknown"),
                )
                stack = payload.get("stack", "")
                if stack:
                    self._log.debug("  JS stack: %s", stack)
        elif message.get("type") == "error":
            self._log.error(
                "Frida script error: %s", message.get("description", message),
            )

    def _to_key_hint_event(self, entry: dict) -> KeyHintEvent | None:
        """Turn one drained JS key-hint entry into a :class:`KeyHintEvent`.

        A malformed/ambiguous address is logged and dropped rather than turned
        into a bogus hint — a false KeyHint pointing at the wrong address is
        worse than none, so anything we cannot parse cleanly is discarded.
        """
        if not isinstance(entry, dict):
            return None
        raw_addr = entry.get("addr")
        try:
            addr = _parse_frida_addr(raw_addr)
        except (TypeError, ValueError):
            self._log.warning(
                "Dropping key-hint with unparseable addr %r (api=%s)",
                raw_addr, entry.get("api", "?"),
            )
            return None
        if not addr:
            self._log.debug(
                "Dropping key-hint with null addr (api=%s)", entry.get("api", "?"),
            )
            return None
        length = entry.get("len", 0)
        try:
            length = int(length)
        except (TypeError, ValueError):
            length = 0
        api = entry.get("api", "")
        self._log.info(
            "KeyHint observed: %s key at 0x%x len=%d", api or "?", addr, length,
        )
        return KeyHintEvent(
            address=addr,
            length=length,
            api=api,
            algorithm=entry.get("algorithm", ""),
        )

    def connect(self) -> None:
        """Attach to target process and load the Frida agent script."""
        import frida as _frida

        if self._device is None:
            self._device = _frida.get_local_device()

        if isinstance(self._target, int):
            self._log.info("Attaching to PID %d...", self._target)
        else:
            self._log.info("Attaching to process '%s'...", self._target)

        session = self._device.attach(self._target)
        self._session = session

        self._log.info("Loading agent script...")
        script = session.create_script(_FRIDA_SCRIPT)
        script.on("message", self._on_message)
        script.load()
        self._api = script.exports_sync

        # Arm key-derivation hooks as early as possible (right after the agent
        # loads) so calls made during the whole capture window are caught.
        if self._collect_key_hints:
            try:
                result = self._api.arm_key_hint_hooks()
                armed = result.get("armed", 0) if isinstance(result, dict) else 0
                errors = result.get("errors", []) if isinstance(result, dict) else []
                self._log.info("KeyHint hooks armed: %d API(s)", armed)
                for err in errors:
                    self._log.debug("KeyHint hook note: %s", err)
                if armed == 0:
                    self._log.warning(
                        "KeyHint collection requested but no key-derivation API "
                        "could be hooked (%s) -- no KeyHint blocks will be "
                        "written for this capture.",
                        ", ".join(errors) or "no detail",
                    )
            except Exception as exc:  # noqa: BLE001
                self._log.warning("Failed to arm KeyHint hooks: %s", exc)

        # Validate API
        api_check = self._api.validate_api()
        self._log.debug(
            "API check: ptr=%s readByteArray=%s pageSize=%s",
            api_check.get("ptrType"),
            api_check.get("readByteArrayType"),
            api_check.get("pageSize"),
        )

        # Resolve PID if attached by name
        pid = self._target if isinstance(self._target, int) else self._api.get_pid()

        # Detect platform
        self._log.info("Querying platform info...")
        frida_arch = self._api.get_arch()
        frida_platform = self._api.get_platform()
        self._modules_cache = self._api.enumerate_modules()
        modules_dicts = [{"name": m["name"], "path": m["path"]} for m in self._modules_cache]

        os_type, arch_type = detect_platform(
            frida_arch, frida_platform, modules_dicts,
        )

        page_size = self._api.get_page_size()
        self._log.debug(
            "platform=%s arch=%s pid=%d page_size=%d",
            frida_platform, frida_arch, pid, page_size,
        )

        self._platform_info = PlatformInfo(
            arch=arch_type,
            os=os_type,
            pid=pid,
            page_size=page_size,
        )

    def get_platform_info(self) -> PlatformInfo:
        """Return cached platform info from connect()."""
        if self._platform_info is None:
            raise RuntimeError("FridaBridge.connect() must be called first")
        return self._platform_info

    def enumerate_ranges(self) -> list[MemoryRange]:
        """Enumerate all memory ranges via Frida RPC."""
        raw = self._api.enumerate_ranges("---")
        ranges: list[MemoryRange] = []
        for r in raw:
            file_info = r.get("file")
            file_path = file_info.get("path", "") if file_info else ""
            ranges.append(MemoryRange(
                base=_parse_frida_addr(r["base"]),
                size=r["size"],
                protection=r["protection"],
                file_path=file_path,
            ))
        return ranges

    def enumerate_modules(self) -> list[ModuleInfo]:
        """Return loaded modules (cached from connect() if available)."""
        raw = self._modules_cache if self._modules_cache is not None else self._api.enumerate_modules()
        return [
            ModuleInfo(
                name=m["name"],
                path=m["path"],
                base=_parse_frida_addr(m["base"]),
                size=m["size"],
            )
            for m in raw
        ]

    # Frida thread.state strings -> MSL ThreadState codes (spec Table 19a).
    _STATE_MAP = {
        "running": 1, "stopped": 3, "waiting": 4,
        "uninterruptible": 4, "halted": 3,
    }

    def enumerate_threads(self) -> list[ThreadInfo]:
        """Enumerate threads with register state via Frida RPC.

        Frida exposes both arch-specific names (``rip``/``rsp``) and the
        generic ``pc``/``sp`` aliases. On x86/x86_64 the generic aliases
        duplicate ``rip``/``rsp``/``eip``/``esp`` and are dropped; on
        AArch64 ``pc``/``sp`` ARE the canonical names and are kept.
        """
        try:
            raw = self._api.enumerate_threads()
        except Exception as exc:
            self._log.warning("Thread enumeration failed: %s", exc)
            return []

        arch = self._platform_info.arch if self._platform_info else None
        width = register_width_bytes(arch) if arch is not None else 8

        threads: list[ThreadInfo] = []
        for idx, t in enumerate(raw):
            ctx = t.get("context", {}) or {}
            names = set(ctx)
            drop_pc = bool(names & {"rip", "eip"})
            drop_sp = bool(names & {"rsp", "esp"})
            regs: list[RegisterValue] = []
            for name, val in ctx.items():
                if name == "pc" and drop_pc:
                    continue
                if name == "sp" and drop_sp:
                    continue
                try:
                    ival = _parse_frida_addr(val)
                except (TypeError, ValueError):
                    continue
                regs.append(RegisterValue(
                    name=name, value=ival,
                    size=vector_register_width(name) or width,
                    role=register_role(name),
                ))
            threads.append(ThreadInfo(
                tid=t.get("id", 0),
                registers=regs,
                is_current=(idx == 0),
                state=self._STATE_MAP.get(t.get("state", ""), 0),
            ))
        return threads

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Read memory via Frida RPC. Returns None on failure."""
        try:
            data = self._api.read_memory(hex(address), size)
            if data is None:
                return None
            return _ensure_bytes(data)
        except Exception as e:
            self._log.debug(
                "Read exception at 0x%x size=%d: %s", address, size, e,
            )
            return None

    def collect_key_hints(self) -> list[KeyHintEvent]:
        """Drain and return key-derivation events observed since ``connect()``.

        Pulls the agent's in-target log synchronously (no async-message race),
        so this returns whatever the target derived during the capture window.
        Empty when key-hint collection was not requested, the agent is gone, or
        the target derived no keys while attached.
        """
        if not self._collect_key_hints or self._api is None:
            return list(self._key_hint_events)
        try:
            raw = self._api.drain_key_hints()
        except Exception as exc:  # noqa: BLE001
            self._log.warning("drainKeyHints failed: %s", exc)
            return list(self._key_hint_events)
        for entry in raw or []:
            ev = self._to_key_hint_event(entry)
            if ev is not None:
                self._key_hint_events.append(ev)
        return list(self._key_hint_events)

    def disconnect(self) -> None:
        """Detach the Frida session."""
        session = self._session
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
            self._session = None
