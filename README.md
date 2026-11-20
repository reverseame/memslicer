# MemSlicer

[![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.2.7-green)](pyproject.toml)

A memory acquisition tool that captures process memory snapshots into the MSL (Memory Slice) binary format. Supports multiple debugger backends (Frida, GDB, LLDB) and targets across Windows, Linux, macOS, Android, and iOS. Designed for forensic analysis, reverse engineering, and security research.

---

## Features

- **Pluggable backends**: Frida (local, USB, remote), GDB (MI3 protocol), LLDB (Python API)
- **Investigation mode**: Captures system-wide context — process tables, network connections, file handles, boot time, OS details
- **AEAD encryption**: AES-256-GCM with Argon2id key derivation (default in investigation mode)
- MSL binary format with region metadata, module info, and page-level granularity
- Compression support: zstd, lz4, or none
- BLAKE3 integrity chain across all blocks
- Region filtering by memory protection, address range, or path patterns
- Page-level acquisition with quality assessment
- RWX region detection for forensic analysis
- Progress reporting with per-region and per-page statistics
- Companion log file captures all debug output regardless of verbosity flag
- Cross-platform OS information collection for forensic context

**Analyzing slices** (see [Emulating & analyzing slices](#emulating--analyzing-slices)):

- **Emulator** (`memslicer-emu`, Unicorn + Capstone): single-step and **reverse execution**, multi-arch
- **Per-thread emulation**: list captured threads and seed from any of them
- **Vector/FP registers** (XMM/YMM) seeded at full width for SIMD/crypto code
- **fs/gs base & Windows TEB/PEB** resolution for TLS / PEB-relative accesses
- **Self-modifying-code / unpacking** detection — flags write-then-execute and dumps the recovered payload
- **Symbolic execution** (angr) and a **behavior graph** (control flow + syscalls/APIs)
- **radare2 plugins** to open, inspect (maps, symbols, PE exports) and emulated-debug a slice

---

## Installation



```bash
pip install memslicer
```

This installs memslicer with all backends (Frida, GDB, LLDB).

### From Source

```bash
git clone git@github.com:MemorySlice/memslicer.git
cd memslicer
pip install -e .
```

Requires Python >= 3.10. Backend-specific requirements:
- **Frida**: A compatible Frida agent on the target device (for USB/remote targets)
- **GDB**: `gdb` binary with MI3 support (installed separately)
- **LLDB**: LLDB Python module on `PYTHONPATH` (typically via Xcode on macOS)

---

## Usage

### Basic Examples

Dump a process by name (Frida backend, default):

```bash
memslicer chrome
```

Dump a process by PID:

```bash
memslicer 1234
```

Specify output file and compression:

```bash
memslicer chrome -o chrome_dump.msl -c zstd
```

### Linux

Dump a local process using Frida (default backend):

```bash
memslicer 1234
```

Use GDB backend (no Frida dependency required):

```bash
memslicer 1234 -b gdb
```

Investigation mode with full system context (encrypted by default):

```bash
memslicer 1234 -I -v
```

This captures process tables, network connections, file handles, boot time, hostname, and OS details from `/proc` alongside the memory dump. The output is encrypted with AES-256-GCM; you will be prompted for a passphrase.

Investigation mode without encryption:

```bash
memslicer 1234 -I --no-encrypt
```

### Android

Dump a process on a USB-connected Android device (requires Frida server on device):

```bash
memslicer com.example.app -U
```

Override OS detection if auto-detection fails:

```bash
memslicer com.example.app -U --os android
```

Investigation mode on Android (captures system properties, process table, network state):

```bash
memslicer com.example.app -U -I
```

Connect to a remote Frida server on Android (e.g., over Wi-Fi):

```bash
memslicer com.example.app -R 192.168.1.10:27042 --os android
```

Dump by PID on a USB Android device:

```bash
memslicer 12345 -U --os android -o app_dump.msl -c zstd
```

### macOS / iOS

Use LLDB backend on macOS (no Frida needed):

```bash
memslicer 1234 -b lldb
```

Dump a process on a USB-connected iOS device (jailbroken, Frida):

```bash
memslicer SpringBoard -U --os ios -I
```

### Windows

Dump a local process on Windows:

```bash
memslicer 1234 -b gdb
```

Or with Frida:

```bash
memslicer notepad.exe
```

### Common Workflows

**Forensic capture with full debug log:**

```bash
memslicer 4892 -v -o evidence.msl -c zstd
```

**Investigation mode with encryption (default):**

```bash
memslicer 4892 -I -o investigation.msl
```

**Capture only readable and writable regions:**

```bash
memslicer chrome --filter-prot rw-
```

**Capture a specific address range:**

```bash
memslicer chrome --filter-addr 0x7fff00000000-0x7fffffffffff
```

**Include regions without read permission (for completeness):**

```bash
memslicer chrome --include-unreadable
```

**Limit region size and set a per-read timeout:**

```bash
memslicer chrome --max-region-size 104857600 --read-timeout 30
```

---

## CLI Reference

```
Usage: memslicer [OPTIONS] TARGET

  Dump process memory to MSL format.

  TARGET is a PID (integer) or process name (string).

  Supports 4 acquisition modes:
    Analysis unencrypted (default), Analysis encrypted (-E),
    Investigation encrypted (-I, default), Investigation unencrypted (-I --no-encrypt).

Options:
  -b, --backend [frida|gdb|lldb]  Debugger backend to use
  -o, --output TEXT               Output .msl file path
  -c, --compress [none|zstd|lz4]  Compression algorithm
  -U, --usb                       Connect to USB device (Frida backend only)
  -R, --remote TEXT               Remote server host:port (Frida: frida-
                                  server, GDB: gdbserver, LLDB: lldb-server)
  --os [windows|linux|macos|android|ios]
                                  Override OS detection
  --filter-prot TEXT              Protection filter (e.g., 'r--', 'rw-')
  --filter-addr TEXT              Address range filter (e.g., '0x1000-0x2000')
  -v, --verbose                   Enable verbose/debug output
  --read-timeout FLOAT            Per-read timeout in seconds (default: 10)
  --include-unreadable            Include regions with no read permission
  --max-region-size INTEGER       Skip regions larger than this size (0 = no
                                  limit)
  -I, --investigation             Investigation mode: capture system-wide
                                  context (encrypted by default)
  -E, --encrypt                   Enable AEAD encryption
  --no-encrypt                    Disable encryption (overrides investigation
                                  default)
  --passphrase TEXT               Encryption passphrase (prompted if --encrypt
                                  and not provided)
  --hash-algo [blake3|sha256|sha512-256]
                                  Integrity hash algorithm (default: blake3)
  --no-registers                  Do not capture thread register state (Thread
                                  Context blocks)
  --key-hints                     Hook Windows CNG key-derivation APIs
                                  (BCryptGenerateSymmetricKey,
                                  NCryptDeriveKey) during capture and record
                                  where derived key material lives as KeyHint
                                  blocks (Frida backend only)
  --examiner, --operator TEXT     Examiner / operator name for
                                  SystemContext.acq_user (defaults to
                                  getpass.getuser())
  --case-ref, --case-id, --case-number TEXT
                                  Case / evidence reference for
                                  SystemContext.case_ref
  --hostname-override TEXT        Override collected hostname (use when remote
                                  collector is blind)
  --domain-override TEXT          Override collected domain
  --include-serials               Emit hardware serials / machine-id in
                                  os_detail (privacy-sensitive)
  --include-network-identity      Emit NIC MAC addresses in os_detail
                                  (privacy-sensitive)
  --include-fingerprint           Emit ro.build.fingerprint in os_detail
                                  (Android; leaks device+region+carrier+build-
                                  date)
  --include-kernel-modules / --no-include-kernel-modules
                                  Emit the KernelModuleList block enumerating
                                  loaded kernel modules from /proc/modules and
                                  /sys/module (default: off, memslicer is
                                  process-centric)
  --include-kernel-symbols / --no-include-kernel-symbols
                                  Emit kernel symbolication anchors in
                                  os_detail and the KernelSymbolBundle block
                                  (page_size, build_id, KASLR base, BTF hash,
                                  clocks; default: off, memslicer is process-
                                  centric)
  --include-module-build-ids / --no-include-module-build-ids
                                  Live build-id extraction: read the first 4
                                  KiB of each loaded module through the
                                  debugger bridge and populate ModuleEntry
                                  build-ids and per-module disk hashes
                                  (default: off). The retroactive
                                  ModuleBuildIdManifest overlay block is
                                  produced separately by memslicer-enrich.
  --include-target-introspection / --no-include-target-introspection
                                  Collect per-target process introspection
                                  (TracerPid, loginuid, SELinux context,
                                  smaps, cgroup, ancestry, etc.) and emit the
                                  TargetIntrospection block (default: off)
  --include-environ               Emit /proc/<pid>/environ in
                                  TargetIntrospection (may leak credentials;
                                  default: off)
  --include-persistence-manifest  Emit the PersistenceManifest block listing
                                  systemd units, cron entries, and other
                                  persistence paths (names+mtime+size only; no
                                  content). May leak application inventory;
                                  default: off.
  --help                          Show this message and exit.
```

---


## Behavior Analysis & Graph Extraction (`memslicer-behavior`)

MemSlicer includes a behavior graph engine that reconstructs execution traces, control flow, syscalls, and Windows API calls from MSL memory snapshots into Dynamic Control-Flow Graphs (DFCG).

### Usage

```bash
# Extract basic-block CFG in IDA Pro disassembly style
memslicer-behavior dump.msl --stublib -g block -o graph.dot
memslicer-behavior dump.msl --stublib -o graph.json

# Extract high-level function call graph
memslicer-behavior dump.msl --stublib -g function -o callgraph.json

# Pass an input argument (e.g., password string in RCX)
memslicer-behavior dump.msl --arg0 "S3cr3tKey!" -g block -o graph.dot
```

### Key Features & Options

- **`-g, --granularity [block|instruction|function]`**:
  - `block` (default): Basic-block level Control Flow Graph (CFG).
  - `instruction`: Single-step instruction execution trace.
  - `function`: High-level **Call Graph** summarizing function-to-function calls and API interactions (collapses thousands of basic blocks for analyzing massive binaries without clutter).
- **`--style [ida|basic]`**:
  - `ida` (default): Renders IDA Pro / Binary Ninja style disassembly tables with memory addresses, hex opcodes, assembly mnemonics, and resolved symbol comments.
  - `basic`: Simple node boxes for basic DOT renderers.
- **`--arg0, --rcx TEXT`**: Pass an input string or memory argument in `RCX` register for analyzing functions that expect arguments.
- **`--start ADDR`**: Override the start address (default: the captured PC).
- **`-n, --max-steps N`**: Cap on emulated instructions (default `100000`).
- **`-f, --format [json|dot|graphml|gexf]`**: Output format (otherwise inferred from the `-o` extension).
- **`--premap-stack / --no-premap-stack`** (default on): a slice only captures a few pages around the
  captured stack pointer, so deeper frames used to stop the trace with `UC_ERR_*_UNMAPPED`. The emulator
  now backs a 64 MB window around SP with blank RW pages. Because that turns a loud fault into a quiet
  zero, every read of such invented memory is tracked and reported (`graph.meta['synthetic_stack_reads']`
  and in the run summary). Use `--no-premap-stack` to get the old fail-loud behaviour.
- **Sub-Graph Module Clustering (`subgraph cluster_*`)**: Automatically groups basic blocks and API call nodes by their owning module (`notepad.exe`, `USER32.dll`, `win32u.dll`, etc.) inside dashed bounding boxes.
- **Color-Coded Branching**:
  - **Green (`#2e7d32`)**: Conditional branch taken (`jump_true`).
  - **Red (`#c62828`)**: Conditional branch not taken / fallthrough (`jump_false`).
  - **Dashed Gray**: API and Syscall invocations.
  - **Dashed Orange**: Dataflow / buffer pointer relationships.

### Interactive Web Viewer (`tools/graph_viewer.html`)

Open [`tools/graph_viewer.html`](tools/graph_viewer.html) in any web browser (`file://` supported) and drag & drop your generated `graph.json` file. It renders an interactive 2D D3.js visualization with HTML5 disassembly cards, color-coded branching, search, and filtering options.

## Symbolic Execution & Analysis (`memslicer-symbex`)

`MemSlicerRev` integrates an advanced symbolic execution bridge powered by `angr` to explore execution paths, deobfuscate memory, and solve path constraints directly from `.msl` snapshot files.

### CLI Usage

```powershell
python -m memslicer.cli_symbex <dump.msl> --find <TARGET_ADDR> --avoid <FAIL_ADDR> [OPTIONS]
```

#### Available Options:
- `-f, --find ADDR` / `-a, --avoid ADDR`: Address(es) to reach / bypass (repeatable, hex or decimal).
- `-m, --avoid-module NAME|LO-HI`: Avoid every address inside a module (by name) or an address range (repeatable).
- `-s, --steps N`: Step forward N symbolic steps when no `--find` target is given (prints live progress).
- `-r, --find-rax-success`: Look for paths where the function returns `RAX == 1`. Only meaningful for
  license/key-check style targets; on generic real-world code almost any function can return 1, so prefer `--find`.
- `-e, --entry ADDR`: Override the start PC (useful when the slice was captured parked in `Sleep`/`fgets`).
- `-c, --call-function ADDR`: Build a clean call state for the function at `ADDR`, passing the symbolic buffer as its first argument.
- `-k, --sym-bytes N`: Size of the injected symbolic buffer (default `16`).
- `-b, --binary-key`: Unconstrained raw bytes instead of printable ASCII (`0x20`-`0x7E`).
- `--buffer-addr ADDR`: Explicit address for the symbolic buffer (otherwise a `RBP-0x40` / `RSP+0x20` heuristic is used).
- `--use-key-hints`: Place the symbolic buffer at a live-captured KeyHint (see below) and adopt its key length as `--sym-bytes`. An explicit `--buffer-addr` still wins.
- `-v, --veritesting`: Hybrid static/dynamic symbolic execution (Veritesting) to merge states and limit path explosion in loops.
- `--bypass-anti-analysis`: Hook common anti-debug APIs and mask PEB debug flags (see feature 3).
- `-u / --no-auto-map-unmapped` (default on): Automatically map unmapped pages and stub missing code/APIs (see feature 4).

---

### 🔍 Key Features

#### 1. Automatic Constraint Provenance & Pointer Mapping
The CLI automatically inspects SMT solver constraints upon reaching target addresses and classifies input vectors by source:
- **CPU Registers**: Formatted in canonical 64/32-bit hexadecimal notation (`0x...`).
- **RAM Memory & Pointer Linkage**: Automatically maps CPU pointers to resolved memory buffers (e.g., `RCX (0xc000000000000000) ---> Points to text: 'S3cr3tKey!'`).
- **Memory Region Classification**: Categorizes virtual addresses (Stack, Heap, Executable Image, or Symbolic Virtual Memory).
- **Multi-Channel Classification**: Symbolic inputs are grouped by the name of their symbolic variable (STDIN, files, sockets, `argv`, environment). This only applies when those inputs are actually symbolic in the state; a slice loaded from a real dump normally only has the injected buffer.

#### 2. Anti-State Explosion (Veritesting)
Reduces $2^N$ exponential path branching by collapsing intermediate conditional decision diamonds (`if-else`) into unified boolean expressions inside the Z3 solver pool.

#### 3. Anti-Analysis & Anti-Debugging Bypass Module (`memslicer.symbex.anti_analysis`)
Includes dedicated SimProcedure stubs and PEB sanitization to bypass evasion checks in malware:
- **API Stubs**: Intercepts `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, and `NtQueryInformationProcess` (`ProcessDebugPort`, `ProcessDebugFlags`).
- **PEB Masking**: Sanitizes `BeingDebugged` (`0`) and `NtGlobalFlag` (`0`) in process memory.
- **Works on real multi-module dumps**: angr only loads the region holding the captured PC as a real CLE
  object, so other DLLs have no symbol table. When symbol hooking finds nothing, the APIs are resolved by
  parsing each module's PE export table directly from captured memory (forwarders are skipped) and hooked
  by address. Use it from the CLI with `--bypass-anti-analysis`.

```python
from memslicer.symbex.angr_loader import load_angr
from memslicer.symbex.anti_analysis import apply_anti_analysis_bypass

# Load MSL slice and apply anti-debugging bypass
project, state = load_angr("snapshot.msl")
apply_anti_analysis_bypass(project, state)

# Explore symbolically
simgr = project.factory.simgr(state, veritesting=True)
simgr.explore(find=0x14000175e, avoid=0x140001765)
```

#### 4. Unmapped Memory Recovery & Syscall Handling (`unmapped_handler`, `syscall_handler`)
A slice only contains what was captured, so symbolic paths regularly touch memory or code that is not in it.
With auto-mapping on (the default), the stack is pre-mapped around SP, missing data pages are mapped on demand,
and calls into missing code get a generic return stub. Recovery only applies to genuinely new (synthetic)
memory, never to already-loaded code that is simply revisited. Direct `syscall`/`sysenter`/`int 0x2e`/`svc`
instructions are resolved per OS/arch (Windows NT and Linux tables) and a state that errored on a syscall is
repaired by skipping the instruction. Syscalls have **no real side effects**.

#### 5. Live KeyHints (capture → symbex)
`memslicer <pid> --backend frida --key-hints` hooks the Windows CNG key-derivation APIs
(`BCryptGenerateSymmetricKey`, `NCryptDeriveKey`) during the capture and records where the derived key
material lives as `KeyHint` blocks (region + offset + length). `memslicer-symbex --use-key-hints` then injects
the symbolic buffer exactly there instead of guessing:

```bash
memslicer 1234 --backend frida --os windows --key-hints -o target.msl
memslicer-symbex target.msl --use-key-hints --steps 50
#   [+] Using KeyHint at 0x7ff7bebf4020, key_len=32 -> --sym-bytes 32 (BCryptGenerateSymmetricKey)
```

Only keys derived **while the capture is running** are caught (hooks are armed at attach time); a one-shot
derivation that happens before or after the capture window produces no hint.

#### Limitations
Useful for targeted symbolic extraction of comparison-based logic and common Windows x64 anti-debug bypass.
It does **not** unpack, defeat anti-VM checks, model real syscall effects or follow other processes.

---

## Output Format

MemSlicer writes memory snapshots to the MSL (Memory Slice) binary format. Each file contains:

- A file header with format version, target metadata, and capture timestamp
- Process identity block (ppid, session ID, start time, executable path, command line)
- Module list with base addresses, sizes, and paths
- Per-region records with base address, size, protection flags, and page-level data
- BLAKE3 integrity chain across all blocks
- Optional compressed data blocks (zstd or lz4)
- Optional AEAD encryption (AES-256-GCM + Argon2id)

When **investigation mode** (`-I`) is enabled, the MSL file additionally contains:
- System context: boot time, hostname, domain, OS detail string
- System-wide process table (all running processes)
- Network connection table (TCP/UDP, IPv4/IPv6)
- File handle table (open file descriptors for the target process)

A companion `.log` file is written alongside every `.msl` file and contains the full debug output of the capture session, regardless of whether `-v` was passed.

### Example Output Summary

```
MemSlicer - Dumping chrome -> chrome_1773528836.msl
Backend: frida | Compression: none | Device: local
Progress: [##################################################] 100.00% Complete
  Regions : 2621/4199 (1578 filtered out)
            1578 no read permission (use --include-unreadable to include)
  Pages   : 12,500/12,800 captured (97.7%)
  Bytes   : 51,200,000 / 52,428,800 readable (97.7%)
  Modules : 142
  Duration: 12.34s
  File    : chrome_1773528836.msl (48,234,567 bytes)
  Log     : chrome_1773528836.msl.log
  Quality : GOOD (page-level: 97.7%)
```

---

## Emulating & analyzing slices

When a slice captures thread registers (the default; disable with
`--no-registers`), its execution can be *advanced by emulation* — a slice is a
static snapshot, so there is no live process to step.

### Built-in emulator (`memslicer-emu`)

A first-party emulator built on [Unicorn](https://www.unicorn-engine.org/) +
[Capstone](https://www.capstone-engine.org/). Install the extra and step:

```bash
pip install memslicer[emu]

memslicer-emu dump.msl --steps 5 -r
#   arch    : x86_64
#   entry   : 0x401000
#   0x00401000  mov rax, 1    [rax=0x1 rip=0x401007]
#   0x00401007  mov rbx, 2    [rbx=0x2 rip=0x40100e]
#   ...
```

Other useful options: `--pc ADDR` overrides the start PC, `--max-steps N` caps `--until`, `-r/--registers`
dumps registers after stepping, and `--unwind-depth N` bounds the stack scan of `--resume-from-syscall`.

It is also usable as a library for programmatic / differential analysis:

```python
from memslicer.emu import open_slice
emu = open_slice("dump.msl")        # registers seeded from the Thread Context
emu.step()
print(hex(emu.read_reg("rax")))
print(hex(emu.read_reg("xmm0")))    # vector/FP registers (XMM/YMM) too
emu.step_back()                     # reverse execution (undo the last step)
```

Captured **vector/FP registers** (XMM/YMM/...) are seeded at full width when the
slice carries them, so SIMD/crypto code emulates from the real CPU state.

It also supports **reverse execution** (`emu.step_back()`, or `--back N` on the
CLI): a CPU-context snapshot plus a memory-write journal per step lets it undo
instructions, reverting both registers and memory.

**Self-modifying code / unpacking.** The emulator tracks every byte the code
writes and flags when execution enters previously-written memory — the moment a
packer jumps into its decoded payload. Recover that payload to disk:

```bash
memslicer-emu packed.msl -u 0x401000 --dump-written ./unpacked
#   [self-modifying code: 1 write-then-execute site(s)]
#     W->X @ 0x000000401020
#   [wrote 1 dirtied range(s) to ./unpacked]
#     0x000000401020-0x000000402000  0xfe0 bytes (executed)  -> ./unpacked/written_0x401020_0x402000.bin
```

```python
emu.step_until(0x401000)
emu.self_modified_exec()    # [0x401020] — addresses run from written memory
emu.written_ranges()        # coalesced dirtied byte ranges
emu.dump_written("out/")    # write each range out (executed ones = the payload)
```

**Parked in a syscall.** A process is often captured blocked in a library/kernel
call (a `Sleep`, a wait, a `recv`), so the captured PC sits in `ntdll`/`kernel`
and stepping forward would hit a syscall the emulator can't service. Unwind back
to your own code with `--resume-from-syscall` (`-R`): it scans the stack for the
caller's return address into the program image and continues there as if the
call had returned.

```bash
memslicer-emu parked.msl -R --until 0xb1070 -r
#   [resume-from-syscall] pc = 0x7c90e514  (ntdll.dll+0x...)
#     caller return @ 0xb3275  (sample.exe)  [stack 0x..., depth 3]
#     resumed: pc -> 0xb3275, esp -> 0x...
```

For a stdcall API that cleans up its own arguments (e.g. `Sleep`'s `ret 4`), add
`--pop-bytes N` so the caller's stack is left balanced. Override the auto-detected
image with `--image-range LO:HI`. As a library:

```python
emu.in_system_call()        # True — PC is outside the program image
frame = emu.resume_from_syscall(pop_bytes=4)   # find caller, reposition pc/sp
emu.pc == frame.return_addr  # now back in the image; keep stepping
```

A slice can capture **more than one thread** (one Thread Context block each).
By default the emulator seeds from the Current thread, but any captured thread
can be selected:

```bash
memslicer-emu dump.msl --list-threads   # list captured threads (Current = '*')
memslicer-emu dump.msl --thread 200 -s 5 -r   # emulate thread tid=200 instead
```

```python
emu = open_slice("dump.msl", thread=200)   # seed from tid 200
emu.switch_thread(100)                      # re-seed from another thread later
```

**Segment bases & Windows TEB/PEB.** Captured `fs_base` / `gs_base` are seeded,
so TEB/PEB- and TLS-relative accesses (`gs:[...]` on x64, `fs:[...]` on x86)
resolve during emulation:

```python
emu.segment_base("gs")      # captured GS base (TEB on Windows x64)
emu.peb_address()           # follow gs:[0x60] / fs:[0x30] to the Windows PEB
```

On Windows the Frida backend recovers each thread's TEB (via
`NtQueryInformationThread`) and records it as `gs_base` (x64) / `fs_base` (x86),
since the CPU context alone carries no segment base. On x86 the emulator installs
a synthetic GDT for the captured base (32-bit `FS`/`GS` can't be set as a
register), so SEH prologues that read `fs:[0]` emulate correctly.

**Stack beyond the captured window.** A slice only captures a few pages around the stack pointer, so
deeper frames used to end emulation with `UC_ERR_*_UNMAPPED`. The emulator now pre-maps a 64 MB blank RW
window around the captured SP (`open_slice(..., premap_stack_mb=64)`, `0` disables it). Reads of that
invented memory are tracked so they are never mistaken for captured data:

```python
emu.synthetic_ranges()        # pre-mapped [lo, hi) windows
emu.is_synthetic(addr)        # True if addr was invented, not captured or written
emu.synthetic_read_count()    # reads of invented zeros (also in behavior graph meta)
```

### Symbolic execution (angr)

Load a slice into [angr](https://angr.io) for symbolic execution from the exact
captured point — the memory and a thread's registers become an angr `SimState`
(the Current thread by default; `load_angr(..., thread=tid)` selects another):

```bash
pip install memslicer[symbex]
memslicer-symbex dump.msl --find 0x401050 --avoid 0x401080
```

```python
from memslicer.symbex import load_angr
project, state = load_angr("dump.msl")     # state at the captured PC
simgr = project.factory.simgr(state)
simgr.explore(find=0x401050)
```

### Behavior graph (`memslicer-behavior`)

Emulate a slice and extract a **behavior graph** — control flow (basic blocks
or instructions) plus the system interactions (syscalls / APIs) the code
performs — for graph-based dynamic analysis:

```bash
pip install memslicer[emu]

# 1. discover which system calls the code makes
memslicer-behavior dump.msl --emit-stubs stubs.py -o graph.dot

# 2. edit stubs.py so each call returns what your investigation needs,
#    then re-run with the edited stubs
memslicer-behavior dump.msl --stubs stubs.py -o graph.json
```

A static snapshot has no OS, so system calls cannot be truly executed. Each one
is modelled by an analyst-editable **stub** (the Speakeasy/Qiling approach): the
first run auto-generates a skeleton (one function per observed call, pre-filled
with the observed arguments); you fill in the bodies to return handles, buffers
or errors and `--stubs` reloads them so emulation advances down the path of
interest. Output is JSON (node-link) or Graphviz DOT; granularity switches
between basic blocks and instructions with `--granularity`.

**API calls** are handled the same way: when a call lands on a module's export
it is resolved to `module!Export`, intercepted, routed to the same stub registry
(Win64/SysV calling conventions), recorded as a behavior node and returned to
the caller — so the API body is never emulated. Both **PE exports** (Windows)
and **ELF `.dynsym` / PLT-GOT imports** (Linux) are resolved; the latter uses
the captured process's already-bound GOT, so `call func@plt` resolves to the
owning library's `lib!symbol`. Other addresses are labelled `module+offset`, and
syscalls are named from per-architecture Linux tables.

**Bundled stub library.** Instead of writing stubs by hand you can start from a
curated, categorized library covering the APIs malware most often touches
(file / network / registry / process / memory / library / crypto / system).
Each stub decodes its interesting arguments, logs them readably, and returns a
plausible value (a fresh handle, an allocation address, success) so emulation
keeps advancing. `--stublib` enables it; `--stubs` merges your edits on top:

```bash
memslicer-behavior dump.msl --stublib -o graph.json              # bundled stubs
memslicer-behavior dump.msl --stublib --stubs mine.py -o g.json  # + overrides
```

Every syscall / API node carries a **behavior category**, so the graph groups
by what the code *does*, not just which symbol it called.

**Data-flow edges.** A lightweight value-equality taint links calls causally:
a `dataflow` edge when one call's return value is later passed as an argument
(the handle `CreateFile` returns, consumed by `WriteFile`; the address
`VirtualAlloc` returns, written by `WriteProcessMemory`), and a `buffer` edge
when two calls share the same pointer/handle argument (`ReadFile` fills a
buffer, `send` ships it). Both run automatically for either backend.

**Memory annotations** (`--memory`, on by default). Writes into executable
memory — unpacking, self-modifying code, code injection — are flagged (the
writing block is highlighted), every write is bucketed by its target region
type (heap / stack / image / …), and statically-RWX regions are listed under
`meta.memory`.

**Dynamic call graph** (`--call-graph`). Overlays function nodes and
`call`/`ret` edges (a shadow call stack tracks the current function) on top of
the basic-block CFG.

**High-fidelity Windows emulation (Speakeasy).** For Windows, `--backend
speakeasy` drives [Speakeasy](https://github.com/mandiant/speakeasy) — built on
the same Unicorn engine but shipping hundreds of real API handlers plus
PEB/TEB, the object manager and a fake filesystem/registry/network — and
projects its emulation onto the same behavior graph. Your `--stublib`/`--stubs`
stubs still override individual handlers when you want to steer a path:

```bash
pip install 'memslicer[speakeasy]'   # git head; the PyPI release pins unicorn 1.x
memslicer-behavior dump.msl --backend speakeasy -o graph.json
```

**Export & features.** The graph serializes to JSON, Graphviz DOT, **GraphML**
and **GEXF** (`-f`, or inferred from the `.json`/`.dot`/`.graphml`/`.gexf`
extension; the XML formats need no extra dependency). `--features` writes a
fixed-key numeric **feature vector** (node/edge counts by kind/type, calls per
category, memory and data-flow tallies) ready to stack into an ML matrix.
`BehaviorGraph.to_networkx()` returns a live `MultiDiGraph` with the optional
`graph` extra.

For deeper analysis you can also hand a *live* emulator off to angr
(concrete → symbolic) and let angr's SimOS model the OS from that point on:

```python
from memslicer.emu import open_slice
from memslicer.symbex import handoff_to_angr
emu = open_slice("dump.msl")
for _ in range(20):
    emu.step()                       # run concretely to a point of interest
project, state = handoff_to_angr(emu)  # continue symbolically from here
simgr = project.factory.simgr(state)
```

```python
from memslicer.behavior import trace_slice
graph = trace_slice("dump.msl")            # registers seeded, hooks installed
print(graph.meta, len(graph.nodes), graph.events)
open("graph.dot", "w").write(graph.to_dot())
```

### radare2 plugins

A slice can also be opened in [radare2](https://github.com/radareorg/radare2)
via the `io.msl` / `bin.msl` / `debug.msl` / `core.msl` plugins:

```bash
r2 dump.msl                          # static analysis: maps, arch, entrypoint
r2 -qc 'il; is' dump.msl             # modules (libraries) and symbols / PE exports
r2 -D msl -d msl://dump.msl          # emulated debugging: ds / dr step via ESIL
#   > dpt        list captured threads     > dpt=<tid>   switch the seeded thread
```

The plugins live in [radareorg/radare2-extras](https://github.com/radareorg/radare2-extras)
under `msl/` (see its `README.md`). `bin.msl` exposes captured modules as
libraries and symbols, including PE export tables so call targets are named;
`debug.msl` lists/selects threads (`dpt`). The `msl://` io plugin decodes lz4
slices; zstd slices are not decodable by radare2 (no zstd) — use `-c lz4`/
`-c none` or `memslicer-emu`. Encrypted slices are not supported by the
plugins. `memslicer-emu` handles both zstd and lz4.

---

## Architecture

```
src/memslicer/
  cli.py                         CLI entry point (click)
  acquirer/
    engine.py                    Backend-agnostic acquisition engine
    bridge.py                    DebuggerBridge protocol definition
    frida_bridge.py              Frida backend
    gdb_bridge.py                GDB/MI3 backend
    lldb_bridge.py               LLDB Python API backend
    frida_acquirer.py            Backward-compatible Frida wrapper
    investigation.py             InvestigationCollector protocol
    platform_detect.py           OS and architecture detection
    region_filter.py             Region filtering logic
    collectors/
      __init__.py                Factory: create_collector()
      linux.py                   Linux collector (/proc)
      android.py                 Android collector (SELinux-aware + system properties)
      darwin.py                  macOS collector (sysctl, ps, lsof)
      ios.py                     iOS collector (sandbox-aware, SystemVersion.plist)
      windows.py                 Windows collector (wmic, tasklist, netstat)
      frida_remote.py            Remote collector via Frida JS RPC
      fallback.py                NullCollector for unsupported platforms
      constants.py               Shared constants (protocols, handle types)
  msl/
    writer.py                    MSL file writer
    encryption.py                AES-256-GCM + Argon2id encryption
    constants.py                 Format constants and enumerations
    integrity.py                 BLAKE3 integrity chain
    types.py                     MSL data types
  utils/
    protection.py                Memory protection parsing
    padding.py                   Alignment utilities
    timestamps.py                Timestamp helpers
```

---

## Development

### Setup

```bash
git clone git@github.com:MemorySlice/memslicer.git
cd memslicer
pip install -e ".[dev]"
```

Dev dependencies include `pytest`, `pytest-cov`, and `ruff`.

### Running Tests

```bash
pytest
```

With coverage:

```bash
pytest --cov=memslicer --cov-report=term-missing
```

### Linting

```bash
ruff check src/
ruff format src/
```

CI (`.github/workflows/tests.yml`) runs `ruff` and the test suite on every pull
request and on pushes to `main`, across Python 3.10 and 3.12.

### Releasing

Releases are automated by `.github/workflows/publish.yml`, triggered by the
**version in `pyproject.toml`**. To cut a release:

1. Bump `version` under `[project]` in `pyproject.toml` (e.g. `0.2.7` → `0.2.8`).
2. Open a PR and merge it to `main`.

On that push to `main` the workflow:

1. Detects that the version changed (compares `pyproject.toml` at `HEAD` vs
   `HEAD~1`; merges that don't change the version skip publishing entirely).
2. Runs the test suite on Python 3.10–3.12.
3. Builds the sdist + wheel and publishes to PyPI via OIDC **trusted
   publishing** (no API token stored).
4. Creates and pushes the `vX.Y.Z` git tag.

A separate workflow (`changelog.yml`) regenerates the `CHANGELOG.md` section for
the new version from the commit messages since the previous tag.

**Before the first PyPI release, two things must be set up:**

- **PyPI trusted publisher** — configure it once at pypi.org → *memslicer* →
  *Publishing*: owner `reverseame`, repository `memslicer`, workflow
  `publish.yml`, environment `pypi`. Without it the publish step fails at the
  OIDC token exchange (`invalid-publisher`).
- **The `speakeasy` extra** — it pins a direct git source, and PyPI rejects
  distributions that declare direct-reference (`@ git+https://…`) dependencies.
  Drop or rework that extra (e.g. document installing Speakeasy manually) before
  publishing, otherwise the upload is rejected even after OIDC is configured.

---

## Dependencies

| Package        | Version  | Purpose                        |
|----------------|----------|--------------------------------|
| frida-tools    | >=12.0   | Frida backend and agent        |
| blake3         | >=0.4    | BLAKE3 integrity checksums     |
| click          | >=8.0    | CLI framework                  |
| zstandard      | >=0.20   | Zstd compression               |
| lz4            | >=4.0    | LZ4 compression                |
| cryptography   | >=42.0   | AES-256-GCM encryption         |
| argon2-cffi    | >=23.1   | Argon2id key derivation         |

---

## License

Apache 2.0
