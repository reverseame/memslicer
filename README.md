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
  -b, --backend [frida|gdb|lldb]  Debugger backend. [default: frida]
  -o, --output PATH               Output .msl file path.
  -c, --compress [none|zstd|lz4]  Compression algorithm. [default: none]
  -U, --usb                       Connect to a USB device (Frida only).
  -R, --remote HOST:PORT          Connect to a remote Frida server (Frida only).
  --os [windows|linux|macos|android|ios]
                                  Override automatic OS detection.
  --filter-prot TEXT              Filter regions by protection (e.g. 'rw-', 'r--').
  --filter-addr TEXT              Filter regions by address range (e.g. '0x1000-0x2000').
  -v, --verbose                   Enable verbose/debug output.
  --read-timeout FLOAT            Per-read timeout in seconds. [default: 10]
  --include-unreadable            Include memory regions with no read permission.
  --max-region-size INT           Skip regions larger than this size (0 = no limit).
  -I, --investigation             Investigation mode: capture system-wide context.
  -E, --encrypt                   Enable AEAD encryption (AES-256-GCM + Argon2id).
  --no-encrypt                    Disable encryption (overrides -I default).
  --passphrase TEXT               Encryption passphrase (prompted if not provided).
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
- **Sub-Graph Module Clustering (`subgraph cluster_*`)**: Automatically groups basic blocks and API call nodes by their owning module (`notepad.exe`, `USER32.dll`, `win32u.dll`, etc.) inside dashed bounding boxes.
- **Color-Coded Branching**:
  - **Green (`#2e7d32`)**: Conditional branch taken (`jump_true`).
  - **Red (`#c62828`)**: Conditional branch not taken / fallthrough (`jump_false`).
  - **Dashed Gray**: API and Syscall invocations.
  - **Dashed Orange**: Dataflow / buffer pointer relationships.

### Interactive Web Viewer (`tools/graph_viewer.html`)

Open [`tools/graph_viewer.html`](tools/graph_viewer.html) in any web browser (`file://` supported) and drag & drop your generated `graph.json` file. It renders an interactive 2D D3.js visualization with HTML5 disassembly cards, color-coded branching, search, and filtering options.

## 🧠 Symbolic Execution & Analysis (`memslicer-symbex`)

`MemSlicerRev` integrates an advanced symbolic execution bridge powered by `angr` to explore execution paths, deobfuscate memory, and solve path constraints directly from `.msl` snapshot files.

### 🚀 CLI Usage

```powershell
python -m memslicer.cli_symbex <dump.msl> --find <TARGET_ADDR> --avoid <FAIL_ADDR> [OPTIONS]
```

#### Available Options:
- `-f, --find ADDR`: Target address(es) to reach (repeatable, hex/dec format).
- `-a, --avoid ADDR`: Address(es) to bypass (repeatable, hex/dec format).
- `-v, --veritesting`: Enables hybrid Static-Dynamic Symbolic Execution (Veritesting) to merge states and prevent path explosion in loops.
- `-s, --steps N`: Step forward N symbolic instructions when no `--find` target is specified.

---

### 🔍 Key Features

#### 1. Automatic Constraint Provenance & Pointer Mapping
The CLI automatically inspects SMT solver constraints upon reaching target addresses and classifies input vectors by source:
- **CPU Registers**: Formatted in canonical 64/32-bit hexadecimal notation (`0x...`).
- **RAM Memory & Pointer Linkage**: Automatically maps CPU pointers to resolved memory buffers (e.g., `RCX (0xc000000000000000) ---> Points to text: 'S3cr3tKey!'`).
- **Memory Region Classification**: Categorizes virtual addresses (Stack, Heap, Executable Image, or Symbolic Virtual Memory).
- **Multi-Channel Detection**: Automatic tracking for STDIN, Disk Files, Network Sockets, CLI Arguments (`argv`), and Environment Variables.

#### 2. Anti-State Explosion (Veritesting)
Reduces $2^N$ exponential path branching by collapsing intermediate conditional decision diamonds (`if-else`) into unified boolean expressions inside the Z3 solver pool.

#### 3. Anti-Analysis & Anti-Debugging Bypass Module (`memslicer.symbex.anti_analysis`)
Includes dedicated SimProcedure stubs and PEB sanitization to bypass evasion checks in malware:
- **API Stubs**: Intercepts `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, and `NtQueryInformationProcess` (`ProcessDebugPort`, `ProcessDebugFlags`).
- **PEB Masking**: Sanitizes `BeingDebugged` (`0`) and `NtGlobalFlag` (`0`) in process memory.

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
