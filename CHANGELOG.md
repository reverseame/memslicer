# Changelog

All notable changes to this project will be documented in this file.


## [Unreleased]

### Features

- Capture per-thread CPU register state into Thread Context blocks
  (0x0011, spec Section 5.7) so a slice can be emulated/stepped by a
  consumer. Supported on the Frida, GDB and LLDB backends; the
  `ThreadContexts` capability bit is set when registers are captured.
  Disable with `--no-registers`. Bumps the MSL format version to 1.1.
- New `memslicer-emu` tool (and `memslicer.emu` library) that emulates a
  slice with Unicorn + Capstone: maps the captured regions, seeds registers
  from the Thread Context, and single-steps execution. Install with the
  `emu` extra (`pip install memslicer[emu]`). Supports x86/x86_64/ARM/ARM64,
  and reverse execution (step back) via a CPU-context + memory-write journal.
- `memslicer-emu --resume-from-syscall` (`-R`): when a slice is captured
  parked in a blocking library/syscall (e.g. a `Sleep`), unwind out of it by
  finding the caller's return address into the program image on the stack and
  continuing there as if the call had returned — stepping forward would
  otherwise hit a syscall the emulator can't service. `--pop-bytes` discards
  stdcall argument cleanup and `--image-range` overrides image auto-detection.
  Exposed in the library as `MSLEmulator.resume_from_syscall()` /
  `find_caller_frame()` / `in_system_call()` / `main_image()`.
- New `memslicer-symbex` tool (and `memslicer.symbex` library) that loads a
  slice into [angr](https://angr.io) — captured memory and registers become a
  `SimState` at the captured PC — for symbolic execution / exploration. Behind
  the optional `symbex` extra (`pip install memslicer[symbex]`).
- New `memslicer-behavior` tool (and `memslicer.behavior` library) that
  extracts a *behavior graph* from a slice: it emulates with Unicorn,
  instruments execution with hooks, and emits control flow (basic blocks or
  instructions) plus system interactions (syscalls/APIs) as JSON or Graphviz
  DOT. Granularity is a one-line switch (`--granularity block|instruction`).
  System calls are modelled by an analyst-editable *stub skeleton*:
  `--emit-stubs` writes a template (one function per observed call, pre-filled
  with the observed arguments) and `--stubs` reloads the edited version so the
  analyst controls return values and side effects. Uses the `emu` extra.
  Windows API calls are resolved too: call targets that land on a module's PE
  export are labelled `module!Export`, intercepted, routed to the same stub
  registry (Win64/SysV calling conventions), and returned to the caller without
  emulating the API body. On Linux, ELF `.dynsym` exports and PLT/GOT imports
  are resolved as well — the latter via the already-bound GOT of the captured
  process, so a `call func@plt` resolves to the owning library's `lib!symbol`.
  The address resolver also maps any address back to `module+offset`.
  Syscalls are named from per-architecture Linux tables (x86-64 complete; i386,
  AArch64 and ARM common subsets).
- `memslicer.symbex.handoff_to_angr(emu)` performs a concrete→symbolic
  hand-off: it builds an angr `Project`/`SimState` from a *live* emulator's
  current registers and memory, so you can emulate concretely up to a point of
  interest and then continue symbolically with angr's SimOS modelling the OS.
- `memslicer-behavior` analysis suite on top of the behavior graph:
  - A bundled, categorized stub library (`--stublib`) covering common
    file/network/registry/process/memory/library/crypto/system APIs, with
    argument decoders, so emulation advances without hand-writing stubs; every
    syscall/API node is tagged with a behavior category. Analyst stubs merge on
    top with `--stubs`.
  - A Speakeasy backend (`--backend speakeasy`) for high-fidelity Windows API
    emulation (hundreds of real handlers, PEB/TEB, object manager, fake
    fs/registry/network), projected onto the same behavior graph; analyst/stub
    library stubs can override individual Speakeasy handlers. Behind the
    optional `speakeasy` extra (`pip install memslicer[speakeasy]`, installed
    from git head — the PyPI release pins an incompatible unicorn).
  - Inter-call data-flow edges by value-equality taint: `dataflow` edges when a
    call's return value is later passed as an argument (handle/pointer/fd
    provenance) and `buffer` edges when two calls share the same pointer/handle.
  - Memory-write annotations (writes into executable memory / self-modifying
    code, write-target region-type buckets, statically-RWX regions) and an
    optional dynamic call graph (`--call-graph`).
  - Graph export to GraphML and GEXF (dependency-free) and to a `networkx`
    `MultiDiGraph` (optional `graph` extra), plus a fixed-key per-graph feature
    vector (`--features`) for ML/triage pipelines.

### Bug Fixes

- Investigation mode: the `SystemProcessTable` / `SystemNetworkTable` /
  `SystemHandleTable` capability bits are now written to the on-disk file
  header. They were previously set on the header object only after it had
  already been serialized into the BLAKE3 chain, so they never reached disk
  and consumers under-reported the captured system tables. The tables are now
  collected before the header is built.


## [0.2.7] - 2026-04-20

### Changes

- fixes regarding the latest changes in the specification; add now the possibility to change the blake3 hash

## [0.2.4] - 2026-04-14

### Changes

- serveral improvements in the linux acquisition

## [0.2.3] - 2026-04-12

### Bug Fixes

- fix: workflow fixes regarding GROUP

## [0.1.0] - 2026-03-15

Initial release of MemSlicer.

- Frida-based memory acquisition by PID or process name
- MSL binary format with region metadata, module info, and page-level granularity
- Compression support: zstd, lz4, none
- BLAKE3 integrity checksums
- Region filtering by protection, address range, and path patterns
- Local, USB (iOS/Android), and remote Frida server support
- Progress bar with page-level quality assessment
- Companion `.msl.log` file with full debug output
- Human-readable skip reason labels in end summary
- CI workflows for PyPI publishing and automated changelog
