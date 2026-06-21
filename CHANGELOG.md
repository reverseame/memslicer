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
