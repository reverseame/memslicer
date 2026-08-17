"""Emulation of MSL slices via Unicorn (execution) + Capstone (disassembly).

This subpackage is optional; it requires the ``emu`` extra::

    pip install memslicer[emu]

A slice is a static snapshot, so "execution" means emulation: the captured
memory regions are mapped into a Unicorn CPU and the registers are seeded from
the Current thread's Thread Context block, after which execution can be stepped
forward.
"""
from memslicer.emu.loader import (
    EmuRegion, EmuThread, SliceImage, load_slice,
)
from memslicer.emu.engine import MSLEmulator, EmuError, StepResult, open_slice

__all__ = [
    "EmuRegion",
    "EmuThread",
    "SliceImage",
    "load_slice",
    "MSLEmulator",
    "EmuError",
    "StepResult",
    "open_slice",
]
