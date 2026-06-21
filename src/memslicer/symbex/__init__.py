"""Bridge an MSL slice into angr for symbolic execution.

Optional; requires the ``symbex`` extra::

    pip install memslicer[symbex]

The captured memory and the Current thread's registers are loaded into an angr
``SimState`` positioned at the captured program counter, so symbolic execution
can start from the exact point the slice was taken.
"""
from memslicer.symbex.angr_loader import load_angr, SymbexError

__all__ = ["load_angr", "SymbexError"]
