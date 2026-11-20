"""Bridge an MSL slice into angr for symbolic execution.

Optional; requires the ``symbex`` extra::

    pip install memslicer[symbex]

The captured memory and the Current thread's registers are loaded into an angr
``SimState`` positioned at the captured program counter, so symbolic execution
can start from the exact point the slice was taken.

Importing this package does not require angr: :func:`load_angr` raises
:class:`SymbexError` when the extra is missing, and the angr-dependent helpers
below are only imported on first access.
"""
from memslicer.symbex.angr_loader import (
    load_angr, load_raw_blob, handoff_to_angr, SymbexError,
)

_UNMAPPED_HANDLER_EXPORTS = (
    "enable_unmapped_memory_recovery",
    "premap_stack_region",
    "repair_errored_states",
)

__all__ = [
    "load_angr",
    "load_raw_blob",
    "handoff_to_angr",
    "SymbexError",
    "enable_unmapped_memory_recovery",
    "premap_stack_region",
    "repair_errored_states",
]


def __getattr__(name: str):
    if name in _UNMAPPED_HANDLER_EXPORTS:
        from memslicer.symbex import unmapped_handler
        return getattr(unmapped_handler, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
