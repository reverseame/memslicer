"""Regression tests for the real provenance inspector in ``memslicer.cli_symbex``.

``tests/test_provenance_inspector.py`` exercises a separate copy of the
inspector (``tests/inspector.py``), so the CLI's own function went untested and
silently reported "No active symbolic sources" even when the solved state was
fully constrained on the injected key.
"""
import pytest

angr = pytest.importorskip("angr")
import claripy  # noqa: E402

from memslicer.cli_symbex import inspect_and_print_provenance  # noqa: E402


KEY = bytes.fromhex("00ff12a55a7e90421337c0defeed8899")


def _state_with_key_constraints():
    state = angr.SimState(arch="AMD64")
    key = claripy.BVS("license_key", len(KEY) * 8)
    for i, byte_ast in enumerate(key.chop(8)):
        state.add_constraints(byte_ast == KEY[i])
    return state, key


def test_inspector_reports_solved_key_value(capsys):
    state, key = _state_with_key_constraints()

    inspect_and_print_provenance(state)
    out = capsys.readouterr().out

    assert "No active symbolic sources" not in out
    assert "DETECTED SOURCE: Symbolic Variables" in out
    # The solved value of the existing variable, not a fresh unconstrained BVS.
    assert f"{next(iter(key.variables))} = {KEY.hex()}" in out


def test_inspector_without_constraints_says_so(capsys):
    inspect_and_print_provenance(angr.SimState(arch="AMD64"))
    assert "No active symbolic sources" in capsys.readouterr().out
