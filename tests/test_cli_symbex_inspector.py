"""Regression tests for the real provenance inspector in ``memslicer.cli_symbex``.

``tests/test_provenance_inspector.py`` exercises a separate copy of the
inspector (``tests/inspector.py``), so the CLI's own function went untested and
silently reported "No active symbolic sources" even when the solved state was
fully constrained on the injected key.
"""
import io

import pytest

angr = pytest.importorskip("angr")
claripy = getattr(angr, "claripy", None) or pytest.importorskip("claripy")

from memslicer.cli_symbex import inspect_and_print_provenance  # noqa: E402


KEY = bytes.fromhex("00ff12a55a7e90421337c0defeed8899")


def _blank_state():
    # angr 10's SimState requires a project, so build one from a 1-byte blob.
    project = angr.Project(io.BytesIO(b"\xc3"), auto_load_libs=False,
                           main_opts={"backend": "blob", "arch": "amd64"})
    return project.factory.blank_state()


def _state_with_key_constraints():
    state = _blank_state()
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
    inspect_and_print_provenance(_blank_state())
    assert "No active symbolic sources" in capsys.readouterr().out
