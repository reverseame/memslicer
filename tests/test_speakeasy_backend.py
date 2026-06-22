"""Tests for the Speakeasy Windows-emulation backend.

The end-to-end tests need the optional ``speakeasy`` package; they are skipped
otherwise. Pure-logic tests (label normalization, availability probe) always
run. The e2e tests drive Speakeasy's bundled decoy PE -- a real PE that calls
``user32!MessageBoxA`` -- so they exercise load -> hook -> run -> graph without
shipping a binary of our own.
"""
import json
import os

import pytest

from memslicer.behavior.speakeasy_backend import (
    SpeakeasyBackend, speakeasy_available,
)


def _decoy_pe() -> str:
    import speakeasy
    root = os.path.dirname(speakeasy.__file__)
    path = os.path.join(root, "winenv", "decoys", "amd64", "default_exe.exe")
    if not os.path.exists(path):
        pytest.skip("speakeasy decoy PE not present")
    return path


# -- pure logic (no speakeasy needed) ----------------------------------------

def test_speakeasy_available_returns_bool():
    assert isinstance(speakeasy_available(), bool)


@pytest.mark.parametrize("api_name,label,bare", [
    ("kernel32.CreateFileW", "kernel32.dll!CreateFileW", "CreateFileW"),
    ("ntdll.NtReadFile", "ntdll.dll!NtReadFile", "NtReadFile"),
    ("foo.dll.Bar", "foo.dll!dll.Bar", "dll.Bar"),  # partition on first dot
    ("nodots", "nodots", "nodots"),
])
def test_norm_label(api_name, label, bare):
    assert SpeakeasyBackend._norm_label(api_name) == (label, bare)


# -- end-to-end (needs speakeasy) --------------------------------------------

def test_trace_pe_captures_api_calls():
    pytest.importorskip("speakeasy")
    from memslicer.behavior.speakeasy_backend import trace_pe_speakeasy

    graph = trace_pe_speakeasy(path=_decoy_pe())
    assert graph.meta["backend"] == "speakeasy"
    # the decoy calls user32!MessageBoxA
    assert "api:user32.dll!MessageBoxA" in graph.nodes
    ev = [e for e in graph.events if e["name"].endswith("!MessageBoxA")]
    assert ev and "category" in ev[0]
    # the decoded string argument survives into the args list
    assert any(isinstance(a, str) for a in ev[0]["args"])


def test_trace_pe_from_data_matches_path():
    pytest.importorskip("speakeasy")
    from memslicer.behavior.speakeasy_backend import trace_pe_speakeasy

    data = open(_decoy_pe(), "rb").read()
    graph = trace_pe_speakeasy(data=data)
    assert "api:user32.dll!MessageBoxA" in graph.nodes


def test_graph_is_serializable():
    pytest.importorskip("speakeasy")
    from memslicer.behavior.speakeasy_backend import trace_pe_speakeasy

    graph = trace_pe_speakeasy(path=_decoy_pe())
    data = json.loads(graph.to_json())          # no non-serializable args leak
    assert data["meta"]["backend"] == "speakeasy"
    assert graph.to_dot().startswith("digraph behavior {")


def test_category_flows_through_for_known_api():
    pytest.importorskip("speakeasy")
    # An API whose name our classifier recognizes lands with its category;
    # drive the backend's hook directly with a fake emulator to stay focused.
    backend = SpeakeasyBackend()

    class FakeEmu:
        def get_ret_address(self):
            return 0x401000

    backend._on_api(FakeEmu(), "kernel32.CreateFileW",
                    lambda p: 0x140, ["C:/x"])
    node = backend.graph.nodes["api:kernel32.dll!CreateFileW"]
    assert node["attrs"]["category"] == "file"
    assert node["attrs"].get("calls") == 1
    ev = backend.graph.events[0]
    assert ev["ret"] == 0x140 and ev["category"] == "file"
    # the caller's return address became the invoking code node + INVOKE edge
    assert "0x401000" in backend.graph.nodes
    assert any(e["type"] == "invoke" for e in backend.graph.edges.values())
