"""Tests for graph export (A4): GraphML, GEXF, networkx, feature vectors."""
import xml.etree.ElementTree as ET

import pytest

from memslicer.behavior.graph import BehaviorGraph


def _sample_graph():
    g = BehaviorGraph()
    g.touch_node_id("0x1", "block", label="entry", addr=1)
    g.touch_node_id("0x2", "block", label="b2", addr=2)
    api = g.touch_node_id("api:CreateFileW", "api", label="CreateFileW")
    api["attrs"]["category"] = "file"
    api["attrs"]["calls"] = 1
    g.touch_node_id("syscall:openat", "syscall", label="openat")
    g.add_edge("0x1", "0x2", "call")
    g.add_edge("0x1", "0x2", "fallthrough")
    g.edges[("api:CreateFileW", "syscall:openat", "dataflow")] = {
        "source": "api:CreateFileW", "target": "syscall:openat",
        "type": "dataflow", "count": 1, "value": "0x100", "arg": 0,
    }
    g.events = [
        {"kind": "api", "name": "CreateFileW", "category": "file",
         "args": [], "ret": 0x100},
        {"kind": "syscall", "name": "openat", "category": "file",
         "args": [0x100], "ret": 0},
    ]
    g.meta = {"memory": {"writes": 5, "exec_writes": 2,
                         "rwx_regions": ["0x1000"]},
              "dataflow_edges": 1, "arch": "x86_64"}
    return g


# -- GraphML ------------------------------------------------------------------

def test_graphml_is_valid_xml_with_nodes_and_edges():
    g = _sample_graph()
    root = ET.fromstring(g.to_graphml())
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
    nodes = root.findall(".//g:node", ns)
    edges = root.findall(".//g:edge", ns)
    assert len(nodes) == 4
    assert len(edges) == 3


def test_graphml_carries_typed_attributes():
    g = _sample_graph()
    xml = g.to_graphml()
    assert 'attr.name="category"' in xml
    assert '>file<' in xml          # the api's category data value
    assert 'attr.name="value"' in xml and '>0x100<' in xml


def test_graphml_escapes_special_chars():
    g = BehaviorGraph()
    g.touch_node_id("n<1>", "block", label='a & "b"', addr=0)
    xml = g.to_graphml()
    assert "&lt;" in xml and "&amp;" in xml and "&quot;" in xml
    ET.fromstring(xml)              # still well-formed


# -- GEXF ---------------------------------------------------------------------

def test_gexf_is_valid_xml():
    g = _sample_graph()
    root = ET.fromstring(g.to_gexf())
    ns = {"x": "http://gexf.net/1.3"}
    assert len(root.findall(".//x:node", ns)) == 4
    assert len(root.findall(".//x:edge", ns)) == 3


def test_gexf_edges_have_weight_and_label():
    g = _sample_graph()
    xml = g.to_gexf()
    assert 'weight="1"' in xml
    assert 'label="call"' in xml or 'label="dataflow"' in xml


# -- networkx -----------------------------------------------------------------

def test_to_networkx_roundtrips_counts():
    pytest.importorskip("networkx")
    g = _sample_graph()
    nx_g = g.to_networkx()
    assert nx_g.number_of_nodes() == 4
    assert nx_g.number_of_edges() == 3
    # parallel edge types are preserved by the multigraph
    assert nx_g.has_edge("0x1", "0x2")
    keys = {k for _, _, k in nx_g.edges(keys=True)}
    assert {"call", "fallthrough"} <= keys
    assert nx_g.nodes["api:CreateFileW"]["category"] == "file"


# -- feature vector -----------------------------------------------------------

def test_feature_vector_counts():
    feats = _sample_graph().feature_vector()
    assert feats["nodes"] == 4 and feats["edges"] == 3
    assert feats["n_block"] == 2 and feats["n_api"] == 1
    assert feats["n_syscall"] == 1 and feats["n_func"] == 0
    assert feats["e_call"] == 1 and feats["e_dataflow"] == 1
    assert feats["e_fallthrough"] == 1 and feats["e_jump"] == 0
    assert feats["cat_file"] == 2 and feats["cat_network"] == 0
    assert feats["unique_apis"] == 1 and feats["unique_syscalls"] == 1
    assert feats["total_calls"] == 2
    assert feats["mem_writes"] == 5 and feats["mem_exec_writes"] == 2
    assert feats["rwx_regions"] == 1 and feats["dataflow_edges"] == 1


def test_feature_vector_keys_are_stable_and_zero_filled():
    empty = BehaviorGraph().feature_vector()
    full = _sample_graph().feature_vector()
    assert empty.keys() == full.keys()          # same schema regardless of content
    assert all(v == 0 for v in empty.values())  # empty graph -> all zeros


def test_feature_vector_is_json_serializable():
    import json
    feats = _sample_graph().feature_vector()
    assert json.loads(json.dumps(feats)) == feats
