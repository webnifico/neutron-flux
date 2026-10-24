from __future__ import annotations

import copy
import json
import xml.etree.ElementTree as ET

from neutron_flux.junit_report import build_junit


def _result(**values):
    return {
        "test_id": "CAPTURE-CHECK",
        "category": "same-subnet",
        "status": "PASS",
        "expected": "reachable",
        "observed": "reachable",
        "message": "Recorded check completed",
        "details": {},
        **values,
    }


def test_junit_historical_ipv6_labels_clarify_scope_and_keep_identity():
    old = "IPv6 project-network connectivity with routing metadata unassigned through "
    source = old + "Public:A (fd00::a)"
    destination = old + "Public:B (fd00::b)"
    payload = {
        "results": [
            _result(
                family=6,
                source=source,
                destination=destination,
                display_name=old + "Public",
                details={"probe": {"command": "ping -6 -I fd00::a fd00::b"}},
            )
        ]
    }
    original = copy.deepcopy(payload)
    case = ET.fromstring(build_junit(payload)).find("testcase")
    properties = {
        node.attrib["name"]: node.attrib["value"]
        for node in case.findall("properties/property")
    }
    for field in ("source", "destination", "display_name"):
        assert "routing metadata unassigned" not in properties[field]
        assert "external routing not tested" in properties[field]
    assert properties["source"].endswith("Public:A (fd00::a)")
    assert properties["destination"].endswith("Public:B (fd00::b)")
    assert case.attrib["name"] == "CAPTURE-CHECK"
    evidence = json.loads(case.find("system-out").text)
    assert evidence["command"] == "ping -6 -I fd00::a fd00::b"
    assert payload == original


def test_junit_self_hairpin_message_describes_one_vm_and_keeps_command():
    message = (
        "Flux owns and verifies both private endpoints and floating-IP mappings "
        "on the same external subnet"
    )
    command = "ping -I 10.0.0.2 192.0.2.2"
    payload = {
        "results": [
            _result(
                category="floating-ip-peer",
                source="Private:A (10.0.0.2)",
                destination="Private:A (192.0.2.2)",
                message=message,
                details={
                    "nat_path": "self-hairpin",
                    "probe": {"command": command},
                },
            )
        ]
    }
    original = copy.deepcopy(payload)
    case = ET.fromstring(build_junit(payload)).find("testcase")
    evidence = json.loads(case.find("system-out").text)
    assert "both private endpoints" not in evidence["message"]
    assert "the VM and its own floating-IP mapping" in evidence["message"]
    assert evidence["command"] == command
    assert payload == original
