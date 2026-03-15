"""
tests/test_parser_hl7.py
Tests for the HL7 v2 / MLLP parser.
"""

import pytest
from tests.conftest import packets_to_flows
from medihunt.parsers.hl7 import HL7Parser
from medihunt.results import Severity


def test_hl7_detects_mllp_traffic(hl7_packets):
    flows = packets_to_flows(hl7_packets)
    parser = HL7Parser(hl7_packets, flows)
    findings = parser.analyze()

    assert len(findings) > 0


def test_hl7_unencrypted_is_critical(hl7_packets):
    flows = packets_to_flows(hl7_packets)
    parser = HL7Parser(hl7_packets, flows)
    findings = parser.analyze()

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) > 0


def test_hl7_detects_adt_message_type(hl7_packets):
    flows = packets_to_flows(hl7_packets)
    parser = HL7Parser(hl7_packets, flows)
    findings = parser.analyze()

    titles = [f.title for f in findings]
    assert any("ADT" in t for t in titles)


def test_hl7_detects_phi_fields(hl7_packets):
    flows = packets_to_flows(hl7_packets)
    parser = HL7Parser(hl7_packets, flows)
    findings = parser.analyze()

    phi_findings = [f for f in findings if f.category == "PHI Leakage"]
    assert len(phi_findings) > 0


def test_hl7_phi_finding_contains_evidence(hl7_packets):
    flows = packets_to_flows(hl7_packets)
    parser = HL7Parser(hl7_packets, flows)
    findings = parser.analyze()

    phi_findings = [f for f in findings if f.category == "PHI Leakage"]
    for f in phi_findings:
        assert f.evidence, "PHI finding has no evidence"


def test_hl7_no_findings_on_empty():
    parser = HL7Parser([], {})
    findings = parser.analyze()
    assert findings == []


def test_hl7_finding_ports_correct(hl7_packets):
    flows = packets_to_flows(hl7_packets)
    parser = HL7Parser(hl7_packets, flows)
    findings = parser.analyze()

    for f in findings:
        assert f.port == 2575
