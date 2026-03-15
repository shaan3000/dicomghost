"""
tests/test_parser_fhir.py
Tests for the FHIR REST API parser.
"""

import pytest
from tests.conftest import packets_to_flows
from medihunt.parsers.fhir import FHIRParser
from medihunt.results import Severity


def test_fhir_detects_http_patient_access(fhir_http_packets):
    flows = packets_to_flows(fhir_http_packets)
    parser = FHIRParser(fhir_http_packets, flows)
    findings = parser.analyze()

    assert len(findings) > 0


def test_fhir_http_is_critical(fhir_http_packets):
    flows = packets_to_flows(fhir_http_packets)
    parser = FHIRParser(fhir_http_packets, flows)
    findings = parser.analyze()

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) > 0


def test_fhir_detects_bearer_token(fhir_http_packets):
    flows = packets_to_flows(fhir_http_packets)
    parser = FHIRParser(fhir_http_packets, flows)
    findings = parser.analyze()

    bearer = [f for f in findings if "Bearer" in f.title]
    assert len(bearer) > 0
    assert bearer[0].severity == Severity.CRITICAL


def test_fhir_no_findings_on_empty():
    parser = FHIRParser([], {})
    findings = parser.analyze()
    assert findings == []


def test_fhir_finding_has_recommendation(fhir_http_packets):
    flows = packets_to_flows(fhir_http_packets)
    parser = FHIRParser(fhir_http_packets, flows)
    findings = parser.analyze()

    for f in findings:
        assert f.recommendation
