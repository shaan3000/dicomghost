"""
tests/test_parser_dicom.py
Tests for the DICOM protocol parser.
"""

import pytest
from tests.conftest import packets_to_flows
from medihunt.parsers.dicom import DicomParser
from medihunt.results import Severity


def test_dicom_detects_unencrypted_traffic(dicom_associate_packets):
    flows = packets_to_flows(dicom_associate_packets)
    parser = DicomParser(dicom_associate_packets, flows)
    findings = parser.analyze()

    assert len(findings) > 0
    titles = [f.title for f in findings]
    assert any("Unencrypted DICOM" in t for t in titles)


def test_dicom_unencrypted_is_high_severity(dicom_associate_packets):
    flows = packets_to_flows(dicom_associate_packets)
    parser = DicomParser(dicom_associate_packets, flows)
    findings = parser.analyze()

    unencrypted = [f for f in findings if "Unencrypted DICOM" in f.title]
    assert len(unencrypted) > 0
    assert unencrypted[0].severity == Severity.HIGH


def test_dicom_detects_association(dicom_associate_packets):
    flows = packets_to_flows(dicom_associate_packets)
    parser = DicomParser(dicom_associate_packets, flows)
    findings = parser.analyze()

    titles = [f.title for f in findings]
    assert any("Association" in t for t in titles)


def test_dicom_cfind_is_critical(dicom_cfind_packets):
    flows = packets_to_flows(dicom_cfind_packets)
    parser = DicomParser(dicom_cfind_packets, flows)
    findings = parser.analyze()

    cfind = [f for f in findings if "C-FIND" in f.title]
    assert len(cfind) > 0
    assert cfind[0].severity == Severity.CRITICAL


def test_dicom_finding_has_recommendation(dicom_associate_packets):
    flows = packets_to_flows(dicom_associate_packets)
    parser = DicomParser(dicom_associate_packets, flows)
    findings = parser.analyze()

    for f in findings:
        assert f.recommendation, f"Finding '{f.title}' has no recommendation"


def test_dicom_finding_has_src_dst(dicom_associate_packets):
    flows = packets_to_flows(dicom_associate_packets)
    parser = DicomParser(dicom_associate_packets, flows)
    findings = parser.analyze()

    for f in findings:
        assert f.src_ip is not None
        assert f.dst_ip is not None


def test_no_findings_on_empty_packets():
    parser = DicomParser([], {})
    findings = parser.analyze()
    assert findings == []
