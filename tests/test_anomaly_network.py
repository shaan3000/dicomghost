"""
tests/test_anomaly_network.py
Tests for the network anomaly detection module.
"""

import pytest
from tests.conftest import packets_to_flows
from medihunt.anomaly.network import NetworkAnomalyDetector, is_public_ip
from medihunt.results import Severity


# ── is_public_ip unit tests ───────────────────────────────────────────────────

def test_public_ip_detected():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("203.0.113.1") is True


def test_private_ip_not_public():
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("172.16.0.1") is False
    assert is_public_ip("127.0.0.1") is False


# ── Telnet detection ──────────────────────────────────────────────────────────

def test_telnet_detected_as_critical(telnet_packets):
    flows = packets_to_flows(telnet_packets)
    detector = NetworkAnomalyDetector(telnet_packets, flows, [])
    findings = detector.detect()

    telnet_findings = [f for f in findings if "Telnet" in f.title]
    assert len(telnet_findings) > 0
    assert telnet_findings[0].severity == Severity.CRITICAL


# ── External DICOM traffic ────────────────────────────────────────────────────

def test_external_dicom_is_critical(external_dicom_packets):
    flows = packets_to_flows(external_dicom_packets)
    detector = NetworkAnomalyDetector(external_dicom_packets, flows, [])
    findings = detector.detect()

    external = [f for f in findings if "external" in f.title.lower()]
    assert len(external) > 0
    assert external[0].severity == Severity.CRITICAL


def test_external_finding_contains_public_ip(external_dicom_packets):
    flows = packets_to_flows(external_dicom_packets)
    detector = NetworkAnomalyDetector(external_dicom_packets, flows, [])
    findings = detector.detect()

    external = [f for f in findings if "external" in f.title.lower()]
    assert len(external) > 0
    assert "8.8.8.8" in external[0].evidence


# ── Empty input ───────────────────────────────────────────────────────────────

def test_no_findings_on_empty():
    detector = NetworkAnomalyDetector([], {}, [])
    findings = detector.detect()
    assert findings == []
