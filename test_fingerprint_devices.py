"""
tests/test_fingerprint_devices.py
Tests for the medical device fingerprinting module.
"""

import pytest
from tests.conftest import packets_to_flows
from medihunt.fingerprint.devices import DeviceFingerprinter


def test_dicom_device_fingerprinted(dicom_associate_packets):
    flows = packets_to_flows(dicom_associate_packets)
    fp = DeviceFingerprinter(dicom_associate_packets, flows)
    devices = fp.fingerprint()

    assert len(devices) > 0
    device_types = [d.device_type for d in devices]
    assert any("DICOM" in dt for dt in device_types)


def test_hl7_device_fingerprinted(hl7_packets):
    flows = packets_to_flows(hl7_packets)
    fp = DeviceFingerprinter(hl7_packets, flows)
    devices = fp.fingerprint()

    assert len(devices) > 0
    device_types = [d.device_type for d in devices]
    assert any("HL7" in dt for dt in device_types)


def test_device_has_ip(dicom_associate_packets):
    flows = packets_to_flows(dicom_associate_packets)
    fp = DeviceFingerprinter(dicom_associate_packets, flows)
    devices = fp.fingerprint()

    for d in devices:
        assert d.ip, "Device missing IP"


def test_device_has_confidence(dicom_associate_packets):
    flows = packets_to_flows(dicom_associate_packets)
    fp = DeviceFingerprinter(dicom_associate_packets, flows)
    devices = fp.fingerprint()

    for d in devices:
        assert d.confidence in ("High", "Medium", "Low")


def test_no_devices_on_empty():
    fp = DeviceFingerprinter([], {})
    devices = fp.fingerprint()
    assert devices == []
