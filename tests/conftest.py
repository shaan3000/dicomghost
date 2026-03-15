"""
tests/conftest.py
Shared fixtures for MediHunt test suite.
Builds synthetic packets using Scapy — no real patient data.
"""

import pytest
from scapy.all import Ether, IP, TCP, Raw, wrpcap, rdpcap
import tempfile
import os

# MLLP framing
MLLP_START = b'\x0b'
MLLP_END   = b'\x1c\x0d'

# Synthetic PHI (fictional, not real patients)
FAKE_HL7_ADT = (
    MLLP_START +
    b"MSH|^~\\&|SENDING|FACILITY|RECV|DEST|20241101120000||ADT^A01|MSG001|P|2.5|\r"
    b"EVN|A01|20241101120000|\r"
    b"PID|1||MRN123456^^^HOSP^MR||DOE^JOHN^A||19800101|M|||123 FAKE ST^^FAKETOWN^CA^90210|\r"
    b"PV1|1|I|WARD^101^A|||||||SURGEON|\r" +
    MLLP_END
)

FAKE_DICOM_ASSOCIATE_RQ = (
    b'\x01\x00'          # PDU type 0x01 = Associate-RQ
    b'\x00\x00'          # reserved
    b'\x00\x00\x00\x44'  # PDU length
    b'\x00\x01'          # protocol version
    b'\x00\x00'          # reserved
    b'MEDIHUNT_SCU    '  # calling AE title (16 bytes)
    b'PACS_SERVER     '  # called AE title (16 bytes)
    b'\x00' * 32         # reserved
)

FAKE_DICOM_CFIND_CMD = b'\x20\x00'  # command field 0x0020 = C-FIND-RQ (little-endian)

FAKE_FHIR_REQUEST = (
    b"GET /fhir/Patient?name=Doe HTTP/1.1\r\n"
    b"Host: fhir.hospital.local\r\n"
    b"Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.fake.token\r\n"
    b"Accept: application/fhir+json\r\n\r\n"
)


def make_tcp_packet(src_ip, dst_ip, sport, dport, payload: bytes, flags="PA"):
    """Build a single TCP packet with payload."""
    return (
        Ether() /
        IP(src=src_ip, dst=dst_ip, ttl=64) /
        TCP(sport=sport, dport=dport, flags=flags) /
        Raw(load=payload)
    )


@pytest.fixture
def hl7_packets():
    """Synthetic HL7 ADT A01 message over MLLP port 2575."""
    return [make_tcp_packet("192.168.1.10", "192.168.1.20", 54321, 2575, FAKE_HL7_ADT)]


@pytest.fixture
def dicom_associate_packets():
    """Synthetic DICOM Associate-RQ on port 104."""
    return [make_tcp_packet("192.168.1.30", "192.168.1.40", 55000, 104, FAKE_DICOM_ASSOCIATE_RQ)]


@pytest.fixture
def dicom_cfind_packets():
    """Synthetic DICOM C-FIND-RQ on port 104."""
    return [make_tcp_packet("192.168.1.30", "192.168.1.40", 55001, 104, FAKE_DICOM_CFIND_CMD)]


@pytest.fixture
def fhir_http_packets():
    """Synthetic FHIR request over HTTP with Bearer token."""
    return [make_tcp_packet("192.168.1.50", "192.168.1.60", 56000, 8080, FAKE_FHIR_REQUEST)]


@pytest.fixture
def telnet_packets():
    """Synthetic Telnet traffic from a medical device IP."""
    return [make_tcp_packet("192.168.1.70", "192.168.1.80", 57000, 23, b"login: admin\r\n")]


@pytest.fixture
def external_dicom_packets():
    """Synthetic DICOM traffic going to a public (non-RFC1918) IP."""
    return [make_tcp_packet("192.168.1.30", "8.8.8.8", 55002, 104, FAKE_DICOM_ASSOCIATE_RQ)]


def packets_to_flows(packets: list) -> dict:
    """Convert packet list to flow dict (mirrors engine._extract_flows)."""
    from scapy.layers.inet import IP, TCP, UDP
    flows = {}
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        proto = ip.proto
        if pkt.haslayer(TCP):
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            sport, dport = 0, 0
        key = (ip.src, ip.dst, sport, dport, proto)
        flows.setdefault(key, []).append(pkt)
    return flows
