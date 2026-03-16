"""dicomghost.parsers.dicom"""
from typing import List
from dicomghost.results import Finding, Severity

DICOM_PORTS = {104, 11112, 4242}
PDU_ASSOCIATE_RQ = 0x01

class DicomParser:
    def __init__(self, packets, flows):
        self.packets = packets
        self.flows = flows

    def analyze(self) -> List[Finding]:
        findings = []
        for flow_key, pkts in self._find_dicom_flows().items():
            src_ip, dst_ip, sport, dport, proto = flow_key
            port = dport if dport in DICOM_PORTS else sport
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Protocol",
                title="Unencrypted DICOM traffic detected",
                description=f"DICOM traffic on port {port} without TLS.",
                evidence=f"{src_ip}:{sport} -> {dst_ip}:{dport} | {len(pkts)} packets",
                src_ip=src_ip, dst_ip=dst_ip, port=port,
                recommendation="Enable DICOM TLS (port 2762). Restrict to known AE titles."
            ))
            if self._has_command(pkts, 0x0020):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category="PHI Leakage",
                    title="DICOM C-FIND: patient record query in cleartext",
                    description="DICOM C-FIND query detected. PHI directly exposed.",
                    evidence=f"C-FIND-RQ from {src_ip} to {dst_ip}:{port}",
                    src_ip=src_ip, dst_ip=dst_ip, port=port,
                    recommendation="Restrict C-FIND access. Enable TLS. Log all queries."
                ))
            if self._has_command(pkts, 0x0001):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="PHI Leakage",
                    title="DICOM C-STORE: medical image transfer in cleartext",
                    description="DICOM C-STORE detected. Images contain patient metadata.",
                    evidence=f"C-STORE-RQ from {src_ip} to {dst_ip}:{port}",
                    src_ip=src_ip, dst_ip=dst_ip, port=port,
                    recommendation="Enforce TLS for all DICOM C-STORE operations."
                ))
        return findings

    def _find_dicom_flows(self):
        return {k: v for k, v in self.flows.items() if k[2] in DICOM_PORTS or k[3] in DICOM_PORTS}

    def _has_command(self, pkts, command_field):
        cmd_bytes = command_field.to_bytes(2, byteorder='little')
        for pkt in pkts:
            raw = self._get_payload(pkt)
            if raw and cmd_bytes in raw:
                return True
        return False

    def _get_payload(self, pkt):
        try:
            from scapy.layers.inet import TCP, UDP
            if pkt.haslayer(TCP): return bytes(pkt[TCP].payload)
            elif pkt.haslayer(UDP): return bytes(pkt[UDP].payload)
        except Exception:
            pass
        return b""
