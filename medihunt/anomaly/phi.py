"""medihunt.anomaly.phi"""
import re
from typing import List
from medihunt.results import Finding, Severity

PHI_PATTERNS = [
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "SSN", Severity.CRITICAL),
    (re.compile(r'[A-Z]{2,20}\^[A-Z]{2,20}'), "HL7 Patient Name", Severity.CRITICAL),
    (re.compile(r'\bMRN[:\s]?\d{6,10}\b', re.IGNORECASE), "MRN", Severity.HIGH),
    (re.compile(r'"resourceType"\s*:\s*"Patient"'), "FHIR Patient Resource", Severity.CRITICAL),
    (re.compile(r'PID\|[^|]*\|[^|]*\|[^|]+\|'), "HL7 PID Segment", Severity.CRITICAL),
]

class PHIDetector:
    def __init__(self, packets, flows):
        self.packets = packets
        self.flows = flows

    def detect(self) -> List[Finding]:
        findings = []
        seen = set()
        for flow_key, pkts in self.flows.items():
            src_ip, dst_ip, sport, dport, proto = flow_key
            if proto != 6: continue
            payload = b""
            for pkt in pkts:
                try:
                    from scapy.layers.inet import TCP
                    if pkt.haslayer(TCP): payload += bytes(pkt[TCP].payload)
                except Exception: pass
            if not payload: continue
            try:
                text = payload.decode("utf-8", errors="replace")
            except Exception:
                continue
            for pattern, phi_type, severity in PHI_PATTERNS:
                matches = pattern.findall(text)
                if not matches: continue
                if (flow_key, phi_type) in seen: continue
                seen.add((flow_key, phi_type))
                findings.append(Finding(
                    severity=severity,
                    category="PHI Leakage",
                    title=f"{phi_type} detected in cleartext traffic",
                    description=f"{phi_type} found in unencrypted stream. {len(matches)} occurrence(s).",
                    evidence=f"{src_ip}:{sport} -> {dst_ip}:{dport}",
                    src_ip=src_ip, dst_ip=dst_ip, port=dport,
                    recommendation="Encrypt all traffic carrying PHI."
                ))
        return findings
