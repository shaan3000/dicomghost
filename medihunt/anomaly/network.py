"""medihunt.anomaly.network"""
import ipaddress
from typing import List
from medihunt.results import Finding, Severity

PRIVATE_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
]

INSECURE_PORTS = {
    23: ("Telnet", Severity.CRITICAL),
    21: ("FTP", Severity.HIGH),
    69: ("TFTP", Severity.HIGH),
}

SENSITIVE_MEDICAL_PORTS = {104, 11112, 2575, 4242}

def is_public_ip(ip_str):
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return not any(addr in net for net in PRIVATE_RANGES)
    except Exception:
        return False

class NetworkAnomalyDetector:
    def __init__(self, packets, flows, devices):
        self.packets = packets
        self.flows = flows
        self.devices = devices

    def detect(self) -> List[Finding]:
        findings = []
        seen = set()
        for flow_key, pkts in self.flows.items():
            src_ip, dst_ip, sport, dport, proto = flow_key
            # Check insecure protocols
            for port, (proto_name, severity) in INSECURE_PORTS.items():
                if dport == port and (src_ip, port) not in seen:
                    seen.add((src_ip, port))
                    findings.append(Finding(
                        severity=severity,
                        category="Insecure Protocol",
                        title=f"{proto_name} detected from medical device",
                        description=f"{proto_name} transmits data in cleartext.",
                        evidence=f"{src_ip} -> {dst_ip}:{port}",
                        src_ip=src_ip, dst_ip=dst_ip, port=port,
                        recommendation=f"Disable {proto_name}. Replace with SSH/SFTP/HTTPS."
                    ))
            # Check external medical traffic
            is_medical = sport in SENSITIVE_MEDICAL_PORTS or dport in SENSITIVE_MEDICAL_PORTS
            if is_medical:
                for ip in [src_ip, dst_ip]:
                    if is_public_ip(ip) and (ip, dport) not in seen:
                        seen.add((ip, dport))
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            category="Network Anomaly",
                            title="Medical protocol traffic to external IP",
                            description=f"Medical device communicating with public IP {ip}.",
                            evidence=f"{src_ip} <-> {dst_ip}:{dport}",
                            src_ip=src_ip, dst_ip=dst_ip, port=dport,
                            recommendation="Block internet access for medical devices immediately."
                        ))
        return findings
