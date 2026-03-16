"""dicomghost.results"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    description: str
    evidence: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None
    recommendation: str = ""

    def to_dict(self):
        return {
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "port": self.port,
            "recommendation": self.recommendation,
        }

@dataclass
class Device:
    ip: str
    mac: Optional[str]
    device_type: str
    confidence: str
    open_ports: List[int] = field(default_factory=list)
    protocols_seen: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "device_type": self.device_type,
            "confidence": self.confidence,
            "open_ports": self.open_ports,
            "protocols_seen": self.protocols_seen,
            "notes": self.notes,
        }

class ScanResults:
    def __init__(self):
        self.findings: List[Finding] = []
        self.devices: List[Device] = []

    def add_findings(self, findings):
        self.findings.extend(findings)

    def has_critical(self):
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    def has_high(self):
        return any(f.severity == Severity.HIGH for f in self.findings)

    def by_severity(self):
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return sorted(self.findings, key=lambda f: order.index(f.severity))

    def summary(self):
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
