"""dicomghost.parsers.fhir"""
from typing import List
from dicomghost.results import Finding, Severity

FHIR_PHI_RESOURCES = ["Patient","Observation","Condition","DiagnosticReport","MedicationRequest","Encounter"]
FHIR_HTTP_PORTS = {80, 8080, 8000, 8081, 3000}

class FHIRParser:
    def __init__(self, packets, flows):
        self.packets = packets
        self.flows = flows

    def analyze(self) -> List[Finding]:
        findings = []
        for flow_key, pkts in self._find_http_flows().items():
            src_ip, dst_ip, sport, dport, proto = flow_key
            for pkt in pkts:
                raw = self._get_payload(pkt)
                if not raw: continue
                try:
                    text = raw.decode("utf-8", errors="replace")
                except Exception:
                    continue
                resource = self._detect_fhir_resource(text)
                if not resource: continue
                if any(text.startswith(v) for v in ["GET ","POST ","PUT ","DELETE "]):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        category="PHI Leakage",
                        title=f"FHIR {resource} resource accessed over HTTP",
                        description="Unencrypted HTTP request to FHIR endpoint.",
                        evidence=text.split("\r\n")[0][:200],
                        src_ip=src_ip, dst_ip=dst_ip, port=dport,
                        recommendation="Enforce HTTPS. Disable HTTP on FHIR server."
                    ))
                if "Authorization: Bearer" in text:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        category="Credential Exposure",
                        title="FHIR Bearer token transmitted in cleartext",
                        description="Bearer token visible in unencrypted HTTP request.",
                        evidence=f"{src_ip} -> {dst_ip}:{dport}",
                        src_ip=src_ip, dst_ip=dst_ip, port=dport,
                        recommendation="Enforce HTTPS. Rotate exposed tokens immediately."
                    ))
        return findings

    def _find_http_flows(self):
        result = {}
        for key, pkts in self.flows.items():
            _, _, sport, dport, proto = key
            if proto != 6: continue
            if dport in FHIR_HTTP_PORTS or sport in FHIR_HTTP_PORTS:
                result[key] = pkts
        return result

    def _detect_fhir_resource(self, text):
        for r in FHIR_PHI_RESOURCES:
            if f"/fhir/{r}" in text or f'"resourceType":"{r}"' in text:
                return r
        return ""

    def _get_payload(self, pkt):
        try:
            from scapy.layers.inet import TCP
            if pkt.haslayer(TCP): return bytes(pkt[TCP].payload)
        except Exception:
            pass
        return b""
