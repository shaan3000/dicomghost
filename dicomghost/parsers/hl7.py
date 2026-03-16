"""dicomghost.parsers.hl7"""
from typing import List
from dicomghost.results import Finding, Severity

MLLP_START = b'\x0b'
MLLP_END = b'\x1c\x0d'
HL7_PORTS = {2575, 2576, 6661}

class HL7Parser:
    def __init__(self, packets, flows):
        self.packets = packets
        self.flows = flows

    def analyze(self) -> List[Finding]:
        findings = []
        for flow_key, pkts in self._find_hl7_flows().items():
            src_ip, dst_ip, sport, dport, proto = flow_key
            port = dport if dport in HL7_PORTS else sport
            messages = self._extract_hl7_messages(pkts)
            if not messages:
                continue
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category="Protocol",
                title="Unencrypted HL7 MLLP traffic detected",
                description=f"{len(messages)} HL7 message(s) captured without TLS.",
                evidence=f"{src_ip} -> {dst_ip}:{port}",
                src_ip=src_ip, dst_ip=dst_ip, port=port,
                recommendation="Wrap MLLP in TLS. Implement IP allowlisting."
            ))
        return findings

    def _find_hl7_flows(self):
        result = {}
        for key, pkts in self.flows.items():
            _, _, sport, dport, _ = key
            if sport in HL7_PORTS or dport in HL7_PORTS:
                result[key] = pkts
        return result

    def _extract_hl7_messages(self, pkts):
        messages = []
        buffer = b""
        for pkt in pkts:
            raw = self._get_payload(pkt)
            if not raw: continue
            buffer += raw
            while MLLP_START in buffer and MLLP_END in buffer:
                start = buffer.index(MLLP_START) + 1
                end = buffer.index(MLLP_END, start)
                try:
                    messages.append(buffer[start:end].decode("utf-8", errors="replace"))
                except Exception:
                    pass
                buffer = buffer[end + len(MLLP_END):]
        return messages

    def _get_payload(self, pkt):
        try:
            from scapy.layers.inet import TCP
            if pkt.haslayer(TCP): return bytes(pkt[TCP].payload)
        except Exception:
            pass
        return b""
