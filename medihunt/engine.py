"""medihunt.engine"""
from medihunt.parsers.dicom import DicomParser
from medihunt.parsers.hl7 import HL7Parser
from medihunt.parsers.fhir import FHIRParser
from medihunt.fingerprint.devices import DeviceFingerprinter
from medihunt.anomaly.phi import PHIDetector
from medihunt.anomaly.network import NetworkAnomalyDetector
from medihunt.results import ScanResults

class MediHuntEngine:
    def __init__(self, packets, verbose=False):
        self.packets = packets
        self.verbose = verbose
        self.results = ScanResults()

    def run(self):
        flows = self._extract_flows()
        for parser_cls in [DicomParser, HL7Parser, FHIRParser]:
            parser = parser_cls(self.packets, flows)
            self.results.add_findings(parser.analyze())
        fp = DeviceFingerprinter(self.packets, flows)
        self.results.devices = fp.fingerprint()
        self.results.add_findings(PHIDetector(self.packets, flows).detect())
        self.results.add_findings(NetworkAnomalyDetector(self.packets, flows, self.results.devices).detect())
        return self.results

    def _extract_flows(self):
        from scapy.layers.inet import IP, TCP, UDP
        flows = {}
        for pkt in self.packets:
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
