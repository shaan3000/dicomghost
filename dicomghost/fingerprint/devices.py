"""dicomghost.fingerprint.devices"""
from typing import List
from dicomghost.results import Device

DEVICE_SIGNATURES = [
    (frozenset({104}),       "DICOM AE (PACS/Modality)",      "High"),
    (frozenset({11112}),     "DICOM AE (non-standard port)",  "High"),
    (frozenset({2575}),      "HL7 Integration Engine",         "High"),
    (frozenset({4242}),      "Orthanc DICOM Server",           "High"),
    (frozenset({8080,8443}), "FHIR / Clinical API Server",     "Medium"),
    (frozenset({161,162}),   "SNMP-managed Medical Device",    "Medium"),
    (frozenset({502}),       "Modbus (Medical ICS)",           "Medium"),
]

class DeviceFingerprinter:
    def __init__(self, packets, flows):
        self.packets = packets
        self.flows = flows

    def fingerprint(self) -> List[Device]:
        ip_data = self._collect_ip_data()
        devices = []
        for ip, data in ip_data.items():
            device_type, confidence = self._classify_device(data["ports"])
            devices.append(Device(
                ip=ip, mac=data.get("mac"),
                device_type=device_type, confidence=confidence,
                open_ports=sorted(data["ports"]),
                protocols_seen=list(data["protocols"]),
                notes=f"TTL={data.get('ttl')}"
            ))
        return devices

    def _collect_ip_data(self):
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.l2 import Ether
        data = {}
        for pkt in self.packets:
            if not pkt.haslayer(IP): continue
            ip_layer = pkt[IP]
            src = ip_layer.src
            if src not in data:
                data[src] = {"ports": set(), "protocols": set(), "ttl": None, "mac": None}
            data[src]["ttl"] = ip_layer.ttl
            if pkt.haslayer(Ether): data[src]["mac"] = pkt[Ether].src
            if pkt.haslayer(TCP):
                data[src]["ports"].add(pkt[TCP].dport)
                data[src]["protocols"].add("TCP")
            elif pkt.haslayer(UDP):
                data[src]["ports"].add(pkt[UDP].dport)
                data[src]["protocols"].add("UDP")
        return data

    def _classify_device(self, ports):
        best, score = ("Unknown Medical Device", "Low"), 0
        for sig_ports, device_type, confidence in DEVICE_SIGNATURES:
            overlap = len(sig_ports & ports)
            if overlap > score:
                score = overlap
                best = (device_type, confidence)
        return best
