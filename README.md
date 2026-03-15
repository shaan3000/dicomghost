# MediHunt 🏥🔍

**Medical Device Network Traffic Analyzer for Security Assessments**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-0.1.0-orange)
![CI](https://github.com/shantanushastri/medihunt/actions/workflows/ci.yml/badge.svg)

> A passive CLI tool that analyzes network traffic for healthcare-specific protocol vulnerabilities, PHI leakage, and medical device anomalies. No packets sent. No active scanning.

⚠️ **For authorized security assessments only. Do not use on systems you do not own or have explicit written permission to test.**

---

## Why MediHunt?

Tools like Wireshark, Zeek, and Scapy are protocol-agnostic — they show you packets but have **zero awareness** of healthcare protocols, PHI exposure, or what kind of medical device is on the other end.

MediHunt fills that gap. It understands:
- **DICOM** — medical imaging protocol (C-FIND, C-STORE, Association requests)
- **HL7 v2 / MLLP** — patient messaging (ADT, ORU, ORM, MDM)
- **FHIR REST APIs** — modern clinical APIs over HTTP
- **Medical device fingerprinting** — identifies device types from traffic patterns

No existing open source tool combines all of these in a single, pentest-ready CLI.

---

## Features

| Module | What it detects |
|--------|----------------|
| **DICOM Parser** | Unencrypted image transfer, unauthenticated C-FIND/C-STORE, PACS exposure |
| **HL7 Parser** | MLLP without TLS, PHI in PID segments, ADT/ORU/ORM/MDM exposure |
| **FHIR Parser** | FHIR over HTTP, Bearer tokens in cleartext, bulk Bundle exposure |
| **Device Fingerprinter** | Identifies PACS, HL7 engines, DICOM modalities, ICS devices from port/TTL/UA |
| **PHI Detector** | Regex scan for SSN, MRN, DOB, patient names, ICD-10 codes in any TCP stream |
| **Network Anomaly** | Medical devices on internet, Telnet/FTP on clinical systems, HTTP Basic Auth |

---

## Installation

**Requirements:** Python 3.8+, pip, root/sudo for live capture

```bash
git clone https://github.com/shantanushastri/medihunt.git
cd medihunt
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Analyze a PCAP file
python medihunt.py --pcap hospital_network.pcap

# Live capture on interface for 60 seconds (requires sudo)
sudo python medihunt.py --iface eth0 --duration 60

# Export JSON report
python medihunt.py --pcap capture.pcap --output json --out report.json

# Verbose mode — show all findings including INFO
python medihunt.py --pcap capture.pcap --verbose
```

---

## Sample Output

```
  __  __          _ _   _   _             _
 |  \/  | ___  __| (_) | | | |_   _ _ __ | |_
 | |\/| |/ _ \/ _` | | | |_| | | | | '_ \| __|
 | |  | |  __/ (_| | | |  _  | |_| | | | | |_
 |_|  |_|\___|\__,_|_| |_| |_|\__,_|_| |_|\__|

  Medical Device Network Recon Tool

──────────────────────────────────────────────────────────────────────
  MediHunt Scan Report  |  2024-11-01 14:23:11
──────────────────────────────────────────────────────────────────────

Summary:
  CRITICAL    4
  HIGH        3
  MEDIUM      2

Discovered Devices (3):
──────────────────────────────────────────────────────────────────────
  192.168.10.42    DICOM AE (PACS/Modality)           [High]
    Ports:        104, 11112
    Protocols:    TCP, DICOM

  192.168.10.55    HL7 Integration Engine              [High]
    Ports:        2575
    Protocols:    TCP, HL7

Findings:
──────────────────────────────────────────────────────────────────────

[!!!] [CRITICAL] PHI LEAKAGE
  DICOM C-FIND: patient record query in cleartext
  A DICOM C-FIND query was detected. PHI directly exposed in query responses.
  Peers:    192.168.10.22 -> 192.168.10.42:104
  Fix:      Restrict C-FIND access. Enable TLS. Log all C-FIND queries.
```

See [examples/example_output.json](examples/example_output.json) for full JSON output.

---

## Severity Levels

| Level | Meaning |
|-------|---------|
| `CRITICAL` | Active PHI exposure or immediate patient safety risk |
| `HIGH` | Unencrypted medical protocol traffic |
| `MEDIUM` | Misconfiguration or policy violation |
| `LOW` | Informational issue |
| `INFO` | Observation with no direct risk |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No HIGH or CRITICAL findings |
| `1` | HIGH findings present |
| `2` | CRITICAL findings present |

Useful for CI/CD integration or automated assessment pipelines.

---

## Documentation

- [Usage Guide](docs/usage.md) — detailed CLI usage and assessment workflow
- [Protocol Reference](docs/protocols.md) — DICOM, HL7, FHIR technical details
- [Contributing](CONTRIBUTING.md) — how to add parsers or report bugs
- [Security Policy](SECURITY.md) — responsible disclosure

---

## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v --cov=medihunt
```

---

## Roadmap

- [ ] MDAP (Medical Device Acquisition Protocol) support
- [ ] BACnet / Modbus medical ICS detection
- [ ] DICOM TLS version fingerprinting
- [ ] HL7 v3 / CDA document support
- [ ] Device CVE correlation from NVD
- [ ] HIPAA risk scoring per finding
- [ ] Wireshark dissector plugin export

---

## Author

**Shantanu Shastri**  
Cybersecurity Professional | GE Healthcare  
Specialization: Medical Device & IoT Security, Hardware Security, Penetration Testing

---

## Legal Disclaimer

MediHunt is a **passive** network analysis tool — it does not transmit any packets. It is intended exclusively for authorized penetration testing engagements, security research in controlled lab environments, and healthcare security assessments with written client authorization.

Use of this tool against systems without explicit written authorization may violate HIPAA, the Computer Fraud and Abuse Act (CFAA), and equivalent legislation in your jurisdiction. The author assumes no liability for misuse.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
