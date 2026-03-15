# Changelog

All notable changes to MediHunt will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.1.0] - 2024-11-01

### Added
- DICOM protocol parser — detects unencrypted C-FIND, C-STORE, and unauthenticated associations
- HL7 v2 / MLLP parser — reassembles TCP streams, extracts PID segments, detects PHI in plaintext
- FHIR REST parser — detects FHIR over HTTP, Bearer token exposure, Bundle data leakage
- Medical device fingerprinter — identifies device type from port signatures and TTL patterns
- PHI regex detector — scans all TCP streams for SSN, MRN, DOB, ICD-10 codes, patient names
- Network anomaly detector — flags Telnet/FTP, HTTP Basic Auth, external IP communication
- CLI interface with PCAP file and live capture modes
- JSON and coloured text report output
- Severity-based exit codes for CI/CD integration

---

## [Unreleased]

### Planned
- MDAP (Medical Device Acquisition Protocol) support
- BACnet / Modbus medical ICS detection
- DICOM TLS version fingerprinting
- HL7 v3 / CDA document support
- Device CVE correlation from NVD
- HIPAA risk scoring per finding
- Wireshark dissector plugin export
