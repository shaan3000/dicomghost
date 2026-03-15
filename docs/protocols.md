# Protocol Reference

Documentation for each medical protocol MediHunt analyzes.

---

## DICOM

**Digital Imaging and Communications in Medicine**

| Property | Value |
|----------|-------|
| Standard | NEMA PS3 |
| Transport | TCP |
| Default ports | 104, 11112, 4242 |
| TLS port | 2762 |
| Encryption | Optional (TLS) |
| Authentication | None (AE Title only) |

### What MediHunt detects
- Unencrypted DICOM traffic on standard ports
- DICOM Association Requests (PDU type 0x01)
- C-FIND queries (patient record lookup) — **CRITICAL**
- C-STORE commands (image transfer) — **HIGH**
- DICOM on non-standard ports

### Why it matters
DICOM has no mandatory authentication or encryption. Any node on the network that knows the AE title can query patient studies, retrieve images, and view full diagnostic reports. C-FIND alone returns patient name, DOB, MRN, study date, and diagnosis description.

### References
- [DICOM PS3.15 Security and System Management Profiles](https://www.dicomstandard.org/current/)
- [FDA Guidance: Cybersecurity in Medical Devices](https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity)

---

## HL7 v2 / MLLP

**Health Level Seven version 2 over Minimal Lower Layer Protocol**

| Property | Value |
|----------|-------|
| Standard | HL7 International |
| Transport | TCP (MLLP framing) |
| Default port | 2575 |
| TLS port | 2576 |
| Encryption | None in MLLP — TLS must be added separately |
| Authentication | None built-in |

### What MediHunt detects
- MLLP framing (`0x0B` start byte) on port 2575 or any port
- HL7 message type extraction (ADT, ORU, ORM, MDM, etc.)
- PHI field extraction from PID segments:
  - PID-3: MRN
  - PID-5: Patient name
  - PID-7: Date of birth
  - PID-11: Address
  - PID-19: SSN (detected, not logged)
- Diagnosis codes from DG1 segments
- HL7 traffic on non-standard ports

### Message types that carry PHI
| Type | Description |
|------|-------------|
| ADT  | Admit/Discharge/Transfer — full patient demographics |
| ORU  | Observation Result — lab results, vitals |
| ORM  | Order Message — medication, procedure orders |
| MDM  | Medical Document — clinical notes, reports |
| DFT  | Financial Transaction — insurance, billing |

### Why it matters
HL7 v2 carries the most sensitive clinical data of any protocol. MLLP has zero security — it was designed for trusted internal networks in the 1980s and is still deployed on production hospital networks today. A single ADT message contains full patient demographics, diagnosis, and location.

### References
- [HL7 International](https://www.hl7.org/)
- [HIPAA Technical Safeguards](https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html)

---

## FHIR REST API

**Fast Healthcare Interoperability Resources**

| Property | Value |
|----------|-------|
| Standard | HL7 FHIR R4 (current) |
| Transport | HTTP or HTTPS |
| Common ports | 80, 443, 8080, 8443 |
| Authentication | SMART on FHIR (OAuth2 + Bearer tokens) |
| Encryption | TLS (HTTPS) required by spec — not always enforced |

### What MediHunt detects
- FHIR resource paths over HTTP (not HTTPS)
- PHI resource types: Patient, Observation, Condition, DiagnosticReport, etc.
- Bearer tokens in Authorization headers (cleartext)
- FHIR Bundle responses (bulk patient data)

### Why it matters
FHIR is the newest and fastest-growing clinical API standard. Many implementations incorrectly run over HTTP — especially on internal networks — exposing both patient data and OAuth tokens. A captured Bearer token can be replayed to access the full FHIR server.

### References
- [HL7 FHIR R4](https://hl7.org/fhir/R4/)
- [SMART on FHIR](https://smarthealthit.org/)
- [ONC 21st Century Cures Act FHIR requirements](https://www.healthit.gov/)

---

## Adding a New Protocol

To add detection for a new protocol, see [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-new-protocol-parser) and add documentation here following the same format.
