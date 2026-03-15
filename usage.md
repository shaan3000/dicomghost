# Usage Guide

## Installation

```bash
git clone https://github.com/shantanushastri/medihunt.git
cd medihunt
pip install -r requirements.txt
```

For system-wide install:
```bash
pip install -e .
```

---

## Basic Usage

### Analyze a PCAP file
```bash
python medihunt.py --pcap hospital_capture.pcap
```

### Live capture on a network interface
```bash
sudo python medihunt.py --iface eth0 --duration 60
```
Root/sudo is required for raw packet capture.

### Export JSON report
```bash
python medihunt.py --pcap capture.pcap --output json --out report.json
```

### Verbose mode (all findings including INFO)
```bash
python medihunt.py --pcap capture.pcap --verbose
```

### Suppress banner (for scripting)
```bash
python medihunt.py --pcap capture.pcap --no-banner
```

---

## Output Formats

### Text (default)
Colour-coded terminal output grouped by severity. Best for interactive use during assessments.

### JSON
Machine-readable output for integration with SIEM, ticketing, or reporting pipelines.

```json
{
  "tool": "MediHunt",
  "version": "0.1.0",
  "timestamp": "2024-11-01T14:23:11",
  "summary": {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
    "INFO": 0
  },
  "devices": [...],
  "findings": [...]
}
```

---

## Exit Codes

| Code | Meaning | Use case |
|------|---------|----------|
| `0`  | No HIGH or CRITICAL findings | CI/CD gate — pass |
| `1`  | HIGH findings present | CI/CD gate — warn |
| `2`  | CRITICAL findings present | CI/CD gate — fail |

Example CI/CD usage:
```bash
python medihunt.py --pcap scan.pcap --no-banner
if [ $? -eq 2 ]; then
    echo "CRITICAL findings — blocking pipeline"
    exit 1
fi
```

---

## Recommended Workflow for Assessments

1. **Passive capture first** — capture 15-30 minutes of traffic during normal operation
   ```bash
   sudo tcpdump -i eth0 -w hospital_traffic.pcap
   ```

2. **Run MediHunt against the PCAP**
   ```bash
   python medihunt.py --pcap hospital_traffic.pcap --output json --out findings.json
   ```

3. **Review device inventory** — verify what was discovered matches expected network topology

4. **Triage CRITICAL findings first** — PHI in cleartext and external IP connections are immediate risks

5. **Export and include in report** — JSON output maps cleanly to pentest report findings

---

## Tips

- Capture from a network TAP or SPAN port for complete visibility
- Run during peak clinical hours to capture all protocol types
- Use `--verbose` to see INFO-level findings (useful for asset inventory)
- DICOM and HL7 traffic may be sparse — longer captures yield more findings
