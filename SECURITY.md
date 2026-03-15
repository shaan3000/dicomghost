# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes     |

---

## Reporting a Vulnerability in MediHunt

If you discover a security vulnerability **in MediHunt itself** (not in the medical devices it analyzes), please do not open a public GitHub issue.

Instead, report it privately:

**Email:** security@[your-domain].com  
**Subject line:** `[MediHunt] Security Vulnerability Report`

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

You will receive a response within **72 hours**. If the vulnerability is confirmed, a fix will be released as soon as possible and you will be credited in the changelog (unless you prefer to remain anonymous).

---

## Scope

Vulnerabilities in scope:
- Code execution via malicious PCAP files
- Path traversal in file output
- Dependency vulnerabilities (scapy, etc.)
- Logic flaws that could cause false negatives in PHI detection

Out of scope:
- Vulnerabilities in the medical devices or protocols MediHunt detects
- Issues in third-party tools or libraries (report those upstream)

---

## Legal

MediHunt is a defensive security research tool. Responsible security research conducted in good faith is welcomed and will not result in legal action. We ask that you:

- Give us reasonable time to fix before public disclosure
- Do not access, modify, or exfiltrate any real patient data during research
- Do not test against systems you don't own or have explicit permission to test

---

## Ethical Use Reminder

MediHunt is designed for **authorized security assessments only**. Using it against systems without written authorization may violate laws including HIPAA, the Computer Fraud and Abuse Act (CFAA), and equivalent legislation in your jurisdiction.
