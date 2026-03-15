# Contributing to MediHunt

Thank you for your interest in contributing. MediHunt is a security research tool focused on medical device network analysis — contributions that improve detection accuracy, add new protocol support, or improve usability are very welcome.

---

## Before You Start

- All contributions must be for **legitimate security research purposes only**
- Do not submit contributions that add active attack capabilities
- Do not include real patient data, real PCAP files from live hospital networks, or any PHI in your contribution

---

## Ways to Contribute

### Report a Bug
Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) issue template.

Include:
- Your OS and Python version
- The command you ran
- What you expected vs what happened
- Any error output (redact any sensitive data)

### Request a Feature
Use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md) template.

Good feature requests include:
- The protocol or attack scenario you want covered
- Why it's relevant to medical device security
- Any references (RFCs, vendor docs, CVEs)

### Submit a Pull Request

1. Fork the repo
2. Create a branch: `git checkout -b feat/your-feature-name`
3. Make your changes
4. Add or update tests in `tests/`
5. Run the test suite: `pytest tests/`
6. Commit with a clear message: `git commit -m "feat: add HL7 v3 CDA detection"`
7. Push and open a PR against `main`

---

## Code Style

- Python 3.8+ compatible
- Follow PEP 8
- Type hints where practical
- Docstrings on all public classes and methods
- Keep modules focused — one protocol or concern per file

---

## Adding a New Protocol Parser

1. Create `medihunt/parsers/yourprotocol.py`
2. Implement a class with `__init__(self, packets, flows)` and `analyze() -> List[Finding]`
3. Import and register it in `medihunt/engine.py`
4. Add tests in `tests/test_parser_yourprotocol.py`
5. Document it in `docs/protocols.md`

---

## Commit Message Convention

```
feat: add MDAP protocol parser
fix: correct HL7 PID-5 name extraction regex
docs: update DICOM detection documentation
test: add FHIR Bearer token test case
refactor: simplify flow reassembly logic
```

---

## Questions?

Open a [Discussion](../../discussions) on GitHub or reach out via the contact in the README.
