"""
tests/test_results.py
Tests for the ScanResults and Finding data structures.
"""

from medihunt.results import ScanResults, Finding, Severity


def make_finding(severity):
    return Finding(
        severity=severity,
        category="Test",
        title="Test finding",
        description="Test description",
        evidence="test evidence",
        recommendation="Fix it",
    )


def test_scan_results_add_findings():
    results = ScanResults()
    results.add_findings([make_finding(Severity.HIGH)])
    assert len(results.findings) == 1


def test_has_critical_true():
    results = ScanResults()
    results.add_findings([make_finding(Severity.CRITICAL)])
    assert results.has_critical() is True


def test_has_critical_false():
    results = ScanResults()
    results.add_findings([make_finding(Severity.HIGH)])
    assert results.has_critical() is False


def test_has_high_true():
    results = ScanResults()
    results.add_findings([make_finding(Severity.HIGH)])
    assert results.has_high() is True


def test_by_severity_ordering():
    results = ScanResults()
    results.add_findings([
        make_finding(Severity.LOW),
        make_finding(Severity.CRITICAL),
        make_finding(Severity.MEDIUM),
    ])
    ordered = results.by_severity()
    assert ordered[0].severity == Severity.CRITICAL
    assert ordered[-1].severity == Severity.LOW


def test_summary_counts():
    results = ScanResults()
    results.add_findings([
        make_finding(Severity.CRITICAL),
        make_finding(Severity.CRITICAL),
        make_finding(Severity.HIGH),
    ])
    summary = results.summary()
    assert summary["CRITICAL"] == 2
    assert summary["HIGH"] == 1
    assert summary["MEDIUM"] == 0


def test_finding_to_dict():
    f = make_finding(Severity.HIGH)
    d = f.to_dict()
    assert d["severity"] == "HIGH"
    assert d["category"] == "Test"
    assert "recommendation" in d
