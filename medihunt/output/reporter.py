"""medihunt.output.reporter"""
import json
from datetime import datetime
from medihunt.results import ScanResults, Severity

RESET = "\033[0m"
BOLD  = "\033[1m"
GRAY  = "\033[90m"

SEV_COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH:     "\033[31m",
    Severity.MEDIUM:   "\033[33m",
    Severity.LOW:      "\033[34m",
    Severity.INFO:     "\033[37m",
}

SEV_ICONS = {
    Severity.CRITICAL: "[!!!]",
    Severity.HIGH:     " [!] ",
    Severity.MEDIUM:   " [~] ",
    Severity.LOW:      " [-] ",
    Severity.INFO:     " [i] ",
}

class Reporter:
    def __init__(self, results, fmt="text", verbose=False):
        self.results = results
        self.fmt = fmt
        self.verbose = verbose

    def print_report(self):
        if self.fmt == "json":
            print(self._build_json())
        else:
            self._print_text()

    def save(self, filepath):
        content = self._build_json() if self.fmt == "json" else self._build_text()
        with open(filepath, "w") as f:
            f.write(content)

    def _print_text(self):
        print(self._build_text())

    def _build_text(self):
        lines = []
        lines.append(f"{BOLD}{'─'*70}{RESET}")
        lines.append(f"{BOLD}  MediHunt Scan Report  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
        lines.append(f"{BOLD}{'─'*70}{RESET}\n")
        summary = self.results.summary()
        lines.append(f"{BOLD}Summary:{RESET}")
        for sev in Severity:
            count = summary[sev.value]
            if count == 0 and not self.verbose: continue
            lines.append(f"  {SEV_COLORS[sev]}{sev.value:<10}{RESET}  {count}")
        lines.append("")
        if self.results.devices:
            lines.append(f"{BOLD}Discovered Devices ({len(self.results.devices)}):{RESET}")
            lines.append(f"{'─'*70}")
            for dev in self.results.devices:
                lines.append(f"  {BOLD}{dev.ip:<18}{RESET}{dev.device_type:<35}{GRAY}[{dev.confidence}]{RESET}")
                if dev.open_ports:
                    lines.append(f"    Ports:        {', '.join(str(p) for p in dev.open_ports)}")
                lines.append("")
        sorted_findings = self.results.by_severity()
        visible = [f for f in sorted_findings if self.verbose or f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
        if visible:
            lines.append(f"{BOLD}Findings ({len(visible)} shown):{RESET}")
            lines.append(f"{'─'*70}")
            for finding in visible:
                color = SEV_COLORS[finding.severity]
                icon  = SEV_ICONS[finding.severity]
                lines.append(f"\n{color}{icon} [{finding.severity.value}] {finding.category.upper()}{RESET}")
                lines.append(f"  {BOLD}{finding.title}{RESET}")
                lines.append(f"  {finding.description}")
                if finding.evidence:
                    lines.append(f"  {GRAY}Evidence: {finding.evidence[:120]}{RESET}")
                if finding.recommendation:
                    lines.append(f"  {BOLD}Fix:{RESET} {finding.recommendation}")
        lines.append(f"\n{BOLD}{'─'*70}{RESET}")
        if self.results.has_critical():
            lines.append(f"\n{SEV_COLORS[Severity.CRITICAL]}{BOLD}[!!!] CRITICAL findings present — immediate action required.{RESET}")
        return "\n".join(lines)

    def _build_json(self):
        report = {
            "tool": "MediHunt",
            "version": "0.1.0",
            "timestamp": datetime.now().isoformat(),
            "summary": self.results.summary(),
            "devices": [d.to_dict() for d in self.results.devices],
            "findings": [f.to_dict() for f in self.results.by_severity()],
        }
        return json.dumps(report, indent=2)
