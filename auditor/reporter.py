"""
Reporter — colored terminal output with risk scoring.
"""

import json
import sys
from datetime import datetime

# ANSI color codes
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
ORANGE = "\033[33m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GRAY   = "\033[90m"
WHITE  = "\033[97m"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": RED,
    "high":     ORANGE,
    "medium":   YELLOW,
    "low":      BLUE,
    "info":     GRAY,
}
SEVERITY_ICONS = {
    "critical": "💀",
    "high":     "🔴",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "ℹ️ ",
}

SCORE_WEIGHTS = {"critical": 40, "high": 20, "medium": 10, "low": 5, "info": 0}


class Reporter:
    def __init__(self, use_color: bool = True):
        self.use_color = use_color and sys.stdout.isatty() or use_color

    def _c(self, text: str, *codes: str) -> str:
        if not self.use_color:
            return text
        return "".join(codes) + text + RESET

    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════╗
║        CI/CD Pipeline Security Auditor                  ║
║        Supply Chain | IAM | Secrets | SAST              ║
╚══════════════════════════════════════════════════════════╝"""
        print(self._c(banner, CYAN, BOLD))

    def info(self, msg: str):
        print(self._c(f"  [*] {msg}", GRAY))

    def error(self, msg: str):
        print(self._c(f"\n  [!] ERROR: {msg}", RED, BOLD), file=sys.stderr)

    def _severity_label(self, severity: str) -> str:
        icon = SEVERITY_ICONS.get(severity, "")
        color = SEVERITY_COLORS.get(severity, WHITE)
        label = severity.upper().ljust(8)
        return f"{icon} {self._c(label, color, BOLD)}"

    def _calculate_score(self, findings: list[dict]) -> tuple[int, str]:
        """Returns (score 0-100, risk_level)."""
        raw = sum(SCORE_WEIGHTS.get(f["severity"], 0) for f in findings)
        score = min(100, raw)
        if score >= 70:
            return score, "CRITICAL RISK"
        if score >= 40:
            return score, "HIGH RISK"
        if score >= 20:
            return score, "MEDIUM RISK"
        if score > 0:
            return score, "LOW RISK"
        return 0, "CLEAN"

    def print_report(self, findings: list[dict], min_severity: str = "low"):
        min_level = SEVERITY_ORDER.get(min_severity, 3)
        filtered = [f for f in findings if SEVERITY_ORDER.get(f["severity"], 3) <= min_level]
        filtered.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 3))

        score, risk_level = self._calculate_score(findings)

        # Summary header
        print()
        print(self._c("══════════════════════════════════════════════════════════", CYAN))
        print(self._c("  AUDIT RESULTS", WHITE, BOLD))
        print(self._c("══════════════════════════════════════════════════════════", CYAN))

        # Counts by severity
        for sev in ("critical", "high", "medium", "low", "info"):
            count = sum(1 for f in findings if f["severity"] == sev)
            color = SEVERITY_COLORS[sev]
            icon = SEVERITY_ICONS[sev]
            print(f"  {icon} {self._c(sev.upper().ljust(10), color, BOLD)} {count} finding(s)")

        # Overall risk score
        score_color = RED if score >= 70 else ORANGE if score >= 40 else YELLOW if score >= 20 else GREEN
        print()
        print(f"  {self._c('RISK SCORE:', WHITE, BOLD)} {self._c(str(score) + '/100', score_color, BOLD)}  {self._c(risk_level, score_color, BOLD)}")
        print(self._c("══════════════════════════════════════════════════════════", CYAN))

        if not filtered:
            print(self._c("\n  ✅  No findings at or above the selected severity threshold.\n", GREEN))
            return

        # Individual findings
        print()
        for i, f in enumerate(filtered, 1):
            sev = f["severity"]
            color = SEVERITY_COLORS.get(sev, WHITE)

            print(self._c(f"  ┌─ Finding #{i} ", color) + self._severity_label(sev))
            print(self._c(f"  │  Check   : ", GRAY) + self._c(f["check"], WHITE, BOLD))
            print(self._c(f"  │  File    : ", GRAY) + f["file"])
            if f.get("line"):
                print(self._c(f"  │  Line    : ", GRAY) + str(f["line"]))
            print(self._c(f"  │  Detail  : ", GRAY) + f["detail"])
            if f.get("snippet"):
                print(self._c(f"  │  Snippet : ", GRAY) + self._c(f["snippet"], YELLOW))
            print(self._c(f"  │  Fix     : ", GRAY) + f["remediation"].replace("\n", "\n  │            "))
            if f.get("reference"):
                print(self._c(f"  │  Ref     : ", GRAY) + self._c(f["reference"], BLUE))
            print(self._c(f"  └{'─' * 58}", color))
            print()

        print(self._c(f"  Total findings shown: {len(filtered)} (filter: >={min_severity})", GRAY))
        print(self._c(f"  Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", GRAY))
        print()

    def export_json(self, findings: list[dict], path: str):
        score_weights = {"critical": 40, "high": 20, "medium": 10, "low": 5}
        score = min(100, sum(score_weights.get(f["severity"], 0) for f in findings))
        output = {
            "scan_time": datetime.now().isoformat(),
            "risk_score": score,
            "total_findings": len(findings),
            "summary": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in ("critical", "high", "medium", "low")
            },
            "findings": findings,
        }
        with open(path, "w") as fp:
            json.dump(output, fp, indent=2)