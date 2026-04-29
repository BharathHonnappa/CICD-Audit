"""
Check: Hardcoded secrets in workflow files.
Looks for API keys, tokens, passwords, and credentials embedded directly
in workflow YAML instead of using GitHub Secrets.
"""

import re

# Pattern: (label, regex, severity)
SECRET_PATTERNS = [
    ("AWS Access Key",         r"AKIA[0-9A-Z]{16}",                                  "critical"),
    ("AWS Secret Key",         r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "critical"),
    ("GitHub Token (classic)", r"ghp_[a-zA-Z0-9]{36}",                               "critical"),
    ("GitHub Fine-grained Token", r"github_pat_[a-zA-Z0-9_]{82}",                    "critical"),
    ("Generic API Key",        r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?", "high"),
    ("Generic Password",       r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?.{6,}['\"]?", "high"),
    ("Generic Secret",         r"(?i)(secret|token)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{8,}['\"]?", "medium"),
    ("Private Key Header",     r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----",  "critical"),
    ("Slack Webhook",          r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "high"),
    ("Stripe Key",             r"sk_(live|test)_[a-zA-Z0-9]{24}",                    "critical"),
]

# Lines to skip — these reference secrets correctly via ${{ secrets.X }}
SAFE_PATTERNS = [
    r"\$\{\{\s*secrets\.",
    r"\$\{\{\s*vars\.",
    r"\$\{\{\s*env\.",
    r"#.*",  # comments (rough skip)
]


def _is_safe_line(line: str) -> bool:
    return any(re.search(p, line) for p in SAFE_PATTERNS)


def run(workflows: list[dict]) -> list[dict]:
    findings = []

    for wf in workflows:
        for line_num, line in enumerate(wf["raw"].splitlines(), start=1):
            if _is_safe_line(line):
                continue
            for label, pattern, severity in SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "check": "Hardcoded Secret",
                        "severity": severity,
                        "file": wf["path"],
                        "line": line_num,
                        "detail": f"{label} pattern detected in workflow file.",
                        "snippet": line.strip()[:120],
                        "remediation": (
                            "Move the value to a GitHub Secret (Settings → Secrets and variables → Actions) "
                            "and reference it as ${{ secrets.YOUR_SECRET_NAME }}."
                        ),
                        "reference": "https://docs.github.com/en/actions/security-guides/encrypted-secrets",
                    })
                    break  # one finding per line max

    return findings