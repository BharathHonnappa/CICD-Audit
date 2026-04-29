"""
Check: Missing SAST / secret scanning / dependency review steps.

A shift-left pipeline should include security scanning before code merges.
We check for presence of common SAST, secret scanning, and SCA tools.
"""

# Known SAST / secret-scan / SCA action patterns
SECURITY_TOOL_SIGNATURES = {
    "SAST": [
        "github/codeql-action",
        "semgrep/semgrep-action",
        "checkmarx",
        "snyk/actions",
        "sonarcloud",
        "sonarqube",
        "devsec-guardrails",
        "trufflehog",
        "gitguardian",
        "horusec",
        "Bearer/bearer-action",
    ],
    "Secret Scanning": [
        "trufflesecurity/trufflehog",
        "gitguardian/ggshield-action",
        "gitleaks/gitleaks-action",
        "secret-scan",
        "detect-secrets",
    ],
    "Dependency / SCA": [
        "actions/dependency-review-action",
        "snyk/actions",
        "anchore/scan-action",
        "aquasecurity/trivy-action",
        "pyupio/safety",
        "renovatebot",
        "dependabot",
    ],
}


def _workflow_uses_tool(raw: str, signatures: list[str]) -> bool:
    raw_lower = raw.lower()
    return any(sig.lower() in raw_lower for sig in signatures)


def run(workflows: list[dict]) -> list[dict]:
    findings = []

    if not workflows:
        return findings

    # Aggregate across all workflow files
    all_raw = "\n".join(wf["raw"] for wf in workflows)

    for category, signatures in SECURITY_TOOL_SIGNATURES.items():
        if not _workflow_uses_tool(all_raw, signatures):
            if category == "SAST":
                severity = "high"
                detail = (
                    "No SAST (Static Application Security Testing) tool found in any workflow. "
                    "Code is merged without automated security analysis."
                )
                remediation = (
                    "Add CodeQL, Semgrep, or another SAST tool to your CI pipeline:\n"
                    "  - uses: github/codeql-action/analyze@<SHA>\n"
                    "  - uses: semgrep/semgrep-action@<SHA>"
                )
                ref = "https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors"

            elif category == "Secret Scanning":
                severity = "high"
                detail = (
                    "No secret scanning tool (Gitleaks, TruffleHog, GitGuardian) found. "
                    "Secrets committed to the repo may go undetected."
                )
                remediation = (
                    "Add a secret scanner to your push/PR workflows:\n"
                    "  - uses: trufflesecurity/trufflehog@<SHA>\n"
                    "  - uses: gitleaks/gitleaks-action@<SHA>"
                )
                ref = "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning"

            else:  # SCA
                severity = "medium"
                detail = (
                    "No dependency review or SCA (Software Composition Analysis) tool found. "
                    "Vulnerable third-party packages may be introduced undetected."
                )
                remediation = (
                    "Add dependency review to PR workflows:\n"
                    "  - uses: actions/dependency-review-action@<SHA>\n"
                    "Or use Snyk / Trivy for deeper SCA."
                )
                ref = "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review"

            findings.append({
                "check": f"Missing {category} Step",
                "severity": severity,
                "file": "(all workflows)",
                "line": None,
                "detail": detail,
                "snippet": None,
                "remediation": remediation,
                "reference": ref,
            })

    return findings