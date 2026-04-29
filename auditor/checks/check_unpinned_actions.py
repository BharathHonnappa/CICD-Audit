"""
Check: Unpinned GitHub Actions (supply chain risk).

Using actions/@main, @master, or @v1 (mutable tags) means the action's
code can change without your knowledge — a key supply chain attack vector
(e.g. tj-actions/changed-files compromise, 2024).

Safe: uses/owner/action@<full commit SHA>
Risky: uses/owner/action@main  or  @v2  or  @latest
"""

import re

# Matches: uses: owner/repo@ref
USES_PATTERN = re.compile(r"uses:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@([^\s#]+)")

# A full commit SHA is exactly 40 hex chars
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")

MUTABLE_TAGS = {"main", "master", "latest", "dev", "develop", "HEAD"}


def _classify_ref(ref: str) -> tuple[str, str]:
    """Returns (risk_level, reason)."""
    if SHA_PATTERN.match(ref):
        return "ok", "pinned to full commit SHA"
    if ref in MUTABLE_TAGS:
        return "critical", f"pinned to mutable branch '{ref}' — code can change silently"
    if re.match(r"^v?\d+$", ref):  # e.g. v2, v3
        return "high", f"pinned to major version tag '{ref}' — patch/minor updates are uncontrolled"
    if re.match(r"^v?\d+\.\d+", ref):  # e.g. v2.1, v3.0.1
        return "medium", f"pinned to version tag '{ref}' — tags are mutable and can be moved"
    return "low", f"non-standard ref '{ref}' — verify it is immutable"


def run(workflows: list[dict]) -> list[dict]:
    findings = []

    for wf in workflows:
        for line_num, line in enumerate(wf["raw"].splitlines(), start=1):
            match = USES_PATTERN.search(line)
            if not match:
                continue
            action, ref = match.group(1), match.group(2)

            # Skip local actions (./.github/actions/...)
            if action.startswith("./") or action.startswith("../"):
                continue

            risk, reason = _classify_ref(ref)
            if risk == "ok":
                continue

            findings.append({
                "check": "Unpinned Action (Supply Chain)",
                "severity": risk,
                "file": wf["path"],
                "line": line_num,
                "detail": f"Action '{action}@{ref}' is {reason}.",
                "snippet": line.strip()[:120],
                "remediation": (
                    f"Pin to a full commit SHA instead: uses: {action}@<40-char-SHA>  # {ref}\n"
                    "  Use a tool like 'pin-github-action' or check the action's commit history."
                ),
                "reference": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
            })

    return findings