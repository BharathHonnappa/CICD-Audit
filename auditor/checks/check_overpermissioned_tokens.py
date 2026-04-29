"""
Check: Overpermissioned GITHUB_TOKEN.

The GITHUB_TOKEN should follow least privilege. Granting write-all
or not scoping permissions at all leaves the token dangerously powerful —
an attacker who hijacks the workflow gets those permissions too.

Rules:
  - 'permissions: write-all'         → CRITICAL
  - No 'permissions' block at all    → HIGH (defaults to repo-level settings)
  - Per-permission 'write' where read would suffice → MEDIUM
"""

WRITE_ONLY_PERMISSIONS = {
    # Permissions where write is rarely justified in CI
    "issues",
    "pull-requests",
    "packages",
    "deployments",
    "pages",
    "security-events",
    "statuses",
}


def _check_permissions_block(perms, location: str, file_path: str) -> list[dict]:
    findings = []

    if perms == "write-all":
        findings.append({
            "check": "Overpermissioned Token",
            "severity": "critical",
            "file": file_path,
            "line": None,
            "detail": f"'permissions: write-all' grants the GITHUB_TOKEN every write permission. ({location})",
            "snippet": "permissions: write-all",
            "remediation": (
                "Scope permissions to only what the job needs:\n"
                "  permissions:\n"
                "    contents: read\n"
                "    pull-requests: write  # only if PRs are needed"
            ),
            "reference": "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
        })
        return findings

    if isinstance(perms, dict):
        for perm, level in perms.items():
            if level == "write" and perm in WRITE_ONLY_PERMISSIONS:
                findings.append({
                    "check": "Overpermissioned Token",
                    "severity": "medium",
                    "file": file_path,
                    "line": None,
                    "detail": (
                        f"Permission '{perm}: write' is granted in {location}. "
                        "Verify write access is strictly required."
                    ),
                    "snippet": f"{perm}: write",
                    "remediation": (
                        f"If write is not required, change to '{perm}: read' or remove it entirely."
                    ),
                    "reference": "https://docs.github.com/en/actions/security-guides/automatic-token-authentication",
                })

    return findings


def run(workflows: list[dict]) -> list[dict]:
    findings = []

    for wf in workflows:
        parsed = wf.get("parsed")
        if not parsed or not isinstance(parsed, dict):
            continue

        # Check top-level permissions
        top_perms = parsed.get("permissions")
        if top_perms is None:
            findings.append({
                "check": "Overpermissioned Token",
                "severity": "high",
                "file": wf["path"],
                "line": None,
                "detail": (
                    "No 'permissions' block found at workflow level. "
                    "GITHUB_TOKEN inherits repository default permissions, which may be write."
                ),
                "snippet": "(no permissions block)",
                "remediation": (
                    "Add an explicit top-level permissions block:\n"
                    "  permissions:\n"
                    "    contents: read\n"
                    "Then grant additional permissions per-job only where needed."
                ),
                "reference": "https://docs.github.com/en/actions/security-guides/automatic-token-authentication",
            })
        else:
            findings += _check_permissions_block(top_perms, "workflow level", wf["path"])

        # Check per-job permissions
        jobs = parsed.get("jobs", {})
        if isinstance(jobs, dict):
            for job_name, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                job_perms = job.get("permissions")
                if job_perms is not None:
                    findings += _check_permissions_block(
                        job_perms, f"job '{job_name}'", wf["path"]
                    )

    return findings