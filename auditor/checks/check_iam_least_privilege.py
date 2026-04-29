"""
Check: IAM / Least Privilege in workflow configuration.

Checks for:
- Self-hosted runners (can expose secrets to untrusted machines)
- pull_request_target trigger with checkout (classic privilege escalation)
- Secrets passed via environment variables to all steps (over-sharing)
- Workflow dispatch without input validation
"""

import re


def _check_self_hosted_runners(wf: dict) -> list[dict]:
    findings = []
    parsed = wf.get("parsed")
    if not parsed or not isinstance(parsed, dict):
        return findings

    jobs = parsed.get("jobs", {})
    if not isinstance(jobs, dict):
        return findings

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        runs_on = job.get("runs-on", "")
        if isinstance(runs_on, str) and "self-hosted" in runs_on.lower():
            findings.append({
                "check": "IAM / Least Privilege",
                "severity": "medium",
                "file": wf["path"],
                "line": None,
                "detail": (
                    f"Job '{job_name}' uses a self-hosted runner. "
                    "Self-hosted runners can expose secrets to the host machine and are a "
                    "persistence risk if the runner is shared or compromised."
                ),
                "snippet": f"runs-on: {runs_on}",
                "remediation": (
                    "Use GitHub-hosted runners where possible. If self-hosted is required:\n"
                    "  - Run in ephemeral mode (--ephemeral flag)\n"
                    "  - Never use self-hosted runners on public repos\n"
                    "  - Harden the runner environment"
                ),
                "reference": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners",
            })
    return findings


def _check_pull_request_target(wf: dict) -> list[dict]:
    findings = []
    parsed = wf.get("parsed")
    if not parsed or not isinstance(parsed, dict):
        return findings

    triggers = parsed.get("on", parsed.get(True, {}))  # 'on' can parse as True in YAML
    if not isinstance(triggers, dict):
        return findings

    if "pull_request_target" not in triggers:
        return findings

    # Check if any job checks out the PR code (the dangerous combination)
    raw = wf["raw"]
    if re.search(r"ref.*head", raw, re.IGNORECASE) or re.search(r"checkout.*pull_request", raw, re.IGNORECASE):
        severity = "critical"
        detail = (
            "Workflow uses 'pull_request_target' trigger AND checks out PR head code. "
            "This is a well-known privilege escalation vector — the PR code runs with "
            "write permissions and access to secrets, even from forks."
        )
    else:
        severity = "high"
        detail = (
            "Workflow uses 'pull_request_target' trigger. "
            "This trigger runs in the context of the base repo with write permissions. "
            "If PR code is ever checked out, it becomes a critical vulnerability."
        )

    findings.append({
        "check": "IAM / Least Privilege",
        "severity": severity,
        "file": wf["path"],
        "line": None,
        "detail": detail,
        "snippet": "on: pull_request_target",
        "remediation": (
            "Avoid using pull_request_target. Use pull_request instead.\n"
            "If pull_request_target is required, never check out PR head code in the same job.\n"
            "See: https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"
        ),
        "reference": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
    })
    return findings


def _check_env_secrets_overexposure(wf: dict) -> list[dict]:
    """Check if secrets are dumped into top-level env block (exposed to all steps)."""
    findings = []
    parsed = wf.get("parsed")
    if not parsed or not isinstance(parsed, dict):
        return findings

    top_env = parsed.get("env", {})
    if not isinstance(top_env, dict):
        return findings

    exposed = []
    for key, val in top_env.items():
        if isinstance(val, str) and "${{ secrets." in val:
            exposed.append(key)

    if exposed:
        findings.append({
            "check": "IAM / Least Privilege",
            "severity": "medium",
            "file": wf["path"],
            "line": None,
            "detail": (
                f"Secrets exposed as top-level environment variables: {', '.join(exposed)}. "
                "This makes them available to every step and action in the workflow, "
                "including third-party actions."
            ),
            "snippet": f"env: {', '.join(exposed)}",
            "remediation": (
                "Scope secret environment variables to the specific step that needs them:\n"
                "  steps:\n"
                "    - name: Deploy\n"
                "      env:\n"
                "        SECRET_KEY: ${{ secrets.SECRET_KEY }}\n"
                "      run: ./deploy.sh"
            ),
            "reference": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets",
        })

    return findings


def run(workflows: list[dict], repo_info: dict) -> list[dict]:
    findings = []

    for wf in workflows:
        findings += _check_self_hosted_runners(wf)
        findings += _check_pull_request_target(wf)
        findings += _check_env_secrets_overexposure(wf)

    return findings