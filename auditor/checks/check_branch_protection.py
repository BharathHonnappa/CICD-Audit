"""
Check: Branch protection rules on the default branch.

Severity is context-aware:
- Private repos: missing branch protection is CRITICAL — direct pushes bypass
  all security controls on production code in a company setting.
- Public repos: flagged as MEDIUM — commonly intentional in open source projects
  where maintainers prioritize velocity over strict review gates.
"""


def run(protection: dict | None, branch: str, is_private: bool = False) -> list[dict]:
    findings = []

    if protection is None:
        if is_private:
            severity = "critical"
            context = (
                "This is a private repository — direct pushes to the default branch "
                "bypass all CI/CD security checks and code review. "
                "Any compromised account with push access can deploy directly to production."
            )
        else:
            severity = "medium"
            context = (
                "This is a public repository — missing branch protection is common "
                "in open source projects by design. If this repo deploys to production, "
                "consider enabling branch protection."
            )

        findings.append({
            "check": "Branch Protection",
            "severity": severity,
            "file": f"branch: {branch}",
            "line": None,
            "detail": (
                f"No branch protection rules found on '{branch}'. "
                f"Direct pushes are allowed. {context}"
            ),
            "snippet": None,
            "remediation": (
                f"Enable branch protection on '{branch}':\n"
                "  - Require pull request reviews before merging\n"
                "  - Require status checks to pass before merging\n"
                "  - Restrict who can push to this branch\n"
                "  Settings → Branches → Add branch protection rule"
            ),
            "reference": "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches",
        })
        return findings

    # Check: require PR reviews
    pr_reviews = protection.get("required_pull_request_reviews")
    if not pr_reviews:
        findings.append({
            "check": "Branch Protection",
            "severity": "high",
            "file": f"branch: {branch}",
            "line": None,
            "detail": f"Pull request reviews are not required before merging to '{branch}'.",
            "snippet": "required_pull_request_reviews: null",
            "remediation": "Enable 'Require pull request reviews before merging' in branch protection settings.",
            "reference": "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches",
        })
    else:
        # Check: dismiss stale reviews
        if not pr_reviews.get("dismiss_stale_reviews"):
            findings.append({
                "check": "Branch Protection",
                "severity": "medium",
                "file": f"branch: {branch}",
                "line": None,
                "detail": (
                    "'Dismiss stale pull request approvals when new commits are pushed' is disabled. "
                    "An approved PR can be updated with malicious commits after approval."
                ),
                "snippet": "dismiss_stale_reviews: false",
                "remediation": "Enable 'Dismiss stale pull request approvals when new commits are pushed'.",
                "reference": "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches",
            })

        # Check: require code owner review
        if not pr_reviews.get("require_code_owner_reviews"):
            findings.append({
                "check": "Branch Protection",
                "severity": "low",
                "file": f"branch: {branch}",
                "line": None,
                "detail": "Code owner reviews are not required. Changes to sensitive files can be approved by anyone.",
                "snippet": "require_code_owner_reviews: false",
                "remediation": "Enable 'Require review from code owners' and set up a CODEOWNERS file.",
                "reference": "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners",
            })

    # Check: require status checks
    status_checks = protection.get("required_status_checks")
    if not status_checks:
        findings.append({
            "check": "Branch Protection",
            "severity": "high",
            "file": f"branch: {branch}",
            "line": None,
            "detail": f"No required status checks on '{branch}'. PRs can merge even if CI/CD checks fail.",
            "snippet": "required_status_checks: null",
            "remediation": (
                "Add required status checks in branch protection settings.\n"
                "Include your security scan jobs (SAST, secret scan, tests) as required checks."
            ),
            "reference": "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches",
        })
    else:
        if not status_checks.get("strict"):
            findings.append({
                "check": "Branch Protection",
                "severity": "medium",
                "file": f"branch: {branch}",
                "line": None,
                "detail": (
                    "Status checks do not require branches to be up to date before merging. "
                    "A branch passing checks on old base code may introduce regressions."
                ),
                "snippet": "strict: false",
                "remediation": "Enable 'Require branches to be up to date before merging'.",
                "reference": "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches",
            })

    # Check: enforce admins
    enforce_admins = protection.get("enforce_admins", {})
    if isinstance(enforce_admins, dict) and not enforce_admins.get("enabled"):
        findings.append({
            "check": "Branch Protection",
            "severity": "medium",
            "file": f"branch: {branch}",
            "line": None,
            "detail": (
                "Branch protection rules are not enforced for administrators. "
                "Admins can push directly to the protected branch, bypassing all checks."
            ),
            "snippet": "enforce_admins: false",
            "remediation": "Enable 'Do not allow bypassing the above settings' (enforce admins).",
            "reference": "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches",
        })

    # Check: allow force pushes
    allow_force_pushes = protection.get("allow_force_pushes", {})
    if isinstance(allow_force_pushes, dict) and allow_force_pushes.get("enabled"):
        findings.append({
            "check": "Branch Protection",
            "severity": "high",
            "file": f"branch: {branch}",
            "line": None,
            "detail": (
                f"Force pushes are allowed on '{branch}'. "
                "This lets users rewrite history, erase audit trails, and bypass review."
            ),
            "snippet": "allow_force_pushes: true",
            "remediation": "Disable 'Allow force pushes' in branch protection settings.",
            "reference": "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches",
        })

    return findings
