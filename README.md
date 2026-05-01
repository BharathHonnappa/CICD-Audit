# CI/CD Pipeline Security Auditor

A CLI tool that audits GitHub Actions workflows for supply chain risks, hardcoded secrets, IAM misconfigurations, and missing security controls.

> **Honest note:** This is a learning project. GitHub already ships GHAS, CodeQL, and secret scanning natively. This tool exists because building something yourself teaches you things that using existing tools never will.

---

## What It Checks

| Category | Severity |
|---|---|
| 🔐 Hardcoded secrets (AWS keys, tokens, passwords) | Critical / High |
| 🔗 Unpinned third-party actions (supply chain risk) | Critical / High |
| 🪪 Overpermissioned GITHUB_TOKEN | High / Medium |
| 🛡 Missing SAST / secret scanning / dependency review | High / Medium |
| 🌿 Branch protection missing or misconfigured | Critical / High |
| 👤 Self-hosted runners, pull_request_target misuse | Critical / Medium |
| ℹ️  Unpinned official GitHub actions (actions/*) | Info only |

Known gaps: script injection detection, cross-workflow analysis, GitLab/Bitbucket support, Kubernetes manifests, container images.

---

## How It Works — File Breakdown

```
cicd-auditor/
├── main.py                                   # CLI entry point + token management
├── requirements.txt
├── README.md
└── auditor/
    ├── core.py                               # GitHub API fetcher + check orchestrator
    ├── reporter.py                           # Colored terminal output + risk scoring
    └── checks/
        ├── check_secrets.py                  # Hardcoded credential detection
        ├── check_unpinned_actions.py         # Supply chain / action pinning
        ├── check_overpermissioned_tokens.py  # GITHUB_TOKEN permissions
        ├── check_missing_sast.py             # Shift-left security step detection
        ├── check_branch_protection.py        # Branch integrity checks
        └── check_iam_least_privilege.py      # Runner & trigger privilege checks
```

### `main.py`
CLI entry point. Handles argument parsing, token management, and first-time setup wizard. Saves your GitHub token to `~/.cicd-auditor/config.json` with `600` permissions so you don't have to paste it every time.

### `auditor/core.py`
Fetches all data from the GitHub API — repo metadata, workflow YAML files, and branch protection rules. Orchestrates all checks and returns a unified findings list.

### `auditor/reporter.py`
Handles all terminal output with ANSI colors and a risk score calculated from finding severities. Weights: Critical=40, High=20, Medium=10, Low=5, Info=0 (capped at 100).

---

### `auditor/checks/check_secrets.py`
Scans workflow files line by line for hardcoded credentials using regex patterns. Uses a safe-line filter to skip lines that correctly reference `${{ secrets.X }}`.

Patterns detected:

| Pattern | Severity |
|---|---|
| AWS Access Key (`AKIA[0-9A-Z]{16}`) | Critical |
| AWS Secret Key | Critical |
| GitHub Token classic (`ghp_`) | Critical |
| GitHub Fine-grained Token (`github_pat_`) | Critical |
| Private Key Header (`-----BEGIN ... PRIVATE KEY-----`) | Critical |
| Stripe Key (`sk_live_` / `sk_test_`) | Critical |
| Slack Webhook URL | High |
| Generic API Key | High |
| Generic Password | High |
| Generic Secret/Token | Medium |

> ⚠️ Uses regex pattern matching, not entropy analysis. Will produce false positives on placeholder values like `password="test123"`. Verify every finding manually. Tools like Gitleaks and TruffleHog use entropy-based detection which is significantly more accurate.

---

### `auditor/checks/check_unpinned_actions.py`
Checks every `uses:` line for mutable refs. A full 40-character commit SHA is the only safe ref — everything else (branch names, version tags) can be silently changed by the action author.

| Ref type | Example | Severity |
|---|---|---|
| Mutable branch | `@main`, `@master` | Critical (third-party) / Info (official) |
| Major version tag | `@v2`, `@v3` | High (third-party) / Info (official) |
| Minor version tag | `@v2.1.0` | Medium (third-party) / Info (official) |
| Full commit SHA | `@a81bbbf8...` | OK — not flagged |

Official GitHub actions (`actions/*`, `github/*`) are downgraded to Info since they are maintained by GitHub and lower risk than third-party actions.

---

### `auditor/checks/check_overpermissioned_tokens.py`
Parses the `permissions:` block at both workflow and job level. Flags `write-all` as Critical, missing permissions blocks as High (token inherits repo defaults which may be write), and unnecessary `write` scopes as Medium.

---

### `auditor/checks/check_missing_sast.py`
Searches all workflow files for known security tool signatures. Flags missing categories as High (SAST, secret scanning) or Medium (dependency review).

Recognises: CodeQL, Semgrep, TruffleHog, Gitleaks, GitGuardian, Snyk, Trivy, Anchore, Checkov, dependency-review-action, and more.

---

### `auditor/checks/check_branch_protection.py`
Fetches branch protection rules via the GitHub API. Severity is context-aware:

- **Private repo + no protection → Critical** — any push access = direct production deploy
- **Public repo + no protection → Medium** — common in open source by design

Also checks for: stale review dismissal, required status checks, admin enforcement, and force push permissions.

---

### `auditor/checks/check_iam_least_privilege.py`
Checks three privilege escalation patterns:

- **Self-hosted runners** — can expose secrets to the host machine, persistent across jobs
- **`pull_request_target` trigger** — runs with write permissions even for fork PRs, dangerous if PR code is checked out in the same job
- **Top-level `env:` secrets** — secrets in the workflow-level env block are exposed to every step including third-party actions

---

## Install

```bash
git clone https://github.com/BharathHonnappa/cicd-auditor
cd cicd-auditor
pip install -r requirements.txt
```

---

## Usage

```bash
# First run — wizard guides you through token setup
python3 main.py --repo owner/repo

# Filter by severity
python3 main.py --repo owner/repo --severity high

# Include info-level findings
python3 main.py --repo owner/repo --severity info

# Export to JSON
python3 main.py --repo owner/repo --json-out results.json

# Update or remove saved token
python3 main.py --update-token github_pat_xxxx
python3 main.py --delete-token
```

---

## Roadmap

- [ ] Script injection detection
- [ ] GitLab CI / Bitbucket / Azure DevOps support
- [ ] Kubernetes manifest auditing
- [ ] Container image scanning
- [ ] Bulk org scanning

---

## Author

Bharath H

---

## Disclaimer

This tool is intended for educational purposes and authorized security research only.
Only scan repositories you own or have explicit permission to audit.
The author is not responsible for any misuse or damage caused by this tool.
