# CI/CD Pipeline Security Auditor

A command-line tool that audits GitHub Actions workflows for supply chain risks,
secret leakage, IAM misconfigurations, and missing security controls.

Built as a **learning project** to understand how CI/CD pipelines become attack
surfaces — and what misconfigured pipelines actually look like in the real world.

---

## Honest Disclaimer

This tool is **not** a replacement for GitHub Advanced Security (GHAS), CodeQL,
or any enterprise-grade security tooling. GitHub already ships secret scanning,
dependency review, and code scanning natively for free on public repos.

What this tool is:

- A personal learning exercise in DevSecOps and supply chain security
- A way to understand what pipeline misconfigurations look like at the YAML level
- A starting point for thinking about CI/CD security beyond just "does the code work"
- Practice building a real security tool from scratch rather than using existing ones

What this tool is **not**:

- Production-ready security tooling
- A replacement for GitHub Advanced Security
- Capable of runtime analysis or dynamic scanning
- Aware of context it reads static YAML and flags patterns, it does not understand intent

If you are a company looking for CI/CD security tooling, use GHAS, Semgrep,
or Snyk. This tool exists because building something yourself teaches you
things that using existing tools never will.

---

## What It Checks

| Category | Checks | Severity |
|---|---|---|
| 🔐 **Hardcoded Secrets** | AWS keys, GitHub tokens, API keys, passwords in workflow YAML | Critical / High |
| 🔗 **Supply Chain** | Third-party actions using mutable refs (@main, @v2) | Critical / High |
| ℹ️  **Official Actions** | GitHub's own actions (actions/*) using version tags | Info only |
| 🪪 **Overpermissioned Tokens** | write-all, missing permissions blocks, unnecessary write scopes | High / Medium |
| 🛡 **Missing Security Steps** | No SAST, no secret scanning, no dependency review in pipeline | High / Medium |
| 🌿 **Branch Protection** | Missing PR reviews, no status checks, force pushes allowed | Critical / High |
| 👤 **IAM / Least Privilege** | Self-hosted runners, pull_request_target misuse, env-level secret overexposure | Critical / Medium |

Each finding includes severity, file, line number, plain-English explanation,
remediation steps, and a link to official GitHub documentation.

### What it does NOT check

- **Script injection** — `${{ github.event.issue.title }}` used directly in `run:` blocks
  is a real critical vulnerability class that this tool currently misses entirely
- **Workflow dependency chains** — a workflow calling another workflow is not analyzed cross-file
- **Runtime behavior** — secrets constructed dynamically or split across env vars
- **Repository settings** — outside of branch protection, repo-level security settings are not audited
- **Non-GitHub platforms** — GitLab CI, Bitbucket Pipelines, Azure DevOps, Jenkins not supported yet
- **Kubernetes manifests** — cluster misconfigurations, RBAC issues, pod security are out of scope
- **Container images** — image vulnerabilities, Dockerfile misconfigs are a separate problem

These are known gaps, not oversights. They are on the roadmap.

---

## Why I Built This Instead of Using Existing Tools

The best way to understand how something can go wrong is to build the thing that
detects it going wrong. Reading about supply chain attacks is one thing. Writing
a check that catches `actions/checkout@main` and understanding *why* that is
dangerous is another.

This project came out of:
- Solving HTB machines weekly and wanting to understand the DevSecOps side of security
- Learning about the tj-actions/changed-files supply chain attack (2024) and the
  XZ Utils backdoor and wanting to understand how those pipeline vectors actually work
- Wanting something on my portfolio that shows I understand security beyond just
  running existing tools

---

## Install

```bash
git clone https://github.com/BharathHonnappa/cicd-auditor
cd cicd-auditor
pip install -r requirements.txt
```

Requirements: Python 3.10+, `requests`, `PyYAML`

---

## Usage

```bash
# Save token once — never type it again
python3 main.py --token ghp_xxxx --save-token

# Audit any repo
python3 main.py --repo owner/repo

# Show only high and critical findings
python3 main.py --repo owner/repo --severity high

# Include informational findings (unpinned official actions etc.)
python3 main.py --repo owner/repo --severity info

# Export results to JSON
python3 main.py --repo owner/repo --json-out results.json

# Update saved token
python3 main.py --update-token ghp_newtoken

# Remove saved token
python3 main.py --delete-token
```

### Getting a GitHub Token

1. GitHub → Settings → Developer Settings → Personal Access Tokens → Fine-grained tokens
2. Permissions needed: `Contents: Read`, `Actions: Read`, `Administration: Read`

Works on both public and private repos your token has access to.

---

## Risk Score

| Severity | Weight | Meaning |
|---|---|---|
| Critical | 40 | Immediate risk, likely exploitable |
| High | 20 | Significant misconfiguration |
| Medium | 10 | Best practice violation |
| Low | 5 | Minor hardening gap |
| Info | 0 | Noted but does not affect score |

| Score | Risk Level |
|---|---|
| 70–100 | 💀 Critical Risk |
| 40–69 | 🔴 High Risk |
| 20–39 | 🟡 Medium Risk |
| 1–19 | 🔵 Low Risk |
| 0 | ✅ Clean |

---

## Limitations I Discovered While Building This

**False positives on overpermissioned tokens:**
Many repos legitimately need `issues: write` or `pull-requests: write` for triage
automation. The tool flags these as medium findings but context matters — a bot
that labels issues needs write access. The tool cannot distinguish intentional
from accidental permissions.

**Branch protection on public repos:**
Most open source projects including large ones like GitHub's own `cli/cli` have
no branch protection on their default branch. This scores as CRITICAL in the tool
but is often an intentional trade-off for maintainer velocity, not negligence.

**Secret detection false positives:**
Regex-based secret detection will flag things that look like secrets but aren't.
Entropy-based detection (what Gitleaks and TruffleHog use) is significantly more
accurate. This tool uses simple pattern matching.

---

## Project Structure

```
cicd-auditor/
├── main.py                               # CLI entry point + token management
├── requirements.txt
├── README.md
└── auditor/
    ├── core.py                           # GitHub API fetcher + orchestrator
    ├── reporter.py                       # Colored terminal output + JSON export
    └── checks/
        ├── check_secrets.py              # Hardcoded credential detection
        ├── check_unpinned_actions.py     # Supply chain / action pinning
        ├── check_overpermissioned_tokens.py  # GITHUB_TOKEN permissions
        ├── check_missing_sast.py         # Shift-left security step detection
        ├── check_branch_protection.py    # Branch integrity checks
        └── check_iam_least_privilege.py  # Runner & trigger privilege checks
```

---

## Roadmap

- [ ] Script injection detection (`${{ github.event.* }}` in `run:` blocks)
- [ ] GitLab CI support (`.gitlab-ci.yml`)
- [ ] Bitbucket Pipelines support
- [ ] Azure DevOps (`azure-pipelines.yml`)
- [ ] Kubernetes manifest auditing (pod security, RBAC, network policies)
- [ ] Container image scanning (Dockerfile misconfigs, CVEs)
- [ ] Bulk org scanning — audit every repo in a GitHub org at once
- [ ] SARIF output — upload findings to GitHub Security tab
- [ ] Reduce false positives on permission checks with context awareness

---

## Author

Bharath H

