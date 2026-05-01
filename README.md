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
