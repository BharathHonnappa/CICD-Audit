"""
Core auditor — fetches GitHub repo data and orchestrates all checks.
"""

import base64
import yaml
import requests
from auditor.checks import (
    check_secrets,
    check_unpinned_actions,
    check_overpermissioned_tokens,
    check_missing_sast,
    check_branch_protection,
    check_iam_least_privilege,
)


GITHUB_API = "https://api.github.com"


class PipelineAuditor:
    def __init__(self, repo: str, token: str, reporter):
        self.repo = repo
        self.token = token
        self.reporter = reporter
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self._validate_repo()

    def _validate_repo(self):
        if "/" not in self.repo or self.repo.count("/") != 1:
            raise ValueError(f"Invalid repo format '{self.repo}'. Use owner/repo.")

    def _get(self, path: str, params: dict = None) -> dict | list:
        url = f"{GITHUB_API}{path}"
        resp = requests.get(url, headers=self.headers, params=params, timeout=15)
        if resp.status_code == 401:
            raise ValueError("GitHub token is invalid or expired.")
        if resp.status_code == 404:
            raise ValueError(f"Repo '{self.repo}' not found or token lacks access.")
        resp.raise_for_status()
        return resp.json()

    def fetch_repo_info(self) -> dict:
        return self._get(f"/repos/{self.repo}")

    def fetch_workflow_files(self) -> list[dict]:
        """Returns list of {name, path, content (parsed YAML), raw} dicts."""
        workflows = []
        try:
            items = self._get(f"/repos/{self.repo}/contents/.github/workflows")
        except Exception:
            return []

        for item in items:
            if not item["name"].endswith((".yml", ".yaml")):
                continue
            file_data = self._get(f"/repos/{self.repo}/contents/{item['path']}")
            raw = base64.b64decode(file_data["content"]).decode("utf-8", errors="replace")
            try:
                parsed = yaml.safe_load(raw)
            except yaml.YAMLError:
                parsed = None
            workflows.append({
                "name": item["name"],
                "path": item["path"],
                "raw": raw,
                "parsed": parsed,
            })
        return workflows

    def fetch_branch_protection(self, branch: str) -> dict | None:
        try:
            return self._get(f"/repos/{self.repo}/branches/{branch}/protection")
        except Exception:
            return None

    def fetch_default_branch(self, repo_info: dict) -> str:
        return repo_info.get("default_branch", "main")

    def run_all_checks(self) -> list[dict]:
        self.reporter.info(f"Auditing repository: {self.repo}")
        self.reporter.info("Fetching repository metadata...")

        repo_info = self.fetch_repo_info()
        default_branch = self.fetch_default_branch(repo_info)

        self.reporter.info(f"Default branch: {default_branch}")
        self.reporter.info("Fetching workflow files...")

        workflows = self.fetch_workflow_files()
        self.reporter.info(f"Found {len(workflows)} workflow file(s)")

        self.reporter.info("Fetching branch protection rules...")
        protection = self.fetch_branch_protection(default_branch)

        findings = []

        self.reporter.info("Running checks...\n")

        # Run all check modules
        findings += check_secrets.run(workflows)
        findings += check_unpinned_actions.run(workflows)
        findings += check_overpermissioned_tokens.run(workflows)
        findings += check_missing_sast.run(workflows)
        is_private = repo_info.get("private", False)
        findings += check_branch_protection.run(protection, default_branch, is_private)
        findings += check_iam_least_privilege.run(workflows, repo_info)

        return findings
