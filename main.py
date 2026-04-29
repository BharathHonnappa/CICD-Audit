#!/usr/bin/env python3
"""
CI/CD Pipeline Security Auditor
Audits GitHub repositories for supply chain and pipeline security risks.
"""

import argparse
import sys
import json
import getpass
from pathlib import Path
from auditor.core import PipelineAuditor
from auditor.reporter import Reporter

CONFIG_DIR  = Path.home() / ".cicd-auditor"
CONFIG_FILE = CONFIG_DIR / "config.json"

# ANSI colors for setup wizard (used before Reporter is initialized)
CYAN  = "\033[96m"
GREEN = "\033[92m"
GRAY  = "\033[90m"
BOLD  = "\033[1m"
RESET = "\033[0m"


# ── Token storage ────────────────────────────────────────────────────────────

def load_token() -> str | None:
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f).get("token")
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_token(token: str):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps({"token": token}, indent=2))
    CONFIG_FILE.chmod(0o600)  # owner read/write only
    print(f"\n  {GREEN}[✓]{RESET} Token saved to {CONFIG_FILE} (permissions: 600)")


def delete_token():
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
        print(f"  {GREEN}[✓]{RESET} Saved token deleted.")
    else:
        print("  [!] No saved token found.")


# ── First-time setup wizard ──────────────────────────────────────────────────

def run_setup_wizard() -> str:
    """
    Interactive wizard shown the first time a user runs the tool without a token.
    Walks them through getting a GitHub PAT and saves it locally.
    Returns the token string.
    """
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════╗
║           First-Time Setup — GitHub Token Required       ║
╚══════════════════════════════════════════════════════════╝{RESET}

  This tool needs a GitHub Personal Access Token (PAT) to
  read repository workflow files and branch protection rules.

  Your token is stored locally at:
  {GRAY}{CONFIG_FILE}{RESET}
  with file permissions 600 (only you can read it).
  It is never sent anywhere except the GitHub API.

{CYAN}{BOLD}  How to get your token:{RESET}

  Step 1 — Go to GitHub and log in
           https://github.com

  Step 2 — Open token settings
           github.com → Profile picture (top right)
           → Settings
           → Developer Settings (bottom of left sidebar)
           → Personal access tokens
           → Fine-grained tokens
           → Generate new token

  Step 3 — Configure the token
           • Token name: cicd-auditor (or anything you like)
           • Expiration: 90 days (recommended)
           • Resource owner: your account
           • Repository access: All repositories
             (or select specific repos)

  Step 4 — Set these permissions (under Repository permissions)
           • Contents          → Read-only
           • Actions           → Read-only
           • Administration    → Read-only  (for branch protection)

  Step 5 — Click "Generate token" and copy it
           ⚠  GitHub shows the token ONCE — copy it before closing

{CYAN}{'─' * 58}{RESET}""")

    while True:
        token = getpass.getpass("  Paste your token here (input hidden): ").strip()

        if not token:
            print("  [!] No token entered. Try again.")
            continue

        # Basic format validation
        if not (token.startswith("ghp_") or token.startswith("github_pat_")):
            print(f"\n  [!] That doesn't look like a GitHub token.")
            print(f"      Fine-grained tokens start with: github_pat_")
            print(f"      Classic tokens start with:      ghp_")
            retry = input("  Try again? (y/n): ").strip().lower()
            if retry != "y":
                sys.exit(1)
            continue

        save_token(token)
        print(f"  {GREEN}[✓]{RESET} Token accepted. You won't need to enter it again.\n")
        return token


# ── CLI argument parser ──────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="CI/CD Pipeline Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # First run — wizard will guide you through token setup
  python3 main.py --repo owner/repo

  # Scan with specific severity filter
  python3 main.py --repo owner/repo --severity high

  # Include informational findings (unpinned official actions)
  python3 main.py --repo owner/repo --severity info

  # Export results to JSON
  python3 main.py --repo owner/repo --json-out results.json

  # Update your saved token
  python3 main.py --update-token github_pat_xxxx

  # Delete your saved token
  python3 main.py --delete-token
        """
    )

    token_group = parser.add_mutually_exclusive_group()
    token_group.add_argument("--update-token", metavar="TOKEN", help="Replace the saved token with a new one")
    token_group.add_argument("--delete-token", action="store_true", help="Remove the saved token from disk")

    parser.add_argument("--repo", help="GitHub repo in owner/repo format (e.g. torvalds/linux)")
    parser.add_argument(
        "--severity", choices=["info", "low", "medium", "high", "critical"],
        default="low", help="Minimum severity to display (default: low)"
    )
    parser.add_argument("--json-out", metavar="FILE", help="Export results to a JSON file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    return parser.parse_args()


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    reporter = Reporter(use_color=not args.no_color)

    # ── Token management commands ────────────────────────────────────────────
    if args.delete_token:
        delete_token()
        sys.exit(0)

    if args.update_token:
        save_token(args.update_token)
        print(f"  [✓] Token updated successfully.")
        sys.exit(0)

    # ── Resolve token — wizard if missing ────────────────────────────────────
    token = load_token()

    if not token:
        token = run_setup_wizard()

    # ── Repo required for scanning ───────────────────────────────────────────
    if not args.repo:
        reporter.error(
            "--repo is required.\n"
            "  Example: python3 main.py --repo owner/repo"
        )
        sys.exit(2)

    # ── Run audit ────────────────────────────────────────────────────────────
    reporter.print_banner()

    try:
        auditor = PipelineAuditor(repo=args.repo, token=token, reporter=reporter)
        results = auditor.run_all_checks()
        reporter.print_report(results, min_severity=args.severity)

        if args.json_out:
            reporter.export_json(results, args.json_out)
            reporter.info(f"JSON results saved to {args.json_out}")

        critical_count = sum(1 for r in results if r["severity"] in ("critical", "high"))
        sys.exit(1 if critical_count > 0 else 0)

    except ValueError as e:
        reporter.error(str(e))
        sys.exit(2)
    except Exception as e:
        reporter.error(f"Unexpected error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()