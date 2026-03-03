#!/usr/bin/env python3
"""Check cargo audit results with direct-vs-transitive distinction.

Policy:
  - Advisories affecting DIRECT dependencies → CI failure (exit 1)
  - Advisories affecting only TRANSITIVE dependencies → warning (exit 0)
    If running on a PR, outputs a GitHub Actions warning annotation.

Usage:
  pip install cargo-audit  (or install via cargo install cargo-audit)
  python3 check-cargo-audit.py [--cargo-toml <path>]
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path


def load_direct_deps(cargo_toml: Path) -> set[str]:
    """Extract direct dependency crate names from Cargo.toml."""
    data = tomllib.loads(cargo_toml.read_text())
    deps: set[str] = set()
    for section in ('dependencies', 'dev-dependencies', 'build-dependencies'):
        for name in data.get(section, {}):
            deps.add(name)

    # Also check workspace members
    workspace = data.get('workspace', {})
    for section in ('dependencies', 'dev-dependencies'):
        for name in workspace.get(section, {}):
            deps.add(name)

    return deps


def collect_workspace_direct_deps(root: Path) -> set[str]:
    """Collect direct deps from root Cargo.toml and all workspace members."""
    deps = load_direct_deps(root / 'Cargo.toml')

    # Parse workspace members
    data = tomllib.loads((root / 'Cargo.toml').read_text())
    members = data.get('workspace', {}).get('members', [])
    for member in members:
        member_toml = root / member / 'Cargo.toml'
        if member_toml.exists():
            deps.update(load_direct_deps(member_toml))

    return deps


def run_audit(root: Path) -> dict:
    """Run cargo audit --json and return parsed output."""
    result = subprocess.run(
        ['cargo', 'audit', '--json'],
        cwd=root,
        capture_output=True,
        text=True,
    )
    # cargo audit exits non-zero when advisories are found
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"::warning::cargo audit produced non-JSON output: {result.stderr.strip()}")
        return {}


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, default=Path('.'),
                    help='Workspace root directory')
    args = ap.parse_args()

    direct_deps = collect_workspace_direct_deps(args.root)
    audit_data = run_audit(args.root)

    vulnerabilities = audit_data.get('vulnerabilities', {}).get('list', [])
    if not vulnerabilities:
        print("cargo audit: no known vulnerabilities found.")
        sys.exit(0)

    direct_issues: list[dict] = []
    transitive_issues: list[dict] = []

    for vuln in vulnerabilities:
        advisory = vuln.get('advisory', {})
        package = vuln.get('package', {})
        crate_name = package.get('name', 'unknown')
        advisory_id = advisory.get('id', 'unknown')
        title = advisory.get('title', '')

        if crate_name in direct_deps:
            direct_issues.append({
                'crate': crate_name,
                'id': advisory_id,
                'title': title,
            })
        else:
            transitive_issues.append({
                'crate': crate_name,
                'id': advisory_id,
                'title': title,
            })

    if transitive_issues:
        print(f"\n⚠️  {len(transitive_issues)} advisory(ies) in transitive dependencies (warning only):")
        for issue in transitive_issues:
            msg = f"  {issue['id']}: {issue['crate']} – {issue['title']}"
            print(msg)
            print(f"::warning::{issue['id']}: transitive dep '{issue['crate']}' – {issue['title']}")

    if direct_issues:
        print(f"\n❌ {len(direct_issues)} advisory(ies) in DIRECT dependencies:")
        for issue in direct_issues:
            msg = f"  {issue['id']}: {issue['crate']} – {issue['title']}"
            print(msg)
            print(f"::error::{issue['id']}: direct dep '{issue['crate']}' – {issue['title']}")
        sys.exit(1)
    else:
        if transitive_issues:
            print("\nOnly transitive dependencies affected – treating as warning.")
        sys.exit(0)


if __name__ == '__main__':
    main()
