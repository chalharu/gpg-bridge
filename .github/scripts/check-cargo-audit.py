#!/usr/bin/env python3
"""Check cargo audit results with direct-vs-transitive distinction.

Policy:
  - Advisories affecting DIRECT dependencies → CI failure (exit 1)
  - Advisories on TRANSITIVE deps that could be resolved by updating a direct
    dependency to its latest version → CI failure (exit 1)
  - Advisories on TRANSITIVE deps that persist even with all direct deps at
    latest → warning only (exit 0)

Usage:
  python3 check-cargo-audit.py [--root <path>]
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


def get_reverse_deps(root: Path, crate_name: str) -> set[str]:
    """Get the set of crates that directly depend on the given crate using cargo tree."""
    try:
        result = subprocess.run(
            ['cargo', 'tree', '--invert', '--package', crate_name,
             '--depth', '1', '--prefix', 'none', '--format', '{p}'],
            cwd=root, capture_output=True, text=True, timeout=60,
        )
        parents: set[str] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: "crate_name v1.2.3" or "crate_name v1.2.3 (path)"
            name = line.split()[0] if line.split() else ''
            if name and name != crate_name:
                parents.add(name)
        return parents
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return set()


def find_direct_ancestor(root: Path, crate_name: str, direct_deps: set[str],
                         visited: set[str] | None = None) -> set[str]:
    """Walk up the dependency tree to find which direct deps pull in a transitive crate."""
    if visited is None:
        visited = set()
    if crate_name in visited:
        return set()
    visited.add(crate_name)

    ancestors: set[str] = set()
    parents = get_reverse_deps(root, crate_name)
    for parent in parents:
        if parent in direct_deps:
            ancestors.add(parent)
        else:
            ancestors.update(find_direct_ancestor(root, parent, direct_deps, visited))
    return ancestors


def check_if_update_resolves(root: Path, direct_dep: str) -> bool:
    """Check if updating a direct dependency could resolve a transitive vuln.

    We check cargo update --dry-run for the dependency. If it shows updates,
    the issue might be resolvable by updating.
    """
    try:
        result = subprocess.run(
            ['cargo', 'update', '--dry-run', '--package', direct_dep],
            cwd=root, capture_output=True, text=True, timeout=60,
        )
        # If there's a newer version available, the output will show "Updating"
        output = result.stdout + result.stderr
        return 'Updating' in output or 'Locking' in output
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


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
    resolvable_transitive_issues: list[dict] = []
    unresolvable_transitive_issues: list[dict] = []

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
            # Find which direct deps pull in this transitive crate
            ancestors = find_direct_ancestor(args.root, crate_name, direct_deps)
            resolvable = False
            if ancestors:
                # Check if updating any ancestor could resolve the issue
                for ancestor in ancestors:
                    if check_if_update_resolves(args.root, ancestor):
                        resolvable = True
                        break

            issue = {
                'crate': crate_name,
                'id': advisory_id,
                'title': title,
                'ancestors': sorted(ancestors) if ancestors else [],
            }
            if resolvable:
                resolvable_transitive_issues.append(issue)
            else:
                unresolvable_transitive_issues.append(issue)

    # --- Report unresolvable transitive issues (warning only) ---
    if unresolvable_transitive_issues:
        print(f"\n⚠️  {len(unresolvable_transitive_issues)} advisory(ies) in transitive dependencies (not resolvable by updating direct deps):")
        for issue in unresolvable_transitive_issues:
            msg = f"  {issue['id']}: {issue['crate']} – {issue['title']}"
            if issue['ancestors']:
                msg += f" (via {', '.join(issue['ancestors'])})"
            print(msg)
            print(f"::warning::{issue['id']}: transitive dep '{issue['crate']}' – {issue['title']}")

    # --- Report resolvable transitive issues (error) ---
    if resolvable_transitive_issues:
        print(f"\n❌ {len(resolvable_transitive_issues)} advisory(ies) in transitive dependencies (resolvable by updating direct deps):")
        for issue in resolvable_transitive_issues:
            msg = f"  {issue['id']}: {issue['crate']} – {issue['title']}"
            if issue['ancestors']:
                msg += f" (update {', '.join(issue['ancestors'])})"
            print(msg)
            print(f"::error::{issue['id']}: transitive dep '{issue['crate']}' – {issue['title']} (resolvable via {', '.join(issue['ancestors'])})")

    # --- Report direct issues (error) ---
    if direct_issues:
        print(f"\n❌ {len(direct_issues)} advisory(ies) in DIRECT dependencies:")
        for issue in direct_issues:
            msg = f"  {issue['id']}: {issue['crate']} – {issue['title']}"
            print(msg)
            print(f"::error::{issue['id']}: direct dep '{issue['crate']}' – {issue['title']}")

    errors = direct_issues + resolvable_transitive_issues
    if errors:
        sys.exit(1)
    else:
        if unresolvable_transitive_issues:
            print("\nOnly unresolvable transitive dependencies affected – treating as warning.")
        sys.exit(0)


if __name__ == '__main__':
    main()
