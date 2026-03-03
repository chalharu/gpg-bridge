#!/usr/bin/env python3
"""Check Dart/Flutter dependency health with direct-vs-transitive distinction.

Policy:
  - Outdated or insecure DIRECT dependencies with available resolutions → CI failure
  - Issues in TRANSITIVE dependencies that could be resolved by updating a
    direct dependency → CI failure
  - Issues in TRANSITIVE deps that persist even after updating all direct deps → warning

Usage:
  python3 check-dart-deps.py [--project-dir <path>]
"""

from __future__ import annotations

import json
import subprocess
import sys
import re
from pathlib import Path


def load_direct_deps(pubspec: Path) -> set[str]:
    """Extract direct dependency names from pubspec.yaml (simple YAML parse)."""
    deps: set[str] = set()
    in_section = False
    section_indent: int | None = None

    for line in pubspec.read_text().splitlines():
        stripped = line.strip()

        # Detect dependency sections
        if re.match(r'^(dependencies|dev_dependencies)\s*:', stripped):
            in_section = True
            section_indent = None
            continue

        if in_section:
            if not stripped or stripped.startswith('#'):
                continue
            # Detect indent level
            indent = len(line) - len(line.lstrip())
            if section_indent is None:
                section_indent = indent
            # End of section if indent returns to top-level
            if indent == 0 and stripped and not stripped.startswith('#'):
                in_section = False
                continue
            if indent == section_indent:
                # This is a dependency name
                name = stripped.split(':')[0].strip()
                if name and not name.startswith('#'):
                    deps.add(name)

    return deps


def run_outdated(project_dir: Path) -> dict:
    """Run dart pub outdated --json."""
    result = subprocess.run(
        ['dart', 'pub', 'outdated', '--json', '--no-dev-dependencies'],
        cwd=project_dir,
        capture_output=True,
        text=True,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        # Try to find JSON in the output (dart may prefix with non-JSON lines)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('{'):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        print(f"::warning::dart pub outdated produced non-JSON output")
        return {}


def run_outdated_all(project_dir: Path) -> dict:
    """Run dart pub outdated --json (including dev deps)."""
    result = subprocess.run(
        ['dart', 'pub', 'outdated', '--json'],
        cwd=project_dir,
        capture_output=True,
        text=True,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('{'):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return {}


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir', type=Path, default=Path('.'),
                    help='Flutter/Dart project directory')
    args = ap.parse_args()

    project_dir = args.project_dir
    pubspec = project_dir / 'pubspec.yaml'
    if not pubspec.exists():
        print(f"::error::pubspec.yaml not found at {pubspec}")
        sys.exit(1)

    direct_deps = load_direct_deps(pubspec)

    # Run outdated check twice: with and without --no-dev-dependencies
    # to get the full picture
    outdated_data = run_outdated_all(project_dir)
    # Also run with --no-transitive to understand direct dep situation
    outdated_no_dev = run_outdated(project_dir)

    packages = outdated_data.get('packages', [])
    if not packages:
        print("Dart dependency check: all dependencies are up to date.")
        sys.exit(0)

    # Build a lookup of direct dep packages and their resolvable versions
    direct_resolvable: dict[str, str | None] = {}
    for pkg in packages:
        name = pkg.get('package', '')
        if name in direct_deps:
            resolvable_info = pkg.get('resolvable') or {}
            r = resolvable_info.get('version') if isinstance(resolvable_info, dict) else None
            direct_resolvable[name] = r

    direct_issues: list[dict] = []
    resolvable_transitive_issues: list[dict] = []
    unresolvable_transitive_issues: list[dict] = []

    for pkg in packages:
        name = pkg.get('package', '')
        current_info = pkg.get('current') or {}
        current = current_info.get('version', 'unknown') if isinstance(current_info, dict) else 'unknown'
        resolvable_info = pkg.get('resolvable') or {}
        resolvable = resolvable_info.get('version') if isinstance(resolvable_info, dict) else None
        latest_info = pkg.get('latest') or {}
        latest = latest_info.get('version') if isinstance(latest_info, dict) else None

        # Only flag if there's an upgrade available beyond current
        if not resolvable or resolvable == current:
            continue

        # Check if this is a discontinued package
        is_discontinued = pkg.get('isDiscontinued', False)

        info = {
            'name': name,
            'current': current,
            'resolvable': resolvable,
            'latest': latest,
            'discontinued': is_discontinued,
        }

        if name in direct_deps:
            direct_issues.append(info)
        else:
            # Transitive dep: check if any direct dep has a pending update
            # If direct deps have updates available, updating them might resolve
            # this transitive dep issue
            has_updatable_direct = any(
                v is not None and v != 'unknown'
                for v in direct_resolvable.values()
                if v is not None
            )
            if has_updatable_direct:
                resolvable_transitive_issues.append(info)
            else:
                unresolvable_transitive_issues.append(info)

    # --- Report unresolvable transitive issues (warning only) ---
    if unresolvable_transitive_issues:
        print(f"\n⚠️  {len(unresolvable_transitive_issues)} transitive dependency update(s) (not resolvable by updating direct deps):")
        for issue in unresolvable_transitive_issues:
            disc = " [DISCONTINUED]" if issue['discontinued'] else ""
            msg = f"  {issue['name']}: {issue['current']} → {issue['resolvable']}{disc}"
            print(msg)
            print(f"::warning::{issue['name']} {issue['current']} → {issue['resolvable']}{disc}")

    # --- Report resolvable transitive issues (error) ---
    if resolvable_transitive_issues:
        print(f"\n❌ {len(resolvable_transitive_issues)} transitive dependency update(s) (resolvable by updating direct deps):")
        for issue in resolvable_transitive_issues:
            disc = " [DISCONTINUED]" if issue['discontinued'] else ""
            msg = f"  {issue['name']}: {issue['current']} → {issue['resolvable']}{disc}"
            print(msg)
            print(f"::error::{issue['name']} {issue['current']} → {issue['resolvable']}{disc}")

    # --- Report direct issues (error) ---
    if direct_issues:
        print(f"\n❌ {len(direct_issues)} direct dependency update(s) available:")
        for issue in direct_issues:
            disc = " [DISCONTINUED]" if issue['discontinued'] else ""
            msg = f"  {issue['name']}: {issue['current']} → {issue['resolvable']}{disc}"
            print(msg)
            print(f"::error::{issue['name']} {issue['current']} → {issue['resolvable']}{disc}")

    errors = direct_issues + resolvable_transitive_issues
    if errors:
        print(f"\n{len(errors)} dependency issue(s) require attention – failing CI.")
        sys.exit(1)
    else:
        if unresolvable_transitive_issues:
            print("\nOnly unresolvable transitive dependencies have updates – no action required.")
        else:
            print("Dart dependency check: all dependencies are up to date.")
        sys.exit(0)


if __name__ == '__main__':
    main()
