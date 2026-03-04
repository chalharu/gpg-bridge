#!/usr/bin/env python3
"""Check Dart/Flutter dependency health.

Policy:
  - Discontinued DIRECT dependencies → CI failure (exit 1)
  - Outdated direct dependencies with resolvable updates → warning
  - Outdated transitive dependencies → warning

Usage:
  python3 check-dart-deps.py [--project-dir <path>]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


def _load_direct_deps_yaml(pubspec: Path) -> set[str]:
    """Extract direct dependency names from pubspec.yaml using PyYAML."""
    data = yaml.safe_load(pubspec.read_text())
    deps: set[str] = set()
    for section in ('dependencies', 'dev_dependencies'):
        section_data = data.get(section)
        if isinstance(section_data, dict):
            deps.update(section_data.keys())
    return deps


def _load_direct_deps_fallback(pubspec: Path) -> set[str]:
    """Extract direct dependency names from pubspec.yaml (simple parser fallback)."""
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
            indent = len(line) - len(line.lstrip())
            if section_indent is None:
                section_indent = indent
            if indent == 0 and stripped and not stripped.startswith('#'):
                in_section = False
                continue
            if indent == section_indent:
                name = stripped.split(':')[0].strip()
                if name and not name.startswith('#'):
                    deps.add(name)

    return deps


def load_direct_deps(pubspec: Path) -> set[str]:
    """Extract direct dependency names from pubspec.yaml."""
    if _HAS_YAML:
        return _load_direct_deps_yaml(pubspec)
    return _load_direct_deps_fallback(pubspec)


def run_outdated_all(project_dir: Path) -> dict:
    """Run dart pub outdated --json (including dev deps)."""
    try:
        result = subprocess.run(
            ['dart', 'pub', 'outdated', '--json'],
            cwd=project_dir,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print('::error::dart not found on PATH — cannot check dependencies')
        sys.exit(1)
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
    # No valid JSON found
    stderr_msg = result.stderr.strip() if result.stderr else '(no stderr)'
    print(f'::error::dart pub outdated produced no valid JSON (exit {result.returncode}): {stderr_msg}')
    sys.exit(1)


def main() -> None:
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
    outdated_data = run_outdated_all(project_dir)

    packages = outdated_data.get('packages', [])
    if not packages:
        print("Dart dependency check: all dependencies are up to date.")
        sys.exit(0)

    discontinued_direct: list[dict] = []
    outdated_direct: list[dict] = []
    outdated_transitive: list[dict] = []

    for pkg in packages:
        name = pkg.get('package', '')
        current_info = pkg.get('current') or {}
        current = current_info.get('version', 'unknown') if isinstance(current_info, dict) else 'unknown'
        resolvable_info = pkg.get('resolvable') or {}
        resolvable = resolvable_info.get('version') if isinstance(resolvable_info, dict) else None
        latest_info = pkg.get('latest') or {}
        latest = latest_info.get('version') if isinstance(latest_info, dict) else None
        is_discontinued = pkg.get('isDiscontinued', False)

        # Only flag if there's an upgrade available beyond current
        if not resolvable or resolvable == current:
            # Still check for discontinued even if no update available
            if is_discontinued and name in direct_deps:
                discontinued_direct.append({
                    'name': name, 'current': current,
                    'resolvable': resolvable, 'latest': latest,
                })
            continue

        info = {
            'name': name,
            'current': current,
            'resolvable': resolvable,
            'latest': latest,
        }

        if name in direct_deps:
            if is_discontinued:
                discontinued_direct.append(info)
            else:
                outdated_direct.append(info)
        else:
            outdated_transitive.append(info)

    # --- Report outdated transitive (warning) ---
    if outdated_transitive:
        print(f"\n⚠️  {len(outdated_transitive)} transitive dependency update(s) available:")
        for issue in outdated_transitive:
            msg = f"  {issue['name']}: {issue['current']} → {issue['resolvable']}"
            print(msg)
            print(f"::warning::{issue['name']} {issue['current']} → {issue['resolvable']}")

    # --- Report outdated direct (warning) ---
    if outdated_direct:
        print(f"\n⚠️  {len(outdated_direct)} direct dependency update(s) available:")
        for issue in outdated_direct:
            msg = f"  {issue['name']}: {issue['current']} → {issue['resolvable']}"
            print(msg)
            print(f"::warning::{issue['name']} {issue['current']} → {issue['resolvable']}")

    # --- Report discontinued direct (error) ---
    if discontinued_direct:
        print(f"\n❌ {len(discontinued_direct)} discontinued DIRECT dependency(ies):")
        for issue in discontinued_direct:
            msg = f"  {issue['name']}: {issue['current']} [DISCONTINUED]"
            print(msg)
            print(f"::error::{issue['name']} {issue['current']} [DISCONTINUED]")
        sys.exit(1)

    total_warnings = len(outdated_direct) + len(outdated_transitive)
    if total_warnings > 0:
        print(f"\n{total_warnings} dependency update(s) available (warnings only).")
    else:
        print("Dart dependency check: all dependencies are up to date.")
    sys.exit(0)


if __name__ == '__main__':
    main()
