#!/usr/bin/env python3
"""Check file and function/method line counts for Rust and Dart.

Thresholds (configurable via CLI):
  --max-file-lines   200   (excluding import lines)
  --max-method-lines  30

Per-file override:   // ci:max-file-lines <N>
Per-method override: // ci:max-method-lines <N>   (place on the line immediately before fn/method)

For Rust files containing #[cfg(test)], production and test portions are
counted independently (each portion gets its own file-line budget).

Baseline:
  --baseline <path>   JSON file listing known violations.
                      Violations matching the baseline (same file, same or fewer lines)
                      are treated as warnings, not errors.  Only *new* or *worsened*
                      violations cause CI failure.
  --update-baseline   Overwrite the baseline file with current violations and exit 0.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    file: str
    line: int
    kind: str          # "file" or "method"
    name: str
    count: int
    limit: int

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: {self.kind} '{self.name}' is {self.count} lines (limit {self.limit})"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_OVERRIDE_RE = re.compile(r'//\s*ci:(max-file-lines|max-method-lines)\s+(\d+)')


def parse_override(line: str, key: str) -> Optional[int]:
    """Return override value if comment matches, else None."""
    m = _OVERRIDE_RE.search(line)
    if m and m.group(1) == key:
        return int(m.group(2))
    return None


def strip_strings_for_braces(line: str) -> str:
    """Remove string literals and line-comments so brace counting is safer."""
    out: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        # Single-line comment
        if ch == '/' and i + 1 < n and line[i + 1] == '/':
            break
        # Double-quoted string
        if ch == '"':
            i += 1
            while i < n and line[i] != '"':
                if line[i] == '\\':
                    i += 1
                i += 1
            i += 1  # skip closing quote
            continue
        # Single-quoted string / char literal
        if ch == "'":
            i += 1
            while i < n and line[i] != "'":
                if line[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


# ---------------------------------------------------------------------------
# Language-specific matchers
# ---------------------------------------------------------------------------

_RUST_IMPORT_RE = re.compile(
    r'^\s*(pub\s*(\(.*?\)\s*)?)?'
    r'(use|mod|extern\s+crate)\s+'
)

_RUST_FN_RE = re.compile(
    r'^\s*(pub\s*(\(.*?\)\s*)?)?'
    r'(async\s+)?(unsafe\s+)?(const\s+)?'
    r'fn\s+(?P<name>\w+)'
)

_RUST_CFG_TEST_RE = re.compile(r'^\s*#\[cfg\(test\)\]')

_DART_IMPORT_RE = re.compile(r'^\s*(import|export|part|library)\s+')

# Dart function/method heuristic:
# Requires at least a return-type word before the function name.
# Rejects chained method calls (e.g. hashInput.add), constructor invocations,
# and control-flow keywords.
_DART_CONTROL_FLOW = {'if', 'for', 'while', 'switch', 'catch', 'else', 'do', 'try'}
_DART_REJECT_PRECEDING = {'return', 'throw', 'yield', 'await', 'new', 'assert', 'const'}


def is_rust_import(line: str) -> bool:
    return bool(_RUST_IMPORT_RE.match(line))


def is_dart_import(line: str) -> bool:
    return bool(_DART_IMPORT_RE.match(line))


def detect_rust_fn(line: str) -> Optional[str]:
    m = _RUST_FN_RE.match(line)
    return m.group('name') if m else None


def detect_dart_func(line: str) -> Optional[str]:
    stripped = line.strip()
    if not stripped or '(' not in stripped:
        return None

    before_paren = stripped.split('(')[0].strip()
    words = before_paren.split()
    # Need at least 2 words: return_type/modifier + function_name
    if len(words) < 2:
        return None

    func_name = words[-1]

    # Must be a valid identifier (rejects [Foo, =bar, etc.)
    if not func_name.isidentifier():
        return None

    # Skip control-flow keywords
    if func_name in _DART_CONTROL_FLOW:
        return None

    # Reject chained method calls like variable.method(
    # Allow factory ClassName.fromJson(
    if '.' in func_name and 'factory' not in words:
        return None

    # Reject lines that are clearly not definitions
    if any(w in _DART_REJECT_PRECEDING for w in words[:-1]):
        return None

    # Reject if '=' appears before the function name (assignment / variable init)
    prefix = before_paren[:before_paren.rfind(func_name)]
    if '=' in prefix:
        return None

    return func_name.split('.')[-1] if '.' in func_name else func_name


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def analyse_file(
    path: Path,
    lang: str,
    default_file_limit: int,
    default_method_limit: int,
) -> list[Violation]:
    """Analyse a single file and return violations."""

    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError as exc:
        print(f"warning: cannot read {path}: {exc}", file=sys.stderr)
        return []

    is_import = is_rust_import if lang == 'rust' else is_dart_import
    detect_func = detect_rust_fn if lang == 'rust' else detect_dart_func

    violations: list[Violation] = []

    # --- file-level override ---
    file_limit = default_file_limit
    for line in lines[:20]:
        ov = parse_override(line, 'max-file-lines')
        if ov is not None:
            file_limit = ov
            break

    # --- Rust: split production / test portions ---
    if lang == 'rust':
        cfg_test_idx: Optional[int] = None
        for i, line in enumerate(lines):
            if _RUST_CFG_TEST_RE.match(line):
                cfg_test_idx = i
                break

        if cfg_test_idx is not None:
            prod_lines = lines[:cfg_test_idx]
            test_lines = lines[cfg_test_idx:]
            violations.extend(
                _check_portion(path, prod_lines, 0, is_import, detect_func,
                               file_limit, default_method_limit, 'production')
            )
            violations.extend(
                _check_portion(path, test_lines, cfg_test_idx, is_import, detect_func,
                               file_limit, default_method_limit, 'test')
            )
        else:
            violations.extend(
                _check_portion(path, lines, 0, is_import, detect_func,
                               file_limit, default_method_limit, None)
            )
    else:
        violations.extend(
            _check_portion(path, lines, 0, is_import, detect_func,
                           file_limit, default_method_limit, None)
        )

    return violations


def _check_portion(
    path: Path,
    lines: list[str],
    offset: int,
    is_import,
    detect_func,
    file_limit: int,
    default_method_limit: int,
    portion_label: Optional[str],
) -> list[Violation]:
    violations: list[Violation] = []

    # --- 1. File line count (excluding imports) ---
    non_import_count = sum(1 for l in lines if not is_import(l))
    if non_import_count > file_limit:
        label = f"{path.name}"
        if portion_label:
            label += f" ({portion_label})"
        violations.append(Violation(
            file=str(path),
            line=offset + 1,
            kind='file',
            name=label,
            count=non_import_count,
            limit=file_limit,
        ))

    # --- 2. Function / method line counts ---
    depth = 0
    # Stack: [(name, start_line_0based, base_depth, method_limit)]
    func_stack: list[tuple[str, int, int, int]] = []
    pending_method_override: Optional[int] = None

    for i, raw_line in enumerate(lines):
        abs_line = offset + i

        # Check for method-level override comment
        ov = parse_override(raw_line, 'max-method-lines')
        if ov is not None:
            pending_method_override = ov

        # Detect function start
        func_name = detect_func(raw_line)
        if func_name is not None:
            mlimit = pending_method_override or default_method_limit
            func_stack.append((func_name, abs_line, depth, mlimit))
            pending_method_override = None
        elif ov is None:
            # Reset pending override only if this line has neither an override
            # comment nor a function definition.
            pending_method_override = None

        # Count braces (with string/comment stripping)
        safe = strip_strings_for_braces(raw_line)
        for ch in safe:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                # Check if any tracked function closed
                while func_stack and func_stack[-1][2] == depth:
                    fname, fstart, _, mlimit = func_stack.pop()
                    count = abs_line - fstart + 1
                    if count > mlimit:
                        violations.append(Violation(
                            file=str(path),
                            line=fstart + 1,
                            kind='method',
                            name=fname,
                            count=count,
                            limit=mlimit,
                        ))

    return violations


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lang', required=True, choices=['rust', 'dart'])
    ap.add_argument('--max-file-lines', type=int, default=200)
    ap.add_argument('--max-method-lines', type=int, default=30)
    ap.add_argument('--baseline', type=Path, default=None,
                    help='JSON baseline file of known violations')
    ap.add_argument('--update-baseline', action='store_true',
                    help='Overwrite baseline with current violations and exit 0')
    ap.add_argument('--warn-only', action='store_true',
                    help='Emit violations as warnings instead of errors (never fail)')
    ap.add_argument('paths', nargs='+', help='Files or directories to scan')
    args = ap.parse_args()

    ext = '.rs' if args.lang == 'rust' else '.dart'
    targets: list[Path] = []
    for p in (Path(s) for s in args.paths):
        if p.is_file() and p.suffix == ext:
            targets.append(p)
        elif p.is_dir():
            targets.extend(sorted(p.rglob(f'*{ext}')))

    all_violations: list[Violation] = []
    for t in targets:
        all_violations.extend(
            analyse_file(t, args.lang, args.max_file_lines, args.max_method_lines)
        )

    # --- Update baseline mode ---
    if args.update_baseline:
        baseline_path = args.baseline
        if baseline_path is None:
            print("error: --baseline is required with --update-baseline", file=sys.stderr)
            sys.exit(2)
        baseline_data = [
            {'file': v.file, 'line': v.line, 'kind': v.kind,
             'name': v.name, 'count': v.count, 'limit': v.limit}
            for v in all_violations
        ]
        baseline_path.write_text(json.dumps(baseline_data, indent=2) + '\n')
        print(f"Baseline updated: {len(all_violations)} violations written to {baseline_path}")
        sys.exit(0)

    # --- Load baseline ---
    baseline: set[tuple[str, str, str]] = set()  # (file, kind, name)
    baseline_counts: dict[tuple[str, str, str], int] = {}
    if args.baseline and args.baseline.exists():
        data = json.loads(args.baseline.read_text())
        for entry in data:
            key = (entry['file'], entry['kind'], entry['name'])
            baseline.add(key)
            baseline_counts[key] = entry['count']

    # --- warn-only mode ---
    if args.warn_only:
        if all_violations:
            print(f"\n⚠️  {len(all_violations)} line-count violation(s) (warning only):")
            for v in all_violations:
                print(f"::warning file={v.file},line={v.line}::{v.kind} '{v.name}' is {v.count} lines (limit {v.limit})")
        total = len(targets)
        print(f"Line-count check passed ({total} {args.lang} files scanned, "
              f"{len(all_violations)} warning(s)).")
        sys.exit(0)

    # --- Classify violations ---
    new_violations: list[Violation] = []
    worsened_violations: list[Violation] = []
    known_violations: list[Violation] = []

    for v in all_violations:
        key = (v.file, v.kind, v.name)
        if key in baseline:
            if v.count > baseline_counts[key]:
                worsened_violations.append(v)
            else:
                known_violations.append(v)
        else:
            new_violations.append(v)

    # --- Report ---
    failures = new_violations + worsened_violations

    if known_violations:
        print(f"ℹ️  {len(known_violations)} known baseline violation(s) (not blocking).")

    if worsened_violations:
        print(f"\n{'='*60}")
        print(f"Worsened violations ({len(worsened_violations)}):")
        print(f"{'='*60}")
        for v in worsened_violations:
            key = (v.file, v.kind, v.name)
            old = baseline_counts.get(key, 0)
            print(f"  {v} (was {old} lines)")

    if new_violations:
        print(f"\n{'='*60}")
        print(f"New violations ({len(new_violations)}):")
        print(f"{'='*60}")
        for v in new_violations:
            print(f"  {v}")

    if failures:
        print(f"\n❌ {len(failures)} new/worsened violation(s) — fix or add exception comments.")
        sys.exit(1)
    else:
        total = len(targets)
        print(f"Line-count check passed ({total} {args.lang} files scanned, "
              f"{len(known_violations)} baselined).")


if __name__ == '__main__':
    main()
