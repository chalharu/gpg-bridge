#!/usr/bin/env python3
"""Validate SQL migration files for consistency.

Checks:
  1. Filenames follow the naming convention: YYYYMMDDNNNN_<description>.sql
  2. Sequence numbers are contiguous (no gaps)
  3. Timestamps are non-decreasing
  4. Each file is valid UTF-8 and non-empty
  5. No duplicate sequence numbers

Usage:
  python3 check-migrations.py <migrations_dir>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Expected pattern: YYYYMMDDNNNN_description.sql
_MIGRATION_RE = re.compile(
    r'^(?P<ts>\d{8})(?P<seq>\d{4})_(?P<desc>[a-z0-9_]+)\.sql$'
)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: check-migrations.py <migrations_dir>", file=sys.stderr)
        sys.exit(1)

    migrations_dir = Path(sys.argv[1])
    if not migrations_dir.is_dir():
        print(f"::error::Migrations directory not found: {migrations_dir}")
        sys.exit(1)

    sql_files = sorted(f.name for f in migrations_dir.iterdir()
                       if f.is_file() and f.suffix == '.sql')

    if not sql_files:
        print("No migration files found – nothing to check.")
        sys.exit(0)

    errors: list[str] = []

    prev_ts: str | None = None
    prev_full_seq: str | None = None
    seen_seqs: dict[str, str] = {}  # full_seq -> filename

    for filename in sql_files:
        m = _MIGRATION_RE.match(filename)
        if not m:
            errors.append(
                f"'{filename}' does not match naming convention "
                f"YYYYMMDDNNNN_description.sql (lowercase, underscores)"
            )
            continue

        ts = m.group('ts')
        seq = m.group('seq')
        full_seq = ts + seq

        # Check non-empty and valid UTF-8
        filepath = migrations_dir / filename
        try:
            content = filepath.read_text(encoding='utf-8')
            if not content.strip():
                errors.append(f"'{filename}' is empty")
        except UnicodeDecodeError:
            errors.append(f"'{filename}' is not valid UTF-8")

        # Check for duplicate sequence numbers
        if full_seq in seen_seqs:
            errors.append(
                f"Duplicate sequence {full_seq}: '{filename}' and '{seen_seqs[full_seq]}'"
            )
        seen_seqs[full_seq] = filename

        # Check timestamp ordering
        if prev_ts is not None and ts < prev_ts:
            errors.append(
                f"'{filename}' has timestamp {ts} which is before previous {prev_ts}"
            )

        # Check sequence contiguity within same timestamp group
        if prev_full_seq is not None and ts == prev_ts:
            prev_seq_num = int(prev_full_seq[-4:])
            curr_seq_num = int(seq)
            if curr_seq_num != prev_seq_num + 1:
                errors.append(
                    f"Sequence gap: expected {prev_seq_num + 1:04d} after "
                    f"'{seen_seqs[prev_full_seq]}', got {seq} in '{filename}'"
                )

        prev_ts = ts
        prev_full_seq = full_seq

    if errors:
        print(f"\n{'='*60}")
        print(f"Migration validation errors ({len(errors)}):")
        print(f"{'='*60}")
        for err in errors:
            print(f"  ❌ {err}")
            print(f"::error::{err}")
        print()
        sys.exit(1)
    else:
        print(f"Migration check passed ({len(sql_files)} files validated).")


if __name__ == '__main__':
    main()
