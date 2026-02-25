# Agent Guidelines

<!-- Do not restructure or delete sections. Update individual values in-place when they change. -->

## Core Principles

- **Do NOT maintain backward compatibility** unless explicitly requested. Break things boldly.
- **Keep this file under 20-30 lines of instructions.** Every line competes for the agent's limited context budget (~150-200 total).

---

## Project Overview

<!-- Update this section as the project takes shape -->

**Project type:** [To be determined - e.g., web app, CLI tool, library]
**Primary language:** [To be determined]
**Key dependencies:** [To be determined]

---

## Commands

<!-- Update these as your workflow evolves - commands change frequently -->

```bash
# Docker build (run once or when Dockerfile changes)
# docker build -t gpg-bridge-dev .

# All commands below run inside Docker (named volumes cache Cargo registry between runs):
# docker run --rm -v "$PWD:/workspace" -v gpg-bridge-cargo-registry:/usr/local/cargo/registry -v gpg-bridge-cargo-git:/usr/local/cargo/git -w /workspace gpg-bridge-dev <command>

# Testing (Rust)
# docker run --rm -v "$PWD:/workspace" -v gpg-bridge-cargo-registry:/usr/local/cargo/registry -v gpg-bridge-cargo-git:/usr/local/cargo/git -w /workspace gpg-bridge-dev sh -c "cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo llvm-cov --workspace --summary-only"

# Testing (Flutter)
# docker run --rm -v "$PWD:/workspace" -v gpg-bridge-cargo-registry:/usr/local/cargo/registry -v gpg-bridge-cargo-git:/usr/local/cargo/git -w /workspace gpg-bridge-dev sh -c "cd mobile && dart format --output=none --set-exit-if-changed lib test && flutter analyze && flutter test --coverage"
```

---

## Code Conventions

<!-- Keep this minimal - let tools like linters handle formatting -->

- Follow the existing patterns in the codebase
- Prefer explicit over clever
- Delete dead code immediately
- **Build/test/lint commands run inside Docker**: `docker run --rm -v "$PWD:/workspace" -v gpg-bridge-cargo-registry:/usr/local/cargo/registry -v gpg-bridge-cargo-git:/usr/local/cargo/git -w /workspace gpg-bridge-dev <command>`
- **Git operations (commit, push, etc.) run on the host**, not inside Docker
- For any source code changes, always run format/lint or static analysis/tests/coverage commands relevant to the changed area before updating a PR
- If coverage is low for the changed area (Rust/Flutter/others), add or adjust tests and re-run until coverage improves before PR update
- If Rust source code is modified, always run inside Docker: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `cargo llvm-cov --workspace --summary-only`
- For Rust changes, include the `cargo llvm-cov --workspace --summary-only` result summary in the related PR body or PR comments
- If Flutter source code is modified, always run inside Docker: `dart format --output=none --set-exit-if-changed lib test`, `flutter analyze`, and `flutter test --coverage`

---

## Architecture

<!-- Major architecture changes MUST trigger a rewrite of this section -->

```
[Add directory structure overview when it stabilizes]
```

---

## Maintenance Notes

<!-- This section is permanent. Do not delete. -->

**Keep this file lean and current:**

1. **Remove placeholder sections** (sections still containing `[To be determined]` or `[Add your ... here]`) once you fill them in
2. **Review regularly** - stale instructions poison the agent's context
3. **CRITICAL: Keep total under 20-30 lines** - move detailed docs to separate files and reference them
4. **Update commands immediately** when workflows change
5. **Rewrite Architecture section** when major architectural changes occur
6. **Delete anything the agent can infer** from your code

**Remember:** Coding agents learn from your actual code. Only document what's truly non-obvious or critically important.

