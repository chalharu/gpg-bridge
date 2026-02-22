---
name: resolve-jira-kan-issue
description: Resolve a Jira issue end-to-end from ISSUEID input. Use when the user asks to implement and complete a Jira issue, including clarification dialogue, code changes, commit, and pull request. Always operate on KAN project issues only, follow jira-kan for Jira operations, follow git-commit for commit execution, and follow CONTRIBUTING.md for branch and PR rules.
---

# Resolve Jira Issue (KAN)

Resolve one Jira issue from input `ISSUEID` through implementation, commit, and PR.

## Input

Required input:

- `ISSUEID` (e.g., `KAN-123`)

If missing, ask for it before any action.

## Scope and Safety

- Target project is only `KAN`.
- Reject non-`KAN-*` issue keys.
- Use `jira-kan` skill rules for all Jira reads/writes.
- For searches, always include `project = KAN`.

## End-to-End Workflow

1. Validate `ISSUEID` and fetch issue details.
2. Confirm problem statement, acceptance criteria, and constraints.
3. If missing/ambiguous, ask the user and resolve via dialogue before coding.
4. Create a **git worktree** inside the repository's `work/` directory to isolate work from the existing environment:
   - If `work/` directory does not exist, create it and add `work/.gitignore` containing `*` to prevent tracking worktree contents.
   - Run `git worktree add work/<issueid> -b <branch> main` to create a separate working directory (e.g., `work/kan-123`).
   - All subsequent implementation and checks must run inside this worktree, not the original repository.
   - Branch naming follows `CONTRIBUTING.md` and always includes `ISSUEID`:
     - `feature/<issueid>-<topic>` for feature work (e.g., `feature/kan-123-add-auth`)
     - `fix/<issueid>-<topic>` for bug fix (e.g., `fix/kan-123-token-expiry`)
     - `chore/<issueid>-<topic>` for maintenance (e.g., `chore/kan-123-update-docs`)
5. Transition the Jira issue status to `進行中`.
6. **Implement** required changes using a subagent (the "implementation agent").
   - The implementation agent must aim for **global optimization**, not minimal or narrowly scoped changes. Consider the overall codebase health, consistency, and design when making changes.
7. **Quality gate** (run by the implementation agent before requesting review):
   - Always run format/lint, static analysis, tests, and coverage commands for the changed area.
   - For Rust changes: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo llvm-cov --workspace --summary-only`.
   - For Flutter changes: `dart format --output=none --set-exit-if-changed lib test`, `flutter analyze`, `flutter test --coverage`.
   - If coverage is low for the changed area, add/adjust tests and re-run until coverage improves.
   - All checks must pass before proceeding to review.
8. **Review** using a **different** subagent (the "review agent").
   - The review agent must **never modify code**. It only inspects and reports findings.
   - If issues are found, the review agent returns a detailed list of required fixes and **rejects** (sends back) the work to the implementation agent.
9. **Rework loop**: If the review agent rejects:
   - The implementation agent fixes all reported issues.
   - Re-run the quality gate (step 7).
   - Re-submit to the review agent (step 8).
   - Repeat until the review agent approves with no remaining issues.
10. Commit changes using `git-commit` skill workflow.
11. Create pull request following `CONTRIBUTING.md` PR template requirements.
12. Report summary and PR URL.
13. Clean up: remove the git worktree (`git worktree remove work/<issueid>`) and return to `main` branch.

## Clarification Dialogue Rules

When issue details are insufficient, ask targeted questions such as:

- expected behavior and non-goals
- edge cases and failure behavior
- compatibility or migration constraints
- deadline/priority trade-offs

Do not proceed with implementation until required unknowns are resolved.

## Jira Handling Rules

- Read issue content, comments, and status before implementation.
- When work begins, transition the issue to `進行中`.
- If scope needs refinement, add concise Jira comment in `KAN`.
- When work is ready for review, update Jira with PR link and summary.
- Never update issues outside `KAN`.

## Commit Rules

Use `git-commit` skill and `CONTRIBUTING.md` Conventional Commits format:

`<type>(<scope>): <subject>`

Allowed types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`.

Prefer one logical change per commit; avoid mixed-purpose commits.

## Pull Request Rules

Follow `CONTRIBUTING.md` exactly.

GitHub operations (PR create/update/comment/search, issue comments, merge checks) must use GitHub MCP tools (`mcp_io_github_*`) only. Do not use `gh` CLI for GitHub interactions.

PR body must include:

- Why (motivation)
- What (summary of changes)
- How to test
- Impact scope
- Related issue (e.g., `Closes KAN-123`)

Ensure branch is not `main` and direct push to `main` is never used.

## Output Format

At completion, provide:

1. Resolved issue key
2. Implemented change summary
3. Commit hash and message
4. PR URL
5. Remaining risks or follow-ups
